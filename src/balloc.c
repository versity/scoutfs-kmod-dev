/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "key.h"
#include "counters.h"
#include "msg.h"
#include "block.h"
#include "btree.h"
#include "per_task.h"
#include "balloc.h"

#include "scoutfs_trace.h"

/*
 * scoutfs tracks free metadata blocks in bitmap items in allocation
 * btrees.  Most of the free metadata is operated on by the server and
 * tracked in large core trees rooted in the super block.  The server
 * moves free items from the core trees to private trees for mounts.
 *
 * Allocation is performed by btrees which are performing cow updates.
 * We can't write to stable blocks during a transaction, we can only
 * write into free space in the previous stable fs image.  This means
 * that we can't satisfy dirty block allocations with frees of
 * previously stable blocks in this transaction.  We implement this by
 * allocating from one tree and freeing into another.  They're merged as
 * the free blocks are committed and can be safely written to in the
 * next transaction.
 *
 * We're allocating and freeing blocks on behalf of btree ops by calling
 * btree ops.  This would deadlock if we always called btree ops from
 * the allocator directly, but instead we recognize recursion and have
 * the called allocator hand blknos back to its calling allocator to
 * store into btrees on its behalf.
 *
 * We use explicit allocation and writing contexts because both the
 * client and server are working on independent allocation and item
 * trees.
 */

struct item_modification {
	struct list_head entry;
	u64 blkno;
	u64 count;
	int op;
	struct scoutfs_balloc_root *root;
	struct scoutfs_balloc_root *src;
};

static bool add_item_mod(struct list_head *list, int op, u64 blkno, u64 count,
			 struct scoutfs_balloc_root *root,
			 struct scoutfs_balloc_root *src)
{
	struct item_modification *im = kmalloc(sizeof(struct item_modification),
					       GFP_NOFS);
	if (im) {
		im->blkno = blkno;
		im->count = count;
		im->op = op;
		im->root = root;
		im->src = src;
		list_add_tail(&im->entry, list);
		return true;
	}

	return false;
}

/* make room to dirty two trees of an absurdly large height */
#define MAX_BLKNOS (2 * ((32 * 2) + 1))

struct blkno_fifo {
	int first;
	int nr;
	u64 blknos[MAX_BLKNOS];
};

static inline void blkno_fifo_init(struct blkno_fifo *bf)
{
	bf->first = 0;
	bf->nr = 0;
}

static inline int blkno_fifo_nr(struct blkno_fifo *bf)
{
	BUG_ON(bf->nr < 0 || bf->nr > MAX_BLKNOS);
	return bf->nr;
}

static inline u64 blkno_fifo_out(struct blkno_fifo *bf)
{
	BUG_ON(blkno_fifo_nr(bf) == 0);
	bf->nr--;
	return bf->blknos[bf->first++];
}

static inline void blkno_fifo_in(struct blkno_fifo *bf, u64 blkno)
{
	unsigned int end = (bf->first + bf->nr) % MAX_BLKNOS;

	BUG_ON(blkno_fifo_nr(bf) == MAX_BLKNOS);
	bf->blknos[end] = blkno;
	bf->nr++;
}

struct caller_blknos {
	struct blkno_fifo free;
	struct blkno_fifo alloced;
	struct blkno_fifo freed;
};

/*
 * Find a number of next free blknos from a starting point.  We can land
 * in the end of an empty item.  If this returns 0 then nr_found have
 * been found.
 */
static int find_next_free(struct super_block *sb,
			  struct scoutfs_balloc_root *root, u64 from,
			  u64 *found, unsigned int nr_found)
{
	struct scoutfs_balloc_item_key bik;
	struct scoutfs_balloc_item_val biv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	unsigned int f = 0;
	unsigned int bit;
	u64 base;
	int ret = 0;

	while (f < nr_found) {
		base = from >> SCOUTFS_BALLOC_ITEM_BASE_SHIFT;
		bit = from & SCOUTFS_BALLOC_ITEM_BIT_MASK;
		bik.base = cpu_to_be64(base);

		ret = scoutfs_btree_next(sb, &root->root,
					 &bik, sizeof(bik), &iref);
		if (ret < 0) /* including ENOENT */
			break;

		if (iref.key_len == sizeof(bik) &&
		    iref.val_len == sizeof(biv)) {
			memcpy(&bik, iref.key, iref.key_len);
			memcpy(&biv, iref.val, iref.val_len);

			/* start from first bit in next whole item */
			if (be64_to_cpu(bik.base) != base)
				bit = 0;

			while (f < nr_found) {
				bit = find_next_bit_le(biv.bits,
						SCOUTFS_BALLOC_ITEM_BITS, bit);
				if (bit >= SCOUTFS_BALLOC_ITEM_BITS)
					break;

				found[f++] = (be64_to_cpu(bik.base) <<
					      SCOUTFS_BALLOC_ITEM_BASE_SHIFT) +
					     bit;
				bit++;
			}

			from = (be64_to_cpu(bik.base) <<
				SCOUTFS_BALLOC_ITEM_BASE_SHIFT) + bit;
			ret = 0;

		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			break;
	}

	return ret;
}

/*
 * Return the first blkno in the next item.  Because from can land in an
 * item we can return a blkno that is less than from.
 */
static int find_next_item(struct super_block *sb,
			  struct scoutfs_balloc_root *root, u64 from,
			  u64 *found)
{
	struct scoutfs_balloc_item_key bik;
	SCOUTFS_BTREE_ITEM_REF(iref);
	u64 base;
	int ret;

	base = from >> SCOUTFS_BALLOC_ITEM_BASE_SHIFT;
	bik.base = cpu_to_be64(base);

	ret = scoutfs_btree_next(sb, &root->root, &bik, sizeof(bik), &iref);
	if (ret < 0) /* including ENOENT */
		goto out;

	if (iref.key_len == sizeof(struct scoutfs_balloc_item_key) &&
	    iref.val_len == sizeof(struct scoutfs_balloc_item_val)) {
		memcpy(&bik, iref.key, iref.key_len);
		*found = be64_to_cpu(bik.base) <<
			 SCOUTFS_BALLOC_ITEM_BASE_SHIFT;
		ret = 0;
	} else {
		ret = -EIO;
	}
	scoutfs_btree_put_iref(&iref);
out:
	return ret;
}

enum {
	IM_OP_SET,
	IM_OP_SET_BULK,
	IM_OP_CLEAR,
	IM_OP_MOVE,
};

static int copy_item_bits(struct scoutfs_balloc_item_val *biv,
			  struct scoutfs_btree_item_ref *iref, int ret,
			  bool *existed)
{
	if (ret < 0) {
		if (ret == -ENOENT) {
			memset(biv, 0, sizeof(struct scoutfs_balloc_item_val));
			if (existed)
				*existed = false;
			ret = 0;
		}
	} else {
		if (iref->key_len == sizeof(struct scoutfs_balloc_item_key) &&
		    iref->val_len == sizeof(struct scoutfs_balloc_item_val)) {
			memcpy(biv, iref->val, iref->val_len);
			if (existed)
				*existed = true;
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(iref);
	}

	return ret;
}

/*
 * We can use native longs to set aligned 64bit regions, but have to use
 * individual _le calls on leading and trailing partial regions.
 */
static void bitmap_set_le(__le64 *map, int start, int nr)
{
	unsigned int full;

	while (start & 63 && nr-- > 0)
		set_bit_le(start++, map);

	if (nr > 64) {
		full = round_down(nr, 64);
		bitmap_set((long *)map, start, full);
		start += full;
		nr -= full;

	}

	while (nr-- > 0)
		set_bit_le(start++, map);
}

/*
 * Modify allocation item bits in service of the caller's operation.
 * This has to be done very carefully so that we don't deadlock in
 * recursion as btree dirtying calls back in to block allocation.
 *
 * A given btree operation can need to allocate blknos for dirty blocks
 * and free the old clean blknos.  The btree code will attempt to call
 * balloc again.  We add a per_task record of allocated and freed blknos
 * which those allocation calls use instead of calling more btree ops.
 * They then return to us and we perform the btree ops to satisfy those
 * allocations and frees that were recorded.
 *
 * Each op that cows btree blocks generates more ops to records those
 * allocations and frees.  Eventually the ops hit existing dirty blocks
 * and we can return.
 */
static int modify_items(struct super_block *sb,
			struct scoutfs_balloc_allocator *alloc,
			struct scoutfs_block_writer *wri,
			int op, u64 blkno, u64 count,
			struct scoutfs_balloc_root *root,
			struct scoutfs_balloc_root *src, u64 next_free)
{
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	struct scoutfs_balloc_item_key bik;
	struct scoutfs_balloc_item_val biv;
	struct scoutfs_balloc_item_val tmp;
	struct item_modification *im;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct caller_blknos *cb;
	unsigned int need_free;
	unsigned int nr;
	LIST_HEAD(mods);
	u64 nexts[16];
	bool existed;
	u64 base;
	int bit;
	int ret;
	int i;

	/* doing native long ops on stack bits */
	BUILD_BUG_ON(offsetof(struct scoutfs_balloc_item_val, bits) %
		     (BITS_PER_LONG / 8));

	cb = kmalloc(sizeof(struct caller_blknos), GFP_NOFS);
	if (!cb) {
		ret = -ENOMEM;
		goto out;
	}

	blkno_fifo_init(&cb->free);
	blkno_fifo_init(&cb->alloced);
	blkno_fifo_init(&cb->freed);

	scoutfs_per_task_add(&alloc->pt_caller_blknos, &pt_ent, cb);

	if (!add_item_mod(&mods, op, blkno, count, root, src)) {
		ret = -ENOENT;
		goto out;
	}

	while ((im = list_first_entry_or_null(&mods, struct item_modification,
					      entry))) {

		base = im->blkno >> SCOUTFS_BALLOC_ITEM_BASE_SHIFT;
		bik.base = cpu_to_be64(base);
		existed = false;

		if (im->op != IM_OP_SET_BULK) {
			/* get the current item to modify */
			ret = scoutfs_btree_lookup(sb, &im->root->root,
						   &bik, sizeof(bik), &iref);
			ret = copy_item_bits(&biv, &iref, ret, &existed);
			if (ret < 0)
				goto out;
			/* XXX corruption */
			BUG_ON(im->op == IM_OP_CLEAR && !existed);
		}

		/* modify the item's bit */
		bit = im->blkno & SCOUTFS_BALLOC_ITEM_BIT_MASK;
		if (im->op == IM_OP_SET) {
			set_bit_le(bit, &biv.bits);
		} else if (im->op == IM_OP_SET_BULK) {
			memset(&biv, 0, sizeof(biv));
			bitmap_set_le(biv.bits, 0, im->count);
		} else if (im->op == IM_OP_CLEAR) {
			clear_bit_le(bit, &biv.bits);
		}

		/* move just read the destination item, or in src item bits */
		if (im->op == IM_OP_MOVE) {
			ret = scoutfs_btree_lookup(sb, &im->src->root, &bik,
						   sizeof(bik), &iref);
			ret = copy_item_bits(&tmp, &iref, ret, NULL);
			if (ret < 0)
				goto out;

			/* shouldn't have free in both places */
			if (bitmap_intersects((long *)biv.bits,
					      (long *)tmp.bits,
					      SCOUTFS_BALLOC_ITEM_BITS)) {
				ret = -EIO;
				goto out;
			}
			bitmap_or((long *)biv.bits, (long *)biv.bits,
				  (long *)tmp.bits, SCOUTFS_BALLOC_ITEM_BITS);
		}

		/* make sure we have enough free blocks for btree dirtying */
		need_free = (im->root->root.height * 2) + 1;
		if (im->op == IM_OP_MOVE)
			need_free += (im->src->root.height * 2) + 1;

		/* fill free fifo for potential dirtying */
		while (blkno_fifo_nr(&cb->free) < need_free) {
			nr = min_t(int, need_free - blkno_fifo_nr(&cb->free),
				   ARRAY_SIZE(nexts));
			ret = find_next_free(sb, &alloc->alloc_root, next_free,
					     nexts, nr);
			if (ret < 0)
				goto out;

			next_free = nexts[nr - 1] + 1;
			for (i = 0; i < nr; i++)
				blkno_fifo_in(&cb->free, nexts[i]);
		}

		/*
		 * Perform the op's item modifications, we go to do the
		 * trouble of differentiating between update and
		 * insertion instead of just using force so that we
		 * don't split when we don't need to.
		 */
		if (im->op == IM_OP_CLEAR &&
		    bitmap_empty((long *)biv.bits, SCOUTFS_BALLOC_ITEM_BITS))
			ret = scoutfs_btree_delete(sb, alloc, wri,
						   &im->root->root,
						   &bik, sizeof(bik));
		else if (im->op == IM_OP_SET_BULK ||
			 (im->op == IM_OP_SET && !existed))
			ret = scoutfs_btree_insert(sb, alloc, wri,
						   &im->root->root,
						   &bik, sizeof(bik),
						   &biv, sizeof(biv));
		else if (im->op == IM_OP_MOVE && existed)
			ret = scoutfs_btree_delete(sb, alloc, wri,
						   &im->src->root,
						   &bik, sizeof(bik)) ?:
			      scoutfs_btree_update(sb, alloc, wri,
						   &im->root->root,
						   &bik, sizeof(bik),
						   &biv, sizeof(biv));
		else if (im->op == IM_OP_MOVE && !existed)
			ret = scoutfs_btree_delete(sb, alloc, wri,
						   &im->src->root,
						   &bik, sizeof(bik)) ?:
			      scoutfs_btree_insert(sb, alloc, wri,
						   &im->root->root,
						   &bik, sizeof(bik),
						   &biv, sizeof(biv));
		else
			ret = scoutfs_btree_update(sb, alloc, wri,
						   &im->root->root,
						   &bik, sizeof(bik),
						   &biv, sizeof(biv));
		if (ret < 0)
			goto out;

		/* update bit counts to reflect op */
		if (im->op == IM_OP_SET) {
			le64_add_cpu(&root->total_free, 1);
		} else if (im->op == IM_OP_SET_BULK) {
			le64_add_cpu(&root->total_free, im->count);
		} else if (im->op == IM_OP_CLEAR) {
			le64_add_cpu(&root->total_free, -1);
		} else if (im->op == IM_OP_MOVE) {
			nr = bitmap_weight((long *)biv.bits,
					   SCOUTFS_BALLOC_ITEM_BITS);
			le64_add_cpu(&root->total_free, nr);
			le64_add_cpu(&src->total_free, -nr);
		}

		list_del(&im->entry);
		kfree(im);

		/* and queue new modifications needed from btree ops */

		while (blkno_fifo_nr(&cb->alloced)) {
			if (!add_item_mod(&mods, IM_OP_CLEAR,
					  blkno_fifo_out(&cb->alloced), 0,
					  &alloc->alloc_root, NULL)) {
				ret = -ENOENT;
				goto out;
			}
		}

		while (blkno_fifo_nr(&cb->freed)) {
			if (!add_item_mod(&mods, IM_OP_SET,
					  blkno_fifo_out(&cb->freed), 0,
					  &alloc->free_root, NULL)) {
				ret = -ENOENT;
				goto out;
			}
		}
	}

	ret = 0;
out:
	scoutfs_per_task_del(&alloc->pt_caller_blknos, &pt_ent);
	BUG_ON(ret < 0); /* dirty block refs and bits are inconsistent */
	BUG_ON(!list_empty(&mods)); /* reminder to clean up */
	kfree(cb);
	return ret;
}

void scoutfs_balloc_init(struct scoutfs_balloc_allocator *alloc,
			 struct scoutfs_balloc_root *alloc_root,
			 struct scoutfs_balloc_root *free_root)
{
	mutex_init(&alloc->mutex);
	scoutfs_per_task_init(&alloc->pt_caller_blknos);
	alloc->alloc_root = *alloc_root;
	alloc->free_root = *free_root;
}

/*
 * Add alloc items for a contiugous regions of blknos.  The starting
 * blkno must be aligned to the start of a bitmap item.  Once these are
 * added they can be used by the current transaction so the caller must
 * be very careful that they're free.
 */
int scoutfs_balloc_add_alloc_bulk(struct super_block *sb,
				  struct scoutfs_balloc_allocator *alloc,
				  struct scoutfs_block_writer *wri,
				  u64 blkno, u64 count)
{
	u64 nr;
	int ret = 0;

	mutex_lock(&alloc->mutex);
	while (count > 0) {
		nr = min_t(u64, count, SCOUTFS_BALLOC_ITEM_BITS),
		ret = modify_items(sb, alloc, wri, IM_OP_SET_BULK, blkno, nr,
				   &alloc->alloc_root, NULL, 0);
		if (ret < 0)
			break;
		blkno += nr;
		count -= nr;
	}
	mutex_unlock(&alloc->mutex);

	return ret;
}

int scoutfs_balloc_alloc(struct super_block *sb,
			 struct scoutfs_balloc_allocator *alloc,
			 struct scoutfs_block_writer *wri, u64 *blkno_ret)
{
	struct caller_blknos *cb;
	u64 next;
	int ret;

	/* if we're called by balloc then the caller works for us */
	cb = scoutfs_per_task_get(&alloc->pt_caller_blknos);
	if (cb) {
		*blkno_ret = blkno_fifo_out(&cb->free);
		blkno_fifo_in(&cb->alloced, *blkno_ret);
		return 0;
	}

	mutex_lock(&alloc->mutex);
	ret = find_next_free(sb, &alloc->alloc_root, 0, &next, 1) ?:
	      modify_items(sb, alloc, wri, IM_OP_CLEAR, next, 0,
			   &alloc->alloc_root, NULL, next + 1);
	mutex_unlock(&alloc->mutex);

	if (ret == 0)
		*blkno_ret = next;

	return ret;
}

int scoutfs_balloc_free(struct super_block *sb,
			struct scoutfs_balloc_allocator *alloc,
			struct scoutfs_block_writer *wri,
			u64 blkno)
{
	struct caller_blknos *cb;
	int ret;

	/* if we're called by balloc then the caller works for us */
	cb = scoutfs_per_task_get(&alloc->pt_caller_blknos);
	if (cb) {
		blkno_fifo_in(&cb->freed, blkno);
		return 0;
	}

	mutex_lock(&alloc->mutex);
	ret = modify_items(sb, alloc, wri, IM_OP_SET, blkno, 0,
			   &alloc->free_root, NULL, 0);
	mutex_unlock(&alloc->mutex);

	return ret;
}

/*
 * Move full items from the source to destination tree, moving at least
 * the given number of blocks but likely more.
 *
 * This has to be done very carefully because we don't want to allocate
 * dirty btree blocks from blknos in the source item that is moving.  We
 * find the first blkno in the next free item in the source tree so that
 * we can start allocating dirty btree blocks after that item.
 *
 * This will not wrap the starting from blkno if it doesn't start at 0
 * and runs out of items.  The caller is expected to deal with this.
 */
int scoutfs_balloc_move(struct super_block *sb,
			struct scoutfs_balloc_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_balloc_root *dst,
			struct scoutfs_balloc_root *src,
			u64 from, u64 at_least, u64 *next_past)
{
	u64 target;
	u64 next;
	int ret = 0;

	mutex_lock(&alloc->mutex);

	target = le64_to_cpu(dst->total_free) + at_least;

	while (le64_to_cpu(dst->total_free) < target &&
	       le64_to_cpu(src->total_free) > 0) {
		ret = find_next_item(sb, src, from, &next) ?:
		      modify_items(sb, alloc, wri, IM_OP_MOVE, next, 0,
				   dst, src,
				   next + SCOUTFS_BALLOC_ITEM_BITS);
		if (ret < 0)
			break;

		from = next + SCOUTFS_BALLOC_ITEM_BITS;
		*next_past = from;
	}

	mutex_unlock(&alloc->mutex);

	return ret;
}
