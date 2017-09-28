/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/random.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"
#include "client.h"
#include "lock.h"
#include "file.h"

/*
 * scoutfs uses block mapping items at a fixed granularity to describe
 * file data block allocations.
 *
 * Each item describes a fixed number of blocks.  To keep the overhead
 * of the items down the series of mapped blocks is encoded.  The
 * mapping items also describe offline blocks.  They can only be written
 * to newly allocated blocks with the staging ioctl.
 *
 * Free segnos and blocks are kept in bitmap items that are private to
 * nodes so they can be modified without cluster locks.
 *
 * Block allocation maintains a fixed number of allocation cursors that
 * remember the position of tasks within free regions.  This is very
 * simple and maintains contiguous allocations for simple streaming
 * writes.  It eventually won't be good enough and we'll spend
 * complexity on delalloc but we want to put that off as long as
 * possible.
 *
 * There's no unwritten extents.  As we dirty file data pages we track
 * their inodes.  Before we commit dirty metadata we write out all
 * tracked inodes.  This ensures that data is persistent before the
 * metadata that references it is visible.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - forced unmount with dirty data
 *  - direct IO
 *  - need trans around each bulk alloc
 */

/* more than enough for a few tasks per core on moderate hardware */
#define NR_CURSORS		4096
#define CURSOR_HASH_HEADS	(PAGE_SIZE / sizeof(void *) / 2)
#define CURSOR_HASH_BITS	ilog2(CURSOR_HASH_HEADS)

struct data_info {
	struct rw_semaphore alloc_rwsem;
	struct list_head cursor_lru;
	struct hlist_head cursor_hash[CURSOR_HASH_HEADS];
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

struct task_cursor {
	u64 blkno;
	struct hlist_node hnode;
	struct list_head list_head;
	struct task_struct *task;
	pid_t pid;
};

/*
 * Block mapping items and their native decoded form can be pretty big.
 * Let's allocate them to avoid blowing the stack.
 */
struct block_mapping {
	/* native representation */
	unsigned long offline[DIV_ROUND_UP(SCOUTFS_BLOCK_MAPPING_BLOCKS,
					   BITS_PER_LONG)];
	u64 blknos[SCOUTFS_BLOCK_MAPPING_BLOCKS];

	/* encoded persistent item */
	u8 encoded[SCOUTFS_BLOCK_MAPPING_MAX_BYTES];
} __packed;

/*
 * We encode u64 blknos as a vlq zigzag encoded delta from the previous
 * blkno.  zigzag moves the sign bit down into the lsb so that small
 * negative values have very few bits set.  Then vlq outputs the least
 * significant set bits into bytes in groups of 7.
 *
 *   https://en.wikipedia.org/wiki/Variable-length_quantity
 *
 * The end result is that a series of blknos, which are limited by
 * device size and often allocated near each other, are encoded with a
 * handful of bytes.
 */
static unsigned zigzag_encode(u8 *bytes, u64 prev, u64 x)
{
	unsigned pos = 0;

	x -= prev;
	/* careful, relying on shifting extending the sign bit */
	x = (x << 1) ^ ((s64)x >> 63);

	do {
		bytes[pos++] = x & 127;
		x >>= 7;
	} while (x);

	bytes[pos - 1] |= 128;

	return pos;
}

static int zigzag_decode(u64 *res, u64 prev, u8 *bytes, unsigned len)
{
	unsigned shift = 0;
	int ret = -EIO;
	u64 x = 0;
	int i;
	u8 b;

	for (i = 0; i < len; i++) {
		b = bytes[i];
		x |= (u64)(b & 127) << shift;
		if (b & 128) {
			ret = i + 1;
			break;
		}
		shift += 7;

		/* falls through to return -EIO if we run out of bytes */
	}

	x = (x >> 1) ^ (-(x & 1));
	*res = prev + x;

	return ret;
}

/*
 * Block mappings are encoded into a byte stream.
 *
 * The first byte's low bits contains the last mapping index that will
 * be decoded.
 *
 * As we walk through the encoded blocks we add control bits to the
 * current control byte for the encoding of the block: zero, offline,
 * increment from prev, or zigzag encoding.
 *
 * When the control byte is full we start filling the next byte in the
 * output as the control byte for the coming blocks.  When we zigzag
 * encode blocks we add them to the output stream.  The result is an
 * interleaving of control bytes and zigzag blocks, when they're needed.
 *
 * In practice the typical mapping will have a zigzag for the first
 * block and then the rest will be described by the control bits.
 * Regions of sparse, advancing allocations, and offline are all
 * described only by control bits, getting us down to 2 bits per block.
 */
static unsigned encode_mapping(struct block_mapping *map)
{
	unsigned shift;
	unsigned len;
	u64 blkno;
	u64 prev;
	u8 *enc;
	u8 *ctl;
	u8 last;
	int ret;
	int i;

	enc = map->encoded;
	ctl = enc++;
	len = 1;

	/* find the last set block in the mapping */
	last = SCOUTFS_BLOCK_MAPPING_BLOCKS;
	for (i = 0; i < SCOUTFS_BLOCK_MAPPING_BLOCKS; i++) {
		if (map->blknos[i] || test_bit(i, map->offline))
			last = i;
	}

	if (last == SCOUTFS_BLOCK_MAPPING_BLOCKS)
		return 0;

	/* start with 6 bits of last */
	*ctl = last;
	shift = 6;

	prev = 0;
	for (i = 0; i <= last; i++) {
		blkno = map->blknos[i];


		if (shift == 8) {
			ctl = enc++;
			len++;
			*ctl = 0;
			shift = 0;
		}


		if (blkno == prev + 1)
			*ctl |= (SCOUTFS_BLOCK_ENC_INC << shift);
		else if (test_bit(i, map->offline))
			*ctl |= (SCOUTFS_BLOCK_ENC_OFFLINE << shift);
		else if (!blkno)
			*ctl |= (SCOUTFS_BLOCK_ENC_ZERO << shift);
		else {
			*ctl |= (SCOUTFS_BLOCK_ENC_DELTA << shift);

			ret = zigzag_encode(enc, prev, blkno);
			enc += ret;
			len += ret;
		}

		shift += 2;
		if (blkno)
			prev = blkno;
	}


	return len;
}

static int decode_mapping(struct block_mapping *map, int size)
{
	unsigned ctl_bits;
	u64 blkno;
	u64 prev;
	u8 *enc;
	u8 ctl;
	u8 last;
	int ret;
	int i;

	if (size < 1 || size > SCOUTFS_BLOCK_MAPPING_MAX_BYTES)
		return -EIO;

	memset(map->blknos, 0, sizeof(map->blknos));
	memset(map->offline, 0, sizeof(map->offline));

	enc = map->encoded;
	ctl = *(enc++);
	size--;

	/* start with lsb 6 bits of last */
	last = ctl & SCOUTFS_BLOCK_MAPPING_MASK;
	ctl >>= 6;
	ctl_bits = 2;

	prev = 0;
	for (i = 0; i <= last; i++) {

		if (ctl_bits == 0) {
			if (size-- == 0)
				return -EIO;
			ctl = *(enc++);
			ctl_bits = 8;
		}


		switch(ctl & SCOUTFS_BLOCK_ENC_MASK) {
		case SCOUTFS_BLOCK_ENC_INC:
			blkno = prev + 1;
			break;
		case SCOUTFS_BLOCK_ENC_OFFLINE:
			set_bit(i, map->offline);
			blkno = 0;
			break;
		case SCOUTFS_BLOCK_ENC_ZERO:
			blkno = 0;
			break;
		case SCOUTFS_BLOCK_ENC_DELTA:
			ret = zigzag_decode(&blkno, prev, enc, size);
			/* XXX corruption, ran out of encoded bytes */
			if (ret <= 0)
				return -EIO;
			enc += ret;
			size -= ret;
			break;
		}

		ctl >>= 2;
		ctl_bits -= 2;

		map->blknos[i] = blkno;
		if (blkno)
			prev = blkno;
	}

	/* XXX corruption: didn't use up all the bytes */
	if (size != 0)
		return -EIO;

	return 0;
}

static void init_mapping_key(struct scoutfs_key_buf *key,
			     struct scoutfs_block_mapping_key *bmk,
			     u64 ino, u64 iblock)
{

	bmk->zone = SCOUTFS_FS_ZONE;
	bmk->ino = cpu_to_be64(ino);
	bmk->type = SCOUTFS_BLOCK_MAPPING_TYPE;
	bmk->base = cpu_to_be64(iblock >> SCOUTFS_BLOCK_MAPPING_SHIFT);

	scoutfs_key_init(key, bmk, sizeof(struct scoutfs_block_mapping_key));
}


static void init_free_key(struct scoutfs_key_buf *key,
			  struct scoutfs_free_bits_key *fbk, u64 node_id,
			  u64 full_bit, u8 type)
{
	fbk->zone = SCOUTFS_NODE_ZONE;
	fbk->node_id = cpu_to_be64(node_id);
	fbk->type = type;
	fbk->base = cpu_to_be64(full_bit >> SCOUTFS_FREE_BITS_SHIFT);

	scoutfs_key_init(key, fbk, sizeof(struct scoutfs_free_bits_key));
}

/*
 * Mark the given segno as allocated.  We set its bit in a free segno
 * item, possibly after creating it.
 */
static int set_segno_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key fbk = {0,};
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	int bit = 0;
	int ret;

	init_free_key(&key, &fbk, sbi->node_id, segno,
		      SCOUTFS_FREE_BITS_SEGNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, val,
					sizeof(struct scoutfs_free_bits),
					lock);
	if (ret && ret != -ENOENT)
		goto out;

	bit = segno & SCOUTFS_FREE_BITS_MASK;

	if (ret == -ENOENT) {
		memset(&frb, 0, sizeof(frb));
		set_bit_le(bit, &frb);
		ret = scoutfs_item_create(sb, &key, val);
		goto out;
	}

	if (test_and_set_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	ret = scoutfs_item_update(sb, &key, val, lock->end);
out:
	trace_scoutfs_data_set_segno_free(sb, segno, be64_to_cpu(fbk.base),
					  bit, ret);
	return ret;
}

/*
 * Create a new free blkno item with all but the given blkno marked
 * free.  We use the caller's key so they can delete it later if they
 * need to.
 */
static int create_blkno_free(struct super_block *sb, u64 blkno,
			     struct scoutfs_key_buf *key,
			     struct scoutfs_free_bits_key *fbk)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_free_bits frb;
	SCOUTFS_DECLARE_KVEC(val);
	int bit;

	init_free_key(key, fbk, sbi->node_id, blkno,
		      SCOUTFS_FREE_BITS_BLKNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));

	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	memset(&frb, 0xff, sizeof(frb));
	clear_bit_le(bit, frb.bits);

	return scoutfs_item_create(sb, key, val);
}

/*
 * Mark the first block in the segno as allocated.  This isn't a general
 * purpose bit clear.  It knows that it's only called from allocation
 * that found the bit so it won't create the segno item.
 *
 * And because it's allocating a block in the segno, it also has to
 * create a free block item that marks the rest of the blknos in segno
 * as free.
 *
 * It deletes the free segno item if it clears the last bit.
 */
static int clear_segno_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key b_fbk;
	struct scoutfs_free_bits_key fbk;
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf b_key;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	u64 blkno;
	int bit;
	int ret;

	init_free_key(&key, &fbk, sbi->node_id, segno,
		      SCOUTFS_FREE_BITS_SEGNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, val,
					sizeof(struct scoutfs_free_bits),
					lock);
	if (ret) {
		/* XXX corruption, caller saw item.. should still exist */
		if (ret == -ENOENT)
			ret = -EIO;
		goto out;
	}

	/* XXX corruption, bit couldn't have been set */
	bit = segno & SCOUTFS_FREE_BITS_MASK;
	if (!test_and_clear_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	/* create the new blkno item, we can safely delete it */
	blkno = segno << SCOUTFS_SEGMENT_BLOCK_SHIFT;
	ret = create_blkno_free(sb, blkno, &b_key, &b_fbk);
	if (ret)
		goto out;

	if (bitmap_empty((long *)frb.bits, SCOUTFS_FREE_BITS_BITS))
		ret = scoutfs_item_delete(sb, &key, lock->end);
	else
		ret = scoutfs_item_update(sb, &key, val, lock->end);
	if (ret)
		scoutfs_item_delete_dirty(sb, &b_key);
out:
	return ret;
}

/*
 * Mark the given blkno free.  Set its bit in its free blkno item,
 * possibly after creating it.  If all the bits are set we try to mark
 * its segno free and delete the blkno item.
 */
static int set_blkno_free(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key fbk;
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	u64 segno;
	int bit;
	int ret;

	/* get the specified item */
	init_free_key(&key, &fbk, sbi->node_id, blkno,
		      SCOUTFS_FREE_BITS_BLKNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, val,
					sizeof(struct scoutfs_free_bits),
					lock);
	if (ret && ret != -ENOENT)
		goto out;

	bit = blkno & SCOUTFS_FREE_BITS_MASK;

	if (ret == -ENOENT) {
		memset(&frb, 0, sizeof(frb));
		set_bit_le(bit, &frb);
		ret = scoutfs_item_create(sb, &key, val);
		goto out;
	}

	if (test_and_set_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	if (!bitmap_full((long *)frb.bits, SCOUTFS_FREE_BITS_BITS)) {
		ret = scoutfs_item_update(sb, &key, val, lock->end);
		goto out;
	}

	/* dirty so we can safely delete if set segno fails */
	ret = scoutfs_item_dirty(sb, &key, lock->end);
	if (ret)
		goto out;

	segno = blkno >> SCOUTFS_SEGMENT_BLOCK_SHIFT;
	ret = set_segno_free(sb, segno);
	if (ret)
		goto out;

	scoutfs_item_delete_dirty(sb, &key);
	ret = 0;
out:
	return ret;
}

/*
 * Mark the given blkno as allocated.  This is working on behalf of a
 * caller who just saw the item, it must exist.  We delete the free
 * blkno item if all its bits are empty.
 */
static int clear_blkno_free(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key fbk;
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	int bit;
	int ret;

	/* get the specified item */
	init_free_key(&key, &fbk, sbi->node_id, blkno,
		      SCOUTFS_FREE_BITS_BLKNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, val,
					sizeof(struct scoutfs_free_bits),
					lock);
	if (ret) {
		/* XXX corruption, bits should have existed */
		if (ret == -ENOENT)
			ret = -EIO;
		goto out;
	}

	/* XXX corruption, bit couldn't have been set */
	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	if (!test_and_clear_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	if (bitmap_empty((long *)frb.bits, SCOUTFS_FREE_BITS_BITS))
		ret = scoutfs_item_delete(sb, &key, lock->end);
	else
		ret = scoutfs_item_update(sb, &key, val, lock->end);
out:
	return ret;
}

/*
 * In each iteration iblock is the logical block and i is the index into
 * blknos array and the bit in the offline bitmap.  The iteration won't
 * advance past the last logical block.
 */
#define for_each_block(i, iblock, last)					\
	for (i = iblock & SCOUTFS_BLOCK_MAPPING_MASK;			\
	     i < SCOUTFS_BLOCK_MAPPING_BLOCKS && iblock <= (last);	\
	     i++, iblock++)

/*
 * Free blocks inside the specified logical block range.
 *
 * If 'offline' is given then blocks are freed an offline mapping is
 * left behind.
 *
 * This is the low level extent item manipulation code.  We hold and
 * release the transaction so the caller doesn't have to deal with
 * partial progress.
 */
int scoutfs_data_truncate_items(struct super_block *sb, u64 ino, u64 iblock,
				u64 len, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_key_buf last_key;
	struct scoutfs_key_buf key;
	struct scoutfs_block_mapping_key last_bmk;
	struct scoutfs_block_mapping_key bmk;
	struct block_mapping *map;
	SCOUTFS_DECLARE_KVEC(val);
	bool holding;
	bool dirtied;
	bool modified;
	u64 blkno;
	u64 last;
	int bytes;
	int ret = 0;
	int i;

	trace_scoutfs_data_truncate_items(sb, iblock, len, offline);

	if (WARN_ON_ONCE(iblock + len < iblock))
		return -EINVAL;

	map = kmalloc(sizeof(struct block_mapping), GFP_NOFS);
	if (!map)
		return -ENOMEM;

	last = iblock + len - 1;
	init_mapping_key(&last_key, &last_bmk, ino, last);

	while (iblock <= last) {
		/* find the mapping that could include iblock */
		init_mapping_key(&key, &bmk, ino, iblock);
		scoutfs_kvec_init(val, map->encoded, sizeof(map->encoded));

		ret = scoutfs_item_next(sb, &key, &last_key, val, lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ret = decode_mapping(map, ret);
		if (ret < 0)
			break;

		/* set iblock to the first in the next item inside last */
		iblock = max(iblock, be64_to_cpu(bmk.base) <<
				     SCOUTFS_BLOCK_MAPPING_SHIFT);

		holding = false;
		dirtied = false;
		modified = false;
		for_each_block(i, iblock, last) {

			blkno = map->blknos[i];

			/* don't need to do anything.. */
			if (!blkno &&
			    !!offline == !!test_bit(i, map->offline))
				continue;

			if (!holding) {
				ret = scoutfs_hold_trans(sb, SIC_TRUNC_BLOCK());
				if (ret)
					break;
				holding = true;
			}

			if (!dirtied) {
				/* dirty item with full size encoded */
				ret = scoutfs_item_update(sb, &key, val,
							  lock->end);
				if (ret)
					break;
				dirtied = true;
			}

			/* free if allocated */
			if (blkno) {
				ret = set_blkno_free(sb, blkno);
				if (ret)
					break;

				map->blknos[i] = 0;
			}

			if (offline && !test_bit(i, map->offline))
				set_bit(i, map->offline);
			else if (!offline && test_bit(i, map->offline))
				clear_bit(i, map->offline);

			modified = true;
		}

		if (modified) {
			/* update how ever much of the item we finished */
			bytes = encode_mapping(map);
			if (bytes) {
				scoutfs_kvec_init(val, map->encoded, bytes);
				scoutfs_item_update_dirty(sb, &key, val);
			} else {
				scoutfs_item_delete_dirty(sb, &key);
			}
		}

		if (holding) {
			scoutfs_release_trans(sb);
			holding = false;
		}

		if (ret)
			break;
	}

	kfree(map);
	return ret;
}

static inline struct hlist_head *cursor_head(struct data_info *datinf,
					     struct task_struct *task,
					     pid_t pid)
{
	unsigned h = hash_ptr(task, CURSOR_HASH_BITS) ^
		     hash_long(pid, CURSOR_HASH_BITS);

	return &datinf->cursor_hash[h];
}

static struct task_cursor *search_head(struct hlist_head *head,
				       struct task_struct *task, pid_t pid)
{
	struct task_cursor *curs;

	hlist_for_each_entry(curs, head, hnode) {
		if (curs->task == task && curs->pid == pid)
			return curs;
	}

	return NULL;
}

static void destroy_cursors(struct data_info *datinf)
{
	struct task_cursor *curs;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < CURSOR_HASH_HEADS; i++) {
		hlist_for_each_entry_safe(curs, tmp, &datinf->cursor_hash[i],
					  hnode) {
			hlist_del_init(&curs->hnode);
			kfree(curs);
		}
	}
}

/*
 * These cheesy cursors are only meant to encourage nice IO patterns for
 * concurrent tasks either streaming large file writes or creating lots
 * of small files.  It will do very poorly in many other situations.  To
 * do better we'd need to go further down the road to delalloc and take
 * more surrounding context into account.
 */
static struct task_cursor *get_cursor(struct data_info *datinf)
{
	struct task_struct *task = current;
	pid_t pid = current->pid;
	struct hlist_head *head;
	struct task_cursor *curs;

	head = cursor_head(datinf, task, pid);
	curs = search_head(head, task, pid);
	if (!curs) {
		curs = list_last_entry(&datinf->cursor_lru,
				       struct task_cursor, list_head);
		trace_scoutfs_data_get_cursor(curs, task, pid);
		hlist_del_init(&curs->hnode);
		curs->task = task;
		curs->pid = pid;
		hlist_add_head(&curs->hnode, head);
		curs->blkno = 0;
	}

	list_move(&curs->list_head, &datinf->cursor_lru);

	return curs;
}

static int bulk_alloc(struct super_block *sb)
{
	u64 *segnos = NULL;
	int ret = 0;
	int i;

	segnos = scoutfs_client_bulk_alloc(sb);
	if (IS_ERR(segnos)) {
		ret = PTR_ERR(segnos);
		goto out;
	}

	for (i = 0; segnos[i]; i++) {
		ret = set_segno_free(sb, segnos[i]);
		if (ret)
			break;
	}

out:
	if (!IS_ERR_OR_NULL(segnos))
		kfree(segnos);

	/* XXX don't orphan segnos on error, crash recovery with server */

	return ret;
}

/*
 * Find the free bit item that contains the blkno and return the next blkno
 * set starting with this blkno.
 *
 * Returns -ENOENT if there's no free blknos at or after the given blkno.
 */
static int find_free_blkno(struct super_block *sb, u64 blkno, u64 *blkno_ret)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key fbk;
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	int ret;
	int bit;

	init_free_key(&key, &fbk, sbi->node_id, blkno,
		      SCOUTFS_FREE_BITS_BLKNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));

	ret = scoutfs_item_lookup_exact(sb, &key, val,
					sizeof(struct scoutfs_free_bits), lock);
	if (ret < 0)
		goto out;

	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	bit = find_next_bit_le(frb.bits, SCOUTFS_FREE_BITS_BITS, bit);
	if (bit >= SCOUTFS_FREE_BITS_BITS) {
		ret = -ENOENT;
		goto out;
	}

	*blkno_ret = (be64_to_cpu(fbk.base) << SCOUTFS_FREE_BITS_SHIFT) + bit;
	ret = 0;
out:
	return ret;
}

/*
 * Find a free segno to satisfy allocation by finding the first bit set
 * in the first free segno item.
 */
static int find_free_segno(struct super_block *sb, u64 *segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits_key last_fbk;
	struct scoutfs_free_bits_key fbk;
	struct scoutfs_free_bits frb;
	struct scoutfs_key_buf last_key;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	int bit;
	int ret;

	init_free_key(&key, &fbk, sbi->node_id, 0,
		      SCOUTFS_FREE_BITS_SEGNO_TYPE);
	init_free_key(&last_key, &last_fbk, sbi->node_id, ~0,
		      SCOUTFS_FREE_BITS_SEGNO_TYPE);
	scoutfs_kvec_init(val, &frb, sizeof(struct scoutfs_free_bits));

	ret = scoutfs_item_next(sb, &key, &last_key, val, lock);
	if (ret < 0)
		goto out;

	bit = find_next_bit_le(frb.bits, SCOUTFS_FREE_BITS_BITS, 0);
	/* XXX corruption, shouldn't see empty items */
	if (bit >= SCOUTFS_FREE_BITS_BITS) {
		ret = -EIO;
		goto out;
	}

	*segno = (be64_to_cpu(fbk.base) << SCOUTFS_FREE_BITS_SHIFT) + bit;
	ret = 0;
out:
	return ret;
}

/*
 * Allocate a single block for the logical block offset in the file.
 *
 * We try to encourage contiguous allocation by having per-task cursors
 * that track blocks inside segments.  Each new allocating task will get
 * a new segment.  Lots of concurrent allocations can interleave at
 * segment granularity.
 */
static int find_alloc_block(struct super_block *sb, struct block_mapping *map,
			    struct scoutfs_key_buf *map_key,
			    unsigned map_ind, bool map_exists)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct task_cursor *curs;
	SCOUTFS_DECLARE_KVEC(val);
	int bytes;
	u64 segno;
	u64 blkno;
	int ret;

	down_write(&datinf->alloc_rwsem);

	curs = get_cursor(datinf);

	trace_scoutfs_data_find_alloc_block_curs(sb, curs, curs->blkno);

	/* try to find the next blkno in our cursor if we have one */
	if (curs->blkno) {
		ret = find_free_blkno(sb, curs->blkno, &blkno);
		if (ret < 0 && ret != -ENOENT)
			goto out;
		if (ret == 0) {
			curs->blkno = blkno;
			segno = 0;
		} else {
			curs->blkno = 0;
		}
	}

	/* try to find segnos, asking the server for more */
	while (curs->blkno == 0) {
		ret = find_free_segno(sb, &segno);
		if (ret < 0 && ret != -ENOENT)
			goto out;
		if (ret == 0) {
			blkno = segno << SCOUTFS_SEGMENT_BLOCK_SHIFT;
			curs->blkno = blkno;
			break;
		}

		ret = bulk_alloc(sb);
		if (ret < 0)
			goto out;
	}

	trace_scoutfs_data_find_alloc_block_found_seg(sb, segno, blkno);

	/* ensure that we can copy in encoded without failing */
	scoutfs_kvec_init(val, map->encoded, sizeof(map->encoded));
	if (map_exists)
		ret = scoutfs_item_update(sb, map_key, val, NULL);
	else
		ret = scoutfs_item_create(sb, map_key, val);
	if (ret)
		goto out;

	/* clear the free bit we found */
	if (segno)
		ret = clear_segno_free(sb, segno);
	else
		ret = clear_blkno_free(sb, blkno);
	if (ret)
		goto out;

	/* update the mapping */
	clear_bit(map_ind, map->offline);
	map->blknos[map_ind] = blkno;

	bytes = encode_mapping(map);
	scoutfs_kvec_init(val, map->encoded, bytes);
	scoutfs_item_update_dirty(sb, map_key, val);

	/* set cursor to next block, clearing if we finish the segment */
	curs->blkno++;
	if ((curs->blkno & SCOUTFS_FREE_BITS_MASK) == 0)
		curs->blkno = 0;

	ret = 0;
out:
	up_write(&datinf->alloc_rwsem);

	trace_scoutfs_data_find_alloc_block_ret(sb, ret);
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_block_mapping_key bmk;
	struct scoutfs_key_buf key;
	struct block_mapping *map;
	SCOUTFS_DECLARE_KVEC(val);
	bool exists;
	int ind;
	int ret;
	int i;

	map = kmalloc(sizeof(struct block_mapping), GFP_NOFS);
	if (!map)
		return -ENOMEM;

	init_mapping_key(&key, &bmk, scoutfs_ino(inode), iblock);
	scoutfs_kvec_init(val, map->encoded, sizeof(map->encoded));

	/* find the mapping item that covers the logical block */
	ret = scoutfs_item_lookup(sb, &key, val, NULL);
	if (ret < 0) {
		if (ret != -ENOENT)
			goto out;
		memset(map->blknos, 0, sizeof(map->blknos));
		memset(map->offline, 0, sizeof(map->offline));
		exists = false;
	} else {
		ret = decode_mapping(map, ret);
		if (ret < 0)
			goto out;
		exists = true;
	}

	ind = iblock & SCOUTFS_BLOCK_MAPPING_MASK;

	/* fail read and write if it's offline and we're not staging */
	if (test_bit(ind, map->offline) && !si->staging) {
		ret = -EINVAL;
		goto out;
	}

	/* try to allocate if we're writing */
	if (create && !map->blknos[ind]) {
		/*
		 * XXX can blow the transaction here.. need to back off
		 * and try again if we've already done a bulk alloc in
		 * our transaction.
		 */
		ret = find_alloc_block(sb, map, &key, ind, exists);
		if (ret)
			goto out;
	}

	/* mark the bh mapped and set the size for as many contig as we see */
	if (map->blknos[ind]) {
		for (i = 1; ind + i < SCOUTFS_BLOCK_MAPPING_BLOCKS; i++) {
			if (map->blknos[ind + i] != map->blknos[ind] + i)
				break;
		}

		map_bh(bh, inode->i_sb, map->blknos[ind]);
		bh->b_size = min_t(u64, bh->b_size, i << SCOUTFS_BLOCK_SHIFT);
		clear_buffer_new(bh);
	}

	ret = 0;
out:
	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				ret, bh->b_blocknr, bh->b_size);

	kfree(map);

	return ret;
}

static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int unlock = 1;
	int ret;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE |
				 SCOUTFS_LKF_TRYLOCK, inode, &inode_lock);
	if (ret) {
		if (ret == -EAGAIN)
			ret = AOP_TRUNCATED_PAGE;
		goto out;
	}

	ret = mpage_readpage(page, scoutfs_get_block);
	unlock = 0;

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
out:
	if (unlock)
		unlock_page(page);
	return ret;
}

static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret)
		return ret;

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
	return ret;
}

static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, scoutfs_get_block, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, scoutfs_get_block);
}

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	int ret;

	trace_scoutfs_write_begin(sb, scoutfs_ino(inode), (__u64)pos, len);

	ret = scoutfs_hold_trans(sb, SIC_WRITE_BEGIN());
	if (ret)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode, NULL);
	if (ret == 0)
		ret = block_write_begin(mapping, pos, len, flags, pagep,
					scoutfs_get_block);
	if (ret)
		scoutfs_release_trans(sb);
out:
        return ret;
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	int ret;

	trace_scoutfs_write_end(sb, scoutfs_ino(inode), page->index, (u64)pos,
				len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		if (!si->staging) {
			scoutfs_inode_set_data_seq(inode);
			scoutfs_inode_inc_data_version(inode);
		}
		/* XXX kind of a big hammer, inode life cycle needs work */
		scoutfs_update_inode_item(inode);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	return ret;
}

struct pending_fiemap {
	u64 logical;
	u64 phys;
	u64 size;
	u32 flags;
};

/*
 * The caller is iterating over mapped blocks.  We merge the current
 * pending fiemap entry with the next block if we can.  If we can't
 * merge then we fill the current entry and start on the next.  We also
 * fill the pending mapping if the caller specifically tells us that
 * this will be the last call.
 *
 * returns 0 to continue, 1 to stop, and -errno to stop with error.
 */
static int merge_or_fill(struct fiemap_extent_info *fieinfo,
			 struct pending_fiemap *pend, u64 logical, u64 phys,
			 bool offline, bool last)
{
	u32 flags = offline ? FIEMAP_EXTENT_UNKNOWN : 0;
	int ret;

	/* merge if we can, returning if we don't have to fill last */
	if (pend->logical + pend->size == logical &&
	    ((pend->phys == 0 && phys == 0) ||
	     (pend->phys + pend->size == phys)) &&
	    pend->flags == flags) {
		pend->size += SCOUTFS_BLOCK_SIZE;
		if (!last)
			return 0;
	}

	if (pend->size) {
		if (last)
			pend->flags |= FIEMAP_EXTENT_LAST;

		/* returns 1 to end, including if we passed in _LAST */
		ret = fiemap_fill_next_extent(fieinfo, pend->logical,
					      pend->phys, pend->size,
					      pend->flags);
		if (ret != 0)
			return ret;
	}

	pend->logical = logical;
	pend->phys = phys;
	pend->size = SCOUTFS_BLOCK_SIZE;
	pend->flags = flags;

	return 0;
}

/*
 * Iterate over non-zero block mapping items merging contiguous blocks and
 * filling extent entries as we cross non-contiguous boundaries.  We set
 * _LAST on the last extent and _UNKNOWN on offline extents.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_key_buf last_key;
	struct scoutfs_key_buf key;
	struct scoutfs_lock *inode_lock = NULL;
	struct block_mapping *map;
	struct pending_fiemap pend;
	struct scoutfs_block_mapping_key last_bmk;
	struct scoutfs_block_mapping_key bmk;
	SCOUTFS_DECLARE_KVEC(val);
	loff_t i_size;
	bool offline;
	u64 blk_off;
	u64 final;
	u64 logical;
	u64 phys;
	int ret;
	int i;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	map = kmalloc(sizeof(struct block_mapping), GFP_NOFS);
	if (!map)
		return -ENOMEM;

	/* initialize to impossible to merge */
	memset(&pend, 0, sizeof(pend));

	/* XXX overkill? */
	mutex_lock(&inode->i_mutex);

	/* stop at i_size, we don't allocate outside i_size */
	i_size = i_size_read(inode);
	if (i_size == 0) {
		ret = 0;
		goto out;
	}

	blk_off = start >> SCOUTFS_BLOCK_SHIFT;
	final = min_t(loff_t, i_size - 1, start + len - 1) >>
		SCOUTFS_BLOCK_SHIFT;
	init_mapping_key(&last_key, &last_bmk, ino, final);

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, 0, inode, &inode_lock);
	if (ret)
		goto out;

	while (blk_off <= final) {
		init_mapping_key(&key, &bmk, ino, blk_off);
		scoutfs_kvec_init(val, &map->encoded, sizeof(map->encoded));

		ret = scoutfs_item_next(sb, &key, &last_key, val, inode_lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ret = decode_mapping(map, ret);
		if (ret < 0)
			break;

		/* set blk_off to the first in the next item inside last */
		blk_off = max(blk_off, be64_to_cpu(bmk.base) <<
				       SCOUTFS_BLOCK_MAPPING_SHIFT);

		for_each_block(i, blk_off, final) {
			offline = !!test_bit(i, map->offline);

			/* nothing to do with sparse regions */
			if (map->blknos[i] == 0 && !offline)
				continue;

			trace_scoutfs_data_fiemap(sb, blk_off, i,
						  map->blknos[i]);

			logical = blk_off << SCOUTFS_BLOCK_SHIFT;
			phys = map->blknos[i] << SCOUTFS_BLOCK_SHIFT;

			ret = merge_or_fill(fieinfo, &pend, logical, phys,
					    offline, false);
			if (ret != 0)
				break;
		}
		if (ret != 0)
			break;
	}

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);

	if (ret == 0) {
		/* catch final last fill */
		ret = merge_or_fill(fieinfo, &pend, 0, 0, false, true);
	}
	if (ret == 1)
		ret = 0;

out:
	mutex_unlock(&inode->i_mutex);
	kfree(map);

	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.readpages		= scoutfs_readpages,
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= scoutfs_file_aio_read,
	.aio_write	= scoutfs_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= scoutfs_file_llseek,
};


int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct hlist_head *head;
	struct data_info *datinf;
	struct task_cursor *curs;
	int i;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	init_rwsem(&datinf->alloc_rwsem);
	INIT_LIST_HEAD(&datinf->cursor_lru);

	for (i = 0; i < CURSOR_HASH_HEADS; i++)
		INIT_HLIST_HEAD(&datinf->cursor_hash[i]);

	/* just allocate all of these up front */
	for (i = 0; i < NR_CURSORS; i++) {
		curs = kzalloc(sizeof(struct task_cursor), GFP_KERNEL);
		if (!curs) {
			destroy_cursors(datinf);
			kfree(datinf);
			return -ENOMEM;
		}

		curs->pid = i;

		head = cursor_head(datinf, curs->task, curs->pid);
		hlist_add_head(&curs->hnode, head);

		list_add(&curs->list_head, &datinf->cursor_lru);
	}

	sbi->data_info = datinf;

	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		destroy_cursors(datinf);
		kfree(datinf);
	}
}

/*
 * Basic correctness tests of u64 and mapping encoding.
 */
int __init scoutfs_data_test(void)
{
	u8 encoded[SCOUTFS_ZIGZAG_MAX_BYTES];
	struct block_mapping *input;
	struct block_mapping *output;
	u64 blkno;
	u8 bits;
	u64 prev;
	u64 in;
	u64 out;
	int ret;
	int len;
	int b;
	int i;

	prev = 0;
	for (i = 0; i < 10000; i++) {
		get_random_bytes_arch(&bits, sizeof(bits));
		get_random_bytes_arch(&in, sizeof(in));
		in &= (1ULL << (bits % 64)) - 1;

		len = zigzag_encode(encoded, prev, in);

		ret = zigzag_decode(&out, prev, encoded, len);

		if (ret <= 0 || ret > SCOUTFS_ZIGZAG_MAX_BYTES || in != out) {
			printk("i %d prev %llu in %llu out %llu len %d ret %d\n",
				i, prev, in, out, len, ret);

			ret = -EINVAL;
		}
		if (ret < 0)
			return ret;

		prev = out;
	}

	input = kmalloc(sizeof(struct block_mapping), GFP_KERNEL);
	output = kmalloc(sizeof(struct block_mapping), GFP_KERNEL);
	if (!input || !output) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < 1000; i++) {
		prev = 0;
		for (b = 0; b < SCOUTFS_BLOCK_MAPPING_BLOCKS; b++) {

			if (b % (64 / 2) == 0)
				get_random_bytes_arch(&in, sizeof(in));

			clear_bit(b, input->offline);

			switch(in & SCOUTFS_BLOCK_ENC_MASK) {
			case SCOUTFS_BLOCK_ENC_INC:
				blkno = prev + 1;
				break;
			case SCOUTFS_BLOCK_ENC_OFFLINE:
				set_bit(b, input->offline);
				blkno = 0;
				break;
			case SCOUTFS_BLOCK_ENC_ZERO:
				blkno = 0;
				break;
			case SCOUTFS_BLOCK_ENC_DELTA:
				get_random_bytes_arch(&bits, sizeof(bits));
				get_random_bytes_arch(&blkno, sizeof(blkno));
				blkno &= (1ULL << (bits % 64)) - 1;
				break;
			}

			input->blknos[b] = blkno;

			in >>= 2;
			if (blkno)
				prev = blkno;
		}

		len = encode_mapping(input);
		if (len >= 1 && len < SCOUTFS_BLOCK_MAPPING_MAX_BYTES)
			memcpy(output->encoded, input->encoded, len);
		ret = decode_mapping(output, len);
		if (ret) {
			printk("map len %d decoding failed %d\n", len, ret);
			ret = -EINVAL;
			goto out;
		}

		for (b = 0; b < SCOUTFS_BLOCK_MAPPING_BLOCKS; b++) {
			if (input->blknos[b] != output->blknos[b] ||
			    !!test_bit(b, input->offline) !=
			    !!test_bit(b, output->offline))
				break;
		}

		if (b < SCOUTFS_BLOCK_MAPPING_BLOCKS) {
			printk("map ind %u: in %llu %u, out %llu %u\n",
			       b, input->blknos[b], 
			       !!test_bit(b, input->offline),
			       output->blknos[b],
			       !!test_bit(b, output->offline));
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;
out:
	kfree(input);
	kfree(output);

	return ret;
}
