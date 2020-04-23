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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/sort.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "key.h"
#include "btree.h"
#include "counters.h"
#include "triggers.h"
#include "options.h"
#include "msg.h"
#include "block.h"
#include "radix.h"

#include "scoutfs_trace.h"

/*
 * scoutfs uses a cow btree to index fs metadata.
 *
 * Using a cow btree lets nodes determine the validity of cached blocks
 * based on a single root ref (blkno, seq) that is communicated through
 * locking and messaging.  As long as their cached blocks aren't
 * overwritten in the ring they can continue to use those cached blocks
 * as the newer cowed blocks continue to reference them.
 *
 * Today callers provide all the locking.  They serialize readers and
 * writers and writers and committing all the dirty blocks.
 *
 * Btree items are stored in each block as a small header with the key
 * followed by the value.  New items are allocated from the back of the
 * block towards the front. 
 *
 * A dense array of item headers after the btree block header stores the
 * offsets of the items and is kept sorted by the item's keys.  The
 * array is small enough that keeping it sorted with memmove() involves
 * a few cache lines at most.
 *
 * Parent blocks in the btree have the same format as leaf blocks.
 * There's one key for every child reference instead of having separator
 * keys between child references.  The key in a child reference contains
 * the largest key that may be found in the child subtree.  The right
 * spine of the tree has maximal keys so that they don't have to be
 * updated if we insert an item with a key greater than everything in
 * the tree.
 */

/*
 * XXX:
 *  - counters and tracing
 *  - could issue read-ahead around reads up to dirty blkno
 *  - have barrier as we cross to prevent refreshing clobbering stale reads
 *  - audit/comment that dirty blknos can wrap around ring
 *  - figure out some max transaction size so ring won't wrap in one
 *  - update the world of comments
 *  - validate structures on read?
 */

/* btree walking has a bunch of behavioural bit flags */
enum {
	 BTW_NEXT	= (1 <<  0), /* return >= key */
	 BTW_AFTER	= (1 <<  1), /* return > key */
	 BTW_PREV	= (1 <<  2), /* return <= key */
	 BTW_BEFORE	= (1 <<  3), /* return < key */
	 BTW_DIRTY	= (1 <<  4), /* cow stable blocks */
	 BTW_ALLOC	= (1 <<  5), /* allocate a new block for 0 ref */
	 BTW_INSERT	= (1 <<  6), /* walking to insert, try splitting */
	 BTW_DELETE	= (1 <<  7), /* walking to delete, try merging */
};

/* number of contiguous bytes used by the item and it's value */
static inline unsigned int len_bytes(unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item) + val_len;
}

/* number of contiguous bytes used an existing item */
static inline unsigned int item_bytes(struct scoutfs_btree_item *item)
{
	return len_bytes(le16_to_cpu(item->val_len));
}

/* total block bytes used by an item: header, item, key, value */
static inline unsigned int all_len_bytes(unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item_header) + len_bytes(val_len);
}

/*
 * The minimum number of bytes we allow in a block.  During descent to
 * modify if we see a block with fewer used bytes then we'll try to
 * merge items from neighbours.  If the neighbour also has less than the
 * min bytes then the two blocks are merged.
 *
 * This is carefully calculated so that if two blocks are merged the
 * resulting block will have at least parent min free bytes free so
 * that it's not immediately split again.
 *
 * new_used = min_used + min_used - hdr
 * new_used <= (bs - parent_min_free)
 *
 * min_used + min_used - hdr <= (bs - parent_min_free)
 * 2 * min_used <= (bs - parent_min_free - hdr)
 * min_used <= (bs - parent_min_free - hdr) / 2
 */
static inline int min_used_bytes(int block_size)
{
	return (block_size - sizeof(struct scoutfs_btree_block) -
		SCOUTFS_BTREE_PARENT_MIN_FREE_BYTES) / 2;
}

/* total block bytes used by an existing item */
static inline unsigned int all_item_bytes(struct scoutfs_btree_item *item)
{
	return all_len_bytes(le16_to_cpu(item->val_len));
}

/* number of free bytes between last item header and first item */
static inline unsigned int free_bytes(struct scoutfs_btree_block *bt)
{
	unsigned int nr = le32_to_cpu(bt->nr_items);

	return le32_to_cpu(bt->free_end) -
	       offsetof(struct scoutfs_btree_block, item_hdrs[nr]);
}

/* all bytes used by item offsets, headers, and values */
static inline unsigned int used_total(struct scoutfs_btree_block *bt)
{
	return SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block) -
	       free_bytes(bt);
}

static inline struct scoutfs_btree_item *
off_item(struct scoutfs_btree_block *bt, __le32 off)
{
	return (void *)bt + le32_to_cpu(off);
}

static inline struct scoutfs_btree_item *
pos_item(struct scoutfs_btree_block *bt, unsigned int pos)
{
	return off_item(bt, bt->item_hdrs[pos].off);
}

static inline struct scoutfs_btree_item *
last_item(struct scoutfs_btree_block *bt)
{
	return pos_item(bt, le32_to_cpu(bt->nr_items) - 1);
}

static inline struct scoutfs_key *item_key(struct scoutfs_btree_item *item)
{
	return &item->key;
}

static inline void *item_val(struct scoutfs_btree_item *item)
{
	return item->val;
}

static inline unsigned item_val_len(struct scoutfs_btree_item *item)
{
	return le16_to_cpu(item->val_len);
}

/*
 * Returns the sorted item position that an item with the given key
 * should occupy.
 *
 * It sets *cmp to the final comparison of the given key and the
 * position's item key.  This can only be -1 or 0 because we bias
 * towards returning the pos that a key should occupy.
 *
 * If the given key is greater then all items' keys then the number of
 * items can be returned.
 */
static int find_pos(struct scoutfs_btree_block *bt, struct scoutfs_key *key,
		    int *cmp)
{
	struct scoutfs_btree_item *item;
	unsigned int start = 0;
	unsigned int end = le32_to_cpu(bt->nr_items);
	unsigned int pos = 0;

	*cmp = -1;

	while (start < end) {
		pos = start + (end - start) / 2;

		item = pos_item(bt, pos);
		*cmp = scoutfs_key_compare(key, item_key(item));
		if (*cmp < 0) {
			end = pos;
		} else if (*cmp > 0) {
			start = ++pos;
			*cmp = -1;
		} else {
			break;
		}
	}

	return pos;
}

/* move a number of contigous elements from the src index to the dst index */
#define memmove_arr(arr, dst, src, nr) \
	memmove(&(arr)[dst], &(arr)[src], (nr) * sizeof(*(arr)))

/*
 * Insert a new item into the block.  The caller has made sure that
 * there's space for the item and its metadata.
 */
static void create_item(struct scoutfs_btree_block *bt, unsigned int pos,
			struct scoutfs_key *key, void *val, unsigned val_len)
{
	unsigned int nr = le32_to_cpu(bt->nr_items);
	struct scoutfs_btree_item *item;
	unsigned all_bytes;

	all_bytes = all_len_bytes(val_len);
	BUG_ON(free_bytes(bt) < all_bytes);

	if (pos < nr)
		memmove_arr(bt->item_hdrs, pos + 1, pos, nr - pos);

	le32_add_cpu(&bt->free_end, -len_bytes(val_len));
	bt->item_hdrs[pos].off = bt->free_end;
	nr++;
	bt->nr_items = cpu_to_le32(nr);

	BUG_ON(le32_to_cpu(bt->free_end) <
	       offsetof(struct scoutfs_btree_block, item_hdrs[nr]));

	item = pos_item(bt, pos);
	*item_key(item) = *key;
	item->val_len = cpu_to_le16(val_len);

	if (val_len)
		memcpy(item_val(item), val, val_len);
}

/*
 * Delete an item from a btree block.
 *
 * This moves all the headers after the item (in sort order) towards the
 * start of the header array.  It moves all the items before the removed
 * item towards the end of the block.  The items that have to be moved
 * can be anywhere in the sort order.  We first move the item region
 * and then walk the headers looking for offsets that need to be updated.
 *
 * The item motion means that callers can not hold item references
 * across item deletion.
 */
static void delete_item(struct scoutfs_btree_block *bt, unsigned int pos)
{
	unsigned int nr = le32_to_cpu(bt->nr_items);
	unsigned int updated;
	unsigned int total;
	unsigned int first;
	unsigned int bytes;
	unsigned int last;
	unsigned int off;
	int i;

	/* calculate region of items to move */
	first = le32_to_cpu(bt->free_end);
	last = le32_to_cpu(bt->item_hdrs[pos].off);
	total = last - first;
	bytes = item_bytes(pos_item(bt, pos));

	/* move items before deleted to the back of the block */
	if (total > 0) {
		/* update headers before memove overwrites deleted item */
		for (i = 0, updated = 0; i < nr && updated < total; i++) {
			off = le32_to_cpu(bt->item_hdrs[i].off);
			if (off >= first && off < last) {
				updated += item_bytes(pos_item(bt, i));
				le32_add_cpu(&bt->item_hdrs[i].off, bytes);
			}
		}
		BUG_ON(updated != total);

		memmove(off_item(bt, cpu_to_le32(first + bytes)),
			off_item(bt, cpu_to_le32(first)), total);

	}

	/* wipe deleted bytes to avoid leaking data */
	memset(off_item(bt, cpu_to_le32(first)), 0, bytes);

	if (pos < (nr - 1))
		memmove_arr(bt->item_hdrs, pos, pos + 1, nr - 1 - pos);

	le32_add_cpu(&bt->free_end, bytes);
	le32_add_cpu(&bt->nr_items, -1);
}

/*
 * Move items from a source block to a destination block.  The caller
 * tells us if we're moving from the tail of the source block right to
 * the head of the destination block, or vice versa.  We stop moving
 * once we've moved enough bytes of items.
 */
static void move_items(struct scoutfs_btree_block *dst,
		       struct scoutfs_btree_block *src, bool move_right,
		       int to_move)
{
	struct scoutfs_btree_item *from;
	unsigned int t;
	unsigned int f;

	if (move_right) {
		f = le32_to_cpu(src->nr_items) - 1;
		t = 0;
	} else {
		f = 0;
		t = le32_to_cpu(dst->nr_items);
	}

	while (f < le32_to_cpu(src->nr_items) && to_move > 0) {
		from = pos_item(src, f);

		create_item(dst, t, item_key(from), item_val(from),
			    item_val_len(from));

		to_move -= all_item_bytes(from);

		delete_item(src, f);
		if (move_right)
			f--;
		else
			t++;
	}
}

/*
 * This is used to lookup cached blocks, read blocks, cow blocks for
 * dirtying, and allocate new blocks.
 *
 * Btree blocks don't have rigid cache consistency.  We can be following
 * block references into cached blocks that are now stale or can be
 * following a stale root into blocks that have been overwritten.  If we
 * hit a block that looks stale we first invalidate the cache and retry,
 * returning -ESTALE if it still looks wrong.  The caller can retry the
 * read from a more current root or decide that this is a persistent
 * error.
 */
static int get_ref_block(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri, int flags,
			 struct scoutfs_btree_ref *ref,
			 struct scoutfs_block **bl_ret)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_block *new;
	struct scoutfs_block *new_bl = NULL;
	struct scoutfs_block *bl = NULL;
	bool retried = false;
	u64 blkno;
	u64 seq;
	int ret;

	/* always get the current block, either to return or cow from */
	if (ref && ref->blkno) {
retry:

		bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
		if (IS_ERR(bl)) {
			trace_scoutfs_btree_read_error(sb, ref);
			scoutfs_inc_counter(sb, btree_read_error);
			ret = PTR_ERR(bl);
			goto out;
		}
		bt = (void *)bl->data;

		if (!scoutfs_block_consistent_ref(sb, bl, ref->seq, ref->blkno,
						  SCOUTFS_BLOCK_MAGIC_BTREE) ||
		    scoutfs_trigger(sb, BTREE_STALE_READ)) {

			scoutfs_inc_counter(sb, btree_stale_read);

			scoutfs_block_invalidate(sb, bl);
			scoutfs_block_put(sb, bl);
			bl = NULL;

			if (!retried) {
				retried = true;
				goto retry;
			}

			ret = -ESTALE;
			goto out;
		}

		/*
		 * We need to create a new dirty copy of the block if
		 * the caller asked for it.  If the block is already
		 * dirty then we can return it.
		 */
		if (!(flags & BTW_DIRTY) ||
		    scoutfs_block_writer_is_dirty(sb, bl)) {
			ret = 0;
			goto out;
		}

	} else if (!(flags & BTW_ALLOC)) {
		ret = -ENOENT;
		goto out;
	}

	ret = scoutfs_radix_alloc(sb, alloc, wri, &blkno);
	if (ret < 0)
		goto out;

	prandom_bytes(&seq, sizeof(seq));

	new_bl = scoutfs_block_create(sb, blkno);
	if (IS_ERR(new_bl)) {
		ret = scoutfs_radix_free(sb, alloc, wri, blkno);
		BUG_ON(ret); /* radix should have been dirty */
		ret = PTR_ERR(new_bl);
		goto out;
	}
	new = (void *)new_bl->data;

	/* free old stable blkno we're about to overwrite */
	if (ref && ref->blkno) {
		ret = scoutfs_radix_free(sb, alloc, wri,
					 le64_to_cpu(ref->blkno));
		if (ret) {
			ret = scoutfs_radix_free(sb, alloc, wri, blkno);
			BUG_ON(ret); /* radix should have been dirty */
			scoutfs_block_put(sb, new_bl);
			new_bl = NULL;
			goto out;
		}
	}

	scoutfs_block_writer_mark_dirty(sb, wri, new_bl);

	trace_scoutfs_btree_dirty_block(sb, blkno, seq,
					bt ? le64_to_cpu(bt->hdr.blkno) : 0,
					bt ? le64_to_cpu(bt->hdr.seq) : 0);

	if (bt) {
		/* returning a cow of an existing block */
		memcpy(new, bt, SCOUTFS_BLOCK_SIZE);
		scoutfs_block_put(sb, bl);
	} else {
		/* returning a newly allocated block */
		memset(new, 0, SCOUTFS_BLOCK_SIZE);
		new->hdr.fsid = super->hdr.fsid;
		new->free_end = cpu_to_le32(SCOUTFS_BLOCK_SIZE);
	}
	bl = new_bl;
	bt = new;

	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(seq);
	if (ref) {
		ref->blkno = bt->hdr.blkno;
		ref->seq = bt->hdr.seq;
	}
	ret = 0;

out:
	if (ret) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	*bl_ret = bl;
	return ret;
}

/*
 * Create a new item in the parent which references the child.  The caller
 * specifies the key in the item that describes the items in the child.
 */
static void create_parent_item(struct scoutfs_btree_block *parent,
			       unsigned pos, struct scoutfs_btree_block *child,
			       struct scoutfs_key *key)
{
	struct scoutfs_btree_ref ref = {
		.blkno = child->hdr.blkno,
		.seq = child->hdr.seq,
	};

	create_item(parent, pos, key, &ref, sizeof(ref));
}

/*
 * Update the parent item that refers to a child by deleting and
 * recreating it.  Descent should have ensured that there was always
 * room for a maximal key in parents.
 */
static void update_parent_item(struct scoutfs_btree_block *parent,
			       unsigned pos, struct scoutfs_btree_block *child)
{
	struct scoutfs_btree_item *item = last_item(child);

	delete_item(parent, pos);
	create_parent_item(parent, pos, child, item_key(item));
}

/*
 * See if we need to split this block while descending for insertion so
 * that we have enough space to insert.  Parent blocks need enough space
 * for a new item and child ref if a child block splits.  Leaf blocks
 * need enough space to insert the new item with its value.
 *
 * We split to the left so that the greatest key in the existing block
 * doesn't change so we don't have to update the key in its parent item.
 *
 * Returns -errno, 0 if nothing done, or 1 if we split.
 */
static int try_split(struct super_block *sb,
		     struct scoutfs_radix_allocator *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_btree_root *root,
		     struct scoutfs_key *key, unsigned val_len,
		     struct scoutfs_btree_block *parent, unsigned pos,
		     struct scoutfs_btree_block *right)
{
	struct scoutfs_block *left_bl = NULL;
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_btree_block *left;
	struct scoutfs_btree_item *item;
	struct scoutfs_key max_key;
	unsigned int all_bytes;
	int ret;
	int err;

	if (scoutfs_option_bool(sb, Opt_btree_force_tiny_blocks))
		all_bytes = SCOUTFS_BLOCK_SIZE - SCOUTFS_BTREE_TINY_BLOCK_SIZE;
	else if (right->level)
		all_bytes = SCOUTFS_BTREE_PARENT_MIN_FREE_BYTES;
	else
		all_bytes = all_len_bytes(val_len);

	if (free_bytes(right) >= all_bytes)
		return 0;

	/* alloc split neighbour first to avoid unwinding tree growth */
	ret = get_ref_block(sb, alloc, wri, BTW_ALLOC, NULL, &left_bl);
	if (ret)
		return ret;
	left = left_bl->data;

	left->level = right->level;

	if (!parent) {
		ret = get_ref_block(sb, alloc, wri, BTW_ALLOC, NULL, &par_bl);
		if (ret) {
			err = scoutfs_radix_free(sb, alloc, wri,
						 le64_to_cpu(left->hdr.blkno));
			BUG_ON(err); /* radix should have been dirty */
			scoutfs_block_put(sb, left_bl);
			return ret;
		}
		parent = par_bl->data;

		parent->level = root->height;
		root->height++;
		root->ref.blkno = parent->hdr.blkno;
		root->ref.seq = parent->hdr.seq;

		scoutfs_key_set_ones(&max_key);

		pos = 0;
		create_parent_item(parent, pos, right, &max_key);
	}

	move_items(left, right, false, used_total(right) / 2);

	item = last_item(left);
	create_parent_item(parent, pos, left, item_key(item));

	scoutfs_block_put(sb, left_bl);
	scoutfs_block_put(sb, par_bl);

	return 1;
}

/*
 * This is called during descent for deletion when we have a parent and
 * might need to merge items from a sibling block if this block has too
 * much free space.  Eventually we'll be able to fit all of the
 * sibling's items in our free space which lets us delete the sibling
 * block.
 *
 * XXX this could more cleverly chose a merge candidate sibling
 */
static int try_merge(struct super_block *sb,
		     struct scoutfs_radix_allocator *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_btree_root *root,
		     struct scoutfs_btree_block *parent, unsigned pos,
		     struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_block *sib;
	struct scoutfs_block *sib_bl;
	struct scoutfs_btree_ref *ref;
	unsigned int min_used;
	unsigned int sib_pos;
	bool move_right;
	int to_move;
	int ret;

	BUILD_BUG_ON(min_used_bytes(SCOUTFS_BTREE_TINY_BLOCK_SIZE) < 0);

	if (scoutfs_option_bool(sb, Opt_btree_force_tiny_blocks))
		min_used = min_used_bytes(SCOUTFS_BTREE_TINY_BLOCK_SIZE);
	else
		min_used = min_used_bytes(SCOUTFS_BLOCK_SIZE);

	if (used_total(bt) >= min_used)
		return 0;

	/* move items right into our block if we have a left sibling */
	if (pos) {
		sib_pos = pos - 1;
		move_right = true;
	} else {
		sib_pos = pos + 1;
		move_right = false;
	}

	ref = item_val(pos_item(parent, sib_pos));
	ret = get_ref_block(sb, alloc, wri, BTW_DIRTY, ref, &sib_bl);
	if (ret)
		return ret;
	sib = sib_bl->data;

	if (used_total(sib) < min_used)
		to_move = used_total(sib);
	else
		to_move = min_used - used_total(bt);

	move_items(bt, sib, move_right, to_move);

	/* update our parent's item */
	if (!move_right)
		update_parent_item(parent, pos, bt);

	/* update or delete sibling's parent item */
	if (le32_to_cpu(sib->nr_items) == 0) {
		delete_item(parent, sib_pos);
		ret = scoutfs_radix_free(sb, alloc, wri,
					 le64_to_cpu(sib->hdr.blkno));
		BUG_ON(ret); /* could have dirtied alloc to avoid error */

	} else if (move_right) {
		update_parent_item(parent, sib_pos, sib);
	}

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le32_to_cpu(parent->nr_items) == 1) {
		root->height--;
		root->ref.blkno = bt->hdr.blkno;
		root->ref.seq = bt->hdr.seq;
		ret = scoutfs_radix_free(sb, alloc, wri,
					 le64_to_cpu(parent->hdr.blkno));
		BUG_ON(ret); /* could have dirtied alloc to avoid error */
	}

	scoutfs_block_put(sb, sib_bl);

	return 1;
}

/*
 * A quick and dirty verification of the btree block.  We could add a
 * lot more checks and make it only verified on read or after
 * significant events like splitting and merging.
 */
static int verify_btree_block(struct scoutfs_btree_block *bt, int level)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_item *prev = NULL;
	unsigned int bytes = 0;
	unsigned int after_off = sizeof(struct scoutfs_btree_block);
	unsigned int first_off;
	unsigned int off;
	unsigned int nr;
	unsigned int i = 0;
	int bad = 1;

	nr = le32_to_cpu(bt->nr_items);
	if (nr == 0)
		goto out;

	after_off = offsetof(struct scoutfs_btree_block, item_hdrs[nr]);
	first_off = SCOUTFS_BLOCK_SIZE;

	if (after_off > SCOUTFS_BLOCK_SIZE) {
		nr = 0;
		goto out;
	}

	for (i = 0; i < nr; i++) {
		off = le32_to_cpu(bt->item_hdrs[i].off);
		if (off >= SCOUTFS_BLOCK_SIZE || off < after_off)
			goto out;

		first_off = min(first_off, off);

		item = pos_item(bt, i);
		bytes += item_bytes(item);

		if (i > 0 && scoutfs_key_compare(item_key(item),
						 item_key(prev)) <= 0)
			goto out;

		prev = item;
	}

	if (first_off < le32_to_cpu(bt->free_end))
		goto out;

	if ((le32_to_cpu(bt->free_end) + bytes) != SCOUTFS_BLOCK_SIZE)
		goto out;

	bad = 0;
out:
	if (bad) {
		printk("bt %p blkno %llu level %d end %u nr %u (after %u bytes %u)\n",
			bt, le64_to_cpu(bt->hdr.blkno), level,
			le32_to_cpu(bt->free_end), le32_to_cpu(bt->nr_items),
			after_off, bytes);
		for (i = 0; i < nr; i++) {
			item = pos_item(bt, i);
			printk("  [%u] off %u val_len %u\n",
			       i, le32_to_cpu(bt->item_hdrs[i].off),
			       item_val_len(item));
		}
		BUG_ON(bad);
	}

	return 0;
}

/*
 * Return the leaf block that should contain the given key.  The caller
 * is responsible for searching the leaf block and performing their
 * operation.
 *
 * Iteration starting from a key can end up in a leaf that doesn't
 * contain the next item in the direction iteration.  As we descend we
 * give the caller the nearest key in the direction of iteration that
 * will land in a different leaf.
 *
 * Migrating is a special kind of dirtying that returns the parent block
 * in the walk if the leaf block is already current and doesn't need to
 * be migrated.  It's presumed that the caller is iterating over keys
 * dirtying old leaf blocks and isn't actually doing anything with the
 * blocks themselves.
 */
static int btree_walk(struct super_block *sb,
		      struct scoutfs_radix_allocator *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_btree_root *root,
		      int flags, struct scoutfs_key *key,
		      unsigned int val_len,
		      struct scoutfs_block **bl_ret,
		      struct scoutfs_key *iter_key)
{
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_block *parent = NULL;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_ref *ref;
	unsigned int level;
	unsigned int pos;
	unsigned int nr;
	int cmp;
	int ret;

	if (WARN_ON_ONCE((flags & (BTW_NEXT|BTW_PREV)) && iter_key == NULL) ||
	    WARN_ON_ONCE((flags & BTW_DIRTY) && (!alloc || !wri)))
		return -EINVAL;

restart:
	scoutfs_block_put(sb, par_bl);
	par_bl = NULL;
	parent = NULL;
	scoutfs_block_put(sb, bl);
	bl = NULL;
	bt = NULL;
	level = root->height;
	pos = 0;
	ret = 0;

	if (!root->height) {
		if (!(flags & BTW_INSERT)) {
			ret = -ENOENT;
		} else {
			ret = get_ref_block(sb, alloc, wri, BTW_ALLOC,
					    &root->ref, &bl);
			if (ret == 0) {
				bt = bl->data;
				bt->level = 0;
				root->height = 1;
			}
		}
		goto out;
	}

	ref = &root->ref;

	while(level-- > 0) {
		ret = get_ref_block(sb, alloc, wri, flags, ref, &bl);
		if (ret)
			break;
		bt = bl->data;

		/* XXX it'd be nice to make this tunable */
		ret = 0 && verify_btree_block(bt, level);
		if (ret)
			break;

		/* XXX more aggressive block verification, before ref updates? */
		if (bt->level != level) {
			scoutfs_corruption(sb, SC_BTREE_BLOCK_LEVEL,
					   corrupt_btree_block_level,
					   "root_height %u root_blkno %llu root_seq %llu blkno %llu seq %llu level %u expected %u",
					   root->height,
					   le64_to_cpu(root->ref.blkno),
					   le64_to_cpu(root->ref.seq),
					   le64_to_cpu(bt->hdr.blkno),
					   le64_to_cpu(bt->hdr.seq), bt->level,
					   level);
			ret = -EIO;
			break;
		}

		/*
		 * Splitting and merging can add or remove parents or
		 * change the pos we take through parents to reach the
		 * block with the search key.  In the rare case that we
		 * split or merge we simply restart the walk rather than
		 * try and special case modifying the path to reflect
		 * the tree changes.
		 */
		ret = 0;
		if (flags & (BTW_INSERT | BTW_DELETE))
			ret = try_split(sb, alloc, wri, root, key, val_len,
					parent, pos, bt);
		if (ret == 0 && (flags & BTW_DELETE) && parent)
			ret = try_merge(sb, alloc, wri, root, parent, pos, bt);
		if (ret > 0)
			goto restart;
		else if (ret < 0)
			break;

		/* done at the leaf */
		if (level == 0)
			break;

		nr = le32_to_cpu(bt->nr_items);

		/* Find the next child block for the search key. */
		pos = find_pos(bt, key, &cmp);
		if (pos >= nr) {
			scoutfs_corruption(sb, SC_BTREE_NO_CHILD_REF,
					   corrupt_btree_block_level,
					   "root_height %u root_blkno %llu root_seq %llu blkno %llu seq %llu level %u nr %u pos %u cmp %d",
					   root->height,
					   le64_to_cpu(root->ref.blkno),
					   le64_to_cpu(root->ref.seq),
					   le64_to_cpu(bt->hdr.blkno),
					   le64_to_cpu(bt->hdr.seq), bt->level,
					   nr, pos, cmp);
			ret = -EIO;
			break;
		}

		/* give the caller the next key to iterate towards */
		if (iter_key && (flags & BTW_NEXT) && (pos < (nr - 1))) {
			item = pos_item(bt, pos);
			*iter_key = *item_key(item);
			scoutfs_key_inc(iter_key);

		} else if (iter_key && (flags & BTW_PREV) && (pos > 0)) {
			item = pos_item(bt, pos - 1);
			*iter_key = *item_key(item);
		}

		scoutfs_block_put(sb, par_bl);
		par_bl = bl;
		parent = bt;
		bl = NULL;
		bt = NULL;

		ref = item_val(pos_item(parent, pos));
	}

out:
	scoutfs_block_put(sb, par_bl);
	if (ret) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	if (bl_ret)
		*bl_ret = bl;
	else
		scoutfs_block_put(sb, bl);

	return ret;
}

static void init_item_ref(struct scoutfs_btree_item_ref *iref,
			  struct super_block *sb,
			  struct scoutfs_block *bl,
			  struct scoutfs_btree_item *item)
{
	iref->sb = sb;
	iref->bl = bl;
	iref->key = item_key(item);
	iref->val = item_val(item);
	iref->val_len = le16_to_cpu(item->val_len);
}

void scoutfs_btree_put_iref(struct scoutfs_btree_item_ref *iref)
{
	if (!IS_ERR_OR_NULL(iref) && !IS_ERR_OR_NULL(iref->bl)) {
		scoutfs_block_put(iref->sb, iref->bl);
		memset(iref, 0, sizeof(struct scoutfs_btree_item_ref));
	}
}

/*
 * Find the item with the given key and point to it from the caller's
 * item ref.  They're given a reference to the block that they'll drop
 * when they're done.
 */
int scoutfs_btree_lookup(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	unsigned int pos;
	int cmp;
	int ret;

	if (WARN_ON_ONCE(iref->key))
		return -EINVAL;

	ret = btree_walk(sb, NULL, NULL, root, 0, key, 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		pos = find_pos(bt, key, &cmp);
		if (cmp == 0) {
			item = pos_item(bt, pos);
			init_item_ref(iref, sb, bl, item);
			ret = 0;
		} else {
			scoutfs_block_put(sb, bl);
			ret = -ENOENT;
		}

	}

	return ret;
}

static bool invalid_item(unsigned val_len)
{
	return WARN_ON_ONCE(val_len > SCOUTFS_BTREE_MAX_VAL_LEN);
}

/*
 * Insert a new item in the tree.
 *
 * 0 is returned on success.  -EEXIST is returned if the key is already
 * present in the tree.
 *
 * If no value pointer is given then the item is created with a zero
 * length value.
 */
int scoutfs_btree_insert(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int pos;
	int cmp;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		pos = find_pos(bt, key, &cmp);
		if (cmp) {
			create_item(bt, pos, key, val, val_len);
			ret = 0;
		} else {
			ret = -EEXIST;
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Update a btree item.  -ENOENT is returned if the item didn't exist.
 *
 * We don't know the existing item's value length as we first descend.
 * We assume that the new value is longer and try to split so that we
 * can insert if that's true.  If the new value is shorter than the
 * existing then the leaf might fall under the minimum watermark, but at
 * least we can do that while we simply can't insert a new longer value
 * which doesn't fit.
 */
int scoutfs_btree_update(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int pos;
	int cmp;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		pos = find_pos(bt, key, &cmp);
		if (cmp == 0) {
			delete_item(bt, pos);
			create_item(bt, pos, key, val, val_len);
			ret = 0;
		} else {
			ret = -ENOENT;
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Create an item, overwriting any item that might exist.  It's _update
 * which will insert instead of returning -ENOENT.
 */
int scoutfs_btree_force(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key,
			void *val, unsigned val_len)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int pos;
	int cmp;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		pos = find_pos(bt, key, &cmp);
		if (cmp == 0)
			delete_item(bt, pos);
		create_item(bt, pos, key, val, val_len);
		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Delete an item from the tree.  -ENOENT is returned if the key isn't
 * found.
 */
int scoutfs_btree_delete(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int pos;
	int cmp;
	int ret;

	ret = btree_walk(sb, alloc, wri, root, BTW_DELETE | BTW_DIRTY, key,
			 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		pos = find_pos(bt, key, &cmp);
		if (cmp == 0) {
			if (le32_to_cpu(bt->nr_items) == 1) {
				/* remove final empty block */
				ret = scoutfs_radix_free(sb, alloc, wri,
							 bl->blkno);
				if (ret == 0) {
					root->height = 0;
					root->ref.blkno = 0;
					root->ref.seq = 0;
				}
			} else {
				delete_item(bt, pos);
				ret = 0;
			}
		} else {
			ret = -ENOENT;
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Iterate from a key value to the next item in the direction of
 * iteration.  Callers set flags to tell which way to iterate and
 * whether the search key is inclusive, or not.
 *
 * Walking can land in a leaf that doesn't contain any items in the
 * direction of the iteration.  Walking gives us the next key to walk
 * towards in this case.  We keep trying until we run out of blocks or
 * find the next item.  This method is aggressively permissive because
 * it lets the tree shape change between each walk and allows empty
 * blocks.
 */
static int btree_iter(struct super_block *sb,struct scoutfs_btree_root *root,
		      int flags, struct scoutfs_key *key,
		      struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	struct scoutfs_key iter_key;
	struct scoutfs_key walk_key;
	int pos;
	int cmp;
	int ret;

	if (WARN_ON_ONCE(flags & BTW_DIRTY) ||
	    WARN_ON_ONCE(iref->key))
		return -EINVAL;

	walk_key = *key;

	for (;;) {
		scoutfs_key_set_zeros(&iter_key);
		ret = btree_walk(sb, NULL, NULL, root, flags, &walk_key,
				 0, &bl, &iter_key);
		if (ret < 0)
			break;
		bt = bl->data;

		pos = find_pos(bt, key, &cmp);

		/* point pos towards iteration, find_pos already for _NEXT */
		if ((flags & BTW_AFTER) && cmp == 0)
			pos++;
		else if ((flags & BTW_PREV) && cmp < 0)
			pos--;
		else if ((flags & BTW_BEFORE) && cmp == 0)
			pos--;

		/* found the next item in this leaf */
		if (pos >= 0 && pos < le32_to_cpu(bt->nr_items)) {
			item = pos_item(bt, pos);
			init_item_ref(iref, sb, bl, item);
			ret = 0;
			break;
		}

		scoutfs_block_put(sb, bl);

		/* nothing in this leaf, walk gave us a key */
		if (!scoutfs_key_is_zeros(&iter_key)) {
			walk_key = iter_key;
			continue;
		}

		ret = -ENOENT;
		break;
	}

	return ret;
}

int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_NEXT, key, iref);
}

int scoutfs_btree_after(struct super_block *sb, struct scoutfs_btree_root *root,
		        struct scoutfs_key *key,
		        struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_NEXT | BTW_AFTER, key, iref);
}

int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_PREV, key, iref);
}

int scoutfs_btree_before(struct super_block *sb,
			 struct scoutfs_btree_root *root,
		         struct scoutfs_key *key,
		         struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_PREV | BTW_BEFORE, key, iref);
}

/*
 * Ensure that the blocks that lead to the item with the given key are
 * dirty.  caller can hold a transaction to pin the dirty blocks and
 * guarantee that later updates of the item will succeed.
 *
 * <0 is returned on error, including -ENOENT if the key isn't present.
 */
int scoutfs_btree_dirty(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int cmp;
	int ret;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY, key, 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;
		find_pos(bt, key, &cmp);
		if (cmp == 0)
			ret = 0;
		else
			ret = -ENOENT;

		scoutfs_block_put(sb, bl);
	}

	return ret;
}
