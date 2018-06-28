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
#include <linux/buffer_head.h>
#include <linux/crc32c.h>
#include <linux/sort.h>
#include <linux/blkdev.h>

#include "super.h"
#include "format.h"
#include "key.h"
#include "btree.h"
#include "sort_priv.h"
#include "counters.h"
#include "triggers.h"
#include "options.h"
#include "msg.h"
#include "block.h"

#include "scoutfs_trace.h"

/*
 * scoutfs uses a cow btree in a ring of preallocated blocks to index
 * the manifest (and allocator, but mostly the manifest).
 *
 * Using a cow btree lets nodes determine the validity of cached blocks
 * based on a single root ref (blkno, seq) that is communicated through
 * locking and messaging.  As long as their cached blocks aren't
 * overwritten in the ring they can continue to use those cached blocks
 * as the newer cowed blocks continue to reference them.
 *
 * New blocks written to the btree are allocated from the tail of the
 * preallocated ring.  This avoids a fine grained persistent record of
 * free btree blocks.  It also gathers all dirty btree blocks into one
 * contiguous write.
 *
 * To ensure that newly written blocks don't overwrite previously valid
 * existing blocks in the ring we take two preventative measures.  First
 * we ensure that there are 4x the number of preallocated blocks that
 * would be needed to store the btrees.  Then, second, for every set of
 * blocks written to the current half of the ring we ensure that at
 * least half of the written blocks are cow copies of valid blocks that
 * were stored in the old half of the ring.  This ensures that the
 * current half of the ring will contain all the valid referenced btree
 * blocks by the time it fills up and wraps around to start overwriting
 * the old half of the ring.
 *
 * To find the blocks in the old half of the ring we store a migration
 * key in the super.  Whenever we need to dirty old blocks we sweep leaf
 * blocks from that key dirtying old blocks we find.
 *
 * Blocks are of a fixed size and are set to 4k to avoid multi-page
 * blocks.  This means they can be smaller than the page size and we can
 * need to pin dirty blocks and invalidate and re-read stable blocks
 * that could fall in the same page.  We use buffer heads to track
 * sub-page block state for us.  We abuse knowledge of the page cache
 * and buffer heads to cast between pointers to the blocks and the
 * buffer heads that contain reference counts of the block contents.
 *
 * We store modified blocks in a list on b_private instead of marking
 * the blocks dirty.  We don't want them written out (and possibly
 * reclaimed and re-read) before we have a chance to update their
 * checksums.  We hold an elevated bh count to avoid the buffers from
 * being removed from the pages while we have them in the list.
 *
 * Today callers provide all the locking.  They serialize readers and
 * writers and writers and committing all the dirty blocks.
 *
 * Btree items are stored in each block as a small header with the key
 * followed by the value.  New items are allocated from the back of the
 * block towards the front.  Deleted items can be reclaimed by packing
 * items towards the back of the block by walking them in reverse offset
 * order.
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

/*
 * There's one physical ring that stores the blocks for all btrees.  We
 * track the state of the ring and all its dirty blocks in this one
 * btree_info per mount/super.
 */
struct btree_info {
	struct mutex mutex;

	unsigned long cur_dirtied;
	unsigned long old_dirtied;
	struct buffer_head *first_dirty_bh;
	struct buffer_head *last_dirty_bh;
	u64 first_dirty_blkno;
	u64 first_dirty_seq;
};

#define DECLARE_BTREE_INFO(sb, name) \
	struct btree_info *name = SCOUTFS_SB(sb)->btree_info

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
	 BTW_MIGRATE	= (1 <<  8), /* don't dirty old leaf blocks */
};

/*
 * This greatest key value is stored down the right spine of the tree
 * and has to be sorted by memcmp() greater than all possible keys in
 * all btrees.
 */
static char max_key[SCOUTFS_BTREE_MAX_KEY_LEN] = {
	[0 ... (SCOUTFS_BTREE_MAX_KEY_LEN - 1)] = 0xff,
};

/* number of contiguous bytes used by the item header, key, and value */
static inline unsigned len_bytes(unsigned key_len, unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item) + key_len + val_len;
}

/* number of contiguous bytes used an existing item */
static inline unsigned int item_bytes(struct scoutfs_btree_item *item)
{
	return len_bytes(le16_to_cpu(item->key_len), le16_to_cpu(item->val_len));
}

/* total block bytes used by an item: header, item, key, value */
static inline unsigned int all_len_bytes(unsigned key_len, unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item_header) +
		len_bytes(key_len, val_len);
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
	return all_len_bytes(le16_to_cpu(item->key_len),
			     le16_to_cpu(item->val_len));
}

/* number of contig free bytes between last item header and first item */
static inline unsigned int contig_free(struct scoutfs_btree_block *bt)
{
	unsigned int nr = le16_to_cpu(bt->nr_items);

	return le16_to_cpu(bt->free_end) -
	       offsetof(struct scoutfs_btree_block, item_hdrs[nr]);
}

/* number of contig bytes free after reclaiming free amongst items */
static inline unsigned int reclaimable_free(struct scoutfs_btree_block *bt)
{
	return contig_free(bt) + le16_to_cpu(bt->free_reclaim);
}

/* all bytes used by item offsets, headers, and values */
static inline unsigned int used_total(struct scoutfs_btree_block *bt)
{
	return SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block) -
	       reclaimable_free(bt);
}

static inline struct scoutfs_btree_item *
off_item(struct scoutfs_btree_block *bt, __le16 off)
{
	return (void *)bt + le16_to_cpu(off);
}

static inline struct scoutfs_btree_item *
pos_item(struct scoutfs_btree_block *bt, unsigned int pos)
{
	return off_item(bt, bt->item_hdrs[pos].off);
}

static inline struct scoutfs_btree_item *
last_item(struct scoutfs_btree_block *bt)
{
	return pos_item(bt, le16_to_cpu(bt->nr_items) - 1);
}

static inline void *item_key(struct scoutfs_btree_item *item)
{
	return item->data;
}

static inline unsigned item_key_len(struct scoutfs_btree_item *item)
{
	return le16_to_cpu(item->key_len);
}

static inline void *item_val(struct scoutfs_btree_item *item)
{
	return item_key(item) + le16_to_cpu(item->key_len);
}

static inline unsigned item_val_len(struct scoutfs_btree_item *item)
{
	return le16_to_cpu(item->val_len);
}

static inline int cmp_keys(void *a, unsigned a_len, void *b, unsigned b_len)
{
	return memcmp(a, b, min(a_len, b_len)) ?:
	       a_len < b_len ? -1 : a_len > b_len ? 1 : 0;
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
static int find_pos(struct scoutfs_btree_block *bt, void *key, unsigned key_len,
		    int *cmp)
{
	struct scoutfs_btree_item *item;
	unsigned int start = 0;
	unsigned int end = le16_to_cpu(bt->nr_items);
	unsigned int pos = 0;

	*cmp = -1;

	while (start < end) {
		pos = start + (end - start) / 2;

		item = pos_item(bt, pos);
		*cmp = cmp_keys(key, key_len, item_key(item), item_key_len(item));
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

/*
 * A block is current if it's in the same half of the ring as the next
 * dirty block in the transaction.
 */
static bool blkno_is_current(struct scoutfs_btree_ring *bring, u64 blkno)
{
	u64 half_blkno = le64_to_cpu(bring->first_blkno) +
			 (le64_to_cpu(bring->nr_blocks) / 2);
	u64 next_blkno = le64_to_cpu(bring->first_blkno) +
			 le64_to_cpu(bring->next_block);

	return (blkno < half_blkno) == (next_blkno < half_blkno);
}

static bool first_block_in_half(struct scoutfs_btree_ring *bring)
{
	u64 block = le64_to_cpu(bring->next_block);

	return block == 0 || block == (le64_to_cpu(bring->nr_blocks) / 2);
}

/* Set next_block to the start of the other half */
static void advance_to_next_half(struct scoutfs_btree_ring *bring)
{
	u64 block = le64_to_cpu(bring->next_block);
	u64 half = le64_to_cpu(bring->nr_blocks) / 2;
	u64 offset;

	if (block >= half) {
		offset = le64_to_cpu(bring->nr_blocks) - block;
		block = 0;
	} else {
		offset = half - block;
		block = half;
	}

	bring->next_block = cpu_to_le64(block);
	le64_add_cpu(&bring->next_seq, offset);
}

static size_t super_root_offsets[] = {
	offsetof(struct scoutfs_super_block, alloc_root),
	offsetof(struct scoutfs_super_block, manifest.root),
};

#define for_each_super_root(super, i, root)				\
	for (i = 0; i < ARRAY_SIZE(super_root_offsets) &&		\
		    (root = ((void *)super + super_root_offsets[i]), 1);\
	     i++)

static bool all_roots_migrated(struct scoutfs_super_block *super)
{
	struct scoutfs_btree_root *root;
	int i;

	for_each_super_root(super, i, root) {
		if (root->migration_key_len)
			return false;
	}

	return true;
}

static int cmp_hdr_item_key(void *priv, const void *a_ptr, const void *b_ptr)
{
	struct scoutfs_btree_block *bt = priv;
	const struct scoutfs_btree_item_header *a_hdr = a_ptr;
	const struct scoutfs_btree_item_header *b_hdr = b_ptr;
	struct scoutfs_btree_item *a_item = off_item(bt, a_hdr->off);
	struct scoutfs_btree_item *b_item = off_item(bt, b_hdr->off);

	return cmp_keys(item_key(a_item), item_key_len(a_item),
		        item_key(b_item), item_key_len(b_item));
}

static int cmp_hdr_off(void *priv, const void *a_ptr, const void *b_ptr)
{
	const struct scoutfs_btree_item_header *a_hdr = a_ptr;
	const struct scoutfs_btree_item_header *b_hdr = b_ptr;

	return (int)le16_to_cpu(a_hdr->off) - (int)le16_to_cpu(b_hdr->off);
}

static void swap_hdr(void *priv, void *a_ptr, void *b_ptr, int size)
{
	struct scoutfs_btree_item_header *a_hdr = a_ptr;
	struct scoutfs_btree_item_header *b_hdr = b_ptr;

	swap(*a_hdr, *b_hdr);
}

/*
 * As items are deleted they create fragmented free space.  Even if we
 * indexed free space in the block it could still get sufficiently
 * fragmented to force a split on insertion even though the two
 * resulting blocks would have less than the minimum space consumed by
 * items.
 *
 * We don't bother implementing free space indexing and addressing that
 * corner case.  Instead we track the number of bytes that could be
 * reclaimed if we compacted the item space after the free_end offset.
 * If this additional free space would satisfy an insertion then we
 * compact the items instead of splitting the block.
 *
 * We move the free space to the center of the block by walking
 * backwards through the items in offset order and packing them towards
 * the end of the block.
 *
 * We don't have specific metadata to either walk the items in offset
 * order or to update the item offsets as we move items.  We sort the
 * item offset array to achieve both ends.  First we sort it by offset
 * so we can walk in reverse order.  As we move items we update their
 * offset and then sort by keys once we're done.
 */
static void compact_items(struct scoutfs_btree_block *bt)
{
	unsigned int nr = le16_to_cpu(bt->nr_items);
	struct scoutfs_btree_item *from;
	struct scoutfs_btree_item *to;
	unsigned int bytes;
	__le16 end;
	int i;

	sort_priv(bt, bt->item_hdrs, nr, sizeof(bt->item_hdrs[0]),
		  cmp_hdr_off, swap_hdr);

	end = cpu_to_le16(SCOUTFS_BLOCK_SIZE);

	for (i = nr - 1; i >= 0; i--) {
		from = pos_item(bt, i);

		bytes = item_bytes(from);
		le16_add_cpu(&end, -bytes);
		to = off_item(bt, end);
		bt->item_hdrs[i].off = end;

		if (from != to)
			memmove(to, from, bytes);
	}

	bt->free_end = end;
	bt->free_reclaim = 0;

	sort_priv(bt, bt->item_hdrs, nr, sizeof(bt->item_hdrs[0]),
		  cmp_hdr_item_key, swap_hdr);
}

/* move a number of contigous elements from the src index to the dst index */
#define memmove_arr(arr, dst, src, nr) \
	memmove(&(arr)[dst], &(arr)[src], (nr) * sizeof(*(arr)))

/*
 * Insert a new item into the block.  The caller has made sure that
 * there's space for the item and its metadata but we might have to
 * compact the block to make that space contiguous.
 *
 * The possibility of compaction means that callers *can not* hold item,
 * key, or value pointers across item creation.  An easy way to verify
 * this is to audit pos_item() callers.
 */
static void create_item(struct scoutfs_btree_block *bt, unsigned int pos,
			void *key, unsigned key_len, void *val,
			unsigned val_len)
{
	unsigned nr = le16_to_cpu(bt->nr_items);
	struct scoutfs_btree_item *item;
	unsigned all_bytes;

	all_bytes = all_len_bytes(key_len, val_len);
	if (contig_free(bt) < all_bytes) {
		BUG_ON(reclaimable_free(bt) < all_bytes);
		compact_items(bt);
	}

	if (pos < nr)
		memmove_arr(bt->item_hdrs, pos + 1, pos, nr - pos);

	le16_add_cpu(&bt->free_end, -len_bytes(key_len, val_len));
	bt->item_hdrs[pos].off = bt->free_end;
	nr++;
	bt->nr_items = cpu_to_le16(nr);

	BUG_ON(le16_to_cpu(bt->free_end) <
	       offsetof(struct scoutfs_btree_block, item_hdrs[nr]));

	item = pos_item(bt, pos);
	item->key_len = cpu_to_le16(key_len);
	item->val_len = cpu_to_le16(val_len);

	memcpy(item_key(item), key, key_len);
	if (val_len)
		memcpy(item_val(item), val, val_len);
}

/*
 * Delete an item from a btree block.  We record the amount of space it
 * frees to later decide if we can satisfy an insertion by compaction
 * instead of splitting.
 */
static void delete_item(struct scoutfs_btree_block *bt, unsigned int pos)
{
	struct scoutfs_btree_item *item = pos_item(bt, pos);
	unsigned int nr = le16_to_cpu(bt->nr_items);

	if (pos < (nr - 1))
		memmove_arr(bt->item_hdrs, pos, pos + 1, nr - 1 - pos);

	le16_add_cpu(&bt->free_reclaim, item_bytes(item));
	nr--;
	bt->nr_items = cpu_to_le16(nr);

	/* wipe deleted items to avoid leaking data */
	memset(item, 0, item_bytes(item));
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
		f = le16_to_cpu(src->nr_items) - 1;
		t = 0;
	} else {
		f = 0;
		t = le16_to_cpu(dst->nr_items);
	}

	while (f < le16_to_cpu(src->nr_items) && to_move > 0) {
		from = pos_item(src, f);

		create_item(dst, t, item_key(from), item_key_len(from),
			    item_val(from), item_val_len(from));

		to_move -= all_item_bytes(from);

		delete_item(src, f);
		if (move_right)
			f--;
		else
			t++;
	}
}

/*
 * This is only used after we've elevated bh reference counts.  Until we
 * drop the counts the bhs won't be removed from the page.  This lets us
 * use pointers to the block contents in the api and not have to litter
 * it with redundant containers.
 */
static struct buffer_head *virt_to_bh(void *kaddr)
{
	struct buffer_head *bh;
	struct page *page;
	long off;

	page = virt_to_page((unsigned long)kaddr);
	BUG_ON(!page_has_buffers(page));
        bh = page_buffers(page);
	BUG_ON((unsigned long)bh->b_data !=
	       ((unsigned long)kaddr & PAGE_CACHE_MASK));

	off = (unsigned long)kaddr & ~PAGE_CACHE_MASK;
        while (off >= SCOUTFS_BLOCK_SIZE) {
                bh = bh->b_this_page;
		off -= SCOUTFS_BLOCK_SIZE;
	}

	return bh;
}

static void put_btree_block(void *ptr)
{
	if (!IS_ERR_OR_NULL(ptr))
		put_bh(virt_to_bh(ptr));
}

enum {
        BH_ScoutfsChecked = BH_PrivateStart,
        BH_ScoutfsValidCrc,
};

BUFFER_FNS(ScoutfsChecked, scoutfs_checked)	/* has had crc checked */
BUFFER_FNS(ScoutfsValidCrc, scoutfs_valid_crc)	/* crc matched */


/*
 * Make sure that we've found a valid block and that it's the block that
 * we're looking for.
 */
static bool valid_referenced_block(struct super_block *sb,
				   struct scoutfs_btree_ref *ref,
				   struct scoutfs_btree_block *bt,
				   struct buffer_head *bh)
{
	smp_rmb(); /* load checked before crc */
	if (!buffer_scoutfs_checked(bh)) {
		lock_buffer(bh);
		if (!buffer_scoutfs_checked(bh)) {
			if (scoutfs_block_valid_crc(&bt->hdr))
				set_buffer_scoutfs_valid_crc(bh);
			else
				clear_buffer_scoutfs_valid_crc(bh);

			smp_wmb(); /* store crc before checked */
			set_buffer_scoutfs_checked(bh);
		}
		unlock_buffer(bh);
	}

	return buffer_scoutfs_valid_crc(bh) &&
	       scoutfs_block_valid_ref(sb, &bt->hdr, ref->seq, ref->blkno);
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
 *
 * btree callers serialize concurrent writers in a btree but not between
 * btrees.  We have to lock around the shared btree_info.  Callers do
 * lock between all btree writers and writing dirty blocks.  We don't
 * have to lock around the bti fields that are only changed by commits.
 */
static int get_ref_block(struct super_block *sb, int flags,
			 struct scoutfs_btree_ref *ref,
			 struct scoutfs_btree_block **bt_ret)
{
	DECLARE_BTREE_INFO(sb, bti);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_btree_ring *bring = &super->bring;
	struct scoutfs_btree_root *root;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_block *new;
	struct buffer_head *bh;
	bool retried = false;
	u64 blkno;
	u64 seq;
	int ret;
	int i;

	/* always get the current block, either to return or cow from */
	if (ref && ref->blkno) {
retry:
		bh = sb_bread(sb, le64_to_cpu(ref->blkno));
		if (!bh) {
			trace_scoutfs_btree_read_error(sb, ref);
			scoutfs_inc_counter(sb, btree_read_error);
			ret = -EIO;
			goto out;
		}
		bt = (void *)bh->b_data;

		if (!valid_referenced_block(sb, ref, bt, bh) ||
		    scoutfs_trigger(sb, BTREE_STALE_READ)) {

			scoutfs_inc_counter(sb, btree_stale_read);

			lock_buffer(bh);
			clear_buffer_uptodate(bh);
			clear_buffer_scoutfs_valid_crc(bh);
			smp_wmb(); /* store crc before checked */
			clear_buffer_scoutfs_checked(bh);
			unlock_buffer(bh);
			put_bh(bh);
			bt = NULL;

			if (!retried) {
				retried = true;
				goto retry;
			}

			ret = -ESTALE;
			goto out;
		}

		/* done if not dirtying or already dirty */
		if (!(flags & BTW_DIRTY) ||
		    (le64_to_cpu(bt->hdr.seq) >= bti->first_dirty_seq)) {
			ret = 0;
			goto out;
		}

	} else if (!(flags & BTW_ALLOC)) {
		ret = -ENOENT;
		goto out;
	}

	mutex_lock(&bti->mutex);

	blkno = le64_to_cpu(bring->first_blkno) + le64_to_cpu(bring->next_block);
	seq = le64_to_cpu(bring->next_seq);

	bh = sb_getblk(sb, blkno);
	if (!bh) {
		ret = -ENOMEM;
		mutex_unlock(&bti->mutex);
		goto out;
	}
	new = (void *)bh->b_data;

	set_buffer_uptodate(bh);
	set_buffer_scoutfs_checked(bh);
	set_buffer_scoutfs_valid_crc(bh);

	/*
	 * Track our contiguous dirty blocks by holding a ref and putting
	 * them in a list.  We don't want them marked dirty or else they
	 * can be written out before we're ready.
	 */
	get_bh(bh);
	bh->b_private = NULL;
	if (bti->last_dirty_bh)
		bti->last_dirty_bh->b_private = bh;
	bti->last_dirty_bh = bh;
	if (!bti->first_dirty_bh)
		bti->first_dirty_bh = bh;

	if (blkno_is_current(bring, blkno))
		bti->cur_dirtied++;
	else
		bti->old_dirtied++;

	/* wrap next block and increase next seq */
	le64_add_cpu(&bring->next_block, 1);
	le64_add_cpu(&bring->next_seq, 1);

	if (le64_to_cpu(bring->next_block) == le64_to_cpu(bring->nr_blocks))
		bring->next_block = 0;

	/* force advancing if migration's done and we didn't just wrap */
	if (all_roots_migrated(super) && !first_block_in_half(bring) &&
	    scoutfs_trigger(sb, BTREE_ADVANCE_RING_HALF))
		advance_to_next_half(bring);

	/* reset the migration keys if we've just entered a new half */
	if (first_block_in_half(bring)) {
		for_each_super_root(super, i, root) {
			memset(root->migration_key, 0,
			       sizeof(root->migration_key));
			root->migration_key_len = cpu_to_le16(1);
		}
	}

	mutex_unlock(&bti->mutex);

	if (bt) {
		/* returning a cow of an existing block */
		memcpy(new, bt, SCOUTFS_BLOCK_SIZE);
		put_btree_block(bt);
		bt = new;
	} else {
		/* returning a newly allocated block */
		bt = new;
		new = NULL;
		memset(bt, 0, SCOUTFS_BLOCK_SIZE);
		bt->hdr.fsid = super->hdr.fsid;
		bt->free_end = cpu_to_le16(SCOUTFS_BLOCK_SIZE);
	}

	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(seq);
	if (ref) {
		ref->blkno = bt->hdr.blkno;
		ref->seq = bt->hdr.seq;
	}
	ret = 0;

out:
	if (ret) {
		put_btree_block(bt);
		bt = NULL;
	}

	*bt_ret = bt;
	return ret;
}

/*
 * Create a new item in the parent which references the child.  The caller
 * specifies the key in the item that describes the items in the child.
 */
static void create_parent_item(struct scoutfs_btree_ring *bring,
			       struct scoutfs_btree_block *parent,
			       unsigned pos, struct scoutfs_btree_block *child,
			       void *key, unsigned key_len)
{
	struct scoutfs_btree_ref ref = {
		.blkno = child->hdr.blkno,
		.seq = child->hdr.seq,
	};

	create_item(parent, pos, key, key_len, &ref, sizeof(ref));
}

/*
 * Update the parent item that refers to a child by deleting and
 * recreating it.  Descent should have ensured that there was always
 * room for a maximal key in parents.
 */
static void update_parent_item(struct scoutfs_btree_ring *bring,
			       struct scoutfs_btree_block *parent,
			       unsigned pos, struct scoutfs_btree_block *child)
{
	struct scoutfs_btree_item *item = last_item(child);

	delete_item(parent, pos);
	create_parent_item(bring, parent, pos, child,
			   item_key(item), item_key_len(item));
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
static int try_split(struct super_block *sb, struct scoutfs_btree_root *root,
		     void *key, unsigned key_len, unsigned val_len,
		     struct scoutfs_btree_block *parent, unsigned pos,
		     struct scoutfs_btree_block *right)
{
	struct scoutfs_btree_ring *bring = &SCOUTFS_SB(sb)->super.bring;
	struct scoutfs_btree_block *left = NULL;
	struct scoutfs_btree_item *item;
	unsigned int all_bytes;
	bool put_parent = false;
	int ret;

	if (scoutfs_option_bool(sb, Opt_btree_force_tiny_blocks))
		all_bytes = SCOUTFS_BLOCK_SIZE - SCOUTFS_BTREE_TINY_BLOCK_SIZE;
	else if (right->level)
		all_bytes = SCOUTFS_BTREE_PARENT_MIN_FREE_BYTES;
	else
		all_bytes = all_len_bytes(key_len, val_len);

	if (reclaimable_free(right) >= all_bytes)
		return 0;

	/* alloc split neighbour first to avoid unwinding tree growth */
	ret = get_ref_block(sb, BTW_ALLOC, NULL, &left);
	if (ret)
		return ret;
	left->level = right->level;

	if (!parent) {
		ret = get_ref_block(sb, BTW_ALLOC, NULL, &parent);
		if (ret) {
			put_btree_block(left);
			return ret;
		}
		put_parent = true;

		parent->level = root->height;
		root->height++;
		root->ref.blkno = parent->hdr.blkno;
		root->ref.seq = parent->hdr.seq;

		pos = 0;
		create_parent_item(bring, parent, pos, right,
				   &max_key, sizeof(max_key));
	}

	move_items(left, right, false, used_total(right) / 2);

	item = last_item(left);
	create_parent_item(bring, parent, pos, left,
			   item_key(item), item_key_len(item));

	put_btree_block(left);
	if (put_parent)
		put_btree_block(parent);

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
static int try_merge(struct super_block *sb, struct scoutfs_btree_root *root,
		     struct scoutfs_btree_block *parent, unsigned pos,
		     struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_ring *bring = &SCOUTFS_SB(sb)->super.bring;
	struct scoutfs_btree_block *sib;
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
	ret = get_ref_block(sb, BTW_DIRTY, ref, &sib);
	if (ret)
		return ret;

	if (used_total(sib) < min_used)
		to_move = used_total(sib);
	else
		to_move = min_used - used_total(bt);

	move_items(bt, sib, move_right, to_move);

	/* update our parent's item */
	if (!move_right)
		update_parent_item(bring, parent, pos, bt);

	/* update or delete sibling's parent item */
	if (le16_to_cpu(sib->nr_items) == 0)
		delete_item(parent, sib_pos);
	else if (move_right)
		update_parent_item(bring, parent, sib_pos, sib);

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le16_to_cpu(parent->nr_items) == 1) {
		root->height--;
		root->ref.blkno = bt->hdr.blkno;
		root->ref.seq = bt->hdr.seq;
	}

	put_btree_block(sib);

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
	struct scoutfs_btree_item *prev;
	unsigned int bytes = 0;
	unsigned int after_off = sizeof(struct scoutfs_btree_block);
	unsigned int first_off;
	unsigned int off;
	unsigned int nr;
	unsigned int i = 0;
	int bad = 1;

	nr = le16_to_cpu(bt->nr_items);
	if (nr == 0)
		goto out;

	after_off = offsetof(struct scoutfs_btree_block, item_hdrs[nr]);
	first_off = SCOUTFS_BLOCK_SIZE;

	if (after_off > SCOUTFS_BLOCK_SIZE) {
		nr = 0;
		goto out;
	}

	for (i = 0; i < nr; i++) {
		off = le16_to_cpu(bt->item_hdrs[i].off);
		if (off >= SCOUTFS_BLOCK_SIZE || off < after_off)
			goto out;

		first_off = min(first_off, off);

		item = pos_item(bt, i);
		bytes += item_bytes(item);

		if (i > 0 && cmp_keys(item_key(item), item_key_len(item),
				      item_key(prev), item_key_len(prev)) <= 0)
			goto out;

		prev = item;
	}

	if (first_off < le16_to_cpu(bt->free_end))
		goto out;

	if ((le16_to_cpu(bt->free_end) + bytes +
	     le16_to_cpu(bt->free_reclaim)) != SCOUTFS_BLOCK_SIZE)
		goto out;

	bad = 0;
out:
	if (bad) {
		printk("bt %p blkno %llu level %d end %u reclaim %u nr %u (after %u bytes %u)\n",
			bt, le64_to_cpu(bt->hdr.blkno), level,
			le16_to_cpu(bt->free_end),
			le16_to_cpu(bt->free_reclaim), le16_to_cpu(bt->nr_items),
			after_off, bytes);
		for (i = 0; i < nr; i++) {
			item = pos_item(bt, i);
			printk("  [%u] off %u key_len %u val_len %u\n",
			       i, le16_to_cpu(bt->item_hdrs[i].off),
			       item_key_len(item), item_val_len(item));
		}
		BUG_ON(bad);
	}

	return 0;
}

/* XXX bleh, this should probably share code with the key_buf equivalent */
static void inc_key(u8 *bytes, unsigned *len)
{
	int i;

	if (*len < SCOUTFS_BTREE_MAX_KEY_LEN) {
		memset(bytes + *len, 0, SCOUTFS_BTREE_MAX_KEY_LEN - *len);
		*len = SCOUTFS_BTREE_MAX_KEY_LEN;
	}

	for (i = *len - 1; i >= 0; i--) {
		if (++bytes[i] != 0)
			break;
	}
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
static int btree_walk(struct super_block *sb, struct scoutfs_btree_root *root,
		      int flags, void *key, unsigned key_len,
		      unsigned int val_len,
		      struct scoutfs_btree_block **bt_ret, void *iter_key,
		      unsigned *iter_len)
{
	struct scoutfs_btree_ring *bring = &SCOUTFS_SB(sb)->super.bring;
	struct scoutfs_btree_block *parent = NULL;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_ref *ref;
	unsigned level;
	unsigned pos;
	unsigned nr;
	int cmp;
	int ret;

	if (WARN_ON_ONCE((flags & (BTW_NEXT|BTW_PREV)) && iter_key == NULL))
		return -EINVAL;

restart:
	put_btree_block(parent);
	parent = NULL;
	put_btree_block(bt);
	bt = NULL;
	level = root->height;
	if (iter_len)
		*iter_len = 0;
	pos = 0;
	ret = 0;

	if (!root->height) {
		if (!(flags & BTW_INSERT)) {
			ret = -ENOENT;
		} else {
			ret = get_ref_block(sb, BTW_ALLOC, &root->ref, &bt);
			if (ret == 0) {
				bt->level = 0;
				root->height = 1;
			}
		}
		goto out;
	}

	ref = &root->ref;

	while(level-- > 0) {
		/* no point in dirtying current leaf blocks for migration */
		if ((flags & BTW_MIGRATE) && level == 0 &&
		    blkno_is_current(bring, le64_to_cpu(ref->blkno))) {
			ret = 0;
			break;
		}

		ret = get_ref_block(sb, flags, ref, &bt);
		if (ret)
			break;

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
			ret = try_split(sb, root, key, key_len, val_len,
					parent, pos, bt);
		if (ret == 0 && (flags & BTW_DELETE) && parent)
			ret = try_merge(sb, root, parent, pos, bt);
		if (ret > 0)
			goto restart;
		else if (ret < 0)
			break;

		/* done at the leaf */
		if (level == 0)
			break;

		nr = le16_to_cpu(bt->nr_items);

		/* Find the next child block for the search key. */
		pos = find_pos(bt, key, key_len, &cmp);
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
			*iter_len = item_key_len(item);
			memcpy(iter_key, item_key(item), *iter_len);
			inc_key(iter_key, iter_len);

		} else if (iter_key && (flags & BTW_PREV) && (pos > 0)) {
			item = pos_item(bt, pos - 1);
			*iter_len = item_key_len(item);
			memcpy(iter_key, item_key(item), *iter_len);
		}

		put_btree_block(parent);
		parent = bt;
		bt = NULL;

		ref = item_val(pos_item(parent, pos));
	}

out:
	put_btree_block(parent);
	if (ret) {
		put_btree_block(bt);
		bt = NULL;
	}

	if (bt_ret)
		*bt_ret = bt;
	else
		put_btree_block(bt);

	return ret;
}

static void init_item_ref(struct scoutfs_btree_item_ref *iref,
			  struct scoutfs_btree_item *item)
{
	iref->key = item_key(item);
	iref->key_len = le16_to_cpu(item->key_len);
	iref->val = item_val(item);
	iref->val_len = le16_to_cpu(item->val_len);
}

void scoutfs_btree_put_iref(struct scoutfs_btree_item_ref *iref)
{
	if (!IS_ERR_OR_NULL(iref) && !IS_ERR_OR_NULL(iref->key)) {
		put_btree_block(iref->key);
		memset(iref, 0, sizeof(struct scoutfs_btree_item_ref));
	}
}

/*
 * Find the item with the given key and point to it from the caller's
 * item ref.  They're given a reference to the block that they'll drop
 * when they're done.
 */
int scoutfs_btree_lookup(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	unsigned int pos;
	int cmp;
	int ret;

	if (WARN_ON_ONCE(iref->key))
		return -EINVAL;

	ret = btree_walk(sb, root, 0, key, key_len, 0, &bt, NULL, NULL);
	if (ret == 0) {
		pos = find_pos(bt, key, key_len, &cmp);
		if (cmp == 0) {
			item = pos_item(bt, pos);
			init_item_ref(iref, item);
			ret = 0;
		} else {
			put_btree_block(bt);
			ret = -ENOENT;
		}

	}

	return ret;
}

static bool invalid_item(void *key, unsigned key_len, unsigned val_len)
{
	return WARN_ON_ONCE(key_len == 0) ||
	       WARN_ON_ONCE(key_len > SCOUTFS_BTREE_MAX_KEY_LEN) ||
	       WARN_ON_ONCE(val_len > SCOUTFS_BTREE_MAX_VAL_LEN);
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
int scoutfs_btree_insert(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_block *bt;
	int pos;
	int cmp;
	int ret;

	if (invalid_item(key, key_len, val_len))
		return -EINVAL;

	ret = btree_walk(sb, root, BTW_DIRTY | BTW_INSERT, key, key_len,
			 val_len, &bt, NULL, NULL);
	if (ret == 0) {
		pos = find_pos(bt, key, key_len, &cmp);
		if (cmp) {
			create_item(bt, pos, key, key_len, val, val_len);
			ret = 0;
		} else {
			ret = -EEXIST;
		}

		put_btree_block(bt);
	}

	return ret;
}

/*
 * Update a btree item.  The key and value must be of the same length (though
 * it would be easy enough for us to change that if a caller cared).
 */
int scoutfs_btree_update(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	int pos;
	int cmp;
	int ret;

	if (invalid_item(key, key_len, val_len))
		return -EINVAL;

	ret = btree_walk(sb, root, BTW_DIRTY, key, key_len, 0, &bt, NULL, NULL);
	if (ret == 0) {
		pos = find_pos(bt, key, key_len, &cmp);
		if (cmp == 0) {
			item = pos_item(bt, pos);
			if (item_key_len(item) != key_len ||
			    item_val_len(item) != val_len) {
				ret = -EINVAL;
			} else {
				memcpy(item_key(item), key, key_len);
				memcpy(item_val(item), val, val_len);
				ret = 0;
			}
			ret = 0;
		} else {
			ret = -ENOENT;
		}

		put_btree_block(bt);
	}

	return ret;
}

/*
 * Delete an item from the tree.  -ENOENT is returned if the key isn't
 * found.
 */
int scoutfs_btree_delete(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len)
{
	struct scoutfs_btree_block *bt;
	int pos;
	int cmp;
	int ret;

	ret = btree_walk(sb, root, BTW_DELETE | BTW_DIRTY, key, key_len, 0,
			 &bt, NULL, NULL);
	if (ret == 0) {
		pos = find_pos(bt, key, key_len, &cmp);
		if (cmp == 0) {
			delete_item(bt, pos);
			ret = 0;

			/* delete the final block in the tree */
			if (bt->nr_items == 0) {
				root->height = 0;
				root->ref.blkno = 0;
				root->ref.seq = 0;
			}
		} else {
			ret = -ENOENT;
		}

		put_btree_block(bt);
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
static int btree_iter(struct super_block *sb, struct scoutfs_btree_root *root,
		      int flags, void *key, unsigned key_len,
		      struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	unsigned iter_len;
	unsigned walk_len;
	void *iter_key;
	void *walk_key;
	int pos;
	int cmp;
	int ret;

	if (WARN_ON_ONCE(flags & BTW_DIRTY) ||
	    WARN_ON_ONCE(iref->key))
		return -EINVAL;

	walk_key = kmalloc(SCOUTFS_BTREE_MAX_KEY_LEN, GFP_NOFS);
	iter_key = kmalloc(SCOUTFS_BTREE_MAX_KEY_LEN, GFP_NOFS);
	if (!walk_key || !iter_key) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(walk_key, key, key_len);
	walk_len = key_len;

	for (;;) {
		ret = btree_walk(sb, root, flags, walk_key, walk_len, 0, &bt,
				 iter_key, &iter_len);
		if (ret < 0)
			break;

		pos = find_pos(bt, key, key_len, &cmp);

		/* point pos towards iteration, find_pos already for _NEXT */
		if ((flags & BTW_AFTER) && cmp == 0)
			pos++;
		else if ((flags & BTW_PREV) && cmp < 0)
			pos--;
		else if ((flags & BTW_BEFORE) && cmp == 0)
			pos--;

		/* found the next item in this leaf */
		if (pos >= 0 && pos < le16_to_cpu(bt->nr_items)) {
			item = pos_item(bt, pos);
			init_item_ref(iref, item);
			ret = 0;
			break;
		}

		put_btree_block(bt);

		/* nothing in this leaf, walk gave us a key */
		if (iter_len > 0) {
			memcpy(walk_key, iter_key, iter_len);
			walk_len = iter_len;
			continue;
		}

		ret = -ENOENT;
		break;
	}

out:
	kfree(walk_key);
	kfree(iter_key);

	return ret;
}

int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       void *key, unsigned key_len,
		       struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_NEXT, key, key_len, iref);
}

int scoutfs_btree_after(struct super_block *sb, struct scoutfs_btree_root *root,
		        void *key, unsigned key_len,
		        struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_NEXT | BTW_AFTER, key, key_len, iref);
}

int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       void *key, unsigned key_len,
		       struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_PREV, key, key_len, iref);
}

int scoutfs_btree_before(struct super_block *sb, struct scoutfs_btree_root *root,
		         void *key, unsigned key_len,
		         struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_PREV | BTW_BEFORE, key, key_len, iref);
}

/*
 * Ensure that the blocks that lead to the item with the given key are
 * dirty.  caller can hold a transaction to pin the dirty blocks and
 * guarantee that later updates of the item will succeed.
 *
 * <0 is returned on error, including -ENOENT if the key isn't present.
 */
int scoutfs_btree_dirty(struct super_block *sb, struct scoutfs_btree_root *root,
			void *key, unsigned key_len)
{
	struct scoutfs_btree_block *bt;
	int cmp;
	int ret;

	ret = btree_walk(sb, root, BTW_DIRTY, key, key_len, 0, &bt, NULL, NULL);
	if (ret == 0) {
		find_pos(bt, key, key_len, &cmp);
		if (cmp == 0)
			ret = 0;
		else
			ret = -ENOENT;
		put_btree_block(bt);
	}

	return ret;
}

/*
 * This initializes all our tracking info based on the super.  Called
 * before dirtying anything after having read the super or finished
 * writing dirty blocks.
 */
static int btree_prepare_write(struct super_block *sb)
{
	struct scoutfs_btree_ring *bring = &SCOUTFS_SB(sb)->super.bring;
	DECLARE_BTREE_INFO(sb, bti);

	bti->cur_dirtied = 0;
	bti->old_dirtied = 0;
	bti->first_dirty_bh = NULL;
	bti->last_dirty_bh = NULL;
	bti->first_dirty_blkno = le64_to_cpu(bring->first_blkno) +
				 le64_to_cpu(bring->next_block);
	bti->first_dirty_seq = le64_to_cpu(bring->next_seq);

	return 0;
}

/*
 * The caller is serializing btree item dirtying and dirty block writing.
 */
bool scoutfs_btree_has_dirty(struct super_block *sb)
{
	DECLARE_BTREE_INFO(sb, bti);

	return bti->first_dirty_bh != NULL;
}

/* dirty block allocation built this list */
#define for_each_dirty_bh(bti, bh, tmp) \
	for (bh = bti->first_dirty_bh; bh && (tmp = bh->b_private, 1); bh = tmp)

/*
 * Write the dirty region of blocks to the ring.  The caller still has
 * to write the super after we're done.  That could fail and we could
 * be asked to write the blocks all over again.
 *
 * We're the only writer.
 */
int scoutfs_btree_write_dirty(struct super_block *sb)
{
	DECLARE_BTREE_INFO(sb, bti);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_btree_root *root;
	struct scoutfs_btree_block *bt;
	struct buffer_head *tmp;
	struct buffer_head *bh;
	struct blk_plug plug;
	unsigned int walk_len;
	unsigned int iter_len;
	bool progress;
	void *walk_key;
	void *iter_key;
	int ret;
	int i;

	if (bti->first_dirty_bh == NULL)
		return 0;

	iter_key = kmalloc(SCOUTFS_BTREE_MAX_KEY_LEN, GFP_NOFS);
	if (!iter_key)
		return -ENOMEM;

	progress = true;
	while (progress && bti->old_dirtied < bti->cur_dirtied) {
		progress = false;

		for_each_super_root(super, i, root) {
			walk_key = root->migration_key;
			walk_len = le16_to_cpu(root->migration_key_len);
			if (walk_len == 0)
				continue;

			ret = btree_walk(sb, root,
					 BTW_DIRTY | BTW_NEXT | BTW_MIGRATE,
					 walk_key, walk_len, 0, &bt,
					 iter_key, &iter_len);
			if (ret < 0)
				goto out;

			root->migration_key_len = cpu_to_le16(iter_len);
			if (iter_len) {
				memcpy(walk_key, iter_key, iter_len);
				progress = true;
			} else {
				memset(walk_key, 0, SCOUTFS_BTREE_MAX_KEY_LEN);
			}
		}
	}

	/* checksum everything to reduce time between io submission merging */
	for_each_dirty_bh(bti, bh, tmp) {
		bt = (void *)bh->b_data;
		bt->hdr._pad = 0;
		bt->hdr.crc = scoutfs_block_calc_crc(&bt->hdr);
	}

        blk_start_plug(&plug);

	for_each_dirty_bh(bti, bh, tmp) {
		lock_buffer(bh);
		set_buffer_mapped(bh);
		bh->b_end_io = end_buffer_write_sync;
		get_bh(bh);
		/* XXX should be more careful with flags */
		submit_bh(WRITE_SYNC | REQ_META | REQ_PRIO, bh);
	}

	blk_finish_plug(&plug);

	ret = 0;
	for_each_dirty_bh(bti, bh, tmp) {
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			scoutfs_inc_counter(sb, btree_write_error);
			ret = -EIO;
		}
	}

out:
	kfree(iter_key);
	return ret;
}

/*
 * The dirty blocks and their super reference have been successfully written.
 * Remove them from the dirty list and drop their references and prepare
 * for the next write.
 */
void scoutfs_btree_write_complete(struct super_block *sb)
{
	DECLARE_BTREE_INFO(sb, bti);
	struct buffer_head *bh;
	struct buffer_head *tmp;

	for_each_dirty_bh(bti, bh, tmp) {
		bh->b_private = NULL;
		put_bh(bh);
	}

	btree_prepare_write(sb);
}

int scoutfs_btree_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct btree_info *bti;

	bti = kzalloc(sizeof(struct btree_info), GFP_KERNEL);
	if (!bti)
		return -ENOMEM;

	mutex_init(&bti->mutex);

	sbi->btree_info = bti;

	btree_prepare_write(sb);

	return 0;
}

void scoutfs_btree_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	kfree(sbi->btree_info);
	sbi->btree_info = NULL;
}
