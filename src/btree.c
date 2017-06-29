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
 * To find the blocks in the old half of the ring we augment the btree
 * items to store bits that are or-ed in parent items up to the root.
 * Parent items have bits set for the half of the ring that their child
 * block is stored in.
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
 * offsets and bits of the items and is kept sorted by the item's keys.
 * The array is small enough that keeping it sorted with memmove()
 * involves a few cache lines at most.
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
 *  - audit split and merge for bit updating
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
	 BTW_BIT	= (1 <<  5), /* search for the first set bit, not key */
	 BTW_DIRTY_OLD	= (1 <<  6), /* dirty old leaf blocks to balance ring */
	 BTW_ALLOC	= (1 <<  7), /* allocate a new block for 0 ref */
	 BTW_INSERT	= (1 <<  8), /* walking to insert, try splitting */
	 BTW_DELETE	= (1 <<  9), /* walking to delete, try merging */
};

/*
 * This greatest key value is stored down the right spine of the tree
 * and has to be sorted by memcmp() greater than all possible keys in
 * all btrees.  We give it room for a decent number of big-endian
 * primary sort values.
 */
static char max_key[SCOUTFS_BTREE_GREATEST_KEY_LEN] = {
	[0 ... (SCOUTFS_BTREE_GREATEST_KEY_LEN - 1)] = 0xff,
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

static inline u8 pos_bits(struct scoutfs_btree_block *bt, unsigned int pos)
{
	return bt->item_hdrs[pos].bits;
}

static inline bool pos_bit_set(struct scoutfs_btree_block *bt, unsigned int pos,
			       u8 bit)
{
	return bt->item_hdrs[pos].bits & bit;
}

static inline u16 bit_count(struct scoutfs_btree_block *bt, u8 bit)
{
	int ind;

	BUG_ON(hweight8(bit) != 1);

	ind = ffs(bit) - 1;
	return le16_to_cpu(bt->bit_counts[ind]);
}

/* find the first item pos with the given bit set */
static int find_pos_bit(struct scoutfs_btree_block *bt, int pos, u8 bit)
{
	unsigned int nr = le16_to_cpu(bt->nr_items);

	while (pos < nr && !pos_bit_set(bt, pos, bit))
		pos++;

	return pos;
}

/*
 * Record the path we took through parent blocks.  Used to set the bits
 * in parent reference items that lead to bits in leaves.
 */
struct btree_path {
	unsigned nr;
	struct scoutfs_btree_block *bt[SCOUTFS_BTREE_MAX_HEIGHT];
	u16 pos[SCOUTFS_BTREE_MAX_HEIGHT];
};

#define DECLARE_BTREE_PATH(name) \
	struct btree_path name = {0, }

/*
 * Add a block to the path for later traversal for updating bits.  Only dirty
 * blocks are put in the path and they have an extra ref to keep them pinned
 * until we write them out.
 */
static void path_push(struct btree_path *path,
		      struct scoutfs_btree_block *bt, unsigned pos)
{
	if (path) {
		BUG_ON(path->nr >= SCOUTFS_BTREE_MAX_HEIGHT);

		path->bt[path->nr] = bt;
		path->pos[path->nr++] = pos;
	}
}

static struct scoutfs_btree_block *path_pop(struct btree_path *path, unsigned *pos)
{
	if (!path || path->nr == 0)
		return NULL;

	*pos = path->pos[--path->nr];
	return path->bt[path->nr];
}

static u8 half_bit(struct scoutfs_btree_ring *bring, u64 blkno)
{
	u64 half_blkno = le64_to_cpu(bring->first_blkno) +
			 (le64_to_cpu(bring->nr_blocks) / 2);

	return blkno < half_blkno ? SCOUTFS_BTREE_BIT_HALF1 :
				    SCOUTFS_BTREE_BIT_HALF2;
}

static u8 other_half_bit(struct scoutfs_btree_ring *bring, u64 blkno)
{
	return half_bit(bring, blkno) ^ (SCOUTFS_BTREE_BIT_HALF1 |
					 SCOUTFS_BTREE_BIT_HALF2);
}

static u8 bits_from_counts(struct scoutfs_btree_block *bt)
{
	u8 bits = 0;
	int i;

	for (i = 0; i < SCOUTFS_BTREE_BITS; i++) {
		if (bt->bit_counts[i])
			bits |= 1 << i;
	}

	return bits;
}

/*
 * Iterate through 0-based bit numbers set in 'bits' from least to
 * greatest.  It modifies 'bits' as it goes!
 */
#define for_each_bit(i, bits) \
	for (i = bits ? ffs(bits) : 0; i-- > 0; bits &= ~(1 < i))

/*
 * Store the new bits and update the counts to match the difference from
 * the previously set bits.  Callers use this to keep item bits in sync
 * with the counts of bits in the block headers.
 */
static void store_pos_bits(struct scoutfs_btree_block *bt, int pos, u8 bits)
{
	u8 diff = bits ^ pos_bits(bt, pos);
	int b;

	if (!diff)
		return;

	for_each_bit(b, diff) {
		if (bits & (1 << b))
			le16_add_cpu(&bt->bit_counts[b], 1);
		else
			le16_add_cpu(&bt->bit_counts[b], -1);
	}

	bt->item_hdrs[pos].bits = bits;
}

/*
 * The caller has descended through parents to a final block.  Each
 * block may have had item bits modified and counts updated but they
 * didn't keep parent item bits in sync with modifications to all the
 * children.  Our job is to ascend back through parents and set their
 * bits to the union of all the bits down through the path to the final
 * block.
 */
static void path_repair_reset(struct btree_path *path)
{
	struct scoutfs_btree_block *parent;
	struct scoutfs_btree_block *bt;
	u8 bits;
	int pos;

	bt = path_pop(path, &pos);

	while ((parent = path_pop(path, &pos))) {
		bits = bits_from_counts(bt);
		store_pos_bits(parent, pos, bits);
		bt = parent;
	}
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
static void create_item(struct scoutfs_btree_block *bt, unsigned int pos, u8 bits,
			void *key, unsigned key_len, void *val, unsigned val_len)
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

	bt->item_hdrs[pos].bits = 0;
	store_pos_bits(bt, pos, bits);

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

	store_pos_bits(bt, pos, 0);

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

		create_item(dst, t, pos_bits(src, f), item_key(from),
			    item_key_len(from), item_val(from),
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
static bool valid_referenced_block(struct scoutfs_super_block *super,
				   struct scoutfs_btree_ref *ref,
				   struct scoutfs_btree_block *bt,
				   struct buffer_head *bh)
{
	__le32 existing;
	u32 calc;

	if (!buffer_scoutfs_checked(bh)) {
		lock_buffer(bh);
		if (!buffer_scoutfs_checked(bh)) {
			existing = bt->crc;
			bt->crc = 0;
			calc = crc32c(~0, bt, SCOUTFS_BLOCK_SIZE);
			bt->crc = existing;

			set_buffer_scoutfs_checked(bh);
			if (calc == le32_to_cpu(existing))
				set_buffer_scoutfs_valid_crc(bh);
			else
				clear_buffer_scoutfs_valid_crc(bh);
		}
		unlock_buffer(bh);
	}

	return buffer_scoutfs_valid_crc(bh) && super->hdr.fsid == bt->fsid &&
	       ref->blkno == bt->blkno && ref->seq == bt->seq;
}

/*
 * This is used to lookup cached blocks, read blocks, cow blocks for
 * dirtying, and allocate new blocks.
 *
 * Btree blocks don't have rigid cache consistency.  We can be following
 * a new root to read refs into previously stale cached blocks.  If we
 * see that the block metadata doesn't match we first assume that we
 * just have a stale block and try and re-read it.  If it still doesn't
 * match we assume that we're an reader racing with a writer overwriting
 * old blocks in the ring.  We return an error that tells the caller to
 * deal with this error: either find a new root or return a hard error
 * if the block is really corrupt.
 *
 * This only sets the caller's reference.  It doesn't know if the
 * caller's ref is in a parent item and would need to update bits and
 * counts based on the blkno.  It's up to the callers to take care of
 * that.
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
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_block *new;
	struct buffer_head *bh;
	int retries = 1;
	u64 blkno;
	u64 seq;
	int ret;

retry:
	/* always get the current block, either to return or cow from */
	if (ref && ref->blkno) {
		bh = sb_bread(sb, le64_to_cpu(ref->blkno));
		if (!bh) {
			ret = -EIO;
			goto out;
		}
		bt = (void *)bh->b_data;

		if (!valid_referenced_block(super, ref, bt, bh)) {
			if (retries-- > 0) {
				lock_buffer(bh);
				clear_buffer_uptodate(bh);
				unlock_buffer(bh);
				put_bh(bh);
				bt = NULL;
				goto retry;
			}
			/* XXX let us know when we eventually hit this */
			ret = WARN_ON_ONCE(-ESTALE);
			goto out;
		}

		/* done if not dirtying or already dirty */
		if (!(flags & BTW_DIRTY) ||
		    (le64_to_cpu(bt->seq) >= bti->first_dirty_seq)) {
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

	/* wrap next block and increase next seq */
	if (le64_to_cpu(bring->next_block) == le64_to_cpu(bring->nr_blocks))
		bring->next_block = 0;
	else
		le64_add_cpu(&bring->next_block, 1);

	le64_add_cpu(&bring->next_seq, 1);

	if (half_bit(bring, blkno) == half_bit(bring, bti->first_dirty_blkno))
		bti->cur_dirtied++;
	else
		bti->old_dirtied++;

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
		bt->fsid = super->hdr.fsid;
		bt->free_end = cpu_to_le16(SCOUTFS_BLOCK_SIZE);
	}

	bt->blkno = cpu_to_le64(blkno);
	bt->seq = cpu_to_le64(seq);
	if (ref) {
		ref->blkno = bt->blkno;
		ref->seq = bt->seq;
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
 * Get the block referenced by the given parent item.  The parent item
 * and its bits are updated.
 */
static int get_parent_ref_block(struct super_block *sb, int flags,
			        struct scoutfs_btree_block *parent, unsigned pos,
			        struct scoutfs_btree_block **bt_ret)
{
	struct scoutfs_btree_ring *bring = &SCOUTFS_SB(sb)->super.bring;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_ref *ref;
	u8 bits;
	int ret;

	/* ref can only be updated, no insertion or compaction */
	item = pos_item(parent, pos);
	ref = item_val(item);

	ret = get_ref_block(sb, flags, ref, bt_ret);
	if (ret == 0) {
		bits = bits_from_counts(*bt_ret) |
		       half_bit(bring, le64_to_cpu(ref->blkno));
		store_pos_bits(parent, pos, bits);
	}

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
		.blkno = child->blkno,
		.seq = child->seq,
	};
	u8 bits = bits_from_counts(child) |
		  half_bit(bring, le64_to_cpu(ref.blkno));

	create_item(parent, pos, bits, key, key_len, &ref, sizeof(ref));
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

/* the parent item key and value are fine, but child items have changed */
static void update_parent_bits(struct scoutfs_btree_ring *bring,
			       struct scoutfs_btree_block *parent,
			       unsigned pos, struct scoutfs_btree_block *child)
{
	u8 bits = bits_from_counts(child) |
		  half_bit(bring, le64_to_cpu(child->blkno));

	store_pos_bits(parent, pos, bits);
}

/*
 * See if we need to split this block while descending for insertion so
 * that we have enough space to insert.  Parent blocks need enough space
 * for a new item and child ref if a child block splits.  Leaf blocks
 * need enough space to insert the new item with its value.
 *
 * We split to the left so that the greatest key in the existing block
 * doesn't change so we don't have to update the key in its parent item.
 * We still have to update its bits.
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

	if (right->level)
		all_bytes = all_len_bytes(SCOUTFS_BTREE_MAX_KEY_LEN,
					  sizeof(struct scoutfs_btree_ref));
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
		root->ref.blkno = parent->blkno;
		root->ref.seq = parent->seq;

		pos = 0;
		create_parent_item(bring, parent, pos, right,
				   &max_key, sizeof(max_key));
	}

	move_items(left, right, false, used_total(right) / 2);
	update_parent_bits(bring, parent, pos, right);

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
	unsigned int sib_pos;
	bool move_right;
	int to_move;
	int ret;

	if (reclaimable_free(bt) <= SCOUTFS_BTREE_FREE_LIMIT)
		return 0;

	/* move items right into our block if we have a left sibling */
	if (pos) {
		sib_pos = pos - 1;
		move_right = true;
	} else {
		sib_pos = pos + 1;
		move_right = false;
	}

	ret = get_parent_ref_block(sb, BTW_DIRTY, parent, sib_pos, &sib);
	if (ret)
		return ret;

	if (used_total(sib) <= reclaimable_free(bt))
		to_move = used_total(sib);
	else
		to_move = reclaimable_free(bt) - SCOUTFS_BTREE_FREE_LIMIT;

	move_items(bt, sib, move_right, to_move);

	/* update our parent's item */
	if (!move_right)
		update_parent_item(bring, parent, pos, bt);
	else
		update_parent_bits(bring, parent, pos, bt);

	/* update or delete sibling's parent item */
	if (le16_to_cpu(sib->nr_items) == 0)
		delete_item(parent, sib_pos);
	else if (move_right)
		update_parent_item(bring, parent, sib_pos, sib);
	else
		update_parent_bits(bring, parent, sib_pos, sib);

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le16_to_cpu(parent->nr_items) == 1) {
		root->height--;
		root->ref.blkno = bt->blkno;
		root->ref.seq = bt->seq;
	}

	put_btree_block(sib);

	return 1;
}

/*
 * This is called before writing dirty blocks to ensure that each batch
 * of dirty blocks migrates half as many blocks from the old half of the
 * ring as it dirties from the current half.  This ensures that by the
 * time we fill the current half of the ring it will no longer reference
 * the old half.
 *
 * We've walked to the parent of the leaf level which might have dirtied
 * more blocks.  Our job is to dirty as many leaves as we need to bring
 * the old count back up to equal the current count.  The caller will
 * keep trying to walk down different paths of each of the btrees.
 */
static int try_dirty_old(struct super_block *sb, struct scoutfs_btree_block *bt,
			 u8 old_bit)
{
	DECLARE_BTREE_INFO(sb, bti);
	struct scoutfs_btree_block *dirtied;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_ref *ref;
	struct blk_plug plug;
	int ret = 0;
	int pos = 0;
	int nr;
	int i;

	if (bti->old_dirtied >= bti->cur_dirtied)
		return 0;

	/* called when first parent level is highest level, can have nothing */
	nr = min_t(int, bti->cur_dirtied - bti->old_dirtied,
		   bit_count(bt, old_bit));
	if (nr == 0)
		return -ENOENT;

        blk_start_plug(&plug);

	/* read 'em all */
	for (i = 0, pos = 0; i < nr; i++, pos++) {
		pos = find_pos_bit(bt, pos, old_bit);
		if (pos >= le16_to_cpu(bt->nr_items)) {
			/* XXX bits in headers didn't match count */
			ret = -EIO;
			blk_finish_plug(&plug);
			goto out;
		}

		item = pos_item(bt, pos);
		ref = item_val(item);

		sb_breadahead(sb, le64_to_cpu(ref->blkno));
	}

	blk_finish_plug(&plug);

	/* then actually try and dirty the blocks */
	for (i = 0, pos = 0; i < nr; i++, pos++) {
		pos = find_pos_bit(bt, pos, old_bit);

		ret = get_parent_ref_block(sb, BTW_DIRTY, bt, pos, &dirtied);
		if (ret)
			break;
		put_btree_block(dirtied);
	}

out:
	return ret;
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
			bt, le64_to_cpu(bt->blkno), level,
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
 * The caller provides the path to record the parent blocks and items
 * used to reach the leaf.  We let them repair the path once they've
 * potentially updated bits in the leaf.  They must always repair the
 * path because we can modify parent bits during descent before
 * returning an error.
 */
static int btree_walk(struct super_block *sb, struct scoutfs_btree_root *root,
		      struct btree_path *path, int flags,
		      void *key, unsigned key_len, unsigned int val_len, u8 bit,
		      struct scoutfs_btree_block **bt_ret,
		      void *iter_key, unsigned *iter_len)
{
	struct scoutfs_btree_block *parent = NULL;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_item *item;
	unsigned level;
	unsigned pos;
	unsigned nr;
	int cmp;
	int ret;

	if (WARN_ON_ONCE((flags & BTW_DIRTY) && path == NULL) ||
	    WARN_ON_ONCE((flags & (BTW_NEXT|BTW_PREV)) && iter_key == NULL))
		return -EINVAL;

restart:
	path_repair_reset(path);
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

	while(level-- > 0) {
		if (parent)
			ret = get_parent_ref_block(sb, flags, parent, pos, &bt);
		else
			ret = get_ref_block(sb, flags, &root->ref, &bt);
		if (ret)
			break;

		/* push the parent once we could have updated its bits */
		if (parent)
			path_push(path, parent, pos);

		/* XXX it'd be nice to make this tunable */
		ret = 0 && verify_btree_block(bt, level);
		if (ret)
			break;

		/* XXX more aggressive block verification, before ref updates? */
		if (bt->level != level) {
			ret = -EIO;
			break;
		}

		/*
		 * Splitting and merging can add or remove parents or
		 * change the pos we take through parents to reach the
		 * block with the search key|bit.  In the rare case that
		 * we split or merge we simply restart the walk rather
		 * than try and special case modifying the path to
		 * reflect the tree changes.
		 */
		if (flags & BTW_INSERT)
			ret = try_split(sb, root, key, key_len, val_len,
				        parent, pos, bt);
		else if ((flags & BTW_DELETE) && parent)
			ret = try_merge(sb, root, parent, pos, bt);
		else
			ret = 0;
		if (ret > 0)
			goto restart;
		else if (ret < 0)
			break;

		/* dirtying old stops at the last parent level */
		if ((flags & BTW_DIRTY_OLD) && (level < 2)) {
			if (level == 1) {
				path_push(path, bt, 0);
				ret = try_dirty_old(sb, bt, bit);
			} else {
				ret = -ENOENT;
			}
			break;
		}

		/* done at the leaf */
		if (level == 0) {
			path_push(path, bt, 0);
			break;
		}

		nr = le16_to_cpu(bt->nr_items);

		/*
		 * Find the next child block for the search key or bit.
		 * Key searches should always find a child, bit searches
		 * can find that the bit isn't set in the first block.
		 */
		if (flags & BTW_BIT) {
			pos = find_pos_bit(bt, 0, bit);
			if (pos >= nr)
				ret = -ENOENT;
		} else {
			pos = find_pos(bt, key, key_len, &cmp);
			if (pos >= nr)
				ret = -EIO;
		}
		if (ret)
			break;

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

	ret = btree_walk(sb, root, NULL, 0, key, key_len, 0, 0, &bt, NULL, NULL);
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
	       WARN_ON_ONCE(val_len > SCOUTFS_BTREE_MAX_VAL_LEN) ||
	       WARN_ON_ONCE(key_len > SCOUTFS_BTREE_GREATEST_KEY_LEN &&
			    cmp_keys(key, key_len, max_key, sizeof(max_key)) > 0);
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
	DECLARE_BTREE_PATH(path);
	int pos;
	int cmp;
	int ret;

	if (invalid_item(key, key_len, val_len))
		return -EINVAL;

	ret = btree_walk(sb, root, &path, BTW_DIRTY | BTW_INSERT, key, key_len,
			 val_len, 0, &bt, NULL, NULL);
	if (ret == 0) {
		pos = find_pos(bt, key, key_len, &cmp);
		if (cmp) {
			create_item(bt, pos, 0, key, key_len, val, val_len);
			ret = 0;
		} else {
			ret = -EEXIST;
		}

		put_btree_block(bt);
	}

	path_repair_reset(&path);
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
	DECLARE_BTREE_PATH(path);
	int pos;
	int cmp;
	int ret;

	if (invalid_item(key, key_len, val_len))
		return -EINVAL;

	ret = btree_walk(sb, root, &path, BTW_DIRTY, key, key_len, 0, 0, &bt,
			 NULL, NULL);
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

	path_repair_reset(&path);
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
	DECLARE_BTREE_PATH(path);
	int pos;
	int cmp;
	int ret;

	ret = btree_walk(sb, root, &path, BTW_DELETE | BTW_DIRTY, key, key_len,
			 0, 0, &bt, NULL, NULL);
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

	path_repair_reset(&path);
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
	if (!walk_key || !iter_key)
		return -ENOMEM;

	memcpy(walk_key, key, key_len);
	walk_len = key_len;

	for (;;) {
		ret = btree_walk(sb, root, NULL, flags, walk_key, walk_len,
				 0, 0, &bt, iter_key, &iter_len);
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
	DECLARE_BTREE_PATH(path);
	int cmp;
	int ret;

	ret = btree_walk(sb, root, &path, BTW_DIRTY, key, key_len, 0, 0, &bt,
			 NULL, NULL);
	if (ret == 0) {
		find_pos(bt, key, key_len, &cmp);
		if (cmp == 0)
			ret = 0;
		else
			ret = -ENOENT;
		put_btree_block(bt);
	}

	path_repair_reset(&path);
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
	struct scoutfs_btree_ring *bring = &super->bring;
	struct scoutfs_btree_root *roots[] = {
		&super->manifest.root,
		&super->alloc_root,
		NULL,
	};
	struct scoutfs_btree_root *root;
	struct scoutfs_btree_block *bt;
	DECLARE_BTREE_PATH(path);
	struct buffer_head *tmp;
	struct buffer_head *bh;
	struct blk_plug plug;
	unsigned next_root;
	u8 bit;
	int ret;

	if (bti->first_dirty_bh == NULL)
		return 0;

	/* cow old dirty blocks to balance ring */
	bit = other_half_bit(bring, bti->first_dirty_blkno);
	next_root = 0;
	root = roots[next_root];
	while (root && bti->old_dirtied < bti->cur_dirtied) {
		ret = btree_walk(sb, root, &path,
				 BTW_DIRTY | BTW_BIT | BTW_DIRTY_OLD,
				 NULL, 0, 0, bit, NULL, NULL, NULL);
		path_repair_reset(&path);
		if (ret == -ENOENT) {
			root = roots[next_root++];
			continue;
		}
		if (ret < 0)
			goto out;
	}

	/* checksum everything to reduce time between io submission merging */
	for_each_dirty_bh(bti, bh, tmp) {
		bt = (void *)bh->b_data;
		bt->crc = 0;
		bt->crc = cpu_to_le32(crc32c(~0, bt, SCOUTFS_BLOCK_SIZE));
	}

        blk_start_plug(&plug);

	for_each_dirty_bh(bti, bh, tmp) {
		lock_buffer(bh);
		set_buffer_dirty(bh);
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
		if (!buffer_uptodate(bh))
			ret = -EIO;
	}
out:
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
