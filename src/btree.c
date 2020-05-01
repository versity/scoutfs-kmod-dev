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
#include "avl.h"

#include "scoutfs_trace.h"

/*
 * scoutfs uses a cow btree to index fs metadata.
 *
 * Today callers provide all the locking.  They serialize readers and
 * writers and writers and committing all the dirty blocks.
 *
 * Block reference have sufficient metadata to discover corrupt
 * references.  If a reader encounters a bad block it backs off which
 * gives the caller the opportunity to resample the root in case it was
 * reading through a stale btree that has been overwritten.  This lets
 * mounts read trees that are modified by other mounts without exclusive
 * locking.
 *
 * Btree items are stored as a dense array of structs at the front of
 * each block.  New items are allocated at the end of the array.
 * Deleted items are swapped with the last item to maintain the dense
 * array.  The items are indexed by a balanced binary tree with parent
 * pointers so the relocated item can have references to it updated.
 *
 * Values are allocated from the end of the block towards the front,
 * consuming the end of free space in the center of the block.  Deleted
 * values can be merged with this free space, but more likely they'll
 * create fragmented free space amongst other existing values.  All
 * values are stored with an offset at the end which contains either the
 * offset of their item or the offset of the start of their free space.
 * This lets an infrequent compaction process move items towards the
 * back of the block to reclaim free space.
 *
 * Exact item searches are only performed on leaf blocks.  Leaf blocks
 * have a hash table at the end of the block which is used to find items
 * with a specific key.  It uses linear probing and maintains a low load
 * factor so any given search will most likely only need a single
 * cacheline.
 *
 * Parent block reference items are stored as items with a block
 * reference as a value.  There's an item with a key for every child
 * reference instead of having separator keys between child references.
 * The key in a child reference contains the largest key that may be
 * found in the child subtree.  The right spine of the tree has maximal
 * keys so that they don't have to be updated if we insert an item with
 * a key greater than everything in the tree.
 */

/* btree walking has a bunch of behavioural bit flags */
enum {
	 BTW_NEXT	= (1 <<  0), /* return >= key */
	 BTW_PREV	= (1 <<  1), /* return <= key */
	 BTW_DIRTY	= (1 <<  2), /* cow stable blocks */
	 BTW_ALLOC	= (1 <<  3), /* allocate a new block for 0 ref */
	 BTW_INSERT	= (1 <<  4), /* walking to insert, try splitting */
	 BTW_DELETE	= (1 <<  5), /* walking to delete, try joining */
};

/* total length of the value payload */
static inline unsigned int val_bytes(unsigned val_len)
{
	return val_len + (val_len ? SCOUTFS_BTREE_VAL_OWNER_BYTES : 0);
}

/* number of bytes in a block used by an item with the given value length */
static inline unsigned int item_len_bytes(unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item) + val_bytes(val_len);
}

/* number of bytes used by an existing item */
static inline unsigned int item_bytes(struct scoutfs_btree_item *item)
{
	return item_len_bytes(le16_to_cpu(item->val_len));
}

/*
 * Join blocks when they both are 1/4 full.  This puts some distance
 * between the join threshold and the full threshold for splitting.
 * Blocks that just split or joined need to undergo a reasonable amount
 * of item modification before they'll split or join again.
 */
static unsigned int join_low_watermark(void)
{
	return (SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block)) / 4;
}

/*
 * return the integer percentages of total space the block could have
 * consumed by items that is currently consumed.
 */
static unsigned int item_full_pct(struct scoutfs_btree_block *bt)
{
	return (int)le16_to_cpu(bt->total_item_bytes) * 100 /
		(SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block));
}

static inline __le16 ptr_off(struct scoutfs_btree_block *bt, void *ptr)
{
	return cpu_to_le16(ptr - (void *)bt);
}

static inline void *off_ptr(struct scoutfs_btree_block *bt, u16 off)
{
	return (void *)bt + off;
}

static inline struct scoutfs_btree_item *
off_item(struct scoutfs_btree_block *bt, __le16 off)
{
	return (void *)bt + le16_to_cpu(off);
}

static struct scoutfs_btree_item *last_item(struct scoutfs_btree_block *bt)
{
	BUG_ON(bt->nr_items == 0);

	return &bt->items[le16_to_cpu(bt->nr_items) - 1];
}

/* offset of the start of the free range in the middle of the block */
static inline unsigned int mid_free_off(struct scoutfs_btree_block *bt)
{
	return le16_to_cpu(ptr_off(bt, &bt->items[le16_to_cpu(bt->nr_items)]));
}

static inline struct scoutfs_key *item_key(struct scoutfs_btree_item *item)
{
	return &item->key;
}

static inline void *item_val(struct scoutfs_btree_block *bt,
			     struct scoutfs_btree_item *item)
{
	return off_ptr(bt, le16_to_cpu(item->val_off));
}

static inline unsigned item_val_len(struct scoutfs_btree_item *item)
{
	return le16_to_cpu(item->val_len);
}

static struct scoutfs_btree_item *node_item(struct scoutfs_avl_node *node)
{
	if (node == NULL)
		return NULL;
	return container_of(node, struct scoutfs_btree_item, node);
}

static struct scoutfs_btree_item *prev_item(struct scoutfs_btree_block *bt,
					    struct scoutfs_btree_item *item)
{
	if (item == NULL)
		return NULL;
	return node_item(scoutfs_avl_prev(&bt->item_root, &item->node));
}

static struct scoutfs_btree_item *next_item(struct scoutfs_btree_block *bt,
					    struct scoutfs_btree_item *item)
{
	if (item == NULL)
		return NULL;
	return node_item(scoutfs_avl_next(&bt->item_root, &item->node));
}

static int cmp_key_item(void *arg, struct scoutfs_avl_node *node)
{
	struct scoutfs_key *key = arg;
	struct scoutfs_btree_item *item = node_item(node);

	return scoutfs_key_compare(key, item_key(item));
}

/*
 * We have a small fixed-size linearly probed hash table at the end of
 * leaf blocks which is used for direct item lookups (as opposed to
 * iterators).  The hash table only stores non-zero offsets to the
 * items.  If an item is moved then its offset is updated.  The hash
 * table is sized to allow a max load of 75%, but most items are larger
 * and most blocks aren't full.
 */
static int leaf_item_hash_ind(struct scoutfs_key *key)
{
	return crc32c(~0, key, sizeof(struct scoutfs_key)) %
	       SCOUTFS_BTREE_LEAF_ITEM_HASH_NR;
}

static __le16 *leaf_item_hash_buckets(struct scoutfs_btree_block *bt)
{
	return (void *)bt + SCOUTFS_BLOCK_LG_SIZE -
		SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;
}

static inline int leaf_item_hash_next_bucket(int i)
{
	if (++i >= SCOUTFS_BTREE_LEAF_ITEM_HASH_NR)
		i = 0;
	return i;
}

#define foreach_leaf_item_hash_bucket(i, nr, key)			       \
	for (i = leaf_item_hash_ind(key), nr = SCOUTFS_BTREE_LEAF_ITEM_HASH_NR;\
	     nr-- > 0;							       \
	     i = leaf_item_hash_next_bucket(i))

static struct scoutfs_btree_item *
leaf_item_hash_search(struct scoutfs_btree_block *bt, struct scoutfs_key *key)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	struct scoutfs_btree_item *item;
	__le16 off;
	int nr;
	int i;

	if (WARN_ON_ONCE(bt->level > 0))
		return NULL;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		if (off == 0)
			return NULL;

		item = off_item(bt, off);
		if (scoutfs_key_compare(key, item_key(item)) == 0)
			return item;
	}

	return NULL;
}

static void leaf_item_hash_insert(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 off)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		if (buckets[i] == 0) {
			buckets[i] = off;
			return;
		}
	}

	/* table should have been been enough for all items */
	BUG();
}

/*
 * Deletion clears the offset in a bucket.  That could create a
 * discontinuity that would stop a search from seeing colliding
 * insertions that were pushed into further buckets.  Each time we zero
 * a bucket we rehash all the populated buckets following it.  There
 * won't be many in our light load tables and this works reliably as the
 * contiguous population wraps past the end of table.  Comparing hashed
 * bucket positions to find candidates to relocate after the wrap is
 * tricky.  
 */
static void leaf_item_hash_delete(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 del_off)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	__le16 off;
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		/* we must find the item we're trying to delete */
		BUG_ON(off == 0);

		if (off == del_off) {
			buckets[i] = 0;
			break;
		}
	}

	while ((i = leaf_item_hash_next_bucket(i)), buckets[i] != 0) {
		off = buckets[i];
		buckets[i] = 0;
		leaf_item_hash_insert(bt, item_key(off_item(bt, off)), off);
	}
}

static void leaf_item_hash_change(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 to,
				  __le16 from)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	__le16 off;
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		/* we must find the item we're trying to change */
		BUG_ON(off == 0);

		if (off == from) {
			buckets[i] = to;
			return;
		}
	}
}

/*
 * Given an offset to the start of a value, return info describing the
 * previous value in the block.  Each value ends with an owner offset
 * which points to either the value's item if it's in use or to the
 * start of the value if it's been freed.  Either the item is returned
 * or the length of the previous value is set.
 */
static struct scoutfs_btree_item *
get_prev_val_owner(struct scoutfs_btree_block *bt, unsigned int off,
		   unsigned int *prev_val_bytes)
{
	__le16 *owner = off_ptr(bt, off - sizeof(*owner));
	unsigned int own = get_unaligned_le16(owner);

	if (own >= mid_free_off(bt)) {
		*prev_val_bytes = off - own;
		return NULL;
	} else {
		*prev_val_bytes = 0;
		return off_ptr(bt, own);
	}
}

/*
 * Set the owner offset at the end of a full value, the given length includes
 * the offset.
 */
static void set_val_owner(struct scoutfs_btree_block *bt, unsigned int val_off,
			  unsigned int vb, __le16 item_off)
{
	__le16 *owner = off_ptr(bt, val_off + vb - sizeof(*owner));

	put_unaligned_le16(le16_to_cpu(item_off) ?: val_off, owner);
}

/*
 * As values are freed they can leave fragmented free space amongst
 * other values.  This is called when we can't insert because there
 * isn't enough free space but we know that there's sufficient free
 * space amongst the values for the new insertion.
 *
 * But we only want to do this when there is enough free space to
 * justify the cost of the compaction.  We don't want to bother
 * compacting if the block is almost full and we just be split in a few
 * more operations.  The split heuristic requires a generous amount of
 * fragmented free space that will avoid a split.
 */
static void compact_values(struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_item *item;
	unsigned int free_off;
	unsigned int free_len;
	unsigned int to_off;
	unsigned int end;
	unsigned int vb;
	void *from;
	void *to;

	if (bt->last_free_off == 0)
		return;

	free_off = le16_to_cpu(bt->last_free_off);
	free_len = le16_to_cpu(bt->last_free_len);
	end = mid_free_off(bt) + le16_to_cpu(bt->mid_free_len);

	while (free_off > end) {
		item = get_prev_val_owner(bt, free_off, &vb);
		if (item == NULL) {
			free_off -= vb;
			free_len += vb;
			continue;
		}

		from = off_ptr(bt, le16_to_cpu(item->val_off));
		vb = val_bytes(le16_to_cpu(item->val_len));
		to_off = free_off + free_len - vb;
		to = off_ptr(bt, to_off);
		if (to >= from + vb)
			memcpy(to, from, vb);
		else
			memmove(to, from, vb);

		free_off = le16_to_cpu(item->val_off);
		item->val_off = cpu_to_le16(to_off);
	}

	le16_add_cpu(&bt->mid_free_len, free_len);
	bt->last_free_off = 0;
	bt->last_free_len = 0;
}

/*
 * Insert an item's value into the block.  The caller has made sure
 * there's free space.  We store the value at the end of free space in
 * the block and point its final offset at its owning item, and copy the
 * value into place.
 */
static __le16 insert_value(struct scoutfs_btree_block *bt, __le16 item_off,
			   void *val, unsigned val_len)
{
	unsigned int val_off;
	unsigned int vb;

	if (val_len == 0)
		return 0;

	BUG_ON(le16_to_cpu(bt->mid_free_len) < val_bytes(val_len));

	vb = val_bytes(val_len);
	val_off = mid_free_off(bt) + le16_to_cpu(bt->mid_free_len) - vb;
	le16_add_cpu(&bt->mid_free_len, -vb);

	memcpy(off_ptr(bt, val_off), val, val_len);
	set_val_owner(bt, val_off, vb, item_off);

	return cpu_to_le16(val_off);
}

/*
 * Delete an item's value from the block.  The caller has updated the
 * item.  We leave behind a free region whose owner offset indicates
 * that the value isn't in use.  It might merge with the central free
 * region or the final freed value, and might become the final freed
 * value.
 */
static void delete_value(struct scoutfs_btree_block *bt,
			 unsigned int val_off, unsigned int val_len)
{
	unsigned int free_off;
	unsigned int free_len;
	bool is_last;

	if (val_len == 0)
		return;

	free_off = val_off;
	free_len = val_bytes(val_len);
	is_last = false;

	/* see if we can merge with mid free region */
	if (mid_free_off(bt) + le16_to_cpu(bt->mid_free_len) == free_off) {
		le16_add_cpu(&bt->mid_free_len, free_len);
		return;
	}

	if (free_off + free_len == le16_to_cpu(bt->last_free_off)) {
		/* merge with front of last free */
		free_len += le16_to_cpu(bt->last_free_len);
		is_last = true;

	} else if ((le16_to_cpu(bt->last_free_off) +
		    le16_to_cpu(bt->last_free_len)) == free_off) {
		/* merge with end of last free */
		free_off = le16_to_cpu(bt->last_free_off);
		free_len += le16_to_cpu(bt->last_free_len);
		is_last = true;

	} else if (free_off > le16_to_cpu(bt->last_free_off)) {
		/* become new last */
		is_last = true;
	}

	set_val_owner(bt, free_off, free_len, 0);
	if (is_last) {
		bt->last_free_off = cpu_to_le16(free_off);
		bt->last_free_len = cpu_to_le16(free_len);
	}
}

/*
 * Insert a new item into the block.  The caller has made sure that
 * there is sufficient free space in block for the new item.  We might
 * have to compact the values to the end of the block to reclaim
 * fragmented free space between values.
 *
 * This only consumes free space.  It's safe to use references to block
 * structures after this call.
 */
static void create_item(struct scoutfs_btree_block *bt,
			struct scoutfs_key *key, void *val, unsigned val_len,
			struct scoutfs_avl_node *parent, int cmp)
{
	struct scoutfs_btree_item *item;

	BUG_ON(le16_to_cpu(bt->mid_free_len) < item_len_bytes(val_len));

	le16_add_cpu(&bt->mid_free_len,
		     -(u16)sizeof(struct scoutfs_btree_item));
	le16_add_cpu(&bt->nr_items, 1);
	item = last_item(bt);

	item->key = *key;

	scoutfs_avl_insert(&bt->item_root, parent, &item->node, cmp);
	leaf_item_hash_insert(bt, item_key(item), ptr_off(bt, item));

	item->val_off = insert_value(bt, ptr_off(bt, item), val, val_len);
	item->val_len = cpu_to_le16(val_len);

	le16_add_cpu(&bt->total_item_bytes, item_bytes(item));
}

/*
 * Delete an item from a btree block.
 *
 * As we delete the item we can relocate an unrelated item to maintain
 * the dense array of items.  The caller can use another single item
 * after this call if they give us the opportunity to let them know if
 * we move it.
 */
static void delete_item(struct scoutfs_btree_block *bt,
			struct scoutfs_btree_item *item,
			struct scoutfs_btree_item **use_after)
{
	struct scoutfs_btree_item *last;
	unsigned int val_off;
	unsigned int val_len;

	/* save some values before we delete the item */
	val_off = le16_to_cpu(item->val_off);
	val_len = le16_to_cpu(item->val_len);
	last = last_item(bt);

	/* delete the item */
	scoutfs_avl_delete(&bt->item_root, &item->node);
	leaf_item_hash_delete(bt, item_key(item), ptr_off(bt, item));
	le16_add_cpu(&bt->nr_items, -1);
	le16_add_cpu(&bt->mid_free_len, sizeof(struct scoutfs_btree_item));
	le16_add_cpu(&bt->total_item_bytes, -item_bytes(item));

	/* move the final item into the deleted space */
	if (last != item) {
		item->key = last->key;
		item->val_off = last->val_off;
		item->val_len = last->val_len;
		if (last->val_len)
			set_val_owner(bt, le16_to_cpu(last->val_off),
				      val_bytes(le16_to_cpu(last->val_len)),
				      ptr_off(bt, item));
		leaf_item_hash_change(bt, &last->key, ptr_off(bt, item),
				      ptr_off(bt, last));
		scoutfs_avl_relocate(&bt->item_root, &item->node,&last->node);
		if (use_after && *use_after == last)
			*use_after = item;
	}

	delete_value(bt, val_off, val_len);
}

/*
 * Move items from a source block to a destination block.  The caller
 * has made sure there's sufficient free space in the destination block,
 * though item creation may need to compact values.  The caller tells us
 * if we're moving from the tail of the source block right to the head
 * of the destination block, or vice versa.  We're always adding the
 * first or last item to the avl, so the parent is always the previous
 * first or last node.
 */
static void move_items(struct scoutfs_btree_block *dst,
		       struct scoutfs_btree_block *src, bool move_right,
		       int to_move)
{
	struct scoutfs_avl_node *par;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_item *from;
	struct scoutfs_btree_item *next;
	int cmp;

	if (move_right) {
		node = scoutfs_avl_last(&src->item_root);
		par = scoutfs_avl_first(&dst->item_root);
		cmp = -1;
	} else {
		node = scoutfs_avl_first(&src->item_root);
		par = scoutfs_avl_last(&dst->item_root);
		cmp = 1;
	}
	from = node_item(node);

	while (to_move > 0 && from != NULL) {
		to_move -= item_bytes(from);

		if (move_right)
			next = prev_item(src, from);
		else
			next = next_item(src, from);

		create_item(dst, item_key(from), item_val(src, from),
			    item_val_len(from), par, cmp);

		if (move_right) {
			if (par)
				par = scoutfs_avl_prev(&dst->item_root, par);
			else
				par = scoutfs_avl_first(&dst->item_root);
		} else {
			if (par)
				par = scoutfs_avl_next(&dst->item_root, par);
			else
				par = scoutfs_avl_last(&dst->item_root);
		}

		delete_item(src, from, &next);
		from = next;
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
		memcpy(new, bt, SCOUTFS_BLOCK_LG_SIZE);
		scoutfs_block_put(sb, bl);
	} else {
		/* returning a newly allocated block */
		memset(new, 0, SCOUTFS_BLOCK_LG_SIZE);
		new->hdr.fsid = super->hdr.fsid;
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
			       struct scoutfs_btree_block *child,
			       struct scoutfs_key *key)
{
	struct scoutfs_avl_node *par;
	int cmp;
	struct scoutfs_btree_ref ref = {
		.blkno = child->hdr.blkno,
		.seq = child->hdr.seq,
	};

	scoutfs_avl_search(&parent->item_root, cmp_key_item, key, &cmp, &par,
			   NULL, NULL);
	create_item(parent, key, &ref, sizeof(ref), par, cmp);
}

/*
 * Update an existing parent item reference to a child who may be new or
 * may have had its last item changed.
 */
static void update_parent_item(struct scoutfs_btree_block *parent,
			       struct scoutfs_btree_item *par_item,
			       struct scoutfs_btree_block *child)
{
	struct scoutfs_btree_ref *ref = item_val(parent, par_item);

	par_item->key = *item_key(last_item(child));
	ref->blkno = child->hdr.blkno;
	ref->seq = child->hdr.seq;
}

static void init_btree_block(struct scoutfs_btree_block *bt, int level)
{
	int free;

	free = SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block);
	if (level == 0)
		free -= SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;

	bt->level = level;
	bt->mid_free_len = cpu_to_le16(free);
}

/*
 * See if we need to split this block while descending for insertion so
 * that we have enough space to insert.  Parent blocks need enough space
 * to insert a new parent item if a child block splits.  Leaf blocks
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
		     struct scoutfs_btree_block *parent,
		     struct scoutfs_btree_block *right)
{
	struct scoutfs_block *left_bl = NULL;
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_btree_block *left;
	struct scoutfs_key max_key;
	int ret;
	int err;

	/* parents need to leave room for child references */
	if (right->level)
		val_len = sizeof(struct scoutfs_btree_ref);

	/* don't need to split if there's enough space for the item */
	if (le16_to_cpu(right->mid_free_len) >= item_len_bytes(val_len))
		return 0;

	if (item_full_pct(right) < 80) {
		compact_values(right);
		return 0;
	}

	/* alloc split neighbour first to avoid unwinding tree growth */
	ret = get_ref_block(sb, alloc, wri, BTW_ALLOC, NULL, &left_bl);
	if (ret)
		return ret;
	left = left_bl->data;

	init_btree_block(left, right->level);

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

		init_btree_block(parent, root->height);
		root->height++;
		root->ref.blkno = parent->hdr.blkno;
		root->ref.seq = parent->hdr.seq;

		scoutfs_key_set_ones(&max_key);
		create_parent_item(parent, right, &max_key);
	}

	move_items(left, right, false,
		   le16_to_cpu(right->total_item_bytes) / 2);

	create_parent_item(parent, left, item_key(last_item(left)));

	scoutfs_block_put(sb, left_bl);
	scoutfs_block_put(sb, par_bl);

	return 1;
}

/*
 * This is called during descent for deletion when we have a parent and
 * might need to join this block with a sibling block if this block has
 * too much free space.  Eventually we'll be able to fit all of the
 * sibling's items in our free space which lets us delete the sibling
 * block.
 */
static int try_join(struct super_block *sb,
		    struct scoutfs_radix_allocator *alloc,
		    struct scoutfs_block_writer *wri,
		    struct scoutfs_btree_root *root,
		    struct scoutfs_btree_block *parent,
		    struct scoutfs_btree_item *par_item,
		    struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_item *sib_par_item;
	struct scoutfs_btree_block *sib;
	struct scoutfs_block *sib_bl;
	struct scoutfs_btree_ref *ref;
	unsigned int sib_tot;
	bool move_right;
	int to_move;
	int ret;

	if (le16_to_cpu(bt->total_item_bytes) >= join_low_watermark())
		return 0;

	/* move items right into our block if we have a left sibling */
	sib_par_item = prev_item(parent, par_item);
	if (sib_par_item) {
		move_right = true;
	} else {
		sib_par_item = next_item(parent, par_item);
		move_right = false;
	}

	ref = item_val(parent, sib_par_item);
	ret = get_ref_block(sb, alloc, wri, BTW_DIRTY, ref, &sib_bl);
	if (ret)
		return ret;
	sib = sib_bl->data;

	sib_tot = le16_to_cpu(bt->total_item_bytes);
	if (sib_tot < join_low_watermark())
		to_move = sib_tot;
	else
		to_move = sib_tot - join_low_watermark();

	if (le16_to_cpu(bt->mid_free_len) < to_move)
		compact_values(bt);
	move_items(bt, sib, move_right, to_move);

	/* update our parent's item */
	if (!move_right)
		update_parent_item(parent, par_item, bt);

	/* update or delete sibling's parent item */
	if (le16_to_cpu(sib->nr_items) == 0) {
		delete_item(parent, sib_par_item, NULL);
		ret = scoutfs_radix_free(sb, alloc, wri,
					 le64_to_cpu(sib->hdr.blkno));
		BUG_ON(ret); /* could have dirtied alloc to avoid error */

	} else if (move_right) {
		update_parent_item(parent, sib_par_item, sib);
	}

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le16_to_cpu(parent->nr_items) == 1) {
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
	struct scoutfs_btree_item *par_item;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_item *prev;
	struct scoutfs_avl_node *next_node;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_ref *ref;
	unsigned int level;
	unsigned int nr;
	int ret;

	if (WARN_ON_ONCE((flags & (BTW_NEXT|BTW_PREV)) && iter_key == NULL) ||
	    WARN_ON_ONCE((flags & BTW_DIRTY) && (!alloc || !wri)))
		return -EINVAL;

restart:
	scoutfs_block_put(sb, par_bl);
	par_bl = NULL;
	parent = NULL;
	par_item = NULL;
	scoutfs_block_put(sb, bl);
	bl = NULL;
	bt = NULL;
	level = root->height;
	ret = 0;

	if (!root->height) {
		if (!(flags & BTW_INSERT)) {
			ret = -ENOENT;
		} else {
			ret = get_ref_block(sb, alloc, wri, BTW_ALLOC,
					    &root->ref, &bl);
			if (ret == 0) {
				bt = bl->data;
				init_btree_block(bt, 0);
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
		 * Splitting and joining can add or remove parents or
		 * change the parent item we use to reach the child
		 * block with the search key.  In the rare case that we
		 * split or join we simply restart the walk instead of
		 * update our state to reflect the tree changes.
		 */
		ret = 0;
		if (flags & (BTW_INSERT | BTW_DELETE))
			ret = try_split(sb, alloc, wri, root, key, val_len,
					parent, bt);
		if (ret == 0 && (flags & BTW_DELETE) && parent)
			ret = try_join(sb, alloc, wri, root, parent, par_item,
				       bt);
		if (ret > 0)
			goto restart;
		else if (ret < 0)
			break;

		/* done at the leaf */
		if (level == 0)
			break;

		nr = le16_to_cpu(bt->nr_items);
		/* Find the next child block for the search key. */
		node = scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					  NULL, NULL, &next_node, NULL);
		item = node_item(node ?: next_node);
		if (item == NULL) {
			scoutfs_corruption(sb, SC_BTREE_NO_CHILD_REF,
					   corrupt_btree_block_level,
					   "root_height %u root_blkno %llu root_seq %llu blkno %llu seq %llu level %u nr %u",
					   root->height,
					   le64_to_cpu(root->ref.blkno),
					   le64_to_cpu(root->ref.seq),
					   le64_to_cpu(bt->hdr.blkno),
					   le64_to_cpu(bt->hdr.seq), bt->level,
					   nr);
			ret = -EIO;
			break;
		}

		/* give the caller the next key to iterate towards */
		if (iter_key && (flags & BTW_NEXT) && next_item(bt, item)) {
			*iter_key = *item_key(item);
			scoutfs_key_inc(iter_key);

		} else if (iter_key && (flags & BTW_PREV) &&
			   (prev = prev_item(bt, item))) {
			*iter_key = *item_key(prev);
		}

		scoutfs_block_put(sb, par_bl);
		par_bl = bl;
		parent = bt;
		bl = NULL;
		bt = NULL;

		par_item = item;
		ref = item_val(parent, par_item);
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
	struct scoutfs_btree_block *bt = bl->data;

	iref->sb = sb;
	iref->bl = bl;
	iref->key = item_key(item);
	iref->val = item_val(bt, item);
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
	int ret;

	if (WARN_ON_ONCE(iref->key))
		return -EINVAL;

	ret = btree_walk(sb, NULL, NULL, root, 0, key, 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item) {
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
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *node;
	struct scoutfs_avl_node *par;
	struct scoutfs_block *bl;
	int cmp;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item) {
			ret = -EEXIST;
		} else {
			node = scoutfs_avl_search(&bt->item_root, cmp_key_item,
						  key, &cmp, &par, NULL, NULL);
			if (node) {
				ret = -EEXIST;
			} else {
				create_item(bt, key, val, val_len, par, cmp);
				ret = 0;
			}
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

static void update_item_value(struct scoutfs_btree_block *bt,
			      struct scoutfs_btree_item *item,
			      void *val, unsigned val_len)
{
	le16_add_cpu(&bt->total_item_bytes, val_bytes(val_len) -
		     val_bytes(le16_to_cpu(item->val_len)));
	delete_value(bt, le16_to_cpu(item->val_off),
		     le16_to_cpu(item->val_len));
	item->val_off = insert_value(bt, ptr_off(bt, item), val, val_len);
	item->val_len = cpu_to_le16(val_len);
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
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item) {
			update_item_value(bt, item, val, val_len);
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
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *par;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int cmp;
	int ret;

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item) {
			update_item_value(bt, item, val, val_len);
		} else {
			scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					   &cmp, &par, NULL, NULL);
			create_item(bt, key, val, val_len, par, cmp);
		}
		ret = 0;

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
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	ret = btree_walk(sb, alloc, wri, root, BTW_DELETE | BTW_DIRTY, key,
			 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item) {
			if (le16_to_cpu(bt->nr_items) == 1) {
				/* remove final empty block */
				ret = scoutfs_radix_free(sb, alloc, wri,
							 bl->blkno);
				if (ret == 0) {
					root->height = 0;
					root->ref.blkno = 0;
					root->ref.seq = 0;
				}
			} else {
				delete_item(bt, item, NULL);
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
 * iteration.  Callers set flags to tell which way to iterate.  The
 * first key is always inclusive.
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
	struct scoutfs_avl_node *node;
	struct scoutfs_avl_node *next;
	struct scoutfs_avl_node *prev;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_key iter_key;
	struct scoutfs_key walk_key;
	struct scoutfs_block *bl;
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

		node = scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					  NULL, NULL, &next, &prev);

		if (node == NULL && (flags & BTW_NEXT))
			node = next;
		else if (node == NULL && (flags & BTW_PREV))
			node = prev;
		item = node_item(node);
		if (item) {
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

int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref)
{
	return btree_iter(sb, root, BTW_PREV, key, iref);
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
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY, key, 0, &bl, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(bt, key);
		if (item)
			ret = 0;
		else
			ret = -ENOENT;

		scoutfs_block_put(sb, bl);
	}

	return ret;
}
