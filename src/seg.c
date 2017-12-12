/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/sched.h>
#include <linux/mm.h>

#include "super.h"
#include "format.h"
#include "seg.h"
#include "bio.h"
#include "kvec.h"
#include "cmp.h"
#include "manifest.h"
#include "alloc.h"
#include "key.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * seg.c should just be about the cache and io, and maybe
 * iteration and stuff.
 *
 * XXX:
 *  - lru and shrinker
 *  - verify csum
 *  - make sure item headers don't cross page boundaries
 *  - just wait on pages instead of weird flags?
 */

struct segment_cache {
	struct super_block *sb;
	spinlock_t lock;
	struct rb_root root;
	wait_queue_head_t waitq;

	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long lru_nr;
};


enum {
	SF_END_IO = 0,
};

static void *off_ptr(struct scoutfs_segment *seg, u32 off)
{
	unsigned int pg = off >> PAGE_SHIFT;
	unsigned int pg_off = off & ~PAGE_MASK;

	return page_address(seg->pages[pg]) + pg_off;
}

static struct scoutfs_segment *alloc_seg(struct super_block *sb, u64 segno)
{
	struct scoutfs_segment *seg;
	struct page *page;
	int i;

	/* don't waste the tail of pages */
	BUILD_BUG_ON(SCOUTFS_SEGMENT_SIZE % PAGE_SIZE);

	seg = kzalloc(sizeof(struct scoutfs_segment), GFP_NOFS);
	if (!seg)
		return seg;

	seg->sb = sb;
	RB_CLEAR_NODE(&seg->node);
	INIT_LIST_HEAD(&seg->lru_entry);
	atomic_set(&seg->refcount, 1);
	seg->segno = segno;

	for (i = 0; i < SCOUTFS_SEGMENT_PAGES; i++) {
		page = alloc_page(GFP_NOFS);
		if (!page) {
			scoutfs_seg_put(seg);
			return ERR_PTR(-ENOMEM);
		}

		seg->pages[i] = page;
	}

	trace_scoutfs_seg_alloc(seg);
	scoutfs_inc_counter(sb, seg_alloc);

	return seg;
}

void scoutfs_seg_get(struct scoutfs_segment *seg)
{
	atomic_inc(&seg->refcount);
}

void scoutfs_seg_put(struct scoutfs_segment *seg)
{
	int i;

	if (!IS_ERR_OR_NULL(seg) && atomic_dec_and_test(&seg->refcount)) {
		trace_scoutfs_seg_free(seg);
		scoutfs_inc_counter(seg->sb, seg_free);
		WARN_ON_ONCE(!RB_EMPTY_NODE(&seg->node));
		WARN_ON_ONCE(!list_empty(&seg->lru_entry));
		for (i = 0; i < SCOUTFS_SEGMENT_PAGES; i++)
			if (seg->pages[i])
				__free_page(seg->pages[i]);
		kfree(seg);
	}
}

static struct scoutfs_segment *find_seg(struct rb_root *root, u64 segno)
{
	struct rb_node *node = root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_segment *seg;
	int cmp;

	while (node) {
		parent = node;
		seg = container_of(node, struct scoutfs_segment, node);

		cmp = scoutfs_cmp_u64s(segno, seg->segno);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return seg;
	}

	return NULL;
}

static void lru_check(struct segment_cache *cac, struct scoutfs_segment *seg)
{
	if (RB_EMPTY_NODE(&seg->node)) {
		if (!list_empty(&seg->lru_entry)) {
			list_del_init(&seg->lru_entry);
			cac->lru_nr--;
		}
	} else {
		if (list_empty(&seg->lru_entry)) {
			list_add_tail(&seg->lru_entry, &cac->lru_list);
			cac->lru_nr++;
		} else {
			list_move_tail(&seg->lru_entry, &cac->lru_list);
		}
	}
}

/*
 * This always inserts the segment into the rbtree.  If there's already
 * a segment at the given seg then it is removed and returned.  The
 * caller doesn't have to erase it from the tree if it's returned but it
 * does have to put the reference that it's given.
 */
static struct scoutfs_segment *replace_seg(struct segment_cache *cac,
					   struct scoutfs_segment *ins)
{
	struct rb_root *root = &cac->root;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_segment *seg;
	struct scoutfs_segment *found = NULL;
	int cmp;

	while (*node) {
		parent = *node;
		seg = container_of(*node, struct scoutfs_segment, node);

		cmp = scoutfs_cmp_u64s(ins->segno, seg->segno);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			rb_replace_node(&seg->node, &ins->node, root);
			RB_CLEAR_NODE(&seg->node);
			lru_check(cac, seg);
			lru_check(cac, ins);
			found = seg;
			break;
		}
	}

	if (!found) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
		lru_check(cac, ins);
	}

	return found;
}

static bool erase_seg(struct segment_cache *cac, struct scoutfs_segment *seg)
{
	if (!RB_EMPTY_NODE(&seg->node)) {
		rb_erase(&seg->node, &cac->root);
		RB_CLEAR_NODE(&seg->node);
		lru_check(cac, seg);
		return true;
	}

	return false;
}

static void seg_end_io(struct super_block *sb, void *data, int err)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment *seg = data;
	unsigned long flags;
	bool erased = false;

	spin_lock_irqsave(&cac->lock, flags);

	set_bit(SF_END_IO, &seg->flags);

	if (err) {
		seg->err = err;
		erased = erase_seg(cac, seg);
	} else {
		lru_check(cac, seg);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	smp_mb__after_atomic();
	if (waitqueue_active(&cac->waitq))
		wake_up(&cac->waitq);

	if (erased)
		scoutfs_seg_put(seg);
	scoutfs_seg_put(seg);
}

static u64 segno_to_blkno(u64 blkno)
{
	return blkno << (SCOUTFS_SEGMENT_SHIFT - SCOUTFS_BLOCK_SHIFT);
}

int scoutfs_seg_alloc(struct super_block *sb, u64 segno,
		      struct scoutfs_segment **seg_ret)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment *existing;
	struct scoutfs_segment *seg;
	unsigned long flags;
	int ret;

	seg = alloc_seg(sb, segno);
	if (!seg) {
		ret = -ENOMEM;
		goto out;
	}

	/* reads shouldn't wait for this */
	set_bit(SF_END_IO, &seg->flags);

	/* zero the block header so the caller knows to initialize */
	memset(page_address(seg->pages[0]), 0,
	       sizeof(struct scoutfs_segment_block));

	/* XXX always remove existing segs, is that necessary? */
	spin_lock_irqsave(&cac->lock, flags);

	atomic_inc(&seg->refcount);
	existing = replace_seg(cac, seg);
	spin_unlock_irqrestore(&cac->lock, flags);
	if (existing)
		scoutfs_seg_put(existing);

	ret = 0;
out:
	*seg_ret = seg;
	return ret;

}

/*
 * This just frees the segno for the given seg.  It's gross but
 * symmetrical with only being able to allocate segnos by allocating a
 * seg.  We'll probably have to do better.
 */
int scoutfs_seg_free_segno(struct super_block *sb, struct scoutfs_segment *seg)
{
	return scoutfs_alloc_free(sb, seg->segno);
}

/*
 * The bios submitted by this don't have page references themselves.  If
 * this succeeds then the caller must call _wait before putting their
 * seg ref.
 */
struct scoutfs_segment *scoutfs_seg_submit_read(struct super_block *sb,
						u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment *existing;
	struct scoutfs_segment *seg;
	unsigned long flags;

	trace_scoutfs_seg_submit_read(sb, segno);

	spin_lock_irqsave(&cac->lock, flags);
	seg = find_seg(&cac->root, segno);
	if (seg) {
		lru_check(cac, seg);
		atomic_inc(&seg->refcount);
	}
	spin_unlock_irqrestore(&cac->lock, flags);
	if (seg)
		return seg;

	seg = alloc_seg(sb, segno);
	if (IS_ERR(seg))
		return seg;

	/* always drop existing segs, could compare seqs */
	spin_lock_irqsave(&cac->lock, flags);
	atomic_inc(&seg->refcount);
	existing = replace_seg(cac, seg);
	spin_unlock_irqrestore(&cac->lock, flags);
	if (existing)
		scoutfs_seg_put(existing);

	atomic_inc(&seg->refcount);
	scoutfs_bio_submit(sb, READ, seg->pages, segno_to_blkno(seg->segno),
			   SCOUTFS_SEGMENT_BLOCKS, seg_end_io, seg);

	return seg;
}

int scoutfs_seg_submit_write(struct super_block *sb,
			     struct scoutfs_segment *seg,
			     struct scoutfs_bio_completion *comp)
{
	trace_scoutfs_seg_submit_write(sb, seg->segno);

	scoutfs_bio_submit_comp(sb, WRITE, seg->pages,
				segno_to_blkno(seg->segno),
				SCOUTFS_SEGMENT_BLOCKS, comp);

	return 0;
}

/*
 * Wait for IO on the segment to complete.  In the cached read fast path
 * the bit is already set by the reads that populated the cache.
 *
 * The caller provides the segno and seq from their segment reference to
 * validate that we found the version of the segment that they were
 * looking for.  If we find an old cached version we return -ESTALE and
 * the caller has to retry its reference to find the current segment for
 * its operation.  (Typically by getting a new manifest btree root and
 * searching for keys in the manifest.)
 *
 * XXX drop stale segments from the cache
 * XXX none of the callers perform that retry today.
 */
int scoutfs_seg_wait(struct super_block *sb, struct scoutfs_segment *seg,
		     u64 segno, u64 seq)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	int ret;

	ret = wait_event_interruptible(cac->waitq,
				       test_bit(SF_END_IO, &seg->flags));
	if (ret)
		goto out;

	if (seg->err) {
		ret = seg->err;
		goto out;
	}

	sblk = off_ptr(seg, 0);

	if (WARN_ON_ONCE(segno != le64_to_cpu(sblk->segno)) ||
	    WARN_ON_ONCE(seq != le64_to_cpu(sblk->seq))) {
		    ret = -ESTALE;
		    goto out;
	}

	ret = 0;
out:
	return ret;
}

static void kvec_from_pages(struct scoutfs_segment *seg,
			    struct kvec *kvec, u32 off, u16 len)
{
	u32 first;

	first = min_t(int, len, PAGE_SIZE - (off & ~PAGE_MASK));

	if (first == len)
		scoutfs_kvec_init(kvec, off_ptr(seg, off), len);
	else
		scoutfs_kvec_init(kvec, off_ptr(seg, off), first,
			          off_ptr(seg, off + first), len - first);
}

static u32 item_bytes(u8 nr_links, u16 key_len, u16 val_len)
{
	return offsetof(struct scoutfs_segment_item, skip_links[nr_links]) +
		key_len + val_len;
}

static inline int item_key_off(struct scoutfs_segment_item *item, int item_off)
{
	return item_off + item_bytes(item->nr_links, 0, 0);
}

static inline void *item_key_ptr(struct scoutfs_segment_item *item)
{
	return (void *)item + item_bytes(item->nr_links, 0, 0);
}

static inline int item_val_off(struct scoutfs_segment_item *item, int item_off)
{
	return item_key_off(item, item_off) + le16_to_cpu(item->key_len);
}

static void item_ptrs(struct scoutfs_segment *seg, int off,
		      struct scoutfs_key_buf *key, struct kvec *val)
{
	struct scoutfs_segment_item *item = off_ptr(seg, off);

	if (key)
		scoutfs_key_init(key, item_key_ptr(item),
				 le16_to_cpu(item->key_len));
	if (val)
		kvec_from_pages(seg, val, item_val_off(item, off),
				le16_to_cpu(item->val_len));
}

static void first_last_keys(struct scoutfs_segment *seg,
			    struct scoutfs_key_buf *first,
			    struct scoutfs_key_buf *last)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);

	item_ptrs(seg, sizeof(struct scoutfs_segment_block), first, NULL);
	item_ptrs(seg, le32_to_cpu(sblk->last_item_off), last, NULL);
}

static int check_caller_off(struct scoutfs_segment_block *sblk, int off)
{
	if (off >= 0 && off < sizeof(struct scoutfs_segment_block))
		off = sizeof(struct scoutfs_segment_block);

	if (off > le32_to_cpu(sblk->last_item_off))
		off = -ENOENT;

	return off;
}

/*
 * Give the caller the key and value of the item at the given offset.
 *
 * Negative offsets are sticky errors and offsets outside the used bytes
 * in the segment return -ENOENT;
 *
 * All other offsets must be initial values less than the segment header
 * size, notably including 0, or returned from _next_off().
 */
int scoutfs_seg_item_ptrs(struct scoutfs_segment *seg, int off,
			  struct scoutfs_key_buf *key, struct kvec *val,
			  u8 *flags)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;

	off = check_caller_off(sblk, off);
	if (off < 0)
		return off;

	item_ptrs(seg, off, key, val);

	if (flags) {
		item = off_ptr(seg, off);
		*flags = item->flags;
	}

	return 0;
}

/*
 * Return the number of links that the *next* added node should have.
 * We're appending in order so we can use the low bits of the node count
 * to get an ideal distribution of the number of links to enable (log n)
 * searching: of links in each node.  Half of the nodes will have 1
 * links, a quarter will have 2, an eighth will have 3, and so on.
 */
static u8 skip_next_nr(u32 nr_items)
{
	return ffs(nr_items + 1);
}

/* The highest 1-based set bit is the max number of links any node can have */
static u8 skip_most_nr(u32 nr_items)
{
	return fls(nr_items);
}

/*
 * Find offset of the first item in the segment whose key is greater
 * than or equal to the search key.  -ENOENT is returned if there's no
 * item that matches.
 *
 * This is a standard skip list search from the segment block through
 * the items.  Follow high less frequent links while the key is greater
 * than the items and descend down to lower more frequent links when the
 * search key is less.
 */
int scoutfs_seg_find_off(struct scoutfs_segment *seg,
			 struct scoutfs_key_buf *key)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf item_key;
	__le32 *links;
	int cmp;
	int ret;
	int i;
	int off;

	links = sblk->skip_links;
	ret = -ENOENT;
	for (i = skip_most_nr(le32_to_cpu(sblk->nr_items)) - 1; i >= 0; i--) {
		if (links[i] == 0)
			continue;

		off = le32_to_cpu(links[i]);
		item = off_ptr(seg, off);
		scoutfs_key_init(&item_key, item_key_ptr(item),
				 le16_to_cpu(item->key_len));

		cmp = scoutfs_key_compare(key, &item_key);
		if (cmp == 0) {
			ret = off;
			break;
		}

		if (cmp > 0) {
			links = item->skip_links;
			i++;
		} else {
			ret = off;
		}
	}

	return ret;
}

/*
 * Return the offset of the next item after the current item.  The input offset
 * must be a valid offset from _find_off().
 */
int scoutfs_seg_next_off(struct scoutfs_segment *seg, int off)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;

	off = check_caller_off(sblk, off);
	if (off > 0) {
		item = off_ptr(seg, off);
		off = le32_to_cpu(item->skip_links[0]);
		if (off == 0)
			off = -ENOENT;
	}
	return off;
}

/*
 * Return the count of bytes of the segment actually used.
 */
u32 scoutfs_seg_total_bytes(struct scoutfs_segment *seg)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);

	return le32_to_cpu(sblk->total_bytes);
}

/*
 * Returns true if the given item population will fit in a single
 * segment.
 *
 * We don't have items cross block boundaries.  It would be too
 * expensive to maintain packing of sorted dirty items in bins.  Instead
 * we assume that we'll lose the worst case largest possible item on every
 * block transition.  This will almost never be the case.  This causes us
 * to lose around 15% of space for level 0 segment writes.
 *
 * Our pattern of item link counts ensures that there will always be fewer
 * than two links per item.  We assume the worst case items have the
 * max number of links.
 */
bool scoutfs_seg_fits_single(u32 nr_items, u32 key_bytes, u32 val_bytes)
{
	u32 header = sizeof(struct scoutfs_segment_block);
	u32 items = nr_items * item_bytes(2, 0, 0);
	u32 item_pad = item_bytes(skip_most_nr(nr_items), SCOUTFS_MAX_KEY_SIZE,
				  SCOUTFS_MAX_VAL_SIZE) - 1;
	u32 padding = (SCOUTFS_SEGMENT_SIZE / SCOUTFS_BLOCK_SIZE) * item_pad;

	return (header + items + key_bytes + val_bytes + padding)
			<= SCOUTFS_SEGMENT_SIZE;
}

static u32 align_item_off(struct scoutfs_segment *seg, u32 item_off, u32 bytes)
{
	u32 space = SCOUTFS_BLOCK_SIZE - (item_off & SCOUTFS_BLOCK_MASK);

	if (bytes > space) {
		memset(off_ptr(seg, item_off), 0, space);
		return item_off + space;
	}

	return item_off;
}


/*
 * Append an item to the segment.  The caller always appends items that
 * have been sorted by their keys.  They may not know how many will fit.
 * We return true if we appended and false if the segment was full.
 */
bool scoutfs_seg_append_item(struct super_block *sb, struct scoutfs_segment *seg,
			     struct scoutfs_key_buf *key, struct kvec *val,
			     u8 flags, __le32 **links)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf item_key;
	SCOUTFS_DECLARE_KVEC(item_val);
	u8 nr_links;
	u32 val_len;
	u32 bytes;
	u32 off;
	int i;

	val_len = scoutfs_kvec_length(val);

	/* initialize the segment and skip links as the first item is appended */
	if (sblk->nr_items == 0) {
		/* XXX the segment block header is a mess, be better */
		sblk->segno = cpu_to_le64(seg->segno);
		sblk->seq = super->next_seg_seq;
		le64_add_cpu(&super->next_seg_seq, 1);
		sblk->total_bytes = cpu_to_le32(sizeof(*sblk));

		for (i = 0; i < SCOUTFS_MAX_SKIP_LINKS; i++)
			links[i] = &sblk->skip_links[i];
	}

	/*
	 * It's very bad data corruption if we write out of order items
	 * to a segment.  It'll mislead the key search during read and
	 * stop it from finding its items.
	 */
	off = le32_to_cpu(sblk->last_item_off);
	if (off) {
		item_ptrs(seg, off, &item_key, NULL);
		BUG_ON(scoutfs_key_compare(key, &item_key) <= 0);
	}

	nr_links = skip_next_nr(le32_to_cpu(sblk->nr_items));
	bytes = item_bytes(nr_links, key->key_len, val_len);
	off = align_item_off(seg, le32_to_cpu(sblk->total_bytes), bytes);

	if ((off + bytes) > SCOUTFS_SEGMENT_SIZE)
		return false;

	sblk->last_item_off = cpu_to_le32(off);
	sblk->total_bytes = cpu_to_le32(off + bytes);
	le32_add_cpu(&sblk->nr_items, 1);

	item = off_ptr(seg, off);
	item->key_len = cpu_to_le16(key->key_len);
	item->val_len = cpu_to_le16(val_len);
	item->flags = flags;

	/* point the previous skip links at our appended item */
	item->nr_links = nr_links;
	for (i = 0; i < nr_links; i++) {
		item->skip_links[i] = 0;
		*links[i] = cpu_to_le32(off);
		links[i] = &item->skip_links[i];
	}

	item_ptrs(seg, off, &item_key, item_val);
	scoutfs_key_copy(&item_key, key);
	scoutfs_kvec_memcpy(item_val, val);

	return true;
}

void scoutfs_seg_init_ment(struct scoutfs_manifest_entry *ment, int level,
			   struct scoutfs_segment *seg)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	first_last_keys(seg, &first, &last);

	scoutfs_manifest_init_entry(ment, level, le64_to_cpu(sblk->segno),
				    le64_to_cpu(sblk->seq), &first, &last);
}

/*
 * We maintain an LRU of segments so that the shrinker can free the
 * oldest under memory pressure.  Segments are only present in the LRU
 * after their IO has completed and while they're in the rbtree.  This
 * shrink only removes them from the rbtree and drops the reference it
 * held.  They may be freed a bit later once all their active references
 * are dropped.
 *
 * If this is called with nr_to_scan == 0 then it only returns the nr.
 * We avoid acquiring the lock in that case.
 *
 * Lookup code only uses the lru entry to change position in the LRU while
 * the segment is in the rbtree.  Once we remove it no one else will use
 * the LRU entry and we can use it to track all the segments that we're
 * going to put outside of the lock.
 *
 * XXX:
 *  - are sc->nr_to_scan and our return meant to be in units of pages?
 *  - should we sync a transaction here?
 */
static int seg_lru_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
	struct segment_cache *cac = container_of(shrink, struct segment_cache,
						 shrinker);
	struct super_block *sb = cac->sb;
	struct scoutfs_segment *seg;
	struct scoutfs_segment *tmp;
	unsigned long flags;
	unsigned long nr;
	LIST_HEAD(list);
	int ret;

	nr = DIV_ROUND_UP(sc->nr_to_scan, SCOUTFS_SEGMENT_PAGES);
	if (!nr)
		goto out;

	spin_lock_irqsave(&cac->lock, flags);

	list_for_each_entry_safe(seg, tmp, &cac->lru_list, lru_entry) {
		/* shouldn't be possible */
		if (WARN_ON_ONCE(RB_EMPTY_NODE(&seg->node)))
			continue;

		if (nr-- == 0)
			break;

		/* using ref that rb tree presence had */
		erase_seg(cac, seg);
		list_add_tail(&seg->lru_entry, &list);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	list_for_each_entry_safe(seg, tmp, &list, lru_entry) {
		trace_scoutfs_seg_shrink(seg);
		scoutfs_inc_counter(sb, seg_shrink);
		list_del_init(&seg->lru_entry);
		scoutfs_seg_put(seg);
	}

out:
	ret = min_t(unsigned long, cac->lru_nr * SCOUTFS_SEGMENT_PAGES,
		    INT_MAX);
	trace_scoutfs_seg_shrink_exit(sb, sc->nr_to_scan, ret);
	return ret;
}

int scoutfs_seg_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac;

	cac = kzalloc(sizeof(struct segment_cache), GFP_KERNEL);
	if (!cac)
		return -ENOMEM;
	sbi->segment_cache = cac;

	cac->sb = sb;
	spin_lock_init(&cac->lock);
	cac->root = RB_ROOT;
	init_waitqueue_head(&cac->waitq);

	cac->shrinker.shrink = seg_lru_shrink;
	cac->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&cac->shrinker);
	INIT_LIST_HEAD(&cac->lru_list);

	return 0;
}

void scoutfs_seg_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment *seg;
	struct rb_node *node;

	if (cac) {
		if (cac->shrinker.shrink == seg_lru_shrink)
			unregister_shrinker(&cac->shrinker);

		for (node = rb_first(&cac->root); node; ) {
			seg = container_of(node, struct scoutfs_segment, node);
			node = rb_next(node);
			erase_seg(cac, seg);
			scoutfs_seg_put(seg);
		}

		kfree(cac);
	}
}
