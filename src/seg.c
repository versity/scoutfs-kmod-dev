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

struct scoutfs_segment {
	struct rb_node node;
	struct list_head lru_entry;
	atomic_t refcount;
	u64 segno;
	unsigned long flags;
	int err;
	struct page *pages[SCOUTFS_SEGMENT_PAGES];
};

enum {
	SF_END_IO = 0,
};

static struct scoutfs_segment *alloc_seg(u64 segno)
{
	struct scoutfs_segment *seg;
	struct page *page;
	int i;

	/* don't waste the tail of pages */
	BUILD_BUG_ON(SCOUTFS_SEGMENT_SIZE % PAGE_SIZE);

	seg = kzalloc(sizeof(struct scoutfs_segment), GFP_NOFS);
	if (!seg)
		return seg;

	RB_CLEAR_NODE(&seg->node);
	INIT_LIST_HEAD(&seg->lru_entry);
	atomic_set(&seg->refcount, 1);
	seg->segno = segno;

	for (i = 0; i < SCOUTFS_SEGMENT_PAGES; i++) {
		page = alloc_page(GFP_NOFS);
		trace_printk("seg %p segno %llu page %u %p\n",
			     seg, segno, i, page);
		if (!page) {
			scoutfs_seg_put(seg);
			return ERR_PTR(-ENOMEM);
		}

		seg->pages[i] = page;
	}

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

	seg = alloc_seg(segno);
	if (!seg) {
		ret = -ENOMEM;
		goto out;
	}

	/* reads shouldn't wait for this */
	set_bit(SF_END_IO, &seg->flags);

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

	trace_printk("segno %llu\n", segno);

	spin_lock_irqsave(&cac->lock, flags);
	seg = find_seg(&cac->root, segno);
	if (seg) {
		lru_check(cac, seg);
		atomic_inc(&seg->refcount);
	}
	spin_unlock_irqrestore(&cac->lock, flags);
	if (seg)
		return seg;

	seg = alloc_seg(segno);
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
	trace_printk("submitting segno %llu\n", seg->segno);

	scoutfs_bio_submit_comp(sb, WRITE, seg->pages,
				segno_to_blkno(seg->segno),
				SCOUTFS_SEGMENT_BLOCKS, comp);

	return 0;
}

int scoutfs_seg_wait(struct super_block *sb, struct scoutfs_segment *seg)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	int ret;

	ret = wait_event_interruptible(cac->waitq,
				       test_bit(SF_END_IO, &seg->flags));
	if (!ret)
		ret = seg->err;

	return ret;
}

static void *off_ptr(struct scoutfs_segment *seg, u32 off)
{
	unsigned int pg = off >> PAGE_SHIFT;
	unsigned int pg_off = off & ~PAGE_MASK;

	return page_address(seg->pages[pg]) + pg_off;
}

static u32 pos_off(u32 pos)
{
	/* items need of be a power of two */
	BUILD_BUG_ON(!is_power_of_2(sizeof(struct scoutfs_segment_item)));
	/* and the first item has to be naturally aligned */
	BUILD_BUG_ON(offsetof(struct scoutfs_segment_block, items) %
		     sizeof(struct scoutfs_segment_item));

	return offsetof(struct scoutfs_segment_block, items[pos]);
}

static void *pos_ptr(struct scoutfs_segment *seg, u32 pos)
{
	return off_ptr(seg, pos_off(pos));
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

int scoutfs_seg_item_ptrs(struct scoutfs_segment *seg, int pos,
			  struct scoutfs_key_buf *key, struct kvec *val,
			  u8 *flags)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;

	if (pos < 0 || pos >= le32_to_cpu(sblk->nr_items))
		return -ENOENT;

	item = pos_ptr(seg, pos);

	if (key)
		scoutfs_key_init(key, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));
	if (val)
		kvec_from_pages(seg, val, le32_to_cpu(item->val_off),
				le16_to_cpu(item->val_len));
	if (flags)
		*flags = item->flags;

	return 0;
}

/*
 * Find the first item array position whose key is >= the search key.
 * This can return the number of positions if the key is greater than
 * all the keys.
 */
static int find_key_pos(struct scoutfs_segment *seg,
			struct scoutfs_key_buf *search)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_key_buf key;
	unsigned int start = 0;
	unsigned int end = le32_to_cpu(sblk->nr_items);
	unsigned int pos = 0;
	int cmp;

	while (start < end) {
		pos = start + (end - start) / 2;
		scoutfs_seg_item_ptrs(seg, pos, &key, NULL, NULL);

		cmp = scoutfs_key_compare(search, &key);
		if (cmp < 0)
			end = pos;
		else if (cmp > 0)
			start = ++pos;
		else
			break;
	}

	return pos;
}

int scoutfs_seg_find_pos(struct scoutfs_segment *seg,
			 struct scoutfs_key_buf *key)
{
	return find_key_pos(seg, key);
}

/*
 * Keys are aligned to the next block boundary if they'd cross a block
 * boundary.  To find the first value offset we have to assume that
 * there will be a worst case key alignment at every block boundary.
 */
static u32 first_val_off(u32 nr_items, u32 key_bytes)
{
	u32 key_padding = SCOUTFS_MAX_KEY_SIZE - 1;
	u32 partial_block = SCOUTFS_BLOCK_SIZE - key_padding;
	u32 first_key_off = pos_off(nr_items);
	u32 block_off = first_key_off & SCOUTFS_BLOCK_MASK;
	u32 total_padding = ((block_off + key_bytes) / partial_block) *
				key_padding;

	return first_key_off + key_bytes + total_padding;
}

/*
 * Returns true if the given number of items with the given total byte
 * counts of keys and values fits inside a single segment.
 */
bool scoutfs_seg_fits_single(u32 nr_items, u32 key_bytes, u32 val_bytes)
{
	return (first_val_off(nr_items, key_bytes) + val_bytes)
			<= SCOUTFS_SEGMENT_SIZE;
}

static u32 align_key_off(struct scoutfs_segment *seg, u32 key_off, u32 len)
{
	u32 space = SCOUTFS_BLOCK_SIZE - (key_off & SCOUTFS_BLOCK_MASK);

	if (len > space) {
		memset(off_ptr(seg, key_off), 0, space);
		return key_off + space;
	}

	return key_off;
}

/*
 * Store the first item in the segment.  The caller knows the number
 * of items and bytes of keys that determine where the keys and values
 * start.  Future items are appended by looking at the last item.
 *
 * This should never fail because any item must always fit in a segment.
 */
void scoutfs_seg_first_item(struct super_block *sb,
			    struct scoutfs_segment *seg,
			    struct scoutfs_key_buf *key, struct kvec *val,
			    u8 flags, unsigned int nr_items,
			    unsigned int key_bytes)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf item_key;
	SCOUTFS_DECLARE_KVEC(item_val);
	u32 key_off;
	u32 val_off;

	/* XXX the segment block header is a mess, be better */
	sblk->segno = cpu_to_le64(seg->segno);
	sblk->seq = super->next_seg_seq;
	le64_add_cpu(&super->next_seg_seq, 1);

	key_off = align_key_off(seg, pos_off(nr_items), key->key_len);
	val_off = first_val_off(nr_items, key_bytes);

	sblk->nr_items = cpu_to_le32(1);

	trace_printk("first item offs key %u val %u\n", key_off, val_off);

	item = pos_ptr(seg, 0);
	item->seq = cpu_to_le64(1);
	item->key_off = cpu_to_le32(key_off);
	item->val_off = cpu_to_le32(val_off);
	item->key_len = cpu_to_le16(key->key_len);
	item->val_len = cpu_to_le16(scoutfs_kvec_length(val));
	item->flags = flags;

	scoutfs_seg_item_ptrs(seg, 0, &item_key, item_val, NULL);
	scoutfs_key_copy(&item_key, key);
	scoutfs_kvec_memcpy(item_val, val);
}

void scoutfs_seg_append_item(struct super_block *sb,
			     struct scoutfs_segment *seg,
			     struct scoutfs_key_buf *key, struct kvec *val,
			     u8 flags)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_segment_item *prev;
	struct scoutfs_key_buf item_key;
	SCOUTFS_DECLARE_KVEC(item_val);
	u32 key_off;
	u32 val_off;
	u32 pos;

	pos = le32_to_cpu(sblk->nr_items);
	sblk->nr_items = cpu_to_le32(pos + 1);

	prev = pos_ptr(seg, pos - 1);
	item = pos_ptr(seg, pos);

	key_off = le32_to_cpu(prev->key_off) + le16_to_cpu(prev->key_len);
	val_off = le32_to_cpu(prev->val_off) + le16_to_cpu(prev->val_len);

	key_off = align_key_off(seg, key_off, key->key_len);

	item->seq = cpu_to_le64(1);
	item->key_off = cpu_to_le32(key_off);
	item->val_off = cpu_to_le32(val_off);
	item->key_len = cpu_to_le16(key->key_len);
	item->val_len = cpu_to_le16(scoutfs_kvec_length(val));
	item->flags = flags;

	trace_printk("item %u offs key %u val %u\n",
		     pos, key_off, val_off);

	scoutfs_seg_item_ptrs(seg, pos, &item_key, item_val, NULL);
	scoutfs_key_copy(&item_key, key);
	scoutfs_kvec_memcpy(item_val, val);
}

/*
 * Add a dirty manifest entry for the given segment at the given level.
 */
int scoutfs_seg_manifest_add(struct super_block *sb,
			     struct scoutfs_segment *seg, u8 level)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	item = pos_ptr(seg, 0);
	scoutfs_key_init(&first, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));

	item = pos_ptr(seg, le32_to_cpu(sblk->nr_items) - 1);
	scoutfs_key_init(&last, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));

	return scoutfs_manifest_add(sb, &first, &last, le64_to_cpu(sblk->segno),
				    le64_to_cpu(sblk->seq), level);
}

int scoutfs_seg_manifest_del(struct super_block *sb,
			     struct scoutfs_segment *seg, u8 level)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf first;

	item = pos_ptr(seg, 0);
	scoutfs_key_init(&first, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));

	return scoutfs_manifest_del(sb, &first, le64_to_cpu(sblk->seq), level);
}

/*
 * Return an allocated manifest entry that describes the segment, returns
 * NULL if it couldn't allocate.
 */
struct scoutfs_manifest_entry *
scoutfs_seg_manifest_entry(struct super_block *sb,
			   struct scoutfs_segment *seg, u8 level)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	item = pos_ptr(seg, 0);
	scoutfs_key_init(&first, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));

	item = pos_ptr(seg, le32_to_cpu(sblk->nr_items) - 1);
	scoutfs_key_init(&last, off_ptr(seg, le32_to_cpu(item->key_off)),
				 le16_to_cpu(item->key_len));

	return scoutfs_manifest_alloc_entry(sb, &first, &last,
					    le64_to_cpu(sblk->segno),
					    le64_to_cpu(sblk->seq), level);
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

	nr = sc->nr_to_scan;
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
		scoutfs_inc_counter(sb, seg_lru_shrink);
		list_del_init(&seg->lru_entry);
		scoutfs_seg_put(seg);
	}

out:
	return min_t(unsigned long, cac->lru_nr, INT_MAX);
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
