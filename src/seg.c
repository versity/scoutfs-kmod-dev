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
	spinlock_t lock;
	struct rb_root root;
	wait_queue_head_t waitq;
};

struct scoutfs_segment {
	struct rb_node node;
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

	return seg;
}

void scoutfs_seg_put(struct scoutfs_segment *seg)
{
	int i;

	if (!IS_ERR_OR_NULL(seg) && atomic_dec_and_test(&seg->refcount)) {
		WARN_ON_ONCE(!RB_EMPTY_NODE(&seg->node));
		for (i = 0; i < SCOUTFS_SEGMENT_PAGES; i++)
			if (seg->pages[i])
				__free_page(seg->pages[i]);
		kfree(seg);
	}
}

static int cmp_u64s(u64 a, u64 b)
{
	return a < b ? -1 : a > b ? 1 : 0;
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

		cmp = cmp_u64s(segno, seg->segno);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return seg;
	}

	return NULL;
}

/*
 * This always inserts the segment into the rbtree.  If there's already
 * a segment at the given seg then it is removed and returned.  The caller
 * doesn't have to erase it from the tree if it's returned.
 */
static struct scoutfs_segment *replace_seg(struct rb_root *root,
					   struct scoutfs_segment *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_segment *seg;
	struct scoutfs_segment *found = NULL;
	int cmp;

	while (*node) {
		parent = *node;
		seg = container_of(*node, struct scoutfs_segment, node);

		cmp = cmp_u64s(ins->segno, seg->segno);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			rb_replace_node(&seg->node, &ins->node, root);
			found = seg;
			break;
		}
	}

	if (!found) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
	}

	return found;
}

static bool erase_seg(struct rb_root *root, struct scoutfs_segment *seg)
{
	if (!RB_EMPTY_NODE(&seg->node)) {
		rb_erase(&seg->node, root);
		RB_CLEAR_NODE(&seg->node);
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
	bool erased;

	if (err) {
		seg->err = err;

		spin_lock_irqsave(&cac->lock, flags);
		erased = erase_seg(&cac->root, seg);
		spin_unlock_irqrestore(&cac->lock, flags);
		if (erased)
			scoutfs_seg_put(seg);
	}

	set_bit(SF_END_IO, &seg->flags);
	smp_mb__after_atomic();
	if (waitqueue_active(&cac->waitq))
		wake_up(&cac->waitq);

	scoutfs_seg_put(seg);
}

static u64 segno_to_blkno(u64 blkno)
{
	return blkno << (SCOUTFS_SEGMENT_SHIFT - SCOUTFS_BLOCK_SHIFT);
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

	spin_lock_irqsave(&cac->lock, flags);
	seg = find_seg(&cac->root, segno);
	if (seg)
		atomic_inc(&seg->refcount);
	spin_unlock_irqrestore(&cac->lock, flags);
	if (seg)
		return seg;

	seg = alloc_seg(segno);
	if (IS_ERR(seg))
		return seg;

	/* always drop existing segs, could compare seqs */
	spin_lock_irqsave(&cac->lock, flags);
	atomic_inc(&seg->refcount);
	existing = replace_seg(&cac->root, seg);
	spin_unlock_irqrestore(&cac->lock, flags);
	if (existing)
		scoutfs_seg_put(existing);

	atomic_inc(&seg->refcount);
	scoutfs_bio_submit(sb, READ, seg->pages, segno_to_blkno(seg->segno),
			   SCOUTFS_SEGMENT_BLOCKS, seg_end_io, seg);

	return seg;
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

/*
 * Return a pointer to the item in the array at the given position.
 *
 * The item structs fill the first block in the segment after the
 * initial segment block struct.  Item structs don't cross block
 * boundaries so the final bytes that would make up a partial item
 * struct are skipped.
 */
static struct scoutfs_segment_item *pos_item(struct scoutfs_segment *seg,
					     int pos)
{
	u32 off;

	if (pos < SCOUTFS_SEGMENT_FIRST_BLOCK_ITEMS) {
		off = sizeof(struct scoutfs_segment_block);
	} else {
		pos -= SCOUTFS_SEGMENT_FIRST_BLOCK_ITEMS;
		off = (1 + (pos / SCOUTFS_SEGMENT_ITEMS_PER_BLOCK)) *
			SCOUTFS_BLOCK_SIZE;
		pos %= SCOUTFS_SEGMENT_ITEMS_PER_BLOCK;
	}

	return off_ptr(seg, off + (pos * sizeof(struct scoutfs_segment_item)));
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

int scoutfs_seg_item_kvecs(struct scoutfs_segment *seg, int pos,
			   struct kvec *key, struct kvec *val)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	struct scoutfs_segment_item *item;

	if (pos < 0 || pos >= le32_to_cpu(sblk->nr_items))
		return -ENOENT;

	item = pos_item(seg, pos);

	if (key)
		kvec_from_pages(seg, key, le32_to_cpu(item->key_off),
				le16_to_cpu(item->key_len));
	if (val)
		kvec_from_pages(seg, val, le32_to_cpu(item->val_off),
				le16_to_cpu(item->val_len));

	return 0;
}

/*
 * Find the first item array position whose key is >= the search key.
 * This can return the number of positions if the key is greater than
 * all the keys.
 */
static int find_key_pos(struct scoutfs_segment *seg, struct kvec *search)
{
	struct scoutfs_segment_block *sblk = off_ptr(seg, 0);
	SCOUTFS_DECLARE_KVEC(key);
	unsigned int start = 0;
	unsigned int end = le32_to_cpu(sblk->nr_items);
	unsigned int pos = 0;
	int cmp;

	while (start < end) {
		pos = start + (end - start) / 2;
		scoutfs_seg_item_kvecs(seg, pos, key, NULL);

		cmp = scoutfs_kvec_memcmp(search, key);
		if (cmp < 0)
			end = pos;
		else if (cmp > 0)
			start = ++pos;
		else
			break;
	}

	return pos;
}

int scoutfs_seg_find_pos(struct scoutfs_segment *seg, struct kvec *key)
{
	return find_key_pos(seg, key);
}

int scoutfs_seg_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac;

	cac = kzalloc(sizeof(struct segment_cache), GFP_KERNEL);
	if (!cac)
		return -ENOMEM;
	sbi->segment_cache = cac;

	spin_lock_init(&cac->lock);
	cac->root = RB_ROOT;
	init_waitqueue_head(&cac->waitq);

	return 0;
}

void scoutfs_seg_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct segment_cache *cac = sbi->segment_cache;
	struct scoutfs_segment *seg;
	struct rb_node *node;

	if (cac) {
		for (node = rb_first(&cac->root); node; ) {
			seg = container_of(node, struct scoutfs_segment, node);
			node = rb_next(node);
			erase_seg(&cac->root, seg);
			scoutfs_seg_put(seg);
		}

		kfree(cac);
	}
}

