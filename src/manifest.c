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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "seg.h"
#include "item.h"
#include "ring.h"
#include "manifest.h"
#include "scoutfs_trace.h"

struct manifest {
	spinlock_t lock;

	struct list_head level0_list;
	unsigned int level0_nr;

	u8 last_level;
	struct rb_root level_roots[SCOUTFS_MANIFEST_MAX_LEVEL + 1];

	struct list_head dirty_list;
};

#define DECLARE_MANIFEST(sb, name) \
	struct manifest *name = SCOUTFS_SB(sb)->manifest

struct manifest_entry {
	union {
		struct list_head level0_entry;
		struct rb_node node;
	};
	struct list_head dirty_entry;

	struct scoutfs_ring_add_manifest am;
	/* u8 key_bytes[am.first_key_len]; */
	/* u8 val_bytes[am.last_key_len]; */
};

/*
 * A reader uses references to segments copied from a walk of the
 * manifest.  The references are a point in time sample of the manifest.
 * The manifest and segments can change while the reader uses their
 * references.  Locking ensures that the items they're reading will be
 * stable while the manifest and segments change, and the segment
 * allocator gives readers time to use immutable stale segments before
 * their reallocated and reused.
 */
struct manifest_ref {
	struct list_head entry;

	u64 segno;
	u64 seq;
	struct scoutfs_segment *seg;
	int found_ctr;
	int pos;
	u16 first_key_len;
	u16 last_key_len;
	u8 level;
	u8 keys[SCOUTFS_MAX_KEY_SIZE * 2];
};

static void init_ment_keys(struct manifest_entry *ment, struct kvec *first,
			   struct kvec *last)
{
	scoutfs_kvec_init(first, &ment->am + 1,
			  le16_to_cpu(ment->am.first_key_len));
	scoutfs_kvec_init(last, (void *)(&ment->am + 1) +
			  le16_to_cpu(ment->am.first_key_len),
			  le16_to_cpu(ment->am.last_key_len));
}

static void init_ref_keys(struct manifest_ref *ref, struct kvec *first,
			  struct kvec *last)
{
	if (first)
		scoutfs_kvec_init(first, ref->keys, ref->first_key_len);
	if (last)
		scoutfs_kvec_init(last, ref->keys + ref->first_key_len,
				  ref->last_key_len);
}

static bool cmp_range_ment(struct kvec *key, struct kvec *end,
			   struct manifest_entry *ment)
{
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);

	init_ment_keys(ment, first, last);

	return scoutfs_kvec_cmp_overlap(key, end, first, last);
}

static struct manifest_entry *find_ment(struct rb_root *root, struct kvec *key)
{
	struct rb_node *node = root->rb_node;
	struct manifest_entry *ment;
	int cmp;

	while (node) {
		ment = container_of(node, struct manifest_entry, node);

		cmp = cmp_range_ment(key, key, ment);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return ment;
	}

	return NULL;
}

/*
 * Insert a new entry into one of the L1+ trees.  There should never be
 * entries that overlap.
 */
static int insert_ment(struct rb_root *root, struct manifest_entry *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct manifest_entry *ment;
	SCOUTFS_DECLARE_KVEC(key);
	SCOUTFS_DECLARE_KVEC(end);
	int cmp;

	init_ment_keys(ins, key, end);

	while (*node) {
		parent = *node;
		ment = container_of(*node, struct manifest_entry, node);

		cmp = cmp_range_ment(key, end, ment);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			return -EEXIST;
		}
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);

	return 0;
}

static void free_ment(struct manifest_entry *ment)
{
	if (!IS_ERR_OR_NULL(ment))
		kfree(ment);
}

static int add_ment(struct manifest *mani, struct manifest_entry *ment,
		    bool dirty)
{
	u8 level = ment->am.level;
	int ret;


	trace_printk("adding ment %p level %u\n", ment, level);

	if (level) {
		ret = insert_ment(&mani->level_roots[level], ment);
		if (!ret)
			mani->last_level = max(mani->last_level, level);
	} else {
		list_add_tail(&ment->level0_entry, &mani->level0_list);
		mani->level0_nr++;
		ret = 0;
	}

	if (dirty)
		list_add_tail(&ment->dirty_entry, &mani->dirty_list);

	return ret;
}

static void update_last_level(struct manifest *mani)
{
	int i;

	for (i = mani->last_level;
	     i > 0 && RB_EMPTY_ROOT(&mani->level_roots[i]); i--)
	     ;

	mani->last_level = i;
}

static void remove_ment(struct manifest *mani, struct manifest_entry *ment)
{
	u8 level = ment->am.level;

	if (level) {
		rb_erase(&ment->node, &mani->level_roots[level]);
		update_last_level(mani);
	} else {
		list_del_init(&ment->level0_entry);
		mani->level0_nr--;
	}

	/* XXX more carefully remove dirty ments.. should be exceptional */
	if (!list_empty(&ment->dirty_entry))
		list_del_init(&ment->dirty_entry);
}

int scoutfs_manifest_add(struct super_block *sb, struct kvec *first,
			 struct kvec *last, u64 segno, u64 seq, u8 level,
			 bool dirty)
{
	DECLARE_MANIFEST(sb, mani);
	struct manifest_entry *ment;
	SCOUTFS_DECLARE_KVEC(ment_first);
	SCOUTFS_DECLARE_KVEC(ment_last);
	unsigned long flags;
	int key_bytes;
	int ret;

	trace_scoutfs_manifest_add(sb, first, last, segno, seq, level, dirty);

	key_bytes = scoutfs_kvec_length(first) + scoutfs_kvec_length(last);
	ment = kmalloc(sizeof(struct manifest_entry) + key_bytes, GFP_NOFS);
	if (!ment)
		return -ENOMEM;

	if (level)
		RB_CLEAR_NODE(&ment->node);
	else
		INIT_LIST_HEAD(&ment->level0_entry);
	INIT_LIST_HEAD(&ment->dirty_entry);

	ment->am.eh.type = SCOUTFS_RING_ADD_MANIFEST;
	ment->am.eh.len = cpu_to_le16(sizeof(struct scoutfs_ring_add_manifest) +
				      key_bytes);
	ment->am.segno = cpu_to_le64(segno);
	ment->am.seq = cpu_to_le64(seq);
	ment->am.first_key_len = cpu_to_le16(scoutfs_kvec_length(first));
	ment->am.last_key_len = cpu_to_le16(scoutfs_kvec_length(last));
	ment->am.level = level;

	init_ment_keys(ment, ment_first, ment_last);
	scoutfs_kvec_memcpy(ment_first, first);
	scoutfs_kvec_memcpy(ment_last, last);

	/* XXX think about where to insert level 0 */
	spin_lock_irqsave(&mani->lock, flags);
	ret = add_ment(mani, ment, dirty);
	spin_unlock_irqrestore(&mani->lock, flags);
	if (WARN_ON_ONCE(ret)) /* XXX can this happen?  ring corruption? */
		free_ment(ment);

	return ret;
}

/*
 * Grab an allocated ref from the src list, fill it with the details
 * from the ment, and add it to the dst list.  The ref is added to the
 * tail of the dst list so that we maintain the caller's manifest walk
 * order.
 */
static void fill_ref_tail(struct list_head *dst, struct list_head *src,
			  struct manifest_entry *ment)
{
	SCOUTFS_DECLARE_KVEC(ment_first);
	SCOUTFS_DECLARE_KVEC(ment_last);
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);
	struct manifest_ref *ref;

	ref = list_first_entry(src, struct manifest_ref, entry);

	ref->segno = le64_to_cpu(ment->am.segno);
	ref->seq = le64_to_cpu(ment->am.seq);
	ref->level = ment->am.level;
	ref->first_key_len = le16_to_cpu(ment->am.first_key_len);
	ref->last_key_len = le16_to_cpu(ment->am.last_key_len);

	init_ment_keys(ment, ment_first, ment_last);
	init_ref_keys(ref, first, last);

	scoutfs_kvec_memcpy(first, ment_first);
	scoutfs_kvec_memcpy(last, ment_last);

	list_move_tail(&ref->entry, dst);
}

/*
 * Get refs on all the segments in the manifest that we'll need to
 * search to populate the cache with the given range.
 *
 * We have to get all the level 0 segments that intersect with the range
 * of items that we want to search because the level 0 segments can
 * arbitrarily overlap with each other.
 *
 * We only need to search for the starting key in all the higher order
 * levels.  They do not overlap so we can iterate through the key space
 * in each segment starting with the key.
 */
static int get_range_refs(struct manifest *mani, struct kvec *key,
			  struct kvec *end, struct list_head *ref_list)
{
	struct manifest_entry *ment;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	struct rb_root *root;
	unsigned long flags;
	unsigned int total;
	unsigned int nr = 0;
	LIST_HEAD(alloced);
	int ret;
	int i;

	trace_printk("getting refs\n");

	spin_lock_irqsave(&mani->lock, flags);

	/* allocate enough refs for the of segments */
	total = mani->level0_nr + mani->last_level;
	while (nr < total) {
		spin_unlock_irqrestore(&mani->lock, flags);

		for (i = nr; i < total; i++) {
			ref = kmalloc(sizeof(struct manifest_ref), GFP_NOFS);
			if (!ref) {
				ret = -ENOMEM;
				goto out;
			}

			memset(ref, 0, offsetof(struct manifest_ref, keys));
			list_add(&ref->entry, &alloced);
		}
		nr = total;

		spin_lock_irqsave(&mani->lock, flags);
	}

	/* find all the overlapping level 0 segments */
	list_for_each_entry(ment, &mani->level0_list, level0_entry) {
		if (cmp_range_ment(key, end, ment))
			continue;

		fill_ref_tail(ref_list, &alloced, ment);
	}

	/* find each segment containing the key at the higher orders */
	for (i = 1; i <= mani->last_level; i++) {
		root = &mani->level_roots[i];
		if (RB_EMPTY_ROOT(root))
			continue;

		ment = find_ment(root, key);
		if (ment)
			fill_ref_tail(ref_list, &alloced, ment);
	}

	spin_unlock_irqrestore(&mani->lock, flags);
	ret = 0;

out:
	if (ret) {
		list_splice_init(ref_list, &alloced);
		list_for_each_entry_safe(ref, tmp, &alloced, entry) {
			list_del_init(&ref->entry);
			kfree(ref);
		}
	}
	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * The caller found a hole in the item cache that they'd like populated.
 *
 * We search the manifest for all the segments we'll need to iterate
 * from the key to the end key.  We walk the segments and insert as many
 * items as we can from the segments, trying to amortize the per-item
 * cost of segment searching.
 *
 * As we insert the batch of items we give the item cache the range of
 * keys that contain these items.  This lets the cache return negative
 * cache lookups for missing items within the range.
 *
 * Returns 0 if we inserted items with a range covering the starting
 * key.  The caller should be able to make progress.
 *
 * Returns -errno if we failed to make any change in the cache.
 *
 * This is asking the seg code to read each entire segment.  The seg
 * code could give it it helpers to submit and wait on blocks within the
 * segment so that we don't have wild bandwidth amplification for cold
 * random reads.
 *
 * The segments are immutable at this point so we can use their contents
 * as long as we hold refs.
 */
#define MAX_ITEMS_READ 32

int scoutfs_manifest_read_items(struct super_block *sb, struct kvec *key,
				struct kvec *end)
{
	DECLARE_MANIFEST(sb, mani);
	SCOUTFS_DECLARE_KVEC(item_key);
	SCOUTFS_DECLARE_KVEC(item_val);
	SCOUTFS_DECLARE_KVEC(found_key);
	SCOUTFS_DECLARE_KVEC(found_val);
	SCOUTFS_DECLARE_KVEC(batch_end);
	SCOUTFS_DECLARE_KVEC(seg_end);
	struct scoutfs_segment *seg;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	LIST_HEAD(ref_list);
	LIST_HEAD(batch);
	int found_ctr;
	bool found;
	int ret = 0;
	int err;
	int cmp;
	int n;

	trace_printk("reading items\n");

	/* get refs on all the segments */
	ret = get_range_refs(mani, key, end, &ref_list);
	if (ret)
		return ret;

	/* submit reads for all the segments */
	list_for_each_entry(ref, &ref_list, entry) {
		seg = scoutfs_seg_submit_read(sb, ref->segno);
		if (IS_ERR(seg)) {
			ret = PTR_ERR(seg);
			break;
		}

		ref->seg = seg;
	}

	/* wait for submitted segments and search for starting pos */
	list_for_each_entry(ref, &ref_list, entry) {
		if (!ref->seg)
			break;

		err = scoutfs_seg_wait(sb, ref->seg);
		if (err && !ret)
			ret = err;

		if (ret == 0)
			ref->pos = scoutfs_seg_find_pos(ref->seg, key);
	}
	if (ret)
		goto out;

	scoutfs_kvec_init_null(batch_end);
	scoutfs_kvec_init_null(seg_end);
	found_ctr = 0;

	for (n = 0; n < MAX_ITEMS_READ; n++) {

		found = false;
		found_ctr++;

		/* find the next least key from the pos in each segment */
		list_for_each_entry_safe(ref, tmp, &ref_list, entry) {

			/*
			 * Check the next item in the segment.  We're
			 * done with the segment if there are no more
			 * items or if the next item is past the
			 * caller's end.  We record either the caller's
			 * end or the segment end if it's a l1+ segment for
			 * use as the batch end if we don't see more items.
			 */
			ret = scoutfs_seg_item_kvecs(ref->seg, ref->pos,
					             item_key, item_val);
			if (ret < 0)  {
				if (ref->level > 0) {
					init_ref_keys(ref, NULL, item_key);
					scoutfs_kvec_clone_less(seg_end,
								item_key);
				}
			} else if (scoutfs_kvec_memcmp(item_key, end) > 0) {
				scoutfs_kvec_clone_less(seg_end, end);
				ret = -ENOENT;
			}
			if (ret < 0) {
				list_del_init(&ref->entry);
				scoutfs_seg_put(ref->seg);
				kfree(ref);
				continue;
			}

			/* see if it's the new least item */
			if (found) {
				cmp = scoutfs_kvec_memcmp(item_key, found_key);
				if (cmp >= 0) {
					if (cmp == 0)
						ref->found_ctr = found_ctr;
					continue;
				}
			}

			/* remember new least key */
			scoutfs_kvec_clone(found_key, item_key);
			scoutfs_kvec_clone(found_val, item_val);
			ref->found_ctr = ++found_ctr;
			found = true;
		}

		/* ran out of keys in segs, range extends to seg end */
		if (!found) {
			scoutfs_kvec_clone(batch_end, seg_end);
			ret = 0;
			break;
		}

		/*
		 * If we fail to add an item we're done.  If we already
		 * have items it's not a failure and the end of the cached
		 * range is the last successfully added item.
		 */
		ret = scoutfs_item_add_batch(sb, &batch, found_key, found_val);
		if (ret) {
			if (n > 0)
				ret = 0;
			break;
		}

		/* the last successful key determines the range */
		scoutfs_kvec_clone(batch_end, found_key);

		/* if we just saw the end key then we're done */
		if (scoutfs_kvec_memcmp(found_key, end) == 0) {
			ret = 0;
			break;
		}

		/* advance all the positions that had the found key */
		list_for_each_entry(ref, &ref_list, entry) {
			if (ref->found_ctr == found_ctr)
				ref->pos++;
		}

		ret = 0;
	}

	if (ret)
		scoutfs_item_free_batch(&batch);
	else
		ret = scoutfs_item_insert_batch(sb, &batch, key, batch_end);
out:
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		list_del_init(&ref->entry);
		scoutfs_seg_put(ref->seg);
		kfree(ref);
	}

	return ret;
}

int scoutfs_manifest_has_dirty(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);

	return !list_empty_careful(&mani->dirty_list);
}

/*
 * Append the dirty manifest entries to the end of the ring.
 *
 * This returns 0 but can't fail.
 */
int scoutfs_manifest_dirty_ring(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);
	struct manifest_entry *ment;
	struct manifest_entry *tmp;

	list_for_each_entry_safe(ment, tmp, &mani->dirty_list, dirty_entry) {
		scoutfs_ring_append(sb, &ment->am.eh);
		list_del_init(&ment->dirty_entry);
	}

	return 0;
}

int scoutfs_manifest_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct manifest *mani;
	int i;

	mani = kzalloc(sizeof(struct manifest), GFP_KERNEL);
	if (!mani)
		return -ENOMEM;
	sbi->manifest = mani;

	spin_lock_init(&mani->lock);
	INIT_LIST_HEAD(&mani->level0_list);
	INIT_LIST_HEAD(&mani->dirty_list);
	for (i = 0; i < ARRAY_SIZE(mani->level_roots); i++)
		mani->level_roots[i] = RB_ROOT;

	return 0;
}

void scoutfs_manifest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct manifest *mani = sbi->manifest;
	struct manifest_entry *ment;
	struct manifest_entry *tmp;
	struct rb_node *node;
	struct rb_root *root;
	int i;

	if (!mani)
		return;

	for (i = 1; i <= mani->last_level; i++) {
		root = &mani->level_roots[i];

		for (node = rb_first(root); node; ) {
			ment = container_of(node, struct manifest_entry, node);
			node = rb_next(node);
			remove_ment(mani, ment);
			free_ment(ment);
		}
	}

	list_for_each_entry_safe(ment, tmp, &mani->level0_list, level0_entry) {
		remove_ment(mani, ment);
		free_ment(ment);
	}

	kfree(mani);
}
