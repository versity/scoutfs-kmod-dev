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
 * A path tracks all the segments from level 0 to the last level that
 * overlap with the search key.
 */
struct manifest_ref {
	u64 segno;
	u64 seq;
	struct scoutfs_segment *seg;
	int pos;
	u8 level;
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

/*
 * returns:
 *   < 0 : key < ment->first_key
 *   > 0 : key > ment->first_key
 *   == 0 : ment->first_key <= key <= ment->last_key
 */
static bool cmp_key_ment(struct kvec *key, struct manifest_entry *ment)
{
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);

	init_ment_keys(ment, first, last);

	return scoutfs_kvec_cmp_overlap(key, key, first, last);
}

static struct manifest_entry *find_ment(struct rb_root *root, struct kvec *key)
{
	struct rb_node *node = root->rb_node;
	struct manifest_entry *ment;
	int cmp;

	while (node) {
		ment = container_of(node, struct manifest_entry, node);

		cmp = cmp_key_ment(key, ment);
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
	int cmp;

	/* either first or last works */
	init_ment_keys(ins, key, key);

	while (*node) {
		parent = *node;
		ment = container_of(*node, struct manifest_entry, node);

		cmp = cmp_key_ment(key, ment);
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

static void set_ref(struct manifest_ref *ref, struct manifest_entry *ment)
{
	ref->segno = le64_to_cpu(ment->am.segno);
	ref->seq = le64_to_cpu(ment->am.seq);
	ref->level = ment->am.level;
}

/*
 * Returns refs if intersecting segments are found, NULL if none intersect,
 * and PTR_ERR on failure.
 */
static struct manifest_ref *get_key_refs(struct manifest *mani,
					 struct kvec *key,
					 unsigned int *nr_ret)
{
	struct manifest_ref *refs = NULL;
	struct manifest_entry *ment;
	struct rb_root *root;
	unsigned long flags;
	unsigned int total;
	unsigned int nr;
	int i;

	trace_printk("getting refs\n");

	spin_lock_irqsave(&mani->lock, flags);

	total = mani->level0_nr + mani->last_level;
	while (nr != total) {
		nr = total;
		spin_unlock_irqrestore(&mani->lock, flags);

		kfree(refs);
		refs = kcalloc(total, sizeof(struct manifest_ref), GFP_NOFS);
		trace_printk("alloc refs %p total %u\n", refs, total);
		if (!refs)
			return ERR_PTR(-ENOMEM);

		spin_lock_irqsave(&mani->lock, flags);
	}

	nr = 0;

	list_for_each_entry(ment, &mani->level0_list, level0_entry) {
		trace_printk("trying l0 ment %p\n", ment);
		if (cmp_key_ment(key, ment))
			continue;

		set_ref(&refs[nr++], ment);
	}

	for (i = 1; i <= mani->last_level; i++) {
		root = &mani->level_roots[i];
		if (RB_EMPTY_ROOT(root))
			continue;

		ment = find_ment(root, key);
		if (ment)
			set_ref(&refs[nr++], ment);
	}

	spin_unlock_irqrestore(&mani->lock, flags);

	*nr_ret = nr;
	if (!nr) {
		kfree(refs);
		refs = NULL;
	}

	trace_printk("refs %p (err %ld)\n",
		     refs, IS_ERR(refs) ? PTR_ERR(refs) : 0);

	return refs;
}

/*
 * The caller didn't find an item for the given key in the item cache
 * and wants us to search for it in the lsm segments.  We search the
 * manifest for all the segments that contain the key.  We then read the
 * segments and iterate over their items looking for ours.  We insert it
 * and some number of other surrounding items to amortize the relatively
 * expensive multi-segment searches.
 *
 * This is asking the seg code to read each entire segment.  The seg
 * code could give it it helpers to submit and wait on blocks within the
 * segment so that we don't have wild bandwidth amplification in the
 * cold random read case.
 *
 * The segments are immutable at this point so we can use their contents
 * as long as we hold refs.
 */
int scoutfs_manifest_read_items(struct super_block *sb, struct kvec *key)
{
	DECLARE_MANIFEST(sb, mani);
	SCOUTFS_DECLARE_KVEC(item_key);
	SCOUTFS_DECLARE_KVEC(item_val);
	SCOUTFS_DECLARE_KVEC(found_key);
	SCOUTFS_DECLARE_KVEC(found_val);
	struct scoutfs_segment *seg;
	struct manifest_ref *refs;
	unsigned long had_found;
	bool found;
	int ret = 0;
	int err;
	int nr_refs;
	int cmp;
	int last;
	int i;
	int n;

	trace_printk("reading items\n");

	refs = get_key_refs(mani, key, &nr_refs);
	if (IS_ERR(refs))
		return PTR_ERR(refs);
	if (!refs)
		return -ENOENT;

	/* submit reads for all the segments */
	for (i = 0; i < nr_refs; i++) {
		seg = scoutfs_seg_submit_read(sb, refs[i].segno);
		if (IS_ERR(seg)) {
			ret = PTR_ERR(seg);
			break;
		}

		refs[i].seg = seg;
	}
	last = i;

	/* wait for submitted segments and search if we haven't seen failure */
	for (i = 0; i < last; i++) {
		seg = refs[i].seg;

		err = scoutfs_seg_wait(sb, seg);
		if (err && !ret)
			ret = err;

		if (!ret)
			refs[i].pos = scoutfs_seg_find_pos(seg, key);
	}

	/* done if we saw errors */
	if (ret)
		goto out;

	/* walk sorted items, resolving across segments, and insert */
	for (n = 0; n < 16; n++) {

		found = false;

		/* find the most recent least key */
		for (i = 0; i < nr_refs; i++) {
			seg = refs[i].seg;
			if (!seg)
				continue;

			/* get kvecs, removing if we ran out of items */
			ret = scoutfs_seg_item_kvecs(seg, refs[i].pos,
					             item_key, item_val);
			if (ret < 0) {
				scoutfs_seg_put(seg);
				refs[i].seg = NULL;
				continue;
			}

			if (found) {
				cmp = scoutfs_kvec_memcmp(item_key, found_key);
				if (cmp >= 0) {
					if (cmp == 0)
						set_bit(i, &had_found);
					continue;
				}
			}

			/* remember new least key */
			scoutfs_kvec_clone(found_key, key);
			scoutfs_kvec_clone(found_val, item_val);
			found = true;
			had_found = 0;
			set_bit(i, &had_found);
		}

		/* return -ENOENT if we didn't find any or the callers item */
		if (n == 0 &&
		    (!found || scoutfs_kvec_memcmp(key, found_key))) {
			ret = -ENOENT;
			break;
		}

		if (!found) {
			ret = 0;
			break;
		}

		ret = scoutfs_item_insert(sb, item_key, item_val);
		if (ret)
			break;

		/* advance all the positions past the found key */
		for_each_set_bit(i, &had_found, BITS_PER_LONG)
			refs[i].pos++;
	}

out:
	for (i = 0; i < nr_refs; i++)
		scoutfs_seg_put(refs[i].seg);

	kfree(refs);
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
