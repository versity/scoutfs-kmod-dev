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
#include "manifest.h"

struct manifest {
	spinlock_t lock;

	struct list_head level0_list;
	unsigned int level0_nr;

	u8 last_level;
	struct rb_root level_roots[SCOUTFS_MANIFEST_MAX_LEVEL + 1];
};

#define DECLARE_MANIFEST(sb, name) \
	struct manifest *name = SCOUTFS_SB(sb)->manifest

struct manifest_entry {
	union {
		struct list_head level0_entry;
		struct rb_node node;
	};

	struct kvec *first;
	struct kvec *last;
	u64 segno;
	u64 seq;
	u8 level;
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

static struct manifest_entry *find_ment(struct rb_root *root, struct kvec *key)
{
	struct rb_node *node = root->rb_node;
	struct manifest_entry *ment;
	int cmp;

	while (node) {
		ment = container_of(node, struct manifest_entry, node);

		cmp = scoutfs_kvec_cmp_overlap(key, key,
					       ment->first, ment->last);
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
	int cmp;

	while (*node) {
		parent = *node;
		ment = container_of(*node, struct manifest_entry, node);

		cmp = scoutfs_kvec_cmp_overlap(ins->first, ins->last,
					       ment->first, ment->last);
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
	if (!IS_ERR_OR_NULL(ment)) {
		scoutfs_kvec_kfree(ment->first);
		scoutfs_kvec_kfree(ment->last);
		kfree(ment);
	}
}

static int add_ment(struct manifest *mani, struct manifest_entry *ment)
{
	int ret;

	if (ment->level) {
		ret = insert_ment(&mani->level_roots[ment->level], ment);
		if (!ret)
			mani->last_level = max(mani->last_level, ment->level);
	} else {
		list_add_tail(&ment->level0_entry, &mani->level0_list);
		mani->level0_nr++;
		ret = 0;
	}

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
	if (ment->level) {
		rb_erase(&ment->node, &mani->level_roots[ment->level]);
		update_last_level(mani);
	} else {
		list_del_init(&ment->level0_entry);
		mani->level0_nr--;
	}
}

int scoutfs_manifest_add(struct super_block *sb, struct kvec *first,
			 struct kvec *last, u64 segno, u64 seq, u8 level)
{
	DECLARE_MANIFEST(sb, mani);
	struct manifest_entry *ment;
	unsigned long flags;
	int ret;

	ment = kmalloc(sizeof(struct manifest_entry), GFP_NOFS);
	if (!ment)
		return -ENOMEM;

	ret = scoutfs_kvec_dup_flatten(ment->first, first) ?:
	      scoutfs_kvec_dup_flatten(ment->first, last);
	if (ret) {
		free_ment(ment);
		return -ENOMEM;
	}

	ment->segno = segno;
	ment->seq = seq;
	ment->level = level;

	/* XXX think about where to insert level 0 */
	spin_lock_irqsave(&mani->lock, flags);
	ret = add_ment(mani, ment);
	spin_unlock_irqrestore(&mani->lock, flags);
	if (WARN_ON_ONCE(ret)) /* XXX can this happen?  ring corruption? */
		free_ment(ment);

	return ret;
}

static void set_ref(struct manifest_ref *ref, struct manifest_entry *mani)
{
	ref->segno = mani->segno;
	ref->seq = mani->seq;
	ref->level = mani->level;
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

	spin_lock_irqsave(&mani->lock, flags);

	total = mani->level0_nr + mani->last_level;
	while (nr != total) {
		nr = total;
		spin_unlock_irqrestore(&mani->lock, flags);

		kfree(refs);
		refs = kcalloc(total, sizeof(struct manifest_ref), GFP_NOFS);
		if (!refs)
			return ERR_PTR(-ENOMEM);

		spin_lock_irqsave(&mani->lock, flags);
	}

	nr = 0;

	list_for_each_entry(ment, &mani->level0_list, level0_entry) {
		if (scoutfs_kvec_cmp_overlap(key, key,
					     ment->first, ment->last))
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
	int i;
	int n;

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

	/* wait for submitted segments and search if we haven't seen failure */
	for (n = 0; n < i; n++) {
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
