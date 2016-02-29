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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "super.h"
#include "format.h"
#include "manifest.h"
#include "key.h"

/*
 * The manifest organizes log segment blocks into a tree structure.
 *
 * Each level of the tree contains an ordered list of log segments whose
 * item keys don't overlap.  The first level (level 0) of the tree is
 * the exception whose segments can have key ranges that overlap.
 *
 * We also store pointers to the manifest entries in a radix tree
 * indexed by their block number so that we can easily find existing
 * entries for deletion.
 *
 * Level 0 segments are stored in the list with the most recent at the
 * head of the list.  Level 0's rb tree will always be empty.
 */
struct scoutfs_manifest {
	spinlock_t lock;

	struct radix_tree_root blkno_radix;
	struct list_head level_zero;

	struct scoutfs_level {
		struct rb_root root;
	} levels[SCOUTFS_MAX_LEVEL + 1];
};

struct scoutfs_manifest_node {
	struct rb_node node;
	struct list_head head;

	struct scoutfs_ring_manifest_entry ment;
};

static void insert_mnode(struct rb_root *root,
			 struct scoutfs_manifest_node *ins)
{
	struct rb_node **node = &root->rb_node;
	struct scoutfs_manifest_node *mnode;
	struct rb_node *parent = NULL;
	int cmp;

	while (*node) {
		parent = *node;
		mnode = rb_entry(*node, struct scoutfs_manifest_node, node);

		cmp = scoutfs_key_cmp(&ins->ment.first, &mnode->ment.first);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static struct scoutfs_manifest_node *find_mnode(struct rb_root *root,
						struct scoutfs_key *key)
{
	struct rb_node *node = root->rb_node;
	struct scoutfs_manifest_node *mnode;
	int cmp;

	while (node) {
		mnode = rb_entry(node, struct scoutfs_manifest_node, node);

		cmp = scoutfs_key_cmp_range(key, &mnode->ment.first,
					    &mnode->ment.last);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return mnode;
	}

	return NULL;
}

static struct scoutfs_manifest_node *delete_mnode(struct scoutfs_manifest *mani,
						  u64 blkno)

{
	struct scoutfs_manifest_node *mnode;

	mnode = radix_tree_lookup(&mani->blkno_radix, blkno);
	if (mnode) {
		if (!list_empty(&mnode->head))
			list_del_init(&mnode->head);
		if (!RB_EMPTY_NODE(&mnode->node)) {
			rb_erase(&mnode->node,
				 &mani->levels[mnode->ment.level].root);
			RB_CLEAR_NODE(&mnode->node);
		}
	}

	return mnode;
}

/*
 * This is called during ring replay.  Because of the way the ring works
 * we can get deletion entries for segments that we don't yet have
 * in the replayed ring state.
 */
void scoutfs_delete_manifest(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;

	spin_lock(&mani->lock);
	mnode = delete_mnode(mani, blkno);
	spin_unlock(&mani->lock);
	if (mnode)
		kfree(mnode);
}

/*
 * This is called during ring replay to reconstruct the manifest state
 * from the ring entries.  Moving segments between levels is recorded
 * with a single ring entry so we always try to look up the segment in
 * the manifest before we add it to the manifest.
 */
int scoutfs_add_manifest(struct super_block *sb,
			 struct scoutfs_ring_manifest_entry *ment)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;

	spin_lock(&mani->lock);

	mnode = delete_mnode(mani, le64_to_cpu(ment->blkno));
	if (!mnode) {
		spin_unlock(&mani->lock);
		mnode = kmalloc(sizeof(struct scoutfs_manifest_node),
				GFP_NOFS);
		if (!mnode)
			return -ENOMEM; /* XXX hmm, fatal?  prealloc?*/

		INIT_LIST_HEAD(&mnode->head);
		RB_CLEAR_NODE(&mnode->node);
		spin_lock(&mani->lock);
	}

	mnode->ment = *ment;
	if (ment->level)
		insert_mnode(&mani->levels[ment->level].root, mnode);
	else
		list_add(&mnode->head, &mani->level_zero);

	spin_unlock(&mani->lock);

	return 0;
}

/*
 * Fill the caller's ment with the next log segment in the manifest that
 * might contain the given key.  The ment is initialized to 0 to return
 * the first entry.
 *
 * This can return multiple log segments from level 0 in decreasing age.
 * Then it can return at most one log segment in each level that
 * intersects with the given key.
 */
bool scoutfs_next_manifest_segment(struct super_block *sb,
				   struct scoutfs_key *key,
				   struct scoutfs_ring_manifest_entry *ment)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;
	bool found = false;
	int i;

	if (ment->level >= SCOUTFS_MAX_LEVEL)
		return false;

	spin_lock(&mani->lock);

	if (ment->level == 0) {
		if (ment->blkno) {
			mnode = radix_tree_lookup(&mani->blkno_radix,
						  le64_to_cpu(ment->blkno));
			mnode = list_next_entry(mnode, head);
		} else {
			mnode = list_first_entry(&mani->level_zero,
						 struct scoutfs_manifest_node,
						 head);
		}

		list_for_each_entry_from(mnode, &mani->level_zero, head) {
			if (scoutfs_key_cmp_range(key, &mnode->ment.first,
						  &mnode->ment.last) == 0) {
				*ment = mnode->ment;
				found = true;
				break;
			}
		}
	}

	if (!found) {
		for (i = ment->level + 1; i <= SCOUTFS_MAX_LEVEL; i++) {
			mnode = find_mnode(&mani->levels[i].root, key);
			if (mnode) {
				*ment = mnode->ment;
				found = true;
				break;
			}
		}
		if (!found)
			ment->level = SCOUTFS_MAX_LEVEL;
	}

	spin_unlock(&mani->lock);

	return found;
}

int scoutfs_setup_manifest(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani;
	int i;

	mani = kmalloc(sizeof(struct scoutfs_manifest), GFP_KERNEL);
	if (!mani)
		return -ENOMEM;

	spin_lock_init(&mani->lock);
	INIT_RADIX_TREE(&mani->blkno_radix, GFP_NOFS);
	INIT_LIST_HEAD(&mani->level_zero);

	for (i = 0; i < ARRAY_SIZE(mani->levels); i++)
		mani->levels[i].root = RB_ROOT;

	sbi->mani = mani;

	return 0;
}

/*
 * This is called once the manifest will no longer be used.  We iterate
 * over the blkno radix deleting radix entries and freeing manifest
 * nodes.
 */
void scoutfs_destroy_manifest(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnodes[16];
	unsigned long first_index = 0;
	int ret;
	int i;

	for (;;) {
		ret = radix_tree_gang_lookup(&mani->blkno_radix,
					     (void **)mnodes, first_index,
					     ARRAY_SIZE(mnodes));
		if (!ret)
			break;

		for (i = 0; i < ret; i++) {
			first_index = le64_to_cpu(mnodes[i]->ment.blkno);
			radix_tree_delete(&mani->blkno_radix, first_index);
			kfree(mnodes[i]);
		}
		first_index++;
	}

	kfree(sbi->mani);
	sbi->mani = NULL;
}
