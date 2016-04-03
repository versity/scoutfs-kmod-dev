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
#include <linux/sort.h>

#include "super.h"
#include "format.h"
#include "manifest.h"
#include "key.h"
#include "ring.h"
#include "ival.h"
#include "scoutfs_trace.h"

/*
 * The manifest organizes log segments into levels of item indexes.  New
 * segments arrive at level 0 which can have many segments with
 * overlapping keys.  Then segments are merged into progressively larger
 * higher levels which do not have segments with overlapping keys.
 *
 * All the segments for all the levels are stored in one interval tree.
 * This lets reads find all the overlapping segments in all levels with
 * one tree walk instead of walks per level.  It also lets us move
 * segments around the levels by updating their level field rather than
 * removing them from one level index and adding them to another.
 */
struct scoutfs_manifest {
	spinlock_t lock;
	struct scoutfs_ival_tree itree;
};

/*
 * There's some redundancy between the interval struct and the manifest
 * entry struct.  If we re-use both we duplicate fields and memory
 * pressure is precious here.  So we have a native combination of the
 * two.
 */
struct scoutfs_manifest_node {
	struct scoutfs_ival ival;
	u64 blkno;
	u64 seq;
	unsigned char level;
};

/*
 * Remove an exact match of the entry from the manifest.  It's normal
 * for ring replay can try to remove an entry that doesn't exist if ring
 * wrapping and manifest deletion combine in just the right way.
 */
static void delete_manifest(struct super_block *sb,
			    struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;
	struct scoutfs_ival *ival;

	ival = NULL;
	while ((ival = scoutfs_next_ival(&mani->itree, &ment->first,
					 &ment->last, ival))) {
		mnode = container_of(ival, struct scoutfs_manifest_node, ival);

		if (mnode->blkno == le64_to_cpu(ment->blkno) &&
		    mnode->seq == le64_to_cpu(ment->seq) &&
		    !scoutfs_key_cmp(&ment->first, &mnode->ival.start) &&
		    !scoutfs_key_cmp(&ment->last, &mnode->ival.end))
			break;
	}

	if (ival) {
		trace_scoutfs_delete_manifest(ment);

		scoutfs_remove_ival(&mani->itree, &mnode->ival);
		kfree(mnode);
	}
}

void scoutfs_delete_manifest(struct super_block *sb,
			     struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;

	spin_lock(&mani->lock);
	delete_manifest(sb, ment);
	spin_unlock(&mani->lock);
}

static void insert_manifest(struct super_block *sb,
			    struct scoutfs_manifest_entry *ment,
			    struct scoutfs_manifest_node *mnode)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;

	trace_scoutfs_insert_manifest(ment);

	mnode->ival.start = ment->first;
	mnode->ival.end = ment->last;
	mnode->blkno = le64_to_cpu(ment->blkno);
	mnode->seq = le64_to_cpu(ment->seq);
	mnode->level = ment->level;

	scoutfs_insert_ival(&mani->itree, &mnode->ival);
}

int scoutfs_insert_manifest(struct super_block *sb,
			    struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;

	mnode = kzalloc(sizeof(struct scoutfs_manifest_node), GFP_NOFS);
	if (!mnode)
		return -ENOMEM; /* XXX hmm, fatal?  prealloc?*/

	spin_lock(&mani->lock);
	insert_manifest(sb, ment, mnode);
	spin_unlock(&mani->lock);

	return 0;
}

/*
 * The caller has inserted a temporary manifest entry while they were
 * dirtying a segment.  It's done now and they want the final segment
 * range stored in the manifest and logged in the ring.
 *
 * If this returns an error then nothing has changed.
 *
 * XXX we'd also need to add stale manifest entry's to the ring
 * XXX In the future we'd send it to the leader
 */
int scoutfs_finalize_manifest(struct super_block *sb,
			      struct scoutfs_manifest_entry *existing,
			      struct scoutfs_manifest_entry *updated)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_node *mnode;
	int ret;

	mnode = kzalloc(sizeof(struct scoutfs_manifest_node), GFP_NOFS);
	if (!mnode)
		return -ENOMEM; /* XXX hmm, fatal?  prealloc?*/

	ret = scoutfs_dirty_ring_entry(sb, SCOUTFS_RING_ADD_MANIFEST,
				       updated,
				       sizeof(struct scoutfs_manifest_entry));
	if (ret) {
		kfree(mnode);
		return ret;
	}

	spin_lock(&mani->lock);
	delete_manifest(sb, existing);
	insert_manifest(sb, updated, mnode);
	spin_unlock(&mani->lock);

	return 0;
}

/* sorted by increasing level then decreasing seq */
static int cmp_ments(const void *A, const void *B)
{
	const struct scoutfs_manifest_entry *a = A;
	const struct scoutfs_manifest_entry *b = B;
	int cmp;

	cmp = (int)a->level - (int)b->level;
	if (cmp)
		return cmp;

	if (le64_to_cpu(a->seq) > le64_to_cpu(b->seq))
		return -1;
	if (le64_to_cpu(a->seq) < le64_to_cpu(b->seq))
		return 1;
	return 0;
}

static void swap_ments(void *A, void *B, int size)
{
	struct scoutfs_manifest_entry *a = A;
	struct scoutfs_manifest_entry *b = B;

	swap(*a, *b);
}

/*
 * Give the caller an allocated array of manifest entries that intersect
 * their search key.  The array is sorted in the order for searching for
 * the most recent item: decreasing sequence in level 0 then increasing
 * levels. 
 *
 * The live manifest can change while the caller walks their array but
 * the segments will not be reclaimed and the caller has grants that
 * protect their items in the segments even if the segments shift over
 * time.
 *
 * The number of elements in the array is returned, or negative errors,
 * and the array is not allocated if 0 is returned.
 *
 * XXX need to actually keep the segments from being reclaimed
 */
int scoutfs_manifest_find_key(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_manifest_entry **ments_ret)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_manifest_entry *ments;
	struct scoutfs_manifest_node *mnode;
	struct scoutfs_ival *ival;
	unsigned nr;
	int i;

	/* make a reasonably large initial guess */
	i = 16;
	ments = NULL;
	do {
		kfree(ments);
		nr = i;
		ments = kmalloc(nr * sizeof(struct scoutfs_manifest_entry),
				GFP_NOFS);
		if (!ments)
			return -ENOMEM;

		spin_lock(&mani->lock);
		i = 0;
		ival = NULL;
		while ((ival = scoutfs_next_ival(&mani->itree, key, key,
						 ival))) {
			if (i < nr) {
				mnode = container_of(ival,
					struct scoutfs_manifest_node, ival);
				ments[i].blkno = cpu_to_le64(mnode->blkno);
				ments[i].seq = cpu_to_le64(mnode->seq);
				ments[i].level = mnode->level;
				ments[i].first = ival->start;
				ments[i].last = ival->end;
			}
			i++;
		}
		spin_unlock(&mani->lock);

	} while (i > nr);

	if (i) {
		sort(ments, i, sizeof(struct scoutfs_manifest_entry),
		     cmp_ments, swap_ments);
	} else {
		kfree(ments);
		ments = NULL;
	}

	*ments_ret = ments;
	return i;
}

int scoutfs_setup_manifest(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani;

	mani = kzalloc(sizeof(struct scoutfs_manifest), GFP_KERNEL);
	if (!mani)
		return -ENOMEM;

	spin_lock_init(&mani->lock);
	scoutfs_init_ival_tree(&mani->itree);

	sbi->mani = mani;

	return 0;
}

/*
 * This is called once the manifest will no longer be used.
 */
void scoutfs_destroy_manifest(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_manifest *mani = sbi->mani;
	struct scoutfs_ival *ival;
	struct rb_node *node;
	struct rb_node tmp;

	if (mani) {
		foreach_postorder_ival_safe(&mani->itree, ival, node, tmp)
			kfree(ival);

		kfree(mani);
		sbi->mani = NULL;
	}
}
