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
#include <linux/radix-tree.h>

#include "super.h"
#include "format.h"
#include "btree.h"
#include "cmp.h"
#include "alloc.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * scoutfs allocates segments using regions of an allocation bitmap
 * stored in btree items.
 *
 * Freed segments are recorded in nodes in an rbtree.  The frees can't
 * satisfy allocation until they're committed to prevent overwriting
 * live data so they're only applied to the region nodes as their
 * transaction is written.
 *
 * We allocate by sweeping a cursor through the volume.  This gives
 * racing unlocked readers more time to try to sample a stale freed
 * segment, when its safe to do so, before it is reallocated and
 * rewritten and they're forced to retry their racey read.
 */

struct seg_alloc {
	struct rw_semaphore rwsem;
	struct rb_root pending_root;
	u64 next_segno;
};

#define DECLARE_SEG_ALLOC(sb, name) \
	struct seg_alloc *name = SCOUTFS_SB(sb)->seg_alloc

struct pending_region {
	struct rb_node node;
	u64 ind;
	struct scoutfs_alloc_region_btree_val reg_val;
};

static struct pending_region *find_pending(struct rb_root *root, u64 ind)
{
	struct rb_node *node = root->rb_node;
	struct pending_region *pend;

	while (node) {
		pend = container_of(node, struct pending_region, node);

		if (ind < pend->ind)
			node = node->rb_left;
		else if (ind > pend->ind)
			node = node->rb_right;
		else
			return pend;
	}

	return NULL;
}

static void insert_pending(struct rb_root *root, struct pending_region *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct pending_region *pend;

	while (*node) {
		parent = *node;
		pend = container_of(*node, struct pending_region, node);

		if (ins->ind < pend->ind)
			node = &(*node)->rb_left;
		else if (ins->ind > pend->ind)
			node = &(*node)->rb_right;
		else
			BUG();
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static int copy_region_item(struct scoutfs_alloc_region_btree_key *reg_key,
			    struct scoutfs_alloc_region_btree_val *reg_val,
			    struct scoutfs_btree_item_ref *iref)
{
	if (iref->key_len != sizeof(struct scoutfs_alloc_region_btree_key) ||
	    iref->val_len != sizeof(struct scoutfs_alloc_region_btree_val))
		return -EIO;

	memcpy(reg_key, iref->key, iref->key_len);
	memcpy(reg_val, iref->val, iref->val_len);
	return 0;
}

/*
 * We're careful to copy the bitmaps out to aligned versions so that
 * we can use native bitops that require aligned longs.
 */
int scoutfs_alloc_segno(struct super_block *sb, u64 *segno)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_alloc_region_btree_key reg_key;
	struct scoutfs_alloc_region_btree_val __aligned(sizeof(long)) reg_val;
	SCOUTFS_BTREE_ITEM_REF(iref);
	DECLARE_SEG_ALLOC(sb, sal);
	u64 ind;
	int ret;
	int nr;

	down_write(&sal->rwsem);

	/* initially sweep through all segments */
	if (super->alloc_uninit != super->total_segs) {
		*segno = le64_to_cpu(super->alloc_uninit);
		/* done when inc hits total_segs */
		le64_add_cpu(&super->alloc_uninit, 1);
		ret = 0;
		goto out;
	}

	/* but usually search for region nodes */
	ind = sal->next_segno >> SCOUTFS_ALLOC_REGION_SHIFT;
	nr = sal->next_segno & SCOUTFS_ALLOC_REGION_MASK;

	for (;;) {
		reg_key.index = cpu_to_be64(ind);
		ret = scoutfs_btree_next(sb, &super->alloc_root,
					 &reg_key, sizeof(reg_key), &iref);
		if (ret == -ENOENT && ind != 0) {
			ind = 0;
			nr = 0;
			continue;
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = -ENOSPC;
			goto out;
		}

		ret = copy_region_item(&reg_key, &reg_val, &iref);
		scoutfs_btree_put_iref(&iref);
		if (ret)
			goto out;

		ind = be64_to_cpu(reg_key.index);
		nr = find_next_bit_le(reg_val.bits, SCOUTFS_ALLOC_REGION_BITS, nr);
		if (nr < SCOUTFS_ALLOC_REGION_BITS) {
			break;
		}

		/* possible for nr to be after all free bits, keep going */
		ind++;
		nr = 0;
	}

	clear_bit_le(nr, reg_val.bits);

	if (bitmap_empty((long *)reg_val.bits, SCOUTFS_ALLOC_REGION_BITS))
		ret = scoutfs_btree_delete(sb, &super->alloc_root,
					   &reg_key, sizeof(reg_key));
	else
		ret = scoutfs_btree_update(sb, &super->alloc_root,
					   &reg_key, sizeof(reg_key),
					   &reg_val, sizeof(reg_val));
	if (ret)
		goto out;

	*segno = (ind << SCOUTFS_ALLOC_REGION_SHIFT) + nr;
	sal->next_segno = *segno + 1;

	ret = 0;
out:
	if (ret == 0) {
		scoutfs_inc_counter(sb, alloc_alloc);
		le64_add_cpu(&super->free_segs, -1);
	}
	up_write(&sal->rwsem);

	trace_scoutfs_alloc_segno(sb, *segno, ret);
	return ret;
}

/*
 * Record newly freed sgements in pending regions.  These are applied to
 * persistent regions in btree items as the transaction commits.
 */
int scoutfs_alloc_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct pending_region *pend;
	DECLARE_SEG_ALLOC(sb, sal);
	u64 ind;
	int ret;
	int nr;

	ind = segno >> SCOUTFS_ALLOC_REGION_SHIFT;
	nr = segno & SCOUTFS_ALLOC_REGION_MASK;

	down_write(&sal->rwsem);

	pend = find_pending(&sal->pending_root, ind);
	if (!pend) {
		pend = kzalloc(sizeof(struct pending_region), GFP_NOFS);
		if (!pend) {
			ret = -ENOMEM;
			goto out;
		}

		pend->ind = ind;
		insert_pending(&sal->pending_root, pend);
	}

	set_bit_le(nr, pend->reg_val.bits);
	scoutfs_inc_counter(sb, alloc_free);
	le64_add_cpu(&super->free_segs, 1);
	ret = 0;
out:
	up_write(&sal->rwsem);

	trace_scoutfs_alloc_free(sb, segno, ind, nr, ret);
	return ret;
}

/*
 * Apply the pending frees to create the final set of dirty btree
 * blocks.  The caller will write the btree blocks.  We're destroying
 * the pending free record here so from this point on the pending free
 * blocks could be visible to allocation.  The caller can't finish with
 * the transaction until the btree is written successfully.
 */
int scoutfs_alloc_apply_pending(struct super_block *sb)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_SEG_ALLOC(sb, sal);
	struct pending_region *pend;
	struct rb_node *node;
	struct scoutfs_alloc_region_btree_key reg_key;
	struct scoutfs_alloc_region_btree_val __aligned(sizeof(long)) reg_val;
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret;

	down_write(&sal->rwsem);

	ret = 0;
	while ((node = rb_first(&sal->pending_root))) {
		pend = container_of(node, struct pending_region, node);

		/* see if we have a region for this index */
		reg_key.index = cpu_to_be64(pend->ind);
		ret = scoutfs_btree_lookup(sb, &super->alloc_root,
					   &reg_key, sizeof(reg_key), &iref);
		if (ret == -ENOENT) {
			/* create a new item if we don't */
			ret = scoutfs_btree_insert(sb, &super->alloc_root,
						   &reg_key, sizeof(reg_key),
						   &pend->reg_val,
						   sizeof(pend->reg_val));
		} else if (ret == 0) {
			/* and update the existing item if we do */
			ret = copy_region_item(&reg_key, &reg_val, &iref);
			scoutfs_btree_put_iref(&iref);
			if (ret)
				break;

			bitmap_or((long *)reg_val.bits, (long *)reg_val.bits,
				  (long *)pend->reg_val.bits,
				  SCOUTFS_ALLOC_REGION_BITS);

			ret = scoutfs_btree_update(sb, &super->alloc_root,
						   &reg_key, sizeof(reg_key),
						   &reg_val, sizeof(reg_val));
		}
		if (ret < 0)
			break;

		rb_erase(&pend->node, &sal->pending_root);
		kfree(pend);
	}

	up_write(&sal->rwsem);

	return ret;
}

/*
 * Return the number of blocks free for statfs.
 */
u64 scoutfs_alloc_bfree(struct super_block *sb)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_SEG_ALLOC(sb, sal);
	u64 bfree;

	down_read(&sal->rwsem);
	bfree = le64_to_cpu(super->free_segs) << SCOUTFS_SEGMENT_BLOCK_SHIFT;
	up_read(&sal->rwsem);

	return bfree;
}

int scoutfs_alloc_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct seg_alloc *sal;

	/* bits need to be aligned so hosts can use native bitops */
	BUILD_BUG_ON(offsetof(struct scoutfs_alloc_region_btree_val, bits) &
		     (sizeof(long) - 1));

	sal = kzalloc(sizeof(struct seg_alloc), GFP_KERNEL);
	if (!sal)
		return -ENOMEM;

	init_rwsem(&sal->rwsem);
	sal->pending_root = RB_ROOT;

	/* XXX read next_segno from super? */

	sbi->seg_alloc = sal;

	return 0;
}

void scoutfs_alloc_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_SEG_ALLOC(sb, sal);
	struct pending_region *pend;
	struct rb_node *node;

	if (sal) {
		while ((node = rb_first(&sal->pending_root))) {
			pend = container_of(node, struct pending_region, node);
			rb_erase(&pend->node, &sal->pending_root);
			kfree(pend);
		}
		kfree(sal);
		sbi->seg_alloc = NULL;
	}
}
