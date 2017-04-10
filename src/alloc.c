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
#include "ring.h"
#include "cmp.h"
#include "alloc.h"
#include "counters.h"

/*
 * scoutfs allocates segments by storing regions of a bitmap in ring
 * nodes.
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
	struct scoutfs_ring_info ring;
	u64 next_segno;
};

#define DECLARE_SEG_ALLOC(sb, name) \
	struct seg_alloc *name = SCOUTFS_SB(sb)->seg_alloc

struct pending_region {
	struct rb_node node;
	struct scoutfs_alloc_region reg;
};

static struct pending_region *find_pending(struct rb_root *root, u64 ind)
{
	struct rb_node *node = root->rb_node;
	struct pending_region *pend;

	while (node) {
		pend = container_of(node, struct pending_region, node);

		if (ind < le64_to_cpu(pend->reg.index))
			node = node->rb_left;
		else if (ind > le64_to_cpu(pend->reg.index))
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
	u64 ind = le64_to_cpu(ins->reg.index);

	while (*node) {
		parent = *node;
		pend = container_of(*node, struct pending_region, node);

		if (ind < le64_to_cpu(pend->reg.index))
			node = &(*node)->rb_left;
		else if (ind > le64_to_cpu(pend->reg.index))
			node = &(*node)->rb_right;
		else
			BUG();
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static bool empty_region(struct scoutfs_alloc_region *reg)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(reg->bits); i++) {
		if (reg->bits[i])
			return false;
	}

	return true;
}

int scoutfs_alloc_segno(struct super_block *sb, u64 *segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_alloc_region *reg;
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

	do {
		reg = scoutfs_ring_lookup_next(&sal->ring, &ind);
	} while (reg == NULL && ind && (ind = 0, nr = 0, 1));

	if (IS_ERR_OR_NULL(reg)) {
		if (IS_ERR(reg))
			ret = PTR_ERR(reg);
		else
			ret = -ENOSPC;
		goto out;
	}

	scoutfs_ring_dirty(&sal->ring, reg);

	nr = find_next_bit_le(reg->bits, SCOUTFS_ALLOC_REGION_BITS, nr);
	if (nr >= SCOUTFS_ALLOC_REGION_BITS) {
		/* XXX corruption?  shouldn't find empty regions */
		ret = -EIO;
		goto out;
	}

	ind = le64_to_cpu(reg->index);

	clear_bit_le(nr, reg->bits);

	if (empty_region(reg))
		scoutfs_ring_delete(&sal->ring, reg);

	*segno = (ind << SCOUTFS_ALLOC_REGION_SHIFT) + nr;
	sal->next_segno = *segno + 1;

	ret = 0;
out:
	if (ret == 0) {
		scoutfs_inc_counter(sb, alloc_alloc);
		le64_add_cpu(&super->free_segs, -1);
	}
	up_write(&sal->rwsem);

	trace_printk("segno %llu ret %d\n", *segno, ret);
	return ret;
}

/*
 * Record newly freed sgements in pending regions.  These are applied to
 * ring nodes as the transaction commits.
 */
int scoutfs_alloc_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
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

		pend->reg.index = cpu_to_le64(ind);
		insert_pending(&sal->pending_root, pend);
	}

	set_bit_le(nr, pend->reg.bits);
	scoutfs_inc_counter(sb, alloc_free);
	le64_add_cpu(&super->free_segs, 1);
	ret = 0;
out:
	up_write(&sal->rwsem);

	trace_printk("freeing segno %llu ind %llu nr %d ret %d\n",
		     segno, ind, nr, ret);
	return ret;
}

static void or_region_bits(struct scoutfs_alloc_region *dst,
			   struct scoutfs_alloc_region *src)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dst->bits); i++)
		dst->bits[i] |= src->bits[i];
}

int scoutfs_alloc_has_dirty(struct super_block *sb)
{
	DECLARE_SEG_ALLOC(sb, sal);
	int ret;

	down_write(&sal->rwsem);
	ret = !!(scoutfs_ring_has_dirty(&sal->ring) ||
		 !RB_EMPTY_ROOT(&sal->pending_root));
	up_write(&sal->rwsem);

	return ret;
}

/*
 * First we apply the pending frees to create the final set of dirty
 * region nodes and then ask the ring to write them to the ring.
 */
int scoutfs_alloc_submit_write(struct super_block *sb,
			       struct scoutfs_bio_completion *comp)
{
	DECLARE_SEG_ALLOC(sb, sal);
	struct scoutfs_alloc_region *reg;
	struct pending_region *pend;
	struct rb_node *node;
	u64 ind;
	int ret;

	down_write(&sal->rwsem);

	while ((node = rb_first(&sal->pending_root))) {
		pend = container_of(node, struct pending_region, node);

		ind = le64_to_cpu(pend->reg.index);

		reg = scoutfs_ring_lookup(&sal->ring, &ind);
		if (!reg) {
			reg = scoutfs_ring_insert(&sal->ring, &ind,
					sizeof(struct scoutfs_alloc_region));
			if (!reg) {
				ret = -ENOMEM;
				goto out;
			}

			memset(reg, 0, sizeof(struct scoutfs_alloc_region));
			reg->index = cpu_to_le64(ind);
		}

		or_region_bits(reg, &pend->reg);
		scoutfs_ring_dirty(&sal->ring, reg);

		rb_erase(&pend->node, &sal->pending_root);
		kfree(pend);
	}

	ret = scoutfs_ring_submit_write(sb, &sal->ring, comp);
out:
	up_write(&sal->rwsem);
	return ret;
}

void scoutfs_alloc_write_complete(struct super_block *sb)
{
	DECLARE_SEG_ALLOC(sb, sal);

	down_write(&sal->rwsem);
	scoutfs_ring_write_complete(&sal->ring);
	up_write(&sal->rwsem);
}

/*
 * Return the number of blocks free for statfs.
 */
u64 scoutfs_alloc_bfree(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	DECLARE_SEG_ALLOC(sb, sal);
	u64 bfree;

	down_read(&sal->rwsem);
	bfree = le64_to_cpu(super->free_segs) << SCOUTFS_SEGMENT_BLOCK_SHIFT;
	up_read(&sal->rwsem);

	return bfree;
}

static int alloc_ring_compare_key(void *key, void *data)
{
	u64 *ind = key;
	struct scoutfs_alloc_region *reg = data;

	return scoutfs_cmp_u64s(*ind, le64_to_cpu(reg->index));
}

static int alloc_ring_compare_data(void *A, void *B)
{
	struct scoutfs_alloc_region *a = A;
	struct scoutfs_alloc_region *b = B;

	return scoutfs_cmp_u64s(le64_to_cpu(a->index), le64_to_cpu(b->index));
}

int scoutfs_alloc_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct seg_alloc *sal;
	int ret;

	/* bits need to be aligned so hosts can use native bitops */
	BUILD_BUG_ON(offsetof(struct scoutfs_alloc_region, bits) &
		     (sizeof(long) - 1));

	sal = kzalloc(sizeof(struct seg_alloc), GFP_KERNEL);
	if (!sal)
		return -ENOMEM;

	init_rwsem(&sal->rwsem);
	sal->pending_root = RB_ROOT;
	scoutfs_ring_init(&sal->ring, &super->alloc_ring,
			  alloc_ring_compare_key, alloc_ring_compare_data);

	ret = scoutfs_ring_load(sb, &sal->ring);
	if (ret) {
		kfree(sal);
		return ret;
	}

	/* XXX read next_segno from super? */

	sbi->seg_alloc = sal;

	return 0;
}

void scoutfs_alloc_destroy(struct super_block *sb)
{
	DECLARE_SEG_ALLOC(sb, sal);
	struct pending_region *pend;
	struct rb_node *node;

	if (sal) {
		scoutfs_ring_destroy(&sal->ring);
		while ((node = rb_first(&sal->pending_root))) {
			pend = container_of(node, struct pending_region, node);
			rb_erase(&pend->node, &sal->pending_root);
			kfree(pend);
		}
		kfree(sal);
	}
}
