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
#include "treap.h"
#include "cmp.h"
#include "alloc.h"
#include "counters.h"

/*
 * scoutfs allocates segments by storing regions of a bitmap in treap
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
	struct scoutfs_treap *treap;
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
		reg = scoutfs_treap_lookup_next_dirty(sal->treap, &ind);
	} while (reg == NULL && ind && (ind = 0, nr = 0, 1));

	if (IS_ERR_OR_NULL(reg)) {
		if (IS_ERR(reg))
			ret = PTR_ERR(reg);
		else
			ret = -ENOSPC;
		goto out;
	}

	nr = find_next_bit_le(reg->bits, SCOUTFS_ALLOC_REGION_BITS, nr);
	if (nr >= SCOUTFS_ALLOC_REGION_BITS) {
		/* XXX corruption?  shouldn't find empty regions */
		ret = -EIO;
		goto out;
	}

	ind = le64_to_cpu(reg->index);

	clear_bit_le(nr, reg->bits);

	if (empty_region(reg)) {
		ret = scoutfs_treap_delete(sal->treap, &ind);
		/* XXX figure out what to do about this inconsistency */
		if (WARN_ON_ONCE(ret))
			goto out;
	}

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
 * treap nodes as the transaction commits.
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
	ret = scoutfs_treap_has_dirty(sal->treap);
	up_write(&sal->rwsem);

	return ret;
}

/*
 * First we apply the pending frees to create the final set of dirty
 * region nodes and then ask the treap to write them to ring pages.
 */
int scoutfs_alloc_dirty_ring(struct super_block *sb)
{
	DECLARE_SEG_ALLOC(sb, sal);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_alloc_region *reg;
	struct pending_region *pend;
	struct rb_node *node;
	u64 ind;
	int ret;

	down_write(&sal->rwsem);

	while ((node = rb_first(&sal->pending_root))) {
		pend = container_of(node, struct pending_region, node);

		ind = le64_to_cpu(pend->reg.index);

		reg = scoutfs_treap_lookup_dirty(sal->treap, &ind);
		if (!reg)
			reg = scoutfs_treap_insert(sal->treap, &ind,
					sizeof(struct scoutfs_alloc_region),
					&ind);
		if (IS_ERR(reg)) {
			ret = PTR_ERR(reg);
			goto out;
		}

		reg->index = pend->reg.index;
		or_region_bits(reg, &pend->reg);

		rb_erase(&pend->node, &sal->pending_root);
		kfree(pend);
	}

	scoutfs_treap_dirty_ring(sal->treap, &super->alloc_treap_root);
	ret = 0;
out:
	up_write(&sal->rwsem);
	return ret;
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

static int alloc_treap_compare(void *key, void *data)
{
	u64 *ind = key;
	struct scoutfs_alloc_region *reg = data;

	return scoutfs_cmp_u64s(*ind, le64_to_cpu(reg->index));
}

static void alloc_treap_fill(void *data, void *fill_arg)
{
	struct scoutfs_alloc_region *reg = data;
	u64 *ind = fill_arg;

	memset(reg, 0, sizeof(struct scoutfs_alloc_region));
	reg->index = cpu_to_le64p(ind);
}

static struct scoutfs_treap_ops alloc_treap_ops = {
	.compare = alloc_treap_compare,
	.fill = alloc_treap_fill,
};

int scoutfs_alloc_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct seg_alloc *sal;

	/* bits need to be aligned so hosts can use native bitops */
	BUILD_BUG_ON(offsetof(struct scoutfs_alloc_region, bits) &
		     (sizeof(long) - 1));

	sal = kzalloc(sizeof(struct seg_alloc), GFP_KERNEL);
	if (!sal)
		return -ENOMEM;

	init_rwsem(&sal->rwsem);
	sal->pending_root = RB_ROOT;
	sal->treap = scoutfs_treap_alloc(sb, &alloc_treap_ops,
					 &super->alloc_treap_root);
	if (!sal->treap) {
		kfree(sal);
		return -ENOMEM;
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
		scoutfs_treap_free(sal->treap);
		while ((node = rb_first(&sal->pending_root))) {
			pend = container_of(node, struct pending_region, node);
			rb_erase(&pend->node, &sal->pending_root);
			kfree(pend);
		}
		kfree(sal);
	}
}
