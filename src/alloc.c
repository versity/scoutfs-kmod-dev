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
#include "alloc.h"

/*
 * scoutfs allocates segments by storing regions of a bitmap in a radix.
 * As the regions are modified their index in the radix is marked dirty
 * for writeout.
 *
 * Frees are tracked in a separate radix.  They're only applied to the
 * free regions as a transaction is written.  The frees can't satisfy
 * allocation until they're committed so that we don't overwrite stable
 * referenced data.
 *
 * The allocated segments are large enough to be effectively
 * independent.  We allocate by sweeping a cursor through the volume.
 * This gives racing unlocked readers more time to try to sample a stale
 * freed segment, when its safe to do so, before it is reallocated and
 * rewritten and they're forced to retry their racey read.
 *
 * XXX
 *  - make sure seg fits in long index
 *  - frees can delete region, leave non-NULL nul behind for logging
 */

struct seg_alloc {
	spinlock_t lock;
	struct radix_tree_root regs;
	struct radix_tree_root pending;
	u64 next_segno;
};

#define DECLARE_SEG_ALLOC(sb, name) \
	struct seg_alloc *name = SCOUTFS_SB(sb)->seg_alloc

enum {
	DIRTY_RADIX_TAG = 0,
};

int scoutfs_alloc_segno(struct super_block *sb, u64 *segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_ring_alloc_region *reg;
	DECLARE_SEG_ALLOC(sb, sal);
	unsigned long flags;
	unsigned long ind;
	int ret;
	int nr;

	spin_lock_irqsave(&sal->lock, flags);

	/* start by sweeping through the device for the first time */
	if (sal->next_segno == le64_to_cpu(super->alloc_uninit)) {
		le64_add_cpu(&super->alloc_uninit, 1);
		*segno = sal->next_segno++;
		if (sal->next_segno == le64_to_cpu(super->total_segs))
			sal->next_segno = 0;
		ret = 0;
		goto out;
	}

	/* then fall back to the allocator */
	ind = sal->next_segno >> SCOUTFS_ALLOC_REGION_SHIFT;
	nr = sal->next_segno & SCOUTFS_ALLOC_REGION_MASK;

	do {
		ret = radix_tree_gang_lookup(&sal->regs, (void **)&reg, ind, 1);
	} while (ret == 0 && ind && (ind = 0, nr = 0, 1));

	if (ret == 0) {
		ret = -ENOSPC;
		goto out;
	}

	nr = find_next_bit_le(reg->bits, SCOUTFS_ALLOC_REGION_BITS, nr);
	if (nr >= SCOUTFS_ALLOC_REGION_BITS) {
		/* XXX corruption?  shouldn't find empty regions */
		ret = -EIO;
		goto out;
	}

	clear_bit_le(nr, reg->bits);
	radix_tree_tag_set(&sal->regs, ind, DIRTY_RADIX_TAG);

	*segno = (ind << SCOUTFS_ALLOC_REGION_SHIFT) + nr;

	/* once this wraps it will never equal alloc_uninit */
	sal->next_segno = *segno + 1;
	if (sal->next_segno == le64_to_cpu(super->total_segs))
		sal->next_segno = 0;

	ret = 0;
out:
	spin_unlock_irqrestore(&sal->lock, flags);

	trace_printk("segno %llu ret %d\n", *segno, ret);
	return ret;
}

/*
 * Record newly freed sgements in pending regions.  These can't be
 * applied to the main allocator regions until the next commit so that
 * they're not still referenced by the stable tree in event of a crash.
 *
 * The pending regions are merged into dirty regions for the next commit.
 */
int scoutfs_alloc_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_ring_alloc_region *reg;
	struct scoutfs_ring_alloc_region *ins;
	DECLARE_SEG_ALLOC(sb, sal);
	unsigned long flags;
	unsigned long ind;
	int ret;
	int nr;

	ind = segno >> SCOUTFS_ALLOC_REGION_SHIFT;
	nr = segno & SCOUTFS_ALLOC_REGION_MASK;

	ins = kzalloc(sizeof(struct scoutfs_ring_alloc_region), GFP_NOFS);
	if (!ins) {
		ret = -ENOMEM;
		goto out;
	}

	ins->eh.type = SCOUTFS_RING_ADD_ALLOC;
	ins->eh.len = cpu_to_le16(sizeof(struct scoutfs_ring_alloc_region));
	ins->index = cpu_to_le64(ind);

	ret = radix_tree_preload(GFP_NOFS);
	if (ret) {
		goto out;
	}

	spin_lock_irqsave(&sal->lock, flags);

	reg = radix_tree_lookup(&sal->pending, ind);
	if (!reg) {
		reg = ins;
		ins = NULL;
		radix_tree_insert(&sal->pending, ind, reg);
	}

	set_bit_le(nr, reg->bits);

	spin_unlock_irqrestore(&sal->lock, flags);
	radix_tree_preload_end();
out:
	kfree(ins);
	trace_printk("freeing segno %llu ind %lu nr %d ret %d\n",
		     segno, ind, nr, ret);
	return ret;
}

/*
 * Add a new clean region from the ring.  It can be replacing existing
 * clean stale entries during replay as we make our way through the
 * ring.
 */
int scoutfs_alloc_add(struct super_block *sb,
		      struct scoutfs_ring_alloc_region *ins)
{
	struct scoutfs_ring_alloc_region *existing;
	struct scoutfs_ring_alloc_region *reg;
	DECLARE_SEG_ALLOC(sb, sal);
	unsigned long flags;
	int ret;

	reg = kmalloc(sizeof(struct scoutfs_ring_alloc_region), GFP_NOFS);
	if (!reg) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(reg, ins, sizeof(struct scoutfs_ring_alloc_region));

	ret = radix_tree_preload(GFP_NOFS);
	if (ret) {
		kfree(reg);
		goto out;
	}

	spin_lock_irqsave(&sal->lock, flags);

	existing = radix_tree_lookup(&sal->regs, le64_to_cpu(reg->index));
	if (existing)
		radix_tree_delete(&sal->regs, le64_to_cpu(reg->index));
	radix_tree_insert(&sal->regs, le64_to_cpu(reg->index), reg);

	spin_unlock_irqrestore(&sal->lock, flags);
	radix_tree_preload_end();

	if (existing)
		kfree(existing);

	ret = 0;
out:
	trace_printk("inserted reg ind %llu ret %d\n",
		     le64_to_cpu(ins->index), ret);
	return ret;
}

/*
 * Append all the dirty alloc regions to the end of the ring.  First we
 * apply the pending frees to create the final set of dirty regions.
 *
 * This can't fail and always returns 0.
 */
int scoutfs_alloc_dirty_ring(struct super_block *sb)
{
	struct scoutfs_ring_alloc_region *regs[16];
	struct scoutfs_ring_alloc_region *reg;
	DECLARE_SEG_ALLOC(sb, sal);
	unsigned long start;
	unsigned long ind;
	int nr;
	int i;
	int b;

	/*
	 * Merge pending free regions into dirty regions.  If the dirty
	 * region doesn't exist we can just move the pending region over.
	 * If it does we or the pending bits in the region.
	 */
	start = 0;
	do {
		nr = radix_tree_gang_lookup(&sal->pending, (void **)regs,
					    start, ARRAY_SIZE(regs));
		for (i = 0; i < nr; i++) {
			ind = le64_to_cpu(regs[i]->index);

			reg = radix_tree_lookup(&sal->regs, ind);
			if (!reg) {
				radix_tree_insert(&sal->regs, ind, regs[i]);
			} else {
				for (b = 0; b < ARRAY_SIZE(reg->bits); b++)
					reg->bits[i] |= regs[i]->bits[i];
				kfree(regs[i]);
			}

			radix_tree_delete(&sal->pending, ind);
			radix_tree_tag_set(&sal->regs, ind, DIRTY_RADIX_TAG);
			start = ind + 1;
		}
	} while (nr);

	/* and append all the dirty regions to the ring */
	start = 0;
	do {
		nr = radix_tree_gang_lookup_tag(&sal->regs, (void **)regs,
					        start, ARRAY_SIZE(regs),
						DIRTY_RADIX_TAG);
		for (i = 0; i < nr; i++) {
			reg = regs[i];
			ind = le64_to_cpu(reg->index);

			scoutfs_ring_append(sb, &reg->eh);
			radix_tree_tag_clear(&sal->regs, ind, DIRTY_RADIX_TAG);
			start = ind + 1;
		}
	} while (nr);

	return 0;
}

int scoutfs_alloc_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct seg_alloc *sal;

	/* bits need to be aligned so hosts can use native bitops */
	BUILD_BUG_ON(offsetof(struct scoutfs_ring_alloc_region, bits) &
		     (sizeof(long) - 1));

	sal = kzalloc(sizeof(struct seg_alloc), GFP_KERNEL);
	if (!sal)
		return -ENOMEM;
	sbi->seg_alloc = sal;

	spin_lock_init(&sal->lock);
	/* inserts preload with _NOFS */
	INIT_RADIX_TREE(&sal->pending, GFP_ATOMIC);
	INIT_RADIX_TREE(&sal->regs, GFP_ATOMIC);
	/* XXX read next_segno from super? */

	return 0;
}

static void destroy_radix_regs(struct radix_tree_root *radix)
{
	struct scoutfs_ring_alloc_region *regs[16];
	int nr;
	int i;


	do {
		nr = radix_tree_gang_lookup(radix, (void **)regs,
					    0, ARRAY_SIZE(regs));
		for (i = 0; i < nr; i++) {
			radix_tree_delete(radix, le64_to_cpu(regs[i]->index));
			kfree(regs[i]);
		}
	} while (nr);
}

void scoutfs_alloc_destroy(struct super_block *sb)
{
	DECLARE_SEG_ALLOC(sb, sal);

	if (sal) {
		destroy_radix_regs(&sal->pending);
		destroy_radix_regs(&sal->regs);
		kfree(sal);
	}
}
