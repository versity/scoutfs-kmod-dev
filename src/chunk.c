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
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "msg.h"
#include "block.h"
#include "ring.h"
#include "chunk.h"

void scoutfs_set_chunk_alloc_bits(struct super_block *sb,
				  struct scoutfs_ring_bitmap *bm)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 off = le32_to_cpu(bm->offset) * ARRAY_SIZE(bm->bits);

	/* XXX check for corruption */

	sbi->chunk_alloc_bits[off] = bm->bits[0];
	sbi->chunk_alloc_bits[off + 1] = bm->bits[1];
}

/*
 * Return the block number of the first block in a free chunk.
 *
 * The region around the cleared free bit for the allocation is always
 * added to the ring and will generate a ton of overlapping ring
 * entries.  This is fine for initial testing but won't be good enough
 * for real use.  We'll have a bitmap of dirtied regions that are only
 * logged as the update is written out. 
 */
int scoutfs_alloc_chunk(struct super_block *sb, u64 *blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	unsigned long size = le64_to_cpu(super->total_chunks);
	struct scoutfs_ring_bitmap bm;
	unsigned long off;
	unsigned long bit;
	int ret;

	spin_lock(&sbi->chunk_alloc_lock);

	bit = find_next_bit_le(sbi->chunk_alloc_bits, size, 0);
	if (bit >= size) {
		ret = -ENOSPC;
	} else {
		clear_bit_le(bit, sbi->chunk_alloc_bits);

		off = round_down(bit, sizeof(bm.bits) * 8);
		bm.offset = cpu_to_le32(off);

		off *= ARRAY_SIZE(bm.bits);
		bm.bits[0] = sbi->chunk_alloc_bits[off];
		bm.bits[1] = sbi->chunk_alloc_bits[off + 1];

		*blkno = bit << SCOUTFS_CHUNK_BLOCK_SHIFT;
		ret = 0;
	}

	spin_unlock(&sbi->chunk_alloc_lock);

	if (!ret) {
		ret = scoutfs_dirty_ring_entry(sb, SCOUTFS_RING_BITMAP, &bm,
					       sizeof(bm));
		WARN_ON_ONCE(ret);
	}

	return ret;
}
