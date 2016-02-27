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
#include <linux/buffer_head.h>
#include <linux/fs.h>

#include "format.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "item.h"
#include "super.h"
#include "manifest.h"
#include "chunk.h"
#include "block.h"

static int replay_ring_block(struct super_block *sb, struct buffer_head *bh)
{
	struct scoutfs_ring_block *ring = (void *)bh->b_data;
	struct scoutfs_ring_entry *ent = (void *)(ring + 1);
	struct scoutfs_ring_manifest_entry *ment;
	struct scoutfs_ring_del_manifest *del;
	struct scoutfs_ring_bitmap *bm;
	int ret = 0;
	int i;

	/* XXX verify */

	for (i = 0; i < le16_to_cpu(ring->nr_entries); i++) {
		switch(ent->type) {
		case SCOUTFS_RING_ADD_MANIFEST:
			ment = (void *)(ent + 1);
			ret = scoutfs_add_manifest(sb, ment);
			break;
		case SCOUTFS_RING_DEL_MANIFEST:
			del = (void *)(ent + 1);
			scoutfs_delete_manifest(sb, le64_to_cpu(del->blkno));
			break;
		case SCOUTFS_RING_BITMAP:
			bm = (void *)(ent + 1);
			scoutfs_set_chunk_alloc_bits(sb, bm);
			break;
		default:
			/* XXX */
			break;
		}

		ent = (void *)(ent + 1) + le16_to_cpu(ent->len);
	}

	return ret;
}

/*
 * Read a given logical ring block.
 *
 * Each ring map block entry maps a chunk's worth of ring blocks.
 */
static struct buffer_head *read_ring_block(struct super_block *sb, u64 block)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_ring_map_block *map;
	struct buffer_head *bh;
	u64 ring_chunk;
	u32 ring_block;
	u64 blkno;
	u64 div;
	u32 rem;

	ring_block = block & SCOUTFS_CHUNK_BLOCK_MASK;
	ring_chunk = block >> SCOUTFS_CHUNK_BLOCK_SHIFT;

	div = div_u64_rem(ring_chunk, SCOUTFS_RING_MAP_BLOCKS, &rem);

	bh = scoutfs_read_block(sb, le64_to_cpu(super->ring_map_blkno) + div);
	if (!bh)
		return NULL;

	/* XXX verify map block */

	map = (void *)bh->b_data;
	blkno = le64_to_cpu(map->blknos[rem]) + ring_block;
	brelse(bh);

	return scoutfs_read_block(sb, blkno);
}

int scoutfs_replay_ring(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buffer_head *bh;
	u64 block;
	int ret;
	int i;

	/* XXX read-ahead map blocks and each set of ring blocks */

	block = le64_to_cpu(super->ring_first_block);
	for (i = 0; i < le64_to_cpu(super->ring_active_blocks); i++) {
		bh = read_ring_block(sb, block);
		if (!bh) {
			ret = -EIO;
			break;
		}

		ret = replay_ring_block(sb, bh);
		brelse(bh);
		if (ret)
			break;

		if (++block == le64_to_cpu(super->ring_total_blocks))
			block = 0;
	}

	return ret;
}
