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
#include "super.h"
#include "manifest.h"
#include "chunk.h"
#include "block.h"
#include "ring.h"

static int replay_ring_block(struct super_block *sb, struct buffer_head *bh)
{
	struct scoutfs_ring_block *ring = (void *)bh->b_data;
	struct scoutfs_ring_entry *ent = (void *)(ring + 1);
	struct scoutfs_manifest_entry *ment;
	struct scoutfs_ring_bitmap *bm;
	int ret = 0;
	int i;

	/* XXX verify */

	for (i = 0; i < le16_to_cpu(ring->nr_entries); i++) {
		switch(ent->type) {
		case SCOUTFS_RING_ADD_MANIFEST:
			ment = (void *)(ent + 1);
			ret = scoutfs_insert_manifest(sb, ment);
			break;
		case SCOUTFS_RING_DEL_MANIFEST:
			ment = (void *)(ent + 1);
			scoutfs_delete_manifest(sb, ment);
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
 * Return the block number of the block that contains the given logical
 * block in the ring.  We look up ring block chunks in the map blocks
 * in the chunk described by the super.
 */
static u64 map_ring_block(struct super_block *sb, u64 block)
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
		return 0;

	/* XXX verify map block */

	map = (void *)bh->b_data;
	blkno = le64_to_cpu(map->blknos[rem]) + ring_block;
	brelse(bh);

	return blkno;
}

/*
 * Read a given logical ring block.
 */
static struct buffer_head *read_ring_block(struct super_block *sb, u64 block)
{
	u64 blkno = map_ring_block(sb, block);

	if (!blkno)
		return NULL;

	return scoutfs_read_block(sb, blkno);
}

/*
 * Return a dirty locked logical ring block.
 */
static struct buffer_head *new_ring_block(struct super_block *sb, u64 block)
{
	u64 blkno = map_ring_block(sb, block);

	if (!blkno)
		return NULL;

	return scoutfs_new_block(sb, blkno);
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

/*
 * The caller is generating ring entries for manifest and allocator
 * bitmap as they write items to blocks.  We pin the block that we're
 * working on so that it isn't written out until we fill it and
 * calculate its checksum.
 */
int scoutfs_dirty_ring_entry(struct super_block *sb, u8 type, void *data,
			     u16 len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_ring_block *ring;
	struct scoutfs_ring_entry *ent;
	struct buffer_head *bh;
	unsigned int avail;
	u64 block;
	int ret = 0;

	bh = sbi->dirty_ring_bh;
	ent = sbi->dirty_ring_ent;
	avail = sbi->dirty_ring_ent_avail;

	if (bh && len > avail) {
		scoutfs_finish_dirty_ring(sb);
		bh = NULL;
	}
	if (!bh) {
		block = le64_to_cpu(super->ring_first_block) +
			le64_to_cpu(super->ring_active_blocks);
		if (block >= le64_to_cpu(super->ring_total_blocks))
			block -= le64_to_cpu(super->ring_total_blocks);

		bh = new_ring_block(sb, block);
		if (!bh) {
			ret = -ENOMEM;
			goto out;
		}

		ring = (void *)bh->b_data;
		ring->nr_entries = 0;
		ent = (void *)(ring + 1);
		/* assuming len fits in new empty block */
	}

	ring = (void *)bh->b_data;

	ent->type = type;
	ent->len = cpu_to_le16(len);
	memcpy(ent + 1, data, len);
	le16_add_cpu(&ring->nr_entries, 1);

	ent = (void *)(ent + 1) + le16_to_cpu(ent->len);
	avail = SCOUTFS_BLOCK_SIZE - ((char *)(ent + 1) - (char *)ring);
out:
	sbi->dirty_ring_bh = bh;
	sbi->dirty_ring_ent = ent;
	sbi->dirty_ring_ent_avail = avail;

	return ret;
}

/*
 * The super might have a pinned partial dirty ring block.  This is
 * called as we finish the block or when the commit is done.  We
 * calculate the checksum and unlock it so it can be written.
 *
 * XXX This is about to write a partial block.  We might as well fill
 * that space with more old entries from the manifest and ring before
 * we write it.
 */
int scoutfs_finish_dirty_ring(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buffer_head *bh;

	bh = sbi->dirty_ring_bh;
	if (!bh)
		return 0;

	sbi->dirty_ring_bh = NULL;

	/*
	 * XXX we're not zeroing the tail of the block here.  We will
	 * when we change the item block format to let us append to
	 * the block without walking all the items.
	 */
	scoutfs_calc_hdr_crc(bh);
	mark_buffer_dirty(bh);
	unlock_buffer(bh);
	brelse(bh);

	le64_add_cpu(&super->ring_active_blocks, 1);

	return 0;
}
