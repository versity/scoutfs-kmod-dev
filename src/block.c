/*
 * Copyright (C) 2015 Versity Software, Inc.  All rights reserved.
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
#include <linux/buffer_head.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "crc.h"

#define BH_Private_Verified BH_PrivateStart

BUFFER_FNS(Private_Verified, private_verified)

static void verify_block_header(struct super_block *sb, struct buffer_head *bh)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_block_header *hdr = (void *)bh->b_data;
	u32 crc = scoutfs_crc_block(hdr);
	u64 blkno = bh->b_blocknr;

	if (le32_to_cpu(hdr->crc) != crc) {
		printk("blkno %llu hdr crc %x != calculated %x\n", blkno,
			le32_to_cpu(hdr->crc), crc);
	} else if (super->hdr.fsid && hdr->fsid != super->hdr.fsid) {
		printk("blkno %llu fsid %llx != super fsid %llx\n", blkno,
			le64_to_cpu(hdr->fsid), le64_to_cpu(super->hdr.fsid));
	} else if (le64_to_cpu(hdr->blkno) != blkno) {
		printk("blkno %llu invalid hdr blkno %llx\n", blkno,
			le64_to_cpu(hdr->blkno));
	} else {
		set_buffer_private_verified(bh);
	}
}

/*
 * Read an existing block from the device and verify its metadata header.
 */
struct buffer_head *scoutfs_read_block(struct super_block *sb, u64 blkno)
{
	struct buffer_head *bh;

	bh = sb_bread(sb, blkno);
	if (!bh || buffer_private_verified(bh))
		return bh;

	lock_buffer(bh);
	if (!buffer_private_verified(bh))
		verify_block_header(sb, bh);
	unlock_buffer(bh);

	if (!buffer_private_verified(bh)) {
		brelse(bh);
		bh = NULL;
	}

	return bh;
}

/*
 * Read the block that contains the given byte offset in the given chunk.
 */
struct buffer_head *scoutfs_read_block_off(struct super_block *sb, u64 blkno,
					   u32 off)
{
	if (WARN_ON_ONCE(off >= SCOUTFS_CHUNK_SIZE))
		return ERR_PTR(-EINVAL);

	return scoutfs_read_block(sb, blkno + (off >> SCOUTFS_BLOCK_SHIFT));
}

/*
 * Return a newly allocated metadata block with an updated block header
 * to match the current dirty super block.  Callers are responsible for
 * serializing access to the block and for zeroing unwritten block
 * contents.
 */
struct buffer_head *scoutfs_new_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_block_header *hdr;
	struct buffer_head *bh;

	bh = sb_getblk(sb, blkno);
	if (bh) {
		if (!buffer_uptodate(bh) || buffer_private_verified(bh)) {
			lock_buffer(bh);
			set_buffer_uptodate(bh);
			set_buffer_private_verified(bh);
			unlock_buffer(bh);
		}

		hdr = (void *)bh->b_data;
		*hdr = super->hdr;
		hdr->blkno = cpu_to_le64(blkno);
	}

	return bh;
}

void scoutfs_calc_hdr_crc(struct buffer_head *bh)
{
	struct scoutfs_block_header *hdr = (void *)bh->b_data;

	hdr->crc = cpu_to_le32(scoutfs_crc_block(hdr));
}
