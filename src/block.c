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


/*
 * A quick metadata read wrapper which knows how to validate the
 * block header.
 */
struct buffer_head *scoutfs_read_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_block_header *hdr;
	struct buffer_head *bh;
	u32 crc;

	bh = sb_bread(sb, blkno);
	if (!bh || buffer_private_verified(bh))
		return bh;

	hdr = (void *)bh->b_data;
	crc = scoutfs_crc_block(hdr);

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
		return bh;
	}

	brelse(bh);
	return NULL;
}

/*
 * Return a locked dirty buffer with undefined contents.  The caller is
 * responsible for initializing the entire block.  Callers can try and
 * read from these dirty blocks so we mark them verified so that they
 * don't try to check uninitialized crcs.
 */
struct buffer_head *scoutfs_dirty_bh(struct super_block *sb, u64 blkno)
{
	struct buffer_head *bh;

	bh = sb_getblk(sb, blkno);
	if (bh) {
		lock_buffer(bh);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		set_buffer_private_verified(bh);
	}

	return bh;
}

/*
 * Return a locked dirty buffer with a partially initialized block
 * header.  The caller has to calculate the header crc before unlocking
 * the block.  The header will have the sequence number of the dirty super
 * by default.
 */
struct buffer_head *scoutfs_dirty_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_block_header *hdr;
	struct buffer_head *bh;

	bh = scoutfs_dirty_bh(sb, blkno);
	if (bh) {
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
