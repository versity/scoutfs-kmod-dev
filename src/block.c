/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <linux/crc32c.h>

#include "format.h"
#include "super.h"
#include "block.h"

__le32 scoutfs_block_calc_crc(struct scoutfs_block_header *hdr)
{
	int off = offsetof(struct scoutfs_block_header, crc) +
		  FIELD_SIZEOF(struct scoutfs_block_header, crc);
	u32 calc = crc32c(~0, (char *)hdr + off, SCOUTFS_BLOCK_SIZE - off);

	return cpu_to_le32(calc);
}

bool scoutfs_block_valid_crc(struct scoutfs_block_header *hdr)
{
	return hdr->crc == scoutfs_block_calc_crc(hdr);
}

bool scoutfs_block_valid_ref(struct super_block *sb,
			     struct scoutfs_block_header *hdr,
			     __le64 seq, __le64 blkno)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	return hdr->fsid == super->hdr.fsid && hdr->seq == seq &&
	       hdr->blkno == blkno;
}
