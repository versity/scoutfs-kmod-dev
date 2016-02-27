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

void scoutfs_set_chunk_alloc_bits(struct super_block *sb,
				  struct scoutfs_ring_bitmap *bm)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 off = le64_to_cpu(bm->offset);

	/* XXX check for corruption */

	sbi->chunk_alloc_bits[off] = bm->bits[0];
	sbi->chunk_alloc_bits[off + 1] = bm->bits[1];

}
