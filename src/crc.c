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
#include <linux/crc32c.h>

#include "format.h"
#include "crc.h"

u32 scoutfs_crc_block(struct scoutfs_block_header *hdr)
{
	return crc32c(~0, (char *)hdr + sizeof(hdr->crc),
		      SCOUTFS_BLOCK_SIZE - sizeof(hdr->crc));
}
