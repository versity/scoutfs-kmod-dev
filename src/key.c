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
#include <linux/bug.h>
#include <linux/errno.h>

#include "format.h"
#include "key.h"

char *scoutfs_zone_strings[SCOUTFS_MAX_ZONE] = {
	[SCOUTFS_INODE_INDEX_ZONE]	= "ind",
	[SCOUTFS_NODE_ZONE]		= "nod",
	[SCOUTFS_FS_ZONE]		= "fs",
};

char *scoutfs_type_strings[SCOUTFS_MAX_ZONE][SCOUTFS_MAX_TYPE] = {
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_META_SEQ_TYPE] = "msq",
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE] = "dsq",
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_EXTENT_BLKNO_TYPE]	      = "fbn",
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_EXTENT_BLOCKS_TYPE]	      = "fbs",
	[SCOUTFS_NODE_ZONE][SCOUTFS_ORPHAN_TYPE]		      = "orp",
	[SCOUTFS_FS_ZONE][SCOUTFS_INODE_TYPE]			      = "ino",
	[SCOUTFS_FS_ZONE][SCOUTFS_XATTR_TYPE]			      = "xat",
	[SCOUTFS_FS_ZONE][SCOUTFS_DIRENT_TYPE]			      = "dnt",
	[SCOUTFS_FS_ZONE][SCOUTFS_READDIR_TYPE]			      = "rdr",
	[SCOUTFS_FS_ZONE][SCOUTFS_LINK_BACKREF_TYPE]		      = "lbr",
	[SCOUTFS_FS_ZONE][SCOUTFS_SYMLINK_TYPE]			      = "sym",
	[SCOUTFS_FS_ZONE][SCOUTFS_FILE_EXTENT_TYPE]		      = "fex",
};

char scoutfs_unknown_u8_strings[U8_MAX][U8_STR_MAX];

int __init scoutfs_key_init(void)
{
	int ret;
	int i;

	for (i = 0; i <= U8_MAX; i++) {
		ret = snprintf(scoutfs_unknown_u8_strings[i], U8_STR_MAX,
			       "u%u", i);
		if (WARN_ONCE(ret <= 0 || ret >= U8_STR_MAX,
			      "snprintf("__stringify(U8_STR_MAX)") ret %d\n",
			      ret))
			return -EINVAL;
	}

	return 0;
}
