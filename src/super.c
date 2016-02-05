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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/magic.h>

#include "super.h"
#include "format.h"
#include "mkfs.h"
#include "inode.h"
#include "dir.h"
#include "lsm.h"

static const struct super_operations scoutfs_super_ops = {
	.alloc_inode = scoutfs_alloc_inode,
	.destroy_inode = scoutfs_destroy_inode,
	.sync_fs = scoutfs_sync_fs,
};

static int scoutfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct scoutfs_sb_info *sbi;
	struct inode *inode;
	int ret;

	sb->s_magic = SCOUTFS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &scoutfs_super_ops;

	sbi = kzalloc(sizeof(struct scoutfs_sb_info), GFP_KERNEL);
	sb->s_fs_info = sbi;
	if (!sbi)
		return -ENOMEM;

	spin_lock_init(&sbi->item_lock);
	sbi->item_root = RB_ROOT;
	sbi->dirty_item_root = RB_ROOT;

	ret = scoutfs_mkfs(sb);
	if (ret)
		return ret;

	inode = scoutfs_iget(sb, SCOUTFS_ROOT_INO);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

static struct dentry *scoutfs_mount(struct file_system_type *fs_type, int flags,
				    const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, scoutfs_fill_super);
}

static void scoutfs_kill_sb(struct super_block *sb)
{
	kill_block_super(sb);
	kfree(sb->s_fs_info);
}

static struct file_system_type scoutfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "scoutfs",
	.mount		= scoutfs_mount,
	.kill_sb	= scoutfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init scoutfs_module_init(void)
{
	return scoutfs_inode_init() ?:
	       scoutfs_dir_init() ?:
	       register_filesystem(&scoutfs_fs_type);
}
module_init(scoutfs_module_init)

static void __exit scoutfs_module_exit(void)
{
	unregister_filesystem(&scoutfs_fs_type);
	scoutfs_dir_exit();
	scoutfs_inode_exit();
}
module_exit(scoutfs_module_exit)

MODULE_AUTHOR("Zach Brown <zab@versity.com>");
MODULE_LICENSE("GPL");
