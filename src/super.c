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
#include <linux/buffer_head.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "msg.h"
#include "block.h"
#include "counters.h"
#include "trans.h"
#include "scoutfs_trace.h"

static struct kset *scoutfs_kset;

static const struct super_operations scoutfs_super_ops = {
	.alloc_inode = scoutfs_alloc_inode,
	.destroy_inode = scoutfs_destroy_inode,
	.sync_fs = scoutfs_sync_fs,
};

/*
 * The caller advances the block number and sequence number in the super
 * every time it wants to dirty it and eventually write it to reference
 * dirty data that's been written.
 */
void scoutfs_advance_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	le64_add_cpu(&super->hdr.blkno, 1);
	if (le64_to_cpu(super->hdr.blkno) == (SCOUTFS_SUPER_BLKNO +
					      SCOUTFS_SUPER_NR))
		super->hdr.blkno = cpu_to_le64(SCOUTFS_SUPER_BLKNO);

	le64_add_cpu(&super->hdr.seq, 1);
}

/*
 * The caller is responsible for setting the super header's blkno
 * and seq to something reasonable.
 */
int scoutfs_write_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	size_t sz = sizeof(struct scoutfs_super_block);
	u64 blkno = le64_to_cpu(sbi->super.hdr.blkno);
	struct scoutfs_block *bl;
	int ret;

	/* XXX prealloc? */
	bl = scoutfs_new_block(sb, blkno);
	if (WARN_ON_ONCE(IS_ERR(bl)))
		return PTR_ERR(bl);

	memcpy(bl->data, &sbi->super, sz);
	memset(bl->data + sz, 0, SCOUTFS_BLOCK_SIZE - sz);
	scoutfs_calc_hdr_crc(bl);
	ret = scoutfs_write_block(bl);

	scoutfs_put_block(bl);
	return ret;
}

static int read_supers(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	struct scoutfs_block *bl = NULL;
	int found = -1;
	int i;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		scoutfs_put_block(bl);
		bl = scoutfs_read_block(sb, SCOUTFS_SUPER_BLKNO + i);
		if (IS_ERR(bl)) {
			scoutfs_warn(sb, "couldn't read super block %u", i);
			continue;
		}

		super = bl->data;

		if (super->id != cpu_to_le64(SCOUTFS_SUPER_ID)) {
			scoutfs_warn(sb, "super block %u has invalid id %llx",
				     i, le64_to_cpu(super->id));
			continue;
		}

		if (found < 0 || (le64_to_cpu(super->hdr.seq) >
				le64_to_cpu(sbi->super.hdr.seq))) {
			memcpy(&sbi->super, super,
			       sizeof(struct scoutfs_super_block));
			found = i;
		}
	}

	scoutfs_put_block(bl);

	if (found < 0) {
		scoutfs_err(sb, "unable to read valid super block");
		return -EINVAL;
	}

	scoutfs_info(sb, "using super %u with seq %llu",
		     found, le64_to_cpu(sbi->super.hdr.seq));

	/*
	 * XXX These don't exist in the super yet.  They should soon.
	 */
	atomic64_set(&sbi->next_ino, SCOUTFS_ROOT_INO + 1);
	atomic64_set(&sbi->next_blkno, 6);

	return 0;
}

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
	sbi->sb = sb;
	if (!sbi)
		return -ENOMEM;

	spin_lock_init(&sbi->block_lock);
	INIT_RADIX_TREE(&sbi->block_radix, GFP_NOFS);
	init_waitqueue_head(&sbi->block_wq);
	atomic_set(&sbi->block_writes, 0);
	init_rwsem(&sbi->btree_rwsem);
	atomic_set(&sbi->trans_holds, 0);
	init_waitqueue_head(&sbi->trans_hold_wq);
	spin_lock_init(&sbi->trans_write_lock);
	INIT_WORK(&sbi->trans_write_work, scoutfs_trans_write_func);
	init_waitqueue_head(&sbi->trans_write_wq);

	/* XXX can have multiple mounts of a  device, need mount id */
	sbi->kset = kset_create_and_add(sb->s_id, NULL, &scoutfs_kset->kobj);
	if (!sbi->kset)
		return -ENOMEM;

	ret = scoutfs_setup_counters(sb) ?:
	      read_supers(sb) ?:
	      scoutfs_setup_trans(sb);
	if (ret)
		return ret;

	scoutfs_advance_dirty_super(sb);

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
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	kill_block_super(sb);
	if (sbi) {
		scoutfs_shutdown_trans(sb);
		scoutfs_destroy_counters(sb);
		if (sbi->kset)
			kset_unregister(sbi->kset);
		kfree(sbi);
	}
}

static struct file_system_type scoutfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "scoutfs",
	.mount		= scoutfs_mount,
	.kill_sb	= scoutfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};

/* safe to call at any failure point in _init */
static void teardown_module(void)
{
	scoutfs_dir_exit();
	scoutfs_inode_exit();
	if (scoutfs_kset)
		kset_unregister(scoutfs_kset);
}

static int __init scoutfs_module_init(void)
{
	int ret;

	scoutfs_init_counters();

	scoutfs_kset = kset_create_and_add("scoutfs", NULL, fs_kobj);
	if (!scoutfs_kset)
		return -ENOMEM;

	ret = scoutfs_inode_init() ?:
	      scoutfs_dir_init() ?:
	      register_filesystem(&scoutfs_fs_type);
	if (ret)
		teardown_module();
	return ret;
}
module_init(scoutfs_module_init)

static void __exit scoutfs_module_exit(void)
{
	unregister_filesystem(&scoutfs_fs_type);
	teardown_module();
}
module_exit(scoutfs_module_exit)

MODULE_AUTHOR("Zach Brown <zab@versity.com>");
MODULE_LICENSE("GPL");
