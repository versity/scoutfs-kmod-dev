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
#include "manifest.h"
#include "ring.h"
#include "segment.h"
#include "scoutfs_trace.h"

/*
 * We've been dirtying log segment blocks and ring blocks as items were
 * modified.  sync makes sure that they're all persistent and updates
 * the super.
 *
 * XXX need to synchronize with transactions
 * XXX is state clean after errors?
 */
static int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;

	return scoutfs_finish_dirty_segment(sb) ?:
	       scoutfs_finish_dirty_ring(sb) ?:
	       filemap_write_and_wait(mapping) ?:
	       scoutfs_write_dirty_super(sb) ?:
	       scoutfs_advance_dirty_super(sb);
}

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
int scoutfs_advance_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	u64 blkno;

	blkno = le64_to_cpu(super->hdr.blkno) - SCOUTFS_SUPER_BLKNO;
	if (++blkno == SCOUTFS_SUPER_NR)
		blkno = 0;
	super->hdr.blkno = cpu_to_le64(SCOUTFS_SUPER_BLKNO + blkno);

	le64_add_cpu(&super->hdr.seq, 1);

	trace_scoutfs_dirty_super(super);

	return 0;
}

/*
 * We've been modifying the super copy in the info as we made changes.
 * Write the super to finalize.
 */
int scoutfs_write_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buffer_head *bh;
	size_t sz;
	int ret;

	bh = scoutfs_new_block(sb, le64_to_cpu(super->hdr.blkno));
	if (!bh)
		return -ENOMEM;

	sz = sizeof(struct scoutfs_super_block);
	memcpy(bh->b_data, super, sz);
	memset(bh->b_data + sz, 0, SCOUTFS_BLOCK_SIZE - sz);

	scoutfs_calc_hdr_crc(bh);
	mark_buffer_dirty(bh);
	trace_scoutfs_write_super(super);
	ret = sync_dirty_buffer(bh);
	brelse(bh);

	return ret;
}

static int read_supers(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	struct buffer_head *bh = NULL;
	unsigned long bytes;
	int found = -1;
	int i;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		if (bh)
			brelse(bh);
		bh = scoutfs_read_block(sb, SCOUTFS_SUPER_BLKNO + i);
		if (!bh) {
			scoutfs_warn(sb, "couldn't read super block %u", i);
			continue;
		}

		super = (void *)bh->b_data;

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

	if (bh)
		brelse(bh);

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
	atomic64_set(&sbi->next_blkno, 2);

	/* Initialize all the sb info fields which depends on the supers. */

	bytes = DIV_ROUND_UP(le64_to_cpu(sbi->super.total_chunks), 64) *
			     sizeof(u64);
	sbi->chunk_alloc_bits = vmalloc(bytes);
	if (!sbi->chunk_alloc_bits)
		return -ENOMEM;

	/* the alloc bits default to all free then ring entries update them */
	memset(sbi->chunk_alloc_bits, 0xff, bytes);

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
	if (!sbi)
		return -ENOMEM;

	spin_lock_init(&sbi->item_lock);
	sbi->item_root = RB_ROOT;
	sbi->dirty_item_root = RB_ROOT;
	spin_lock_init(&sbi->chunk_alloc_lock);
	mutex_init(&sbi->dirty_mutex);

	if (!sb_set_blocksize(sb, SCOUTFS_BLOCK_SIZE)) {
		printk(KERN_ERR "couldn't set blocksize\n");
		return -EINVAL;
	}

	ret = read_supers(sb);
	if (ret)
		return ret;

	ret = scoutfs_setup_manifest(sb);
	if (ret)
		return ret;

	ret = scoutfs_replay_ring(sb);
	if (ret)
		return ret;

	inode = scoutfs_iget(sb, SCOUTFS_ROOT_INO);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	scoutfs_advance_dirty_super(sb);

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
		/* kill block super should have synced */
		WARN_ON_ONCE(sbi->dirty_blkno);
		scoutfs_destroy_manifest(sb);
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
