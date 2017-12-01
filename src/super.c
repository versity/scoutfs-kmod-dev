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
#include <linux/pagemap.h>
#include <linux/magic.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/sched.h>
#include <linux/debugfs.h>

#include "super.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "xattr.h"
#include "msg.h"
#include "counters.h"
#include "trans.h"
#include "item.h"
#include "manifest.h"
#include "seg.h"
#include "bio.h"
#include "alloc.h"
#include "compact.h"
#include "data.h"
#include "lock.h"
#include "client.h"
#include "server.h"
#include "options.h"
#include "scoutfs_trace.h"

static struct kset *scoutfs_kset;
static struct dentry *scoutfs_debugfs_root;

/*
 * Ask the server for the current statfs fields.  The message is very
 * cheap so we're not worrying about spinning in statfs flooding the
 * server with requests.  We can add a cache and stale results if that
 * becomes a problem.
 *
 * We fake the number of free inodes value by assuming that we can fill
 * free blocks with a certain number of inodes.  We then the number of
 * current inodes to that free count to determine the total possible
 * inodes.
 *
 * The fsid that we report is constructed from the xor of the first two
 * and second two little endian u32s that make up the uuid bytes.
 */
static int scoutfs_statfs(struct dentry *dentry, struct kstatfs *kst)
{
	struct super_block *sb = dentry->d_inode->i_sb;
	struct scoutfs_net_statfs nstatfs;
	__le32 * __packed uuid;
	int ret;

	ret = scoutfs_client_statfs(sb, &nstatfs);
	if (ret)
		return ret;

	kst->f_bfree = le64_to_cpu(nstatfs.bfree);
	kst->f_type = SCOUTFS_SUPER_MAGIC;
	kst->f_bsize = SCOUTFS_BLOCK_SIZE;
	kst->f_blocks = le64_to_cpu(nstatfs.total_segs) *
			SCOUTFS_SEGMENT_BLOCKS;
	kst->f_bavail = kst->f_bfree;

	kst->f_ffree = kst->f_bfree * 16;
	kst->f_files = kst->f_ffree + le64_to_cpu(nstatfs.next_ino);

	uuid = (void *)nstatfs.uuid;
	kst->f_fsid.val[0] = le32_to_cpu(uuid[0]) ^ le32_to_cpu(uuid[1]);
	kst->f_fsid.val[1] = le32_to_cpu(uuid[2]) ^ le32_to_cpu(uuid[3]);
	kst->f_namelen = SCOUTFS_NAME_LEN;
	kst->f_frsize = SCOUTFS_BLOCK_SIZE;
	/* the vfs fills f_flags */

	return 0;
}

static int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	trace_scoutfs_sync_fs(sb, wait);
	scoutfs_inc_counter(sb, trans_commit_sync_fs);

	return scoutfs_trans_sync(sb, wait);
}

/*
 * This destroys all the state that's built up in the sb info during
 * mount.  It's called by us on errors during mount if we haven't set
 * s_root, by mount after returning errors if we have set s_root, and by
 * unmount after having synced the super.
 */
static void scoutfs_put_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	trace_scoutfs_put_super(sb);

	scoutfs_unlock_flags(sb, sbi->node_id_lock, DLM_LOCK_EX,
			     SCOUTFS_LKF_NO_TASK_REF);
	sbi->node_id_lock = NULL;

	scoutfs_shutdown_trans(sb);
	scoutfs_client_destroy(sb);
	scoutfs_data_destroy(sb);
	scoutfs_inode_destroy(sb);
	scoutfs_item_destroy(sb);

	/* the server locks the listen address and compacts */
	scoutfs_server_destroy(sb);
	scoutfs_seg_destroy(sb);
	scoutfs_lock_destroy(sb);

	debugfs_remove(sbi->debug_root);
	scoutfs_destroy_counters(sb);
	if (sbi->kset)
		kset_unregister(sbi->kset);
	kfree(sbi);

	sb->s_fs_info = NULL;
}

static const struct super_operations scoutfs_super_ops = {
	.alloc_inode = scoutfs_alloc_inode,
	.drop_inode = scoutfs_drop_inode,
	.evict_inode = scoutfs_evict_inode,
	.destroy_inode = scoutfs_destroy_inode,
	.sync_fs = scoutfs_sync_fs,
	.statfs = scoutfs_statfs,
	.put_super = scoutfs_put_super,
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

	trace_scoutfs_advance_dirty_super(sb, le64_to_cpu(super->hdr.seq));
}

/*
 * The caller is responsible for setting the super header's blkno
 * and seq to something reasonable.
 *
 * XXX it'd be pretty easy to preallocate to avoid failure here.
 */
int scoutfs_write_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	struct page *page;
	int ret;

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	super = page_address(page);
	memcpy(super, &sbi->super, sizeof(*super));

	ret = scoutfs_bio_write(sb, &page, le64_to_cpu(super->hdr.blkno), 1);
	WARN_ON_ONCE(ret);

	__free_page(page);

	return ret;
}

/*
 * Read the pair of super blocks and store the most recent one in the sb
 * info.  Clients reference but don't modify the super.  The server has
 * to re-read the super every time it comes up so that it can work from
 * the most recent persistent state.
 */
int scoutfs_read_supers(struct super_block *sb,
			struct scoutfs_super_block *local)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	struct page *page;
	int found = -1;
	int ret;
	int i;
	u64 seq = 0;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {

		ret = scoutfs_bio_read(sb, &page, SCOUTFS_SUPER_BLKNO + i, 1);
		if (ret) {
			scoutfs_warn(sb, "couldn't read super block %u", i);
			continue;
		}

		super = scoutfs_page_block_address(&page, 0);

		if (super->id != cpu_to_le64(SCOUTFS_SUPER_ID)) {
			scoutfs_warn(sb, "super block %u has invalid id %llx",
				     i, le64_to_cpu(super->id));
			continue;
		}

		if (super->format_hash != cpu_to_le64(SCOUTFS_FORMAT_HASH)) {
			scoutfs_warn(sb, "super block %u has invalid format hash 0x%llx, expected 0x%llx",
				     i, le64_to_cpu(super->format_hash),
				     SCOUTFS_FORMAT_HASH);
			continue;
		}

		if (found < 0 || (le64_to_cpu(super->hdr.seq) > seq)) {
			*local = *super;
			seq = le64_to_cpu((*local).hdr.seq);
			found = i;
		}
	}

	__free_page(page);

	if (found < 0) {
		scoutfs_err(sb, "unable to read valid super block");
		return -EINVAL;
	}

	scoutfs_info(sb, "using super %u with seq %llu",
		     found, le64_to_cpu(sbi->super.hdr.seq));

	return 0;
}

static int scoutfs_debugfs_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	char name[32];

	/*
	 * XXX: Move the name variable to sbi and use it in
	 * init_lock_info as well.
	 */
	snprintf(name, 32, "%llx", le64_to_cpu(sbi->super.hdr.fsid));

	sbi->debug_root = debugfs_create_dir(name, scoutfs_debugfs_root);
	if (!sbi->debug_root)
		return -ENOMEM;

	return 0;
}

static int scoutfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct scoutfs_sb_info *sbi;
	struct mount_options opts;
	struct inode *inode;
	int ret;

	trace_scoutfs_fill_super(sb);

	sb->s_magic = SCOUTFS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &scoutfs_super_ops;

	/* btree blocks use long lived bh->b_data refs */
	mapping_set_gfp_mask(sb->s_bdev->bd_inode->i_mapping, GFP_NOFS);

	sbi = kzalloc(sizeof(struct scoutfs_sb_info), GFP_KERNEL);
	sb->s_fs_info = sbi;
	sbi->sb = sb;
	if (!sbi)
		return -ENOMEM;

	/*
	 * XXX this is random today for initial testing, but we'll want
	 * it to be assigned by the server.
	 */
	get_random_bytes_arch(&sbi->node_id, sizeof(sbi->node_id));

	spin_lock_init(&sbi->next_ino_lock);
	init_waitqueue_head(&sbi->trans_hold_wq);
	spin_lock_init(&sbi->trans_write_lock);
	INIT_DELAYED_WORK(&sbi->trans_write_work, scoutfs_trans_write_func);
	init_waitqueue_head(&sbi->trans_write_wq);

	/* XXX can have multiple mounts of a  device, need mount id */
	sbi->kset = kset_create_and_add(sb->s_id, NULL, &scoutfs_kset->kobj);
	if (!sbi->kset) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_parse_options(sb, data, &opts);
	if (ret)
		goto out;

	sbi->opts = opts;

	ret = scoutfs_setup_counters(sb) ?:
	      scoutfs_read_supers(sb, &SCOUTFS_SB(sb)->super) ?:
	      scoutfs_debugfs_setup(sb) ?:
	      scoutfs_seg_setup(sb) ?:
	      scoutfs_item_setup(sb) ?:
	      scoutfs_inode_setup(sb) ?:
	      scoutfs_data_setup(sb) ?:
	      scoutfs_setup_trans(sb) ?:
	      scoutfs_lock_setup(sb) ?:
	      scoutfs_server_setup(sb) ?:
	      scoutfs_client_setup(sb) ?:
	      scoutfs_lock_node_id(sb, DLM_LOCK_EX, 0, sbi->node_id,
				   &sbi->node_id_lock);
	if (ret)
		goto out;

	inode = scoutfs_iget(sb, SCOUTFS_ROOT_INO);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_client_advance_seq(sb, &sbi->trans_seq);
	if (ret)
		goto out;

	scoutfs_trans_restart_sync_deadline(sb);
//	scoutfs_scan_orphans(sb);
	ret = 0;
out:
	/* on error, generic_shutdown_super calls put_super if s_root */
	if (ret && !sb->s_root)
		scoutfs_put_super(sb);

	return ret;
}

static struct dentry *scoutfs_mount(struct file_system_type *fs_type, int flags,
				    const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, scoutfs_fill_super);
}

/*
 * kill_block_super eventually calls ->put_super if s_root is set
 */
static void scoutfs_kill_sb(struct super_block *sb)
{
	trace_scoutfs_kill_sb(sb);

	kill_block_super(sb);
}

static struct file_system_type scoutfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "scoutfs",
	.mount		= scoutfs_mount,
	.kill_sb	= scoutfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("scoutfs");

/* safe to call at any failure point in _init */
static void teardown_module(void)
{
	debugfs_remove(scoutfs_debugfs_root);
	scoutfs_dir_exit();
	scoutfs_inode_exit();
	if (scoutfs_kset)
		kset_unregister(scoutfs_kset);
}

static int __init scoutfs_module_init(void)
{
	int ret;

	/*
	 * gcc only recently learned to let __attribute__(section) add
	 * SHT_NOTE notes.  But the assembler always could.
	 */
	__asm__ __volatile__ (
		".section	.note.git_describe,\"a\"\n"
		".string	\""SCOUTFS_GIT_DESCRIBE"\\n\"\n"
		".previous\n");

	scoutfs_init_counters();

	ret = scoutfs_data_test();
	if (ret)
		return ret;

	scoutfs_kset = kset_create_and_add("scoutfs", NULL, fs_kobj);
	if (!scoutfs_kset)
		return -ENOMEM;

	scoutfs_debugfs_root = debugfs_create_dir("scoutfs", NULL);
	if (!scoutfs_debugfs_root) {
		ret = -ENOMEM;
		goto out;
	}
	ret = scoutfs_inode_init() ?:
	      scoutfs_dir_init() ?:
	      scoutfs_xattr_init() ?:
	      register_filesystem(&scoutfs_fs_type);
out:
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
MODULE_INFO(git_describe, SCOUTFS_GIT_DESCRIBE);
