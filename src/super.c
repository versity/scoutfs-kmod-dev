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
#include <linux/percpu.h>

#include "super.h"
#include "block.h"
#include "export.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "msg.h"
#include "counters.h"
#include "triggers.h"
#include "trans.h"
#include "item.h"
#include "manifest.h"
#include "seg.h"
#include "bio.h"
#include "compact.h"
#include "data.h"
#include "lock.h"
#include "net.h"
#include "client.h"
#include "server.h"
#include "options.h"
#include "sysfs.h"
#include "quorum.h"
#include "scoutfs_trace.h"

static struct dentry *scoutfs_debugfs_root;

static DEFINE_PER_CPU(u64, clock_sync_ids) = 0;

/*
 * Give the caller a unique clock sync id for a message they're about to
 * send.  We make the ids reasonably globally unique by using randomly
 * initialized per-cpu 64bit counters.
 */
__le64 scoutfs_clock_sync_id(void)
{
	u64 rnd = 0;
	u64 ret;
	u64 *id;

retry:
	preempt_disable();
	id = this_cpu_ptr(&clock_sync_ids);
	if (*id == 0) {
		if (rnd == 0) {
			preempt_enable();
			get_random_bytes(&rnd, sizeof(rnd));
			goto retry;
		}
		*id = rnd;
	}

	ret = ++(*id);
	preempt_enable();

	return cpu_to_le64(ret);
}

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
	__le32 uuid[4];
	int ret;

	ret = scoutfs_client_statfs(sb, &nstatfs);
	if (ret)
		return ret;

	kst->f_bfree = le64_to_cpu(nstatfs.bfree);
	kst->f_type = SCOUTFS_SUPER_MAGIC;
	kst->f_bsize = SCOUTFS_BLOCK_SIZE;
	kst->f_blocks = le64_to_cpu(nstatfs.total_blocks);
	kst->f_bavail = kst->f_bfree;

	kst->f_ffree = kst->f_bfree * 16;
	kst->f_files = kst->f_ffree + le64_to_cpu(nstatfs.next_ino);

	BUILD_BUG_ON(sizeof(uuid) != sizeof(nstatfs.uuid));
	memcpy(uuid, &nstatfs, sizeof(uuid));
	kst->f_fsid.val[0] = le32_to_cpu(uuid[0]) ^ le32_to_cpu(uuid[1]);
	kst->f_fsid.val[1] = le32_to_cpu(uuid[2]) ^ le32_to_cpu(uuid[3]);
	kst->f_namelen = SCOUTFS_NAME_LEN;
	kst->f_frsize = SCOUTFS_BLOCK_SIZE;
	/* the vfs fills f_flags */

	/*
	 * We don't take cluster locks in statfs which makes it a very
	 * convenient place to trigger lock reclaim for debugging. We
	 * try to free as many locks as possible.
	 */
	if (scoutfs_trigger(sb, STATFS_LOCK_PURGE))
		scoutfs_free_unused_locks(sb, -1UL);

	return 0;
}

static int scoutfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct mount_options *opts = &SCOUTFS_SB(sb)->opts;

	seq_printf(seq, ",uniq_name=%s", opts->uniq_name);

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

	sbi->shutdown = true;

	scoutfs_data_destroy(sb);

	scoutfs_unlock(sb, sbi->node_id_lock, SCOUTFS_LOCK_WRITE);
	sbi->node_id_lock = NULL;

	scoutfs_shutdown_trans(sb);
	scoutfs_client_destroy(sb);
	scoutfs_quorum_destroy(sb);
	scoutfs_inode_destroy(sb);

	/* the server locks the listen address and compacts */
	scoutfs_lock_shutdown(sb);
	scoutfs_server_destroy(sb);
	scoutfs_net_destroy(sb);
	scoutfs_seg_destroy(sb);
	scoutfs_lock_destroy(sb);

	scoutfs_item_destroy(sb);
	scoutfs_destroy_triggers(sb);
	scoutfs_options_destroy(sb);
	debugfs_remove(sbi->debug_root);
	scoutfs_destroy_counters(sb);
	scoutfs_destroy_sysfs(sb);
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
	.show_options = scoutfs_show_options,
	.put_super = scoutfs_put_super,
};

/*
 * The caller advances the sequence number in the super block header
 * every time it wants to dirty it and eventually write it to reference
 * dirty data that's been written.
 */
void scoutfs_advance_dirty_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

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
	super->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SUPER);
	super->hdr.crc = scoutfs_block_calc_crc(&super->hdr);

	ret = scoutfs_bio_write(sb, &page, le64_to_cpu(super->hdr.blkno), 1);
	WARN_ON_ONCE(ret);

	__free_page(page);

	return ret;
}

/*
 * Read the super block.  If it's valid store it in the caller's super
 * struct.
 */
int scoutfs_read_super(struct super_block *sb,
		       struct scoutfs_super_block *super_res)
{
	struct scoutfs_super_block *super;
	struct page *page;
	__le32 calc;
	int ret;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = scoutfs_bio_read(sb, &page, SCOUTFS_SUPER_BLKNO, 1);
	if (ret) {
		scoutfs_err(sb, "error reading super block: %d", ret);
		goto out;
	}

	super = scoutfs_page_block_address(&page, 0);

	if (super->hdr.magic != cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SUPER)) {
		scoutfs_err(sb, "super block has invalid magic value 0x%08x",
			    le32_to_cpu(super->hdr.magic));
		ret = -EINVAL;
		goto out;
	}

	calc = scoutfs_block_calc_crc(&super->hdr);
	if (calc != super->hdr.crc) {
		scoutfs_err(sb, "super block has invalid crc 0x%08x, calculated 0x%08x",
			    le32_to_cpu(super->hdr.crc), le32_to_cpu(calc));
		ret = -EINVAL;
	}

	if (le64_to_cpu(super->hdr.blkno) != SCOUTFS_SUPER_BLKNO) {
		scoutfs_err(sb, "super block has invalid block number %llu, data read from %llu",
		le64_to_cpu(super->hdr.blkno), SCOUTFS_SUPER_BLKNO);
		ret = -EINVAL;
		goto out;
	}


	if (super->format_hash != cpu_to_le64(SCOUTFS_FORMAT_HASH)) {
		scoutfs_err(sb, "super block has invalid format hash 0x%llx, expected 0x%llx",
			    le64_to_cpu(super->format_hash),
			    SCOUTFS_FORMAT_HASH);
		ret = -EINVAL;
		goto out;
	}

	*super_res = *super;
	ret = 0;
out:
	__free_page(page);
	return ret;
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
	sb->s_export_op = &scoutfs_export_ops;

	/* btree blocks use long lived bh->b_data refs */
	mapping_set_gfp_mask(sb->s_bdev->bd_inode->i_mapping, GFP_NOFS);

	sbi = kzalloc(sizeof(struct scoutfs_sb_info), GFP_KERNEL);
	sb->s_fs_info = sbi;
	sbi->sb = sb;
	if (!sbi)
		return -ENOMEM;

	spin_lock_init(&sbi->next_ino_lock);
	init_waitqueue_head(&sbi->trans_hold_wq);
	spin_lock_init(&sbi->data_wait_root.lock);
	sbi->data_wait_root.root = RB_ROOT;
	spin_lock_init(&sbi->trans_write_lock);
	INIT_DELAYED_WORK(&sbi->trans_write_work, scoutfs_trans_write_func);
	init_waitqueue_head(&sbi->trans_write_wq);

	ret = scoutfs_parse_options(sb, data, &opts);
	if (ret)
		goto out;

	sbi->opts = opts;

	ret = sb_set_blocksize(sb, SCOUTFS_BLOCK_SIZE);
	if (ret != SCOUTFS_BLOCK_SIZE) {
		scoutfs_err(sb, "failed to set blocksize, returned %d", ret);
		ret = -EIO;
		goto out;
	}

	ret = scoutfs_setup_sysfs(sb) ?:
	      scoutfs_setup_counters(sb) ?:
	      scoutfs_read_super(sb, &SCOUTFS_SB(sb)->super) ?:
	      scoutfs_debugfs_setup(sb) ?:
	      scoutfs_options_setup(sb) ?:
	      scoutfs_setup_triggers(sb) ?:
	      scoutfs_seg_setup(sb) ?:
	      scoutfs_item_setup(sb) ?:
	      scoutfs_inode_setup(sb) ?:
	      scoutfs_data_setup(sb) ?:
	      scoutfs_setup_trans(sb) ?:
	      scoutfs_lock_setup(sb) ?:
	      scoutfs_net_setup(sb) ?:
	      scoutfs_quorum_setup(sb) ?:
	      scoutfs_server_setup(sb) ?:
	      scoutfs_client_setup(sb) ?:
	      scoutfs_client_wait_node_id(sb) ?:
	      scoutfs_lock_node_id(sb, SCOUTFS_LOCK_WRITE, 0, sbi->node_id,
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
	scoutfs_sysfs_exit();
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

	ret = scoutfs_sysfs_init();
	if (ret)
		return ret;

	scoutfs_debugfs_root = debugfs_create_dir("scoutfs", NULL);
	if (!scoutfs_debugfs_root) {
		ret = -ENOMEM;
		goto out;
	}
	ret = scoutfs_inode_init() ?:
	      scoutfs_dir_init() ?:
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
