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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/xattr.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include "format.h"
#include "super.h"
#include "key.h"
#include "inode.h"
#include "dir.h"
#include "data.h"
#include "scoutfs_trace.h"
#include "xattr.h"
#include "trans.h"
#include "msg.h"
#include "kvec.h"
#include "item.h"

/*
 * XXX
 *  - worry about i_ino trunctation, not sure if we do anything
 *  - use inode item value lengths for forward/back compat
 */

static struct kmem_cache *scoutfs_inode_cachep;

static void scoutfs_inode_ctor(void *obj)
{
	struct scoutfs_inode_info *ci = obj;

	init_rwsem(&ci->xattr_rwsem);

	inode_init_once(&ci->inode);
}

struct inode *scoutfs_alloc_inode(struct super_block *sb)
{
	struct scoutfs_inode_info *ci;

	ci = kmem_cache_alloc(scoutfs_inode_cachep, GFP_NOFS);
	if (!ci)
		return NULL;

	return &ci->inode;
}

static void scoutfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	trace_printk("freeing inode %p\n", inode);
	kmem_cache_free(scoutfs_inode_cachep, SCOUTFS_I(inode));
}

void scoutfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, scoutfs_i_callback);
}

static const struct inode_operations scoutfs_file_iops = {
	.setxattr	= scoutfs_setxattr,
	.getxattr	= scoutfs_getxattr,
	.listxattr	= scoutfs_listxattr,
	.removexattr	= scoutfs_removexattr,
};

/*
 * Called once new inode allocation or inode reading has initialized
 * enough of the inode for us to set the ops based on the mode.
 */
static void set_inode_ops(struct inode *inode)
{
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &scoutfs_file_aops;
		inode->i_op = &scoutfs_file_iops;
		inode->i_fop = &scoutfs_file_fops;
		break;
	case S_IFDIR:
		inode->i_op = &scoutfs_dir_iops;
		inode->i_fop = &scoutfs_dir_fops;
		break;
	case S_IFLNK:
		inode->i_op = &scoutfs_symlink_iops;
		break;
	default:
//		inode->i_op = &scoutfs_special_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	}

	/* ephemeral data items avoid kmap for pointers to page contents */
	mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}

static void load_inode(struct inode *inode, struct scoutfs_inode *cinode)
{
	struct scoutfs_inode_info *ci = SCOUTFS_I(inode);

	i_size_write(inode, le64_to_cpu(cinode->size));
	set_nlink(inode, le32_to_cpu(cinode->nlink));
	i_uid_write(inode, le32_to_cpu(cinode->uid));
	i_gid_write(inode, le32_to_cpu(cinode->gid));
	inode->i_mode = le32_to_cpu(cinode->mode);
	inode->i_rdev = le32_to_cpu(cinode->rdev);
	inode->i_atime.tv_sec = le64_to_cpu(cinode->atime.sec);
	inode->i_atime.tv_nsec = le32_to_cpu(cinode->atime.nsec);
	inode->i_mtime.tv_sec = le64_to_cpu(cinode->mtime.sec);
	inode->i_mtime.tv_nsec = le32_to_cpu(cinode->mtime.nsec);
	inode->i_ctime.tv_sec = le64_to_cpu(cinode->ctime.sec);
	inode->i_ctime.tv_nsec = le32_to_cpu(cinode->ctime.nsec);

	ci->data_version = le64_to_cpu(cinode->data_version);
	ci->next_readdir_pos = le64_to_cpu(cinode->next_readdir_pos);
}

void scoutfs_inode_init_key(struct scoutfs_key_buf *key,
			    struct scoutfs_inode_key *ikey, u64 ino)
{
	ikey->type = SCOUTFS_INODE_KEY;
	ikey->ino = cpu_to_be64(ino);

	scoutfs_key_init(key, ikey, sizeof(struct scoutfs_inode_key));
}

static int scoutfs_read_locked_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf key;
	struct scoutfs_inode sinode;
	SCOUTFS_DECLARE_KVEC(val);
	int ret;

	scoutfs_inode_init_key(&key, &ikey, scoutfs_ino(inode));
	scoutfs_kvec_init(val, &sinode, sizeof(sinode));

	ret = scoutfs_item_lookup_exact(sb, &key, val, sizeof(sinode));
	if (ret == 0)
		load_inode(inode, &sinode);

	return ret;
}

void scoutfs_inode_inc_data_version(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	if (!si->staging) {
		preempt_disable();
		write_seqcount_begin(&si->seqcount);
		si->data_version++;
		write_seqcount_end(&si->seqcount);
		preempt_enable();
	}
}

u64 scoutfs_inode_get_data_version(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	unsigned int seq;
	u64 vers;

	do {
		seq = read_seqcount_begin(&si->seqcount);
		vers = si->data_version;
	} while (read_seqcount_retry(&si->seqcount, seq));

	return vers;
}

static int scoutfs_iget_test(struct inode *inode, void *arg)
{
	struct scoutfs_inode_info *ci = SCOUTFS_I(inode);
	u64 *ino = arg;

	return ci->ino == *ino;
}

static int scoutfs_iget_set(struct inode *inode, void *arg)
{
	struct scoutfs_inode_info *ci = SCOUTFS_I(inode);
	u64 *ino = arg;

	inode->i_ino = *ino;
	ci->ino = *ino;

	return 0;
}

struct inode *scoutfs_iget(struct super_block *sb, u64 ino)
{
	struct inode *inode;
	int ret;

	inode = iget5_locked(sb, ino, scoutfs_iget_test, scoutfs_iget_set,
			     &ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		ret = scoutfs_read_locked_inode(inode);
		if (ret) {
			iget_failed(inode);
			inode = ERR_PTR(ret);
		} else {
			set_inode_ops(inode);
			unlock_new_inode(inode);
		}
	}

	return inode;
}

static void store_inode(struct scoutfs_inode *cinode, struct inode *inode)
{
	struct scoutfs_inode_info *ci = SCOUTFS_I(inode);

	cinode->size = cpu_to_le64(i_size_read(inode));
	cinode->nlink = cpu_to_le32(inode->i_nlink);
	cinode->uid = cpu_to_le32(i_uid_read(inode));
	cinode->gid = cpu_to_le32(i_gid_read(inode));
	cinode->mode = cpu_to_le32(inode->i_mode);
	cinode->rdev = cpu_to_le32(inode->i_rdev);
	cinode->atime.sec = cpu_to_le64(inode->i_atime.tv_sec);
	cinode->atime.nsec = cpu_to_le32(inode->i_atime.tv_nsec);
	cinode->ctime.sec = cpu_to_le64(inode->i_ctime.tv_sec);
	cinode->ctime.nsec = cpu_to_le32(inode->i_ctime.tv_nsec);
	cinode->mtime.sec = cpu_to_le64(inode->i_mtime.tv_sec);
	cinode->mtime.nsec = cpu_to_le32(inode->i_mtime.tv_nsec);

	cinode->data_version = cpu_to_le64(ci->data_version);
	cinode->next_readdir_pos = cpu_to_le64(ci->next_readdir_pos);
}

/*
 * Create a pinned dirty inode item so that we can later update the
 * inode item without risking failure.  We often wouldn't want to have
 * to unwind inode modifcations (perhaps by shared vfs code!) if our
 * item update failed.  This is our chance to return errors for enospc
 * for lack of space for new logged dirty inode items.
 *
 * This dirty inode item will be found by lookups in the interim so we
 * have to update it now with the current inode contents.
 *
 * Callers don't delete these dirty items on errors.  They're still
 * valid and will be merged with the current item eventually.  They can
 * be found in the dirty block to avoid future dirtying (say repeated
 * creations in a directory).
 *
 * The caller has to prevent sync between dirtying and updating the
 * inodes.
 *
 * XXX this will have to do something about variable length inodes
 */
int scoutfs_dirty_inode_item(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf key;
	struct scoutfs_inode sinode;
	int ret;

	store_inode(&sinode, inode);

	scoutfs_inode_init_key(&key, &ikey, scoutfs_ino(inode));

	ret = scoutfs_item_dirty(sb, &key);
	if (!ret)
		trace_scoutfs_dirty_inode(inode);
	return ret;
}

/*
 * Every time we modify the inode in memory we copy it to its inode
 * item.  This lets us write out items without having to track down
 * dirty vfs inodes.
 *
 * The caller makes sure that the item is dirty and pinned so they don't
 * have to deal with errors and unwinding after they've modified the
 * vfs inode and get here.
 */
void scoutfs_update_inode_item(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf key;
	struct scoutfs_inode sinode;
	SCOUTFS_DECLARE_KVEC(val);
	int err;

	store_inode(&sinode, inode);

	scoutfs_inode_init_key(&key, &ikey, scoutfs_ino(inode));
	scoutfs_kvec_init(val, &sinode, sizeof(sinode));

	err = scoutfs_item_update(sb, &key, val);
	BUG_ON(err);

	trace_scoutfs_update_inode(inode);
}

/*
 * sop->dirty_inode() can't return failure.  Our use of it has to be
 * careful to pin the inode during a transaction.  The generic write
 * paths pin the inode in write_begin and get called to update the inode
 * in write_end.
 *
 * The caller should have a trans but it's cheap for us to grab it
 * ourselves to make sure.
 *
 * This will holler at us if a caller didn't pin the inode and we
 * couldn't dirty the inode ourselves.
 */
void scoutfs_dirty_inode(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	int ret;

	ret = scoutfs_hold_trans(sb);
	if (ret == 0) {
		ret = scoutfs_dirty_inode_item(inode);
		if (ret == 0)
			scoutfs_update_inode_item(inode);
		scoutfs_release_trans(sb);
	}

	WARN_ON_ONCE(ret);
}

/*
 * A quick atomic sample of the last inode number that's been allocated.
 */
u64 scoutfs_last_ino(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	u64 last;

	spin_lock(&sbi->next_ino_lock);
	last = le64_to_cpu(super->next_ino);
	spin_unlock(&sbi->next_ino_lock);

	return last;
}

static int alloc_ino(struct super_block *sb, u64 *ino)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	int ret;

	spin_lock(&sbi->next_ino_lock);

	if (super->next_ino == 0) {
		ret = -ENOSPC;
	} else {
		*ino = le64_to_cpu(super->next_ino);
		le64_add_cpu(&super->next_ino, 1);
		ret = 0;
	}

	spin_unlock(&sbi->next_ino_lock);

	return ret;
}

/*
 * Allocate and initialize a new inode.  The caller is responsible for
 * creating links to it and updating it.  @dir can be null.
 */
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev)
{
	struct scoutfs_inode_info *ci;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf key;
	struct scoutfs_inode sinode;
	SCOUTFS_DECLARE_KVEC(val);
	struct inode *inode;
	u64 ino;
	int ret;

	ret = alloc_ino(sb, &ino);
	if (ret)
		return ERR_PTR(ret);

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	ci = SCOUTFS_I(inode);
	ci->ino = ino;
	seqcount_init(&ci->seqcount);
	ci->data_version = 0;
	ci->next_readdir_pos = SCOUTFS_DIRENT_FIRST_POS;
	ci->staging = false;

	inode->i_ino = ino; /* XXX overflow */
	inode_init_owner(inode, dir, mode);
	inode_set_bytes(inode, 0);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_rdev = rdev;
	set_inode_ops(inode);

	store_inode(&sinode, inode);
	scoutfs_inode_init_key(&key, &ikey, scoutfs_ino(inode));
	scoutfs_kvec_init(val, &sinode, sizeof(sinode));

	ret = scoutfs_item_create(sb, &key, val);
	if (ret) {
		iput(inode);
		return ERR_PTR(ret);
	}

	return inode;
}

static void init_orphan_key(struct scoutfs_key_buf *key,
			    struct scoutfs_orphan_key *okey, u64 ino)
{
	okey->type = SCOUTFS_ORPHAN_KEY;
	okey->ino = cpu_to_be64(ino);

	scoutfs_key_init(key, okey, sizeof(struct scoutfs_orphan_key));
}

static int remove_orphan_item(struct super_block *sb, u64 ino)
{
	struct scoutfs_orphan_key okey;
	struct scoutfs_key_buf key;
	int ret;

	init_orphan_key(&key, &okey, ino);

	ret = scoutfs_item_delete(sb, &key);
	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

static int __delete_inode(struct super_block *sb, struct scoutfs_key_buf *key,
			  u64 ino, umode_t mode)
{
	bool release = false;
	int ret;

	trace_delete_inode(sb, ino, mode);

	ret = scoutfs_hold_trans(sb);
	if (ret)
		goto out;
	release = true;

#if 0
	ret = scoutfs_xattr_drop(sb, ino);
	if (ret)
		goto out;

	if (S_ISLNK(mode))
		ret = scoutfs_symlink_drop(sb, ino);
	else if (S_ISREG(mode))
		ret = scoutfs_truncate_extent_items(sb, ino, 0, ~0ULL, false);
	if (ret)
		goto out;

#endif
	ret = scoutfs_item_delete(sb, key);
	if (ret)
		goto out;

	ret = remove_orphan_item(sb, ino);
out:
	if (release)
		scoutfs_release_trans(sb);
	return ret;
}

/*
 * Remove all the items associated with a given inode.
 */
static void delete_inode(struct super_block *sb, u64 ino)
{
	struct scoutfs_inode sinode;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	umode_t mode;
	int ret;

	/* sample the inode mode, XXX don't need to copy whole thing here */
	scoutfs_inode_init_key(&key, &ikey, ino);
	scoutfs_kvec_init(val, &sinode, sizeof(sinode));

	ret = scoutfs_item_lookup_exact(sb, &key, val, sizeof(sinode));
	if (ret < 0)
		goto out;

	mode = le32_to_cpu(sinode.mode);

	ret = __delete_inode(sb, &key, ino, mode);
out:
	if (ret)
		trace_printk("drop items failed ret %d ino %llu\n", ret, ino);
}

/*
 * iput_final has already written out the dirty pages to the inode
 * before we get here.  We're left with a clean inode that we have to
 * tear down.  If there are no more links to the inode then we also
 * remove all its persistent structures.
 */
void scoutfs_evict_inode(struct inode *inode)
{
	trace_printk("ino %llu nlink %d bad %d\n",
		     scoutfs_ino(inode), inode->i_nlink, is_bad_inode(inode));

	if (is_bad_inode(inode))
		goto clear;

	truncate_inode_pages_final(&inode->i_data);

	if (inode->i_nlink == 0)
		delete_inode(inode->i_sb, scoutfs_ino(inode));
clear:
	clear_inode(inode);
}

int scoutfs_drop_inode(struct inode *inode)
{
	int ret = generic_drop_inode(inode);

	trace_printk("ret %d nlink %d unhashed %d\n",
		     ret, inode->i_nlink, inode_unhashed(inode));
	return ret;
}

static int process_orphaned_inode(struct super_block *sb, u64 ino)
{
	struct scoutfs_inode_key ikey;
	struct scoutfs_inode sinode;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	int ret;

	scoutfs_inode_init_key(&key, &ikey, ino);
	scoutfs_kvec_init(val, &sinode, sizeof(sinode));

	ret = scoutfs_item_lookup_exact(sb, &key, val, sizeof(sinode));
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		return ret;
	}

	if (le32_to_cpu(sinode.nlink) == 0)
		__delete_inode(sb, &key, ino, le32_to_cpu(sinode.mode));
	else
		scoutfs_warn(sb, "Dangling orphan item for inode %llu.", ino);

	return ret;
}

/*
 * Find orphan items and process each one.
 *
 * Runtime of this will be bounded by the number of orphans, which could
 * theoretically be very large. If that becomes a problem we might want to push
 * this work off to a thread.
 */
int scoutfs_scan_orphans(struct super_block *sb)
{
	struct scoutfs_orphan_key okey;
	struct scoutfs_orphan_key last_okey;
	struct scoutfs_key_buf key;
	struct scoutfs_key_buf last;
	int err = 0;
	int ret;

	trace_scoutfs_scan_orphans(sb);

	init_orphan_key(&key, &okey, 0);
	init_orphan_key(&last, &last_okey, ~0ULL);

	while (1) {
		ret = scoutfs_item_next_same(sb, &key, &last, NULL);
		if (ret == -ENOENT) /* No more orphan items */
			break;
		if (ret < 0)
			goto out;

		ret = process_orphaned_inode(sb, be64_to_cpu(okey.ino));
		if (ret && ret != -ENOENT && !err)
			err = ret;

		scoutfs_key_inc_cur_len(&key);
	}

	ret = 0;
out:
	return err ? err : ret;
}

int scoutfs_orphan_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_orphan_key okey;
	struct scoutfs_key_buf key;
	int ret;

	trace_scoutfs_orphan_inode(sb, inode);

	init_orphan_key(&key, &okey, scoutfs_ino(inode));

	ret = scoutfs_item_create(sb, &key, NULL);

	return ret;
}

void scoutfs_inode_exit(void)
{
	if (scoutfs_inode_cachep) {
		rcu_barrier();
		kmem_cache_destroy(scoutfs_inode_cachep);
		scoutfs_inode_cachep = NULL;
	}
}

int scoutfs_inode_init(void)
{
	scoutfs_inode_cachep = kmem_cache_create("scoutfs_inode_info",
					sizeof(struct scoutfs_inode_info), 0,
					SLAB_RECLAIM_ACCOUNT,
					scoutfs_inode_ctor);
	if (!scoutfs_inode_cachep)
		return -ENOMEM;

	return 0;
}
