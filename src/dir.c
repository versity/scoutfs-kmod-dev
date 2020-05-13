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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/uio.h>
#include <linux/xattr.h>
#include <linux/namei.h>

#include "format.h"
#include "file.h"
#include "dir.h"
#include "inode.h"
#include "ioctl.h"
#include "key.h"
#include "msg.h"
#include "super.h"
#include "trans.h"
#include "xattr.h"
#include "kvec.h"
#include "forest.h"
#include "lock.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * Directory entries are stored in three different items.  Each has the
 * same key format and all have identical values which contain the full
 * entry name.
 *
 * Entries for name lookup are stored at the hash of the name and the
 * readdir position.  Including the position lets us create names
 * without having to read the items to check for hash collisions.
 * Lookup iterates over all the positions with the same hash values and
 * compares the names.
 *
 * Entries for readdir are stored in an increasing unique readdir
 * position.  This results in returning entries in creation order which
 * matches inode allocation order and avoids random inode access
 * patterns during readdir.
 *
 * Entries for link backref traversal are stored at the target inode
 * sorted by the parent dir and the entry's position in the parent dir.
 * This keeps link backref users away from the higher contention area of
 * dirent items in parent dirs.
 *
 * All the entries have a dirent struct with the full name in their
 * value.  The dirent struct contains the name hash and readdir position
 * so that any item use can reference all the items for a given entry.
 * This is important for deleting all the items given a dentry that was
 * populated by lookup.
 */

static unsigned int mode_to_type(umode_t mode)
{
#define S_SHIFT 12
	static unsigned char mode_types[S_IFMT >> S_SHIFT] = {
		[S_IFIFO >> S_SHIFT]	= SCOUTFS_DT_FIFO,
		[S_IFCHR >> S_SHIFT]	= SCOUTFS_DT_CHR,
		[S_IFDIR >> S_SHIFT]	= SCOUTFS_DT_DIR,
		[S_IFBLK >> S_SHIFT]	= SCOUTFS_DT_BLK,
		[S_IFREG >> S_SHIFT]	= SCOUTFS_DT_REG,
		[S_IFLNK >> S_SHIFT]	= SCOUTFS_DT_LNK,
		[S_IFSOCK >> S_SHIFT]	= SCOUTFS_DT_SOCK,
	};

	return mode_types[(mode & S_IFMT) >> S_SHIFT];
#undef S_SHIFT
}

static unsigned int dentry_type(unsigned int type)
{
	static unsigned char types[] = {
		[SCOUTFS_DT_FIFO]	= DT_FIFO,
		[SCOUTFS_DT_CHR]	= DT_CHR,
		[SCOUTFS_DT_DIR]	= DT_DIR,
		[SCOUTFS_DT_BLK]	= DT_BLK,
		[SCOUTFS_DT_REG]	= DT_REG,
		[SCOUTFS_DT_LNK]	= DT_LNK,
		[SCOUTFS_DT_SOCK]	= DT_SOCK,
		[SCOUTFS_DT_WHT]	= DT_WHT,
	};

	if (type < ARRAY_SIZE(types))
		return types[type];

	return DT_UNKNOWN;
}

/*
 * @lock_cov: tells revalidation that the dentry is still locked and valid.
 *
 * @pos, @hash: lets us remove items on final unlink without having to
 * look them up.
 */
struct dentry_info {
	struct scoutfs_lock_coverage lock_cov;
	u64 hash;
	u64 pos;
};

static struct kmem_cache *dentry_info_cache;

static void scoutfs_d_release(struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct dentry_info *di = dentry->d_fsdata;

	if (di) {
		scoutfs_lock_del_coverage(sb, &di->lock_cov);
		kmem_cache_free(dentry_info_cache, di);
		dentry->d_fsdata = NULL;
	}
}

static int scoutfs_d_revalidate(struct dentry *dentry, unsigned int flags);

static const struct dentry_operations scoutfs_dentry_ops = {
	.d_release = scoutfs_d_release,
	.d_revalidate = scoutfs_d_revalidate,
};

static int alloc_dentry_info(struct dentry *dentry)
{
	struct dentry_info *di;

	/* XXX read mb? */
	if (dentry->d_fsdata)
		return 0;

	di = kmem_cache_zalloc(dentry_info_cache, GFP_NOFS);
	if (!di)
		return -ENOMEM;

	scoutfs_lock_init_coverage(&di->lock_cov);

	spin_lock(&dentry->d_lock);
	if (!dentry->d_fsdata) {
		dentry->d_fsdata = di;
		d_set_d_op(dentry, &scoutfs_dentry_ops);
	}
	spin_unlock(&dentry->d_lock);

	if (di != dentry->d_fsdata)
		kmem_cache_free(dentry_info_cache, di);

	return 0;
}

static void update_dentry_info(struct super_block *sb, struct dentry *dentry,
			       u64 hash, u64 pos, struct scoutfs_lock *lock)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (WARN_ON_ONCE(di == NULL))
		return;

	scoutfs_lock_add_coverage(sb, lock, &di->lock_cov);
	di->hash = hash;
	di->pos = pos;
}

static u64 dentry_info_hash(struct dentry *dentry)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (WARN_ON_ONCE(di == NULL))
		return 0;

	return di->hash;
}

static u64 dentry_info_pos(struct dentry *dentry)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (WARN_ON_ONCE(di == NULL))
		return 0;

	return di->pos;
}

static void init_dirent_key(struct scoutfs_key *key, u8 type, u64 ino,
			    u64 major, u64 minor)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skd_ino = cpu_to_le64(ino),
		.sk_type = type,
		.skd_major = cpu_to_le64(major),
		.skd_minor = cpu_to_le64(minor),
	};
}

static unsigned int dirent_bytes(unsigned int name_len)
{
	return offsetof(struct scoutfs_dirent, name[name_len]);
}

static struct scoutfs_dirent *alloc_dirent(unsigned int name_len)
{
	return kmalloc(dirent_bytes(name_len), GFP_NOFS);
}

static u64 dirent_name_hash(const char *name, unsigned int name_len)
{
       unsigned int half = (name_len + 1) / 2;

       return crc32c(~0, name, half) |
              ((u64)crc32c(~0, name + name_len - half, half) << 32);
}

static u64 dirent_names_equal(const char *a_name, unsigned int a_len,
			      const char *b_name, unsigned int b_len)
{
	return a_len == b_len && memcmp(a_name, b_name, a_len) == 0;
}

/*
 * Looks for the dirent item and fills the caller's dirent if it finds
 * it.  Returns item lookup errors including -ENOENT if it's not found.
 */
static int lookup_dirent(struct super_block *sb, u64 dir_ino, const char *name,
			 unsigned name_len, u64 hash,
			 struct scoutfs_dirent *dent_ret,
			 struct scoutfs_lock *lock)
{
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	struct scoutfs_dirent *dent = NULL;
	struct kvec val;
	int ret;

	dent = alloc_dirent(SCOUTFS_NAME_LEN);
	if (!dent) {
		ret = -ENOMEM;
		goto out;
	}

	init_dirent_key(&key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, 0);
	init_dirent_key(&last_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, U64_MAX);
	kvec_init(&val, dent, dirent_bytes(SCOUTFS_NAME_LEN));

	for (;;) {
		ret = scoutfs_forest_next(sb, &key, &last_key, &val, lock);
		if (ret < 0)
			break;

		ret -= sizeof(struct scoutfs_dirent);
		if (ret < 1 || ret > SCOUTFS_NAME_LEN) {
			scoutfs_corruption(sb, SC_DIRENT_NAME_LEN,
					   corrupt_dirent_name_len,
					   "dir_ino %llu hash %llu key "SK_FMT" len %d",
					   dir_ino, hash, SK_ARG(&key), ret);
			ret = -EIO;
			goto out;
		}

		if (dirent_names_equal(name, name_len, dent->name, ret)) {
			*dent_ret = *dent;
			ret = 0;
			break;
		}

		if (le64_to_cpu(key.skd_minor) == U64_MAX) {
			ret = -ENOENT;
			break;
		}
		le64_add_cpu(&key.skd_minor, 1);
	}

out:
	kfree(dent);
	return ret;
}

static int scoutfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dentry->d_sb;
	struct dentry_info *di = dentry->d_fsdata;
	struct dentry *parent = dget_parent(dentry);
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_dirent dent;
	bool is_covered = false;
	struct inode *dir;
	u64 dentry_ino;
	int ret;

	/* don't think this happens but we can find out */
	if (IS_ROOT(dentry)) {
		scoutfs_inc_counter(sb, dentry_revalidate_root);
		if (!dentry->d_inode ||
		    (scoutfs_ino(dentry->d_inode) != SCOUTFS_ROOT_INO)) {
			ret = -EIO;
		} else {
			ret = 1;
		}
		goto out;
	}

	/* XXX what are the rules for _RCU? */
	if (flags & LOOKUP_RCU) {
		scoutfs_inc_counter(sb, dentry_revalidate_rcu);
		ret = -ECHILD;
		goto out;
	}

	if (WARN_ON_ONCE(di == NULL)) {
		ret = 0;
		goto out;
	}

	is_covered = scoutfs_lock_is_covered(sb, &di->lock_cov);
	if (is_covered) {
		scoutfs_inc_counter(sb, dentry_revalidate_locked);
		ret = 1;
		goto out;
	}

	if (!parent || !parent->d_inode) {
		scoutfs_inc_counter(sb, dentry_revalidate_orphan);
		ret = 0;
		goto out;
	}
	dir = parent->d_inode;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, dir, &lock);
	if (ret)
		goto out;

	ret = lookup_dirent(sb, scoutfs_ino(dir),
			    dentry->d_name.name, dentry->d_name.len,
			    dirent_name_hash(dentry->d_name.name,
					     dentry->d_name.len),
			    &dent, lock);
	if (ret == -ENOENT) {
		dent.ino = 0;
		dent.hash = 0;
		dent.pos = 0;
	} else if (ret < 0) {
		goto out;
	}

	dentry_ino = dentry->d_inode ? scoutfs_ino(dentry->d_inode) : 0;

	if ((dentry_ino == le64_to_cpu(dent.ino))) {
		update_dentry_info(sb, dentry, le64_to_cpu(dent.hash),
				   le64_to_cpu(dent.pos), lock);
		scoutfs_inc_counter(sb, dentry_revalidate_valid);
		ret = 1;
	} else {
		scoutfs_inc_counter(sb, dentry_revalidate_invalid);
		ret = 0;
	}

out:
	trace_scoutfs_d_revalidate(sb, dentry, flags, parent, is_covered, ret);

	dput(parent);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);

	if (ret < 0 && ret != -ECHILD)
		scoutfs_inc_counter(sb, dentry_revalidate_error);

	return ret;
}

/*
 * Because of rename, locks are ordered by inode number.  To hold the
 * dir lock while calling iget, we might have to already hold a lesser
 * inode's lock while telling iget whether or not to lock.  Instead of
 * adding all those moving pieces we drop the dir lock before calling
 * iget.  We don't reuse inode numbers so we don't have to worry about
 * the target of the link changing.  We will only follow the entry as it
 * existed before or after whatever modification is happening under the
 * dir lock and that can already legally race before or after our
 * lookup.
 */
static struct dentry *scoutfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_dirent dent;
	struct inode *inode;
	u64 ino = 0;
	u64 hash;
	int ret;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	ret = alloc_dentry_info(dentry);
	if (ret)
		goto out;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, dir, &dir_lock);
	if (ret)
		goto out;

	ret = lookup_dirent(sb, scoutfs_ino(dir), dentry->d_name.name,
			    dentry->d_name.len, hash, &dent, dir_lock);
	if (ret == -ENOENT) {
		ino = 0;
		ret = 0;
	} else if (ret == 0) {
		ino = le64_to_cpu(dent.ino);
		update_dentry_info(sb, dentry, le64_to_cpu(dent.hash),
				   le64_to_cpu(dent.pos), dir_lock);
	}
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_READ);

out:
	if (ret < 0)
		inode = ERR_PTR(ret);
	else if (ino == 0)
		inode = NULL;
	else
		inode = scoutfs_iget(sb, ino);

	return d_splice_alias(inode, dentry);
}

/*
 * readdir simply iterates over the dirent items for the dir inode and
 * uses their offset as the readdir position.
 *
 * It will need to be careful not to read past the region of the dirent
 * hash offset keys that it has access to.
 */
static int KC_DECLARE_READDIR(scoutfs_readdir, struct file *file,
			      void *dirent, kc_readdir_ctx_t ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_dirent *dent;
	struct scoutfs_key key;
	struct scoutfs_key last_key;
	struct scoutfs_lock *dir_lock;
	struct kvec val;
	int name_len;
	u64 pos;
	int ret;

	if (!kc_dir_emit_dots(file, dirent, ctx))
		return 0;

	dent = alloc_dirent(SCOUTFS_NAME_LEN);
	if (!dent) {
		ret = -ENOMEM;
		goto out;
	}

	init_dirent_key(&last_key, SCOUTFS_READDIR_TYPE, scoutfs_ino(inode),
			SCOUTFS_DIRENT_LAST_POS, 0);
	kvec_init(&val, dent, dirent_bytes(SCOUTFS_NAME_LEN));

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &dir_lock);
	if (ret)
		goto out;

	for (;;) {
		init_dirent_key(&key, SCOUTFS_READDIR_TYPE, scoutfs_ino(inode),
				kc_readdir_pos(file, ctx), 0);

		ret = scoutfs_forest_next(sb, &key, &last_key, &val, dir_lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		name_len = ret - sizeof(struct scoutfs_dirent);
		if (name_len < 1 || name_len > SCOUTFS_NAME_LEN) {
			scoutfs_corruption(sb, SC_DIRENT_READDIR_NAME_LEN,
					   corrupt_dirent_readdir_name_len,
					   "dir_ino %llu pos %llu key "SK_FMT" len %d",
					   scoutfs_ino(inode),
					   kc_readdir_pos(file, ctx),
					   SK_ARG(&key), name_len);
			ret = -EIO;
			goto out;
		}

		pos = le64_to_cpu(key.skd_major);
		kc_readdir_pos(file, ctx) = pos;

		if (!kc_dir_emit(ctx, dirent, dent->name, name_len, pos,
				le64_to_cpu(dent->ino),
				dentry_type(dent->type))) {
			ret = 0;
			break;
		}

		kc_readdir_pos(file, ctx) = pos + 1;
	}

out:
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_READ);

	kfree(dent);
	return ret;
}

/*
 * Add all the items for the named link to the inode in the dir.  Only
 * items are modified.  The caller is responsible for locking, entering
 * a transaction, dirtying items, and managing the vfs structs.
 *
 * If this returns an error then nothing will have changed.
 */
static int add_entry_items(struct super_block *sb, u64 dir_ino, u64 hash,
			   u64 pos, const char *name, unsigned name_len,
			   u64 ino, umode_t mode, struct scoutfs_lock *dir_lock,
			   struct scoutfs_lock *inode_lock)
{
	struct scoutfs_key rdir_key;
	struct scoutfs_key ent_key;
	struct scoutfs_key lb_key;
	struct scoutfs_dirent *dent;
	bool del_ent = false;
	bool del_rdir = false;
	struct kvec val;
	int ret;

	dent = alloc_dirent(name_len);
	if (!dent) {
		ret = -ENOMEM;
		goto out;
	}

	/* initialize the dent */
	dent->ino = cpu_to_le64(ino);
	dent->hash = cpu_to_le64(hash);
	dent->pos = cpu_to_le64(pos);
	dent->type = mode_to_type(mode);
	memcpy(dent->name, name, name_len);

	init_dirent_key(&ent_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, pos);
	init_dirent_key(&rdir_key, SCOUTFS_READDIR_TYPE, dir_ino, pos, 0);
	init_dirent_key(&lb_key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, pos);
	kvec_init(&val, dent, dirent_bytes(name_len));

	ret = scoutfs_forest_create(sb, &ent_key, &val, dir_lock);
	if (ret)
		goto out;
	del_ent = true;

	ret = scoutfs_forest_create(sb, &rdir_key, &val, dir_lock);
	if (ret)
		goto out;
	del_rdir = true;

	ret = scoutfs_forest_create(sb, &lb_key, &val, inode_lock);
out:
	if (ret < 0) {
		if (del_ent)
			scoutfs_forest_delete_dirty(sb, &ent_key);
		if (del_rdir)
			scoutfs_forest_delete_dirty(sb, &rdir_key);
	}

	kfree(dent);

	return ret;
}

/*
 * Delete all the items for the named link to the inode in the dir.
 * Only items are modified.  The caller is responsible for locking,
 * entering a transaction, dirtying items, and managing the vfs structs.
 *
 * If this returns an error then nothing will have changed.
 */
static int del_entry_items(struct super_block *sb, u64 dir_ino, u64 hash,
			   u64 pos, u64 ino, struct scoutfs_lock *dir_lock,
			   struct scoutfs_lock *inode_lock)
{
	struct scoutfs_key rdir_key;
	struct scoutfs_key ent_key;
	struct scoutfs_key lb_key;
	LIST_HEAD(dir_saved);
	LIST_HEAD(inode_saved);
	int ret;

	init_dirent_key(&ent_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, pos);
	init_dirent_key(&rdir_key, SCOUTFS_READDIR_TYPE, dir_ino, pos, 0);
	init_dirent_key(&lb_key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, pos);

	ret = scoutfs_forest_delete_save(sb, &ent_key, &dir_saved, dir_lock) ?:
	      scoutfs_forest_delete_save(sb, &rdir_key, &dir_saved, dir_lock) ?:
	      scoutfs_forest_delete_save(sb, &lb_key, &inode_saved, inode_lock);
	if (ret < 0) {
		scoutfs_forest_restore(sb, &dir_saved, dir_lock);
		scoutfs_forest_restore(sb, &inode_saved, inode_lock);
	} else {
		scoutfs_forest_free_batch(sb, &dir_saved);
		scoutfs_forest_free_batch(sb, &inode_saved);
	}

	return ret;
}

/*
 * Inode creation needs to hold dir and inode locks which can be greater
 * or less than each other.  It seems easiest to keep the dual locking
 * here like it is for all the other dual locking of established inodes.
 * Except we don't have the inode struct yet when we're getting locks,
 * so we roll our own comparion between the two instead of pushing
 * complexity down the locking paths that acquire existing inodes in
 * order.
 */
static struct inode *lock_hold_create(struct inode *dir, struct dentry *dentry,
				      umode_t mode, dev_t rdev,
				      const struct scoutfs_item_count cnt,
				      struct scoutfs_lock **dir_lock,
				      struct scoutfs_lock **inode_lock,
				      struct list_head *ind_locks)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	u64 ind_seq;
	int ret = 0;
	u64 ino;

	ret = alloc_dentry_info(dentry);
	if (ret)
		return ERR_PTR(ret);

	ret = scoutfs_alloc_ino(sb, S_ISDIR(mode), &ino);
	if (ret)
		return ERR_PTR(ret);

	if (ino < scoutfs_ino(dir)) {
		ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_WRITE, 0, ino,
				       inode_lock) ?:
		      scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				         SCOUTFS_LKF_REFRESH_INODE, dir,
					 dir_lock);
	} else {
		ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				         SCOUTFS_LKF_REFRESH_INODE, dir,
					 dir_lock) ?:
		      scoutfs_lock_ino(sb, SCOUTFS_LOCK_WRITE, 0, ino,
				       inode_lock);
	}
	if (ret)
		goto out_unlock;

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, ind_locks, dir, true) ?:
	      scoutfs_inode_index_prepare_ino(sb, ind_locks, ino, mode) ?:
	      scoutfs_inode_index_try_lock_hold(sb, ind_locks, ind_seq, cnt);
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	inode = scoutfs_new_inode(sb, dir, mode, rdev, ino, *inode_lock);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	ret = scoutfs_dirty_inode_item(dir, *dir_lock);
out:
	if (ret)
		scoutfs_release_trans(sb);
out_unlock:
	if (ret) {
		scoutfs_inode_index_unlock(sb, ind_locks);
		scoutfs_unlock(sb, *dir_lock, SCOUTFS_LOCK_WRITE);
		scoutfs_unlock(sb, *inode_lock, SCOUTFS_LOCK_WRITE);
		*dir_lock = NULL;
		*inode_lock = NULL;

		inode = ERR_PTR(ret);
	}

	return inode;
}

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	LIST_HEAD(ind_locks);
	u64 hash;
	u64 pos;
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);
	inode = lock_hold_create(dir, dentry, mode, rdev,
				 SIC_MKNOD(dentry->d_name.len),
				 &dir_lock, &inode_lock, &ind_locks);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret)
		goto out;

	update_dentry_info(sb, dentry, hash, pos, dir_lock);

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	inode->i_mtime = inode->i_atime = inode->i_ctime = dir->i_mtime;

	if (S_ISDIR(mode)) {
		inc_nlink(inode);
		inc_nlink(dir);
	}

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);
	scoutfs_inode_index_unlock(sb, &ind_locks);

	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);

	/* XXX delete the inode item here */
	if (ret && !IS_ERR_OR_NULL(inode))
		iput(inode);
	return ret;
}

/* XXX hmm, do something with excl? */
static int scoutfs_create(struct inode *dir, struct dentry *dentry,
			  umode_t mode, bool excl)
{
	return scoutfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int scoutfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return scoutfs_mknod(dir, dentry, mode | S_IFDIR, 0);
}

static int scoutfs_link(struct dentry *old_dentry,
			struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	struct scoutfs_lock *dir_lock;
	struct scoutfs_lock *inode_lock = NULL;
	LIST_HEAD(ind_locks);
	u64 dir_size;
	u64 ind_seq;
	u64 hash;
	u64 pos;
	int ret;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  dir, &dir_lock, inode, &inode_lock,
				  NULL, NULL, NULL, NULL);
	if (ret)
		return ret;

	if (inode->i_nlink >= SCOUTFS_LINK_MAX) {
		ret = -EMLINK;
		goto out_unlock;
	}

	ret = alloc_dentry_info(dentry);
	if (ret)
		goto out_unlock;

	dir_size = i_size_read(dir) + dentry->d_name.len;
retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq,
						SIC_LINK(dentry->d_name.len));
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	ret = scoutfs_dirty_inode_item(dir, dir_lock);
	if (ret)
		goto out;

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret)
		goto out;
	update_dentry_info(sb, dentry, hash, pos, dir_lock);

	i_size_write(dir, dir_size);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	inode->i_ctime = dir->i_mtime;
	inc_nlink(inode);

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

	atomic_inc(&inode->i_count);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
out_unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);
	return ret;
}

static bool should_orphan(struct inode *inode)
{
	if (inode == NULL)
		return false;

	if (S_ISDIR(inode->i_mode))
		return inode->i_nlink == 2;

	return inode->i_nlink == 1;
}

/*
 * Unlink removes the entry from its item and removes the item if ours
 * was the only remaining entry.
 */
static int scoutfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dentry->d_inode;
	struct timespec ts = current_kernel_time();
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	LIST_HEAD(ind_locks);
	u64 ind_seq;
	int ret = 0;

	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  dir, &dir_lock, inode, &inode_lock,
				  NULL, NULL, NULL, NULL);
	if (ret)
		return ret;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode)) {
		ret = -ENOTEMPTY;
		goto unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq,
						SIC_UNLINK(dentry->d_name.len));
	if (ret > 0)
		goto retry;
	if (ret)
		goto unlock;

	ret = del_entry_items(sb, scoutfs_ino(dir), dentry_info_hash(dentry),
			      dentry_info_pos(dentry), scoutfs_ino(inode),
			      dir_lock, inode_lock);
	if (ret)
		goto out;

	if (should_orphan(inode)) {
		/*
		 * Insert the orphan item before we modify any inode
		 * metadata so we can gracefully exit should it
		 * fail.
		 */
		ret = scoutfs_orphan_inode(inode);
		WARN_ON_ONCE(ret); /* XXX returning error but items deleted */
		if (ret)
			goto out;
	}

	dir->i_ctime = ts;
	dir->i_mtime = ts;
	i_size_write(dir, i_size_read(dir) - dentry->d_name.len);

	inode->i_ctime = ts;
	drop_nlink(inode);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
		drop_nlink(inode);
	}
	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

out:
	scoutfs_release_trans(sb);
unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);

	return ret;
}

static void init_symlink_key(struct scoutfs_key *key, u64 ino, u8 nr)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.sks_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_SYMLINK_TYPE,
		.sks_nr = cpu_to_le64(nr),
	};
}

/*
 * Operate on all the items that make up a symlink whose target might
 * have to be split up into multiple items each with a maximally sized
 * value.
 *
 * returns 0 or -errno from the item calls, particularly including
 * EEXIST, EIO, or ENOENT if the item population doesn't match what was
 * expected given the op.
 *
 * The target name can be null for deletion when val isn't used.  Size
 * still has to be provided to determine the number of items.
 */
enum {
	SYM_CREATE = 0,
	SYM_LOOKUP,
	SYM_DELETE,
};
static int symlink_item_ops(struct super_block *sb, int op, u64 ino,
			    struct scoutfs_lock *lock, const char *target,
			    size_t size)
{
	struct scoutfs_key key;
	struct kvec val;
	unsigned bytes;
	unsigned nr;
	int ret;
	int i;

	if (WARN_ON_ONCE(size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE ||
		         op > SYM_DELETE))
		return -EINVAL;

	nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);
	for (i = 0; i < nr; i++) {

		init_symlink_key(&key, ino, i);
		bytes = min_t(u64, size, SCOUTFS_MAX_VAL_SIZE);
		kvec_init(&val, (void *)target, bytes);

		if (op == SYM_CREATE)
			ret = scoutfs_forest_create(sb, &key, &val, lock);
		else if (op == SYM_LOOKUP)
			ret = scoutfs_forest_lookup_exact(sb, &key, &val, lock);
		else if (op == SYM_DELETE)
			ret = scoutfs_forest_delete(sb, &key, lock);
		if (ret)
			break;

		target += SCOUTFS_MAX_VAL_SIZE;
		size -= bytes;
	}

	return ret;
}

/*
 * Full a buffer with the null terminated symlink, point nd at it, and
 * return it so put_link can free it once the vfs is done.
 *
 * We chose to pay the runtime cost of per-call allocation and copy
 * overhead instead of wiring up symlinks to the page cache, storing
 * each small link in a full page, and later having to reclaim them.
 */
static void *scoutfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	char *path = NULL;
	loff_t size;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		return ERR_PTR(ret);

	size = i_size_read(inode);

	if (size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE) {
		scoutfs_corruption(sb, SC_SYMLINK_INODE_SIZE,
				   corrupt_symlink_inode_size,
				   "ino %llu size %llu",
				   scoutfs_ino(inode), (u64)size);
		ret = -EIO;
		goto out;
	}

	/* unlikely, but possible I suppose */
	if (size > PATH_MAX) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	path = kmalloc(size, GFP_NOFS);
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	ret = symlink_item_ops(sb, SYM_LOOKUP, scoutfs_ino(inode), inode_lock,
			       path, size);

	if (ret == -ENOENT) {
		scoutfs_corruption(sb, SC_SYMLINK_MISSING_ITEM,
				   corrupt_symlink_missing_item,
				   "ino %llu size %llu", scoutfs_ino(inode),
				   size);
		ret = -EIO;

	} else if (ret == 0 && path[size - 1]) {
		scoutfs_corruption(sb, SC_SYMLINK_NOT_NULL_TERM,
				   corrupt_symlink_not_null_term,
				   "ino %llu last %u",
				   scoutfs_ino(inode), path[size - 1]);
		ret = -EIO;
	}

out:
	if (ret < 0) {
		kfree(path);
		path = ERR_PTR(ret);
	} else {
		nd_set_link(nd, path);
	}
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	return path;
}

static void scoutfs_put_link(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
{
	if (!IS_ERR_OR_NULL(cookie))
		kfree(cookie);
}

const struct inode_operations scoutfs_symlink_iops = {
	.readlink       = generic_readlink,
	.follow_link    = scoutfs_follow_link,
	.put_link       = scoutfs_put_link,
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
	.setxattr	= scoutfs_setxattr,
	.getxattr	= scoutfs_getxattr,
	.listxattr	= scoutfs_listxattr,
	.removexattr	= scoutfs_removexattr,
};

/*
 * Symlink target paths can be annoyingly large.  We store relatively
 * rare large paths in multiple items.
 */
static int scoutfs_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	struct super_block *sb = dir->i_sb;
	const int name_len = strlen(symname) + 1;
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	LIST_HEAD(ind_locks);
	u64 hash;
	u64 pos;
	int ret;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	/* path_max includes null as does our value for nd_set_link */
	if (dentry->d_name.len > SCOUTFS_NAME_LEN ||
	    name_len > PATH_MAX || name_len > SCOUTFS_SYMLINK_MAX_SIZE)
		return -ENAMETOOLONG;

	ret = alloc_dentry_info(dentry);
	if (ret)
		return ret;

	inode = lock_hold_create(dir, dentry, S_IFLNK|S_IRWXUGO, 0,
				 SIC_SYMLINK(dentry->d_name.len, name_len),
				 &dir_lock, &inode_lock, &ind_locks);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	ret = symlink_item_ops(sb, SYM_CREATE, scoutfs_ino(inode), inode_lock,
			       symname, name_len);
	if (ret)
		goto out;

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret)
		goto out;

	update_dentry_info(sb, dentry, hash, pos, dir_lock);

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

	inode->i_ctime = dir->i_mtime;
	i_size_write(inode, name_len);

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

	insert_inode_hash(inode);
	/* XXX need to set i_op/fop before here for sec callbacks */
	d_instantiate(dentry, inode);
out:
	if (ret < 0) {
		/* XXX remove inode items */
		if (!IS_ERR_OR_NULL(inode))
			iput(inode);

		symlink_item_ops(sb, SYM_DELETE, scoutfs_ino(inode), inode_lock,
				 NULL, name_len);
	}

	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);

	return ret;
}

int scoutfs_symlink_drop(struct super_block *sb, u64 ino,
			 struct scoutfs_lock *lock, u64 i_size)
{
	int ret;

	ret = symlink_item_ops(sb, SYM_DELETE, ino, lock, NULL, i_size);
	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

/*
 * Find the next link backref key for the given ino starting from the
 * given dir inode and final entry position.  If we find a backref item
 * we add an allocated copy of it to the head of the caller's list.
 *
 * Returns 0 if we added an entry, -ENOENT if we didn't, and -errno for
 * search errors.
 *
 * Callers are comfortable with the race inherent to incrementally
 * building up a path with individual locked backref item lookups.
 */
int scoutfs_dir_add_next_linkref(struct super_block *sb, u64 ino,
				 u64 dir_ino, u64 dir_pos,
				 struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	struct scoutfs_lock *lock = NULL;
	struct kvec val;
	int len;
	int ret;

	ent = kmalloc(offsetof(struct scoutfs_link_backref_entry,
			       dent.name[SCOUTFS_NAME_LEN]), GFP_KERNEL);
	if (!ent) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&ent->head);

	init_dirent_key(&key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, dir_pos);
	init_dirent_key(&last_key, SCOUTFS_LINK_BACKREF_TYPE, ino, U64_MAX,
			U64_MAX);
	kvec_init(&val, &ent->dent, dirent_bytes(SCOUTFS_NAME_LEN));

	ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_READ, 0, ino, &lock);
	if (ret)
		goto out;

	ret = scoutfs_forest_next(sb, &key, &last_key, &val, lock);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	lock = NULL;
	if (ret < 0)
		goto out;

	len = ret - sizeof(struct scoutfs_dirent);
	if (len < 1 || len > SCOUTFS_NAME_LEN) {
		scoutfs_corruption(sb, SC_DIRENT_BACKREF_NAME_LEN,
				   corrupt_dirent_backref_name_len,
				   "ino %llu dir_ino %llu pos %llu key "SK_FMT" len %d",
				   ino, dir_ino, dir_pos, SK_ARG(&key), len);
		ret = -EIO;
		goto out;
	}

	list_add(&ent->head, list);
	ent->dir_ino = le64_to_cpu(key.skd_major);
	ent->dir_pos = le64_to_cpu(key.skd_minor);
	ent->name_len = len;
	ret = 0;
out:
	trace_scoutfs_dir_add_next_linkref(sb, ino, dir_ino, dir_pos, ret,
					   ent ? ent->dir_ino : 0,
					   ent ? ent->dir_pos : 0,
					   ent ? ent->name_len : 0);

	if (ent && list_empty(&ent->head))
		kfree(ent);
	return ret;
}

static u64 first_backref_dir_ino(struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;

	ent = list_first_entry(list, struct scoutfs_link_backref_entry, head);
	return ent->dir_ino;
}

void scoutfs_dir_free_backref_path(struct super_block *sb,
				   struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;
	struct scoutfs_link_backref_entry *pos;

	list_for_each_entry_safe(ent, pos, list, head) {
		list_del_init(&ent->head);
		kfree(ent);
	}
}

/*
 * Give the caller the next path from the root to the inode by walking
 * backref items from the dir and name position, putting the backref keys
 * we find in the caller's list.
 *
 * Return 0 if we found a path, -ENOENT if we didn't, and -errno on error.
 *
 * If parents get unlinked while we're searching we can fail to make it
 * up to the root.  We restart the search in that case.  Parent dirs
 * couldn't have been unlinked while they still had entries and we won't
 * see links to the inode that have been unlinked.
 *
 * XXX Each path component traversal is consistent but that doesn't mean
 * that the total traversed path is consistent.  If renames hit dirs
 * that have been visited and then dirs to be visited we can return a
 * path that was never present in the system:
 *
 * path to inode     mv performed           built up path
 * ----
 * a/b/c/d/e/f
 *                                          d/e/f
 *                   mv a/b/c/d/e a/b/c/
 * a/b/c/e/f
 *                   mv a/b/c     a/
 * a/c/e/f
 *                                          a/c/d/e/f
 *
 * XXX We'll protect against this by sampling the seq before the
 * traversal and restarting if we saw backref items whose seq was
 * greater than the start point.  It's not precise in that it doesn't
 * also capture the rename of a dir that we already traversed but it
 * lets us complete the traversal in one pass that very rarely restarts.
 *
 * XXX and worry about traversing entirely dirty backref items with
 * equal seqs that have seen crazy modification?  seems like we have to
 * sync if we see our dirty seq.
 */
int scoutfs_dir_get_backref_path(struct super_block *sb, u64 ino, u64 dir_ino,
				 u64 dir_pos, struct list_head *list)
{
	int retries = 10;
	u64 par_ino;
	int ret;

retry:
	if (retries-- == 0) {
		scoutfs_inc_counter(sb, dir_backref_excessive_retries);
		ret = -ELOOP;
		goto out;
	}

	/* get the next link name to the given inode */
	ret = scoutfs_dir_add_next_linkref(sb, ino, dir_ino, dir_pos, list);
	if (ret < 0)
		goto out;

	/* then get the names of all the parent dirs */
	par_ino = first_backref_dir_ino(list);
	while (par_ino != SCOUTFS_ROOT_INO) {

		ret = scoutfs_dir_add_next_linkref(sb, par_ino, 0, 0, list);
		if (ret < 0) {
			if (ret == -ENOENT) {
				/* restart if there was no parent component */
				scoutfs_dir_free_backref_path(sb, list);
				goto retry;
			}
			goto out;
		}

		par_ino = first_backref_dir_ino(list);
	}
out:
	if (ret < 0)
		scoutfs_dir_free_backref_path(sb, list);
	return ret;
}

/*
 * Given two parent dir inos, return the ancestor of p2 that is p1's
 * child when p1 is also an ancestor of p2: p1/p/[...]/p2.  This can
 * return p2.
 *
 * We do this by walking link backref items.  Each entry can be thought
 * of as a dirent stored at the target.  So the parent dir is stored in
 * the target.
 *
 * The caller holds the global rename lock and link backref walk locks
 * each inode as it looks up backrefs.
 */
static int item_d_ancestor(struct super_block *sb, u64 p1, u64 p2, u64 *p_ret)
{
	struct scoutfs_link_backref_entry *ent;
	LIST_HEAD(list);
	int ret;
	u64 p;

	*p_ret = 0;

	ret = scoutfs_dir_get_backref_path(sb, p2, 0, 0, &list);
	if (ret)
		goto out;

	p = p2;
	list_for_each_entry(ent, &list, head) {
		if (ent->dir_ino == p1) {
			*p_ret = p;
			ret = 0;
			break;
		}
		p = ent->dir_ino;
	}

out:
	scoutfs_dir_free_backref_path(sb, &list);
	return ret;
}

/*
 * The vfs checked the relationship between dirs, the source, and target
 * before acquiring clusters locks.  All that could have changed.  If
 * we're renaming between parent dirs then we try to verify the basics
 * of those checks using our backref items.
 *
 * Compare this to lock_rename()'s use of d_ancestor() and what it's
 * caller does with the returned ancestor.
 *
 * The caller only holds the global rename cluster lock.
 * item_d_ancestor is going to walk backref paths and acquire and
 * release locks for each target inode in the path.
 */
static int verify_ancestors(struct super_block *sb, u64 p1, u64 p2,
			    u64 old_ino, u64 new_ino)
{
	int ret;
	u64 p;

	ret = item_d_ancestor(sb, p1, p2, &p);
	if (ret == 0 && p == 0)
		ret = item_d_ancestor(sb, p2, p1, &p);
	if (ret == 0 && p && (p == old_ino || p == new_ino))
		ret = -EINVAL;

	return ret;
}

/*
 * Make sure that a dirent from the dir to the inode exists at the name.
 * The caller has the name locked in the dir.
 */
static int verify_entry(struct super_block *sb, u64 dir_ino, const char *name,
			unsigned name_len, u64 hash, u64 ino,
			struct scoutfs_lock *lock)
{
	struct scoutfs_dirent dent;
	int ret;

	ret = lookup_dirent(sb, dir_ino, name, name_len, hash, &dent, lock);
	if (ret == 0 && le64_to_cpu(dent.ino) != ino)
		ret = -ENOENT;
	else if (ret == -ENOENT && ino == 0)
		ret = 0;

	return ret;
}

/*
 * The vfs performs checks on cached inodes and dirents before calling
 * here.  It doesn't hold any locks so all of those checks can be based
 * on cached state that has been invalidated by other operations in the
 * cluster before we get here.
 *
 * We do the expedient thing today and verify the basic structural
 * checks after we get cluster locks.  We perform  topology checks
 * analagous to the d_ancestor() walks in lock_rename() after acquiring
 * a clustered equivalent of the vfs rename lock.  We then lock the dir
 * and target inodes and verify that the entries assumed by the function
 * arguments still exist.
 *
 * We don't duplicate all the permissions checking in the vfs
 * (may_create(), etc, are all static.).  This means racing renames can
 * succeed after other nodes have gotten success out of changes to
 * permissions that should have forbidden renames.
 *
 * All of this wouldn't be necessary if we could get prepare/complete
 * callbacks around rename that'd let us lock the inodes, dirents, and
 * topology while the vfs walks dentries and uses inodes.
 *
 * We acquire the inode locks in inode number order.  Because of our
 * inode group locking we can't define lock ordering correctness by
 * properties that can be different in a given group.  This prevents us
 * from using parent/child locking orders as two groups can have both
 * parent and child relationships to each other.
 */
static int scoutfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry)
{
	struct super_block *sb = old_dir->i_sb;
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct scoutfs_lock *rename_lock = NULL;
	struct scoutfs_lock *old_dir_lock = NULL;
	struct scoutfs_lock *new_dir_lock = NULL;
	struct scoutfs_lock *old_inode_lock = NULL;
	struct scoutfs_lock *new_inode_lock = NULL;
	struct timespec now;
	bool ins_new = false;
	bool del_new = false;
	bool ins_old = false;
	LIST_HEAD(ind_locks);
	u64 ind_seq;
	u64 old_hash;
	u64 new_hash;
	u64 new_pos;
	int ret;
	int err;

	trace_scoutfs_rename(sb, old_dir, old_dentry, new_dir, new_dentry);

	old_hash = dirent_name_hash(old_dentry->d_name.name,
				    old_dentry->d_name.len);
	new_hash = dirent_name_hash(new_dentry->d_name.name,
				    new_dentry->d_name.len);

	if (new_dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	/* if dirs are different make sure ancestor relationships are valid */
	if (old_dir != new_dir) {
		ret = scoutfs_lock_rename(sb, SCOUTFS_LOCK_WRITE, 0,
					  &rename_lock);
		if (ret)
			return ret;

		ret = verify_ancestors(sb, scoutfs_ino(old_dir),
				       scoutfs_ino(new_dir),
				       scoutfs_ino(old_inode),
				       new_inode ? scoutfs_ino(new_inode) : 0);
		if (ret)
			goto out_unlock;
	}

	/* lock all the inodes */
	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  old_dir, &old_dir_lock,
				  new_dir, &new_dir_lock,
				  old_inode, &old_inode_lock,
				  new_inode, &new_inode_lock);
	if (ret)
		goto out_unlock;

	/* test dir i_size now that it's refreshed */
	if (new_inode && S_ISDIR(new_inode->i_mode) && i_size_read(new_inode)) {
		ret = -ENOTEMPTY;
		goto out_unlock;
	}

	/* make sure that the entries assumed by the argument still exist */
	ret = verify_entry(sb, scoutfs_ino(old_dir), old_dentry->d_name.name,
			   old_dentry->d_name.len, old_hash,
			   scoutfs_ino(old_inode), old_dir_lock) ?:
	      verify_entry(sb, scoutfs_ino(new_dir), new_dentry->d_name.name,
			   new_dentry->d_name.len, new_hash,
			   new_inode ? scoutfs_ino(new_inode) : 0,
			   new_dir_lock);
	if (ret)
		goto out_unlock;

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, old_dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, old_inode, false) ?:
	      (new_dir == old_dir ? 0 :
	       scoutfs_inode_index_prepare(sb, &ind_locks, new_dir, false)) ?:
	      (new_inode == NULL ? 0 :
	       scoutfs_inode_index_prepare(sb, &ind_locks, new_inode, false)) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq,
					    SIC_RENAME(old_dentry->d_name.len,
						       new_dentry->d_name.len));
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	/* get a pos for the new entry */
	new_pos = SCOUTFS_I(new_dir)->next_readdir_pos++;

	/* dirty the inodes so that updating doesn't fail */
	ret = scoutfs_dirty_inode_item(old_dir, old_dir_lock) ?:
	      scoutfs_dirty_inode_item(old_inode, old_inode_lock) ?:
	      (old_dir != new_dir ?
		scoutfs_dirty_inode_item(new_dir, new_dir_lock) : 0) ?:
	      (new_inode ?
		scoutfs_dirty_inode_item(new_inode, new_inode_lock) : 0);
	if (ret)
		goto out;

	/* remove the new entry if it exists */
	if (new_inode) {
		ret = del_entry_items(sb, scoutfs_ino(new_dir),
				      dentry_info_hash(new_dentry),
				      dentry_info_pos(new_dentry),
				      scoutfs_ino(new_inode),
				      new_dir_lock, new_inode_lock);
		if (ret)
			goto out;
		ins_new = true;
	}

	/* create the new entry */
	ret = add_entry_items(sb, scoutfs_ino(new_dir), new_hash, new_pos,
			      new_dentry->d_name.name, new_dentry->d_name.len,
			      scoutfs_ino(old_inode), old_inode->i_mode,
			      new_dir_lock, old_inode_lock);
	if (ret)
		goto out;
	del_new = true;

	/* remove the old entry */
	ret = del_entry_items(sb, scoutfs_ino(old_dir),
			      dentry_info_hash(old_dentry),
			      dentry_info_pos(old_dentry),
			      scoutfs_ino(old_inode),
			      old_dir_lock, old_inode_lock);
	if (ret)
		goto out;
	ins_old = true;

	if (should_orphan(new_inode)) {
		ret = scoutfs_orphan_inode(new_inode);
		if (ret)
			goto out;
	}

	/* won't fail from here on out, update all the vfs structs */

	/* the caller will use d_move to move the old_dentry into place */
	update_dentry_info(sb, old_dentry, new_hash, new_pos, new_dir_lock);

       i_size_write(old_dir, i_size_read(old_dir) - old_dentry->d_name.len);
       if (!new_inode)
               i_size_write(new_dir, i_size_read(new_dir) +
                            new_dentry->d_name.len);

	if (new_inode) {
		drop_nlink(new_inode);
		if (S_ISDIR(new_inode->i_mode)) {
			drop_nlink(new_dir);
			drop_nlink(new_inode);
		}

	}

	if (S_ISDIR(old_inode->i_mode) && (old_dir != new_dir)) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	now = CURRENT_TIME;
	old_dir->i_ctime = now;
	old_dir->i_mtime = now;
	if (new_dir != old_dir) {
		new_dir->i_ctime = now;
		new_dir->i_mtime = now;
	}
	old_inode->i_ctime = now;
	if (new_inode)
		old_inode->i_ctime = now;

	scoutfs_update_inode_item(old_dir, old_dir_lock, &ind_locks);
	scoutfs_update_inode_item(old_inode, old_inode_lock, &ind_locks);
	if (new_dir != old_dir)
		scoutfs_update_inode_item(new_dir, new_dir_lock, &ind_locks);
	if (new_inode)
		scoutfs_update_inode_item(new_inode, new_inode_lock,
					  &ind_locks);
	ret = 0;
out:
	if (ret) {
		/*
		 * XXX We have to clean up partial item deletions today
		 * because we can't have two dirents existing in a
		 * directory that point to different inodes.  If we
		 * could we'd create the new name then everything after
		 * that is deletion that will only fail cleanly or
		 * succeed.  Maybe we could have an item replace call
		 * that gives us the dupe to re-insert on cleanup?  Not
		 * sure.
		 *
		 * It's safe to use dentry_info here 'cause they haven't
		 * been updated if we saw an error.
		 */
		err = 0;
		if (ins_old)
			err = add_entry_items(sb, scoutfs_ino(old_dir),
					      dentry_info_hash(old_dentry),
					      dentry_info_pos(old_dentry),
					      old_dentry->d_name.name,
					      old_dentry->d_name.len,
					      scoutfs_ino(old_inode),
					      old_inode->i_mode,
					      old_dir_lock,
					      old_inode_lock);

		if (del_new && err == 0)
			err = del_entry_items(sb, scoutfs_ino(new_dir),
					      new_hash, new_pos,
					      scoutfs_ino(old_inode),
					      new_dir_lock, old_inode_lock);

		if (ins_new && err == 0)
			err = add_entry_items(sb, scoutfs_ino(new_dir),
					      dentry_info_hash(new_dentry),
					      dentry_info_pos(new_dentry),
					      new_dentry->d_name.name,
					      new_dentry->d_name.len,
					      scoutfs_ino(new_inode),
					      new_inode->i_mode,
					      new_dir_lock,
					      new_inode_lock);
		/* XXX freak out: panic, go read only, etc */
		BUG_ON(err);
	}

	scoutfs_release_trans(sb);

out_unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, old_inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, new_inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, old_dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, new_dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, rename_lock, SCOUTFS_LOCK_WRITE);

	return ret;
}

#ifdef KC_FMODE_KABI_ITERATE
/* we only need this to set the iterate flag for kabi :/ */
static int scoutfs_dir_open(struct inode *inode, struct file *file)
{
        file->f_mode |= FMODE_KABI_ITERATE;
        return 0;
}
#endif

const struct file_operations scoutfs_dir_fops = {
	.KC_FOP_READDIR	= scoutfs_readdir,
#ifdef KC_FMODE_KABI_ITERATE
	.open		= scoutfs_dir_open,
#endif
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= generic_file_llseek,
};

const struct inode_operations scoutfs_dir_iops = {
	.lookup		= scoutfs_lookup,
	.mknod		= scoutfs_mknod,
	.create		= scoutfs_create,
	.mkdir		= scoutfs_mkdir,
	.link		= scoutfs_link,
	.unlink		= scoutfs_unlink,
	.rmdir		= scoutfs_unlink,
	.rename		= scoutfs_rename,
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
	.setxattr	= scoutfs_setxattr,
	.getxattr	= scoutfs_getxattr,
	.listxattr	= scoutfs_listxattr,
	.removexattr	= scoutfs_removexattr,
	.symlink	= scoutfs_symlink,
	.permission	= scoutfs_permission,
};

void scoutfs_dir_exit(void)
{
	if (dentry_info_cache) {
		kmem_cache_destroy(dentry_info_cache);
		dentry_info_cache = NULL;
	}
}

int scoutfs_dir_init(void)
{
	dentry_info_cache = kmem_cache_create("scoutfs_dentry_info",
					      sizeof(struct dentry_info), 0,
					      SLAB_RECLAIM_ACCOUNT, NULL);
	if (!dentry_info_cache)
		return -ENOMEM;

	return 0;
}
