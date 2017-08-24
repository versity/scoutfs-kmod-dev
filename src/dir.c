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
#include "dir.h"
#include "inode.h"
#include "ioctl.h"
#include "key.h"
#include "super.h"
#include "trans.h"
#include "xattr.h"
#include "kvec.h"
#include "item.h"
#include "lock.h"

/*
 * Directory entries are stored in entries with offsets calculated from
 * the hash of their entry name.
 *
 * Having a single index of items used for both lookup and readdir
 * iteration reduces the storage overhead of directories.  It also
 * avoids having to manage the allocation of readdir positions as
 * directories age and the aggregate create count inches towards the
 * small 31 bit position limit.  The downside is that dirent name
 * operations produce random item access patterns.
 *
 * Hash values are limited to 31 bits primarily to support older
 * deployed protocols that only support 31 bits of file entry offsets,
 * but also to avoid unlikely bugs in programs that store offsets in
 * signed ints.
 *
 * We have to worry about hash collisions.  We linearly probe a fixed
 * number of hash values past the natural value.  In a typical small
 * directory this search will terminate immediately because adjacent
 * items will have distant offset values.  It's only as the directory
 * gets very large that hash values will start to be this dense and
 * sweeping over items in a btree leaf is reasonably efficient.
 *
 * For each directory entry item stored in a directory inode there is a
 * corresponding link backref item stored at the target inode.  This
 * lets us find all the paths that refer to a given inode.  The link
 * backref offset comes from an advancing counter in the inode and the
 * item value contains the dir inode and dirent offset of the referring
 * link.
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
 * Each dentry stores the values that are needed to build the keys of
 * the items that are removed on unlink so that we don't to search
 * through items on unlink.
 */
struct dentry_info {
	u64 readdir_pos;
};

static struct kmem_cache *dentry_info_cache;

static void scoutfs_d_release(struct dentry *dentry)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (di) {
		kmem_cache_free(dentry_info_cache, di);
		dentry->d_fsdata = NULL;
	}
}

static int scoutfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;
	return 0;/* Always revalidate for now */
}

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

static void update_dentry_info(struct dentry *dentry,
			       struct scoutfs_dirent *dent)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (WARN_ON_ONCE(di == NULL))
		return;

	di->readdir_pos = le64_to_cpu(dent->readdir_pos);
}

static u64 dentry_info_pos(struct dentry *dentry)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (WARN_ON_ONCE(di == NULL))
		return 0;

	return di->readdir_pos;
}

static struct scoutfs_key_buf *alloc_dirent_key(struct super_block *sb,
						struct inode *dir,
						struct dentry *dentry)
{
	struct scoutfs_dirent_key *dkey;
	struct scoutfs_key_buf *key;

	key = scoutfs_key_alloc(sb, offsetof(struct scoutfs_dirent_key,
					     name[dentry->d_name.len]));
	if (key) {
		dkey = key->data;
		dkey->zone = SCOUTFS_FS_ZONE;
		dkey->ino = cpu_to_be64(scoutfs_ino(dir));
		dkey->type = SCOUTFS_DIRENT_TYPE;
		memcpy(dkey->name, (void *)dentry->d_name.name,
		       dentry->d_name.len);
	}

	return key;
}

static void init_link_backref_key(struct scoutfs_key_buf *key,
			          struct scoutfs_link_backref_key *lbrkey,
				  u64 ino, u64 dir_ino,
				  char *name, unsigned name_len)
{
	lbrkey->zone = SCOUTFS_FS_ZONE;
	lbrkey->ino = cpu_to_be64(ino);
	lbrkey->type = SCOUTFS_LINK_BACKREF_TYPE;
	lbrkey->dir_ino = cpu_to_be64(dir_ino);
	if (name_len)
		memcpy(lbrkey->name, name, name_len);

	scoutfs_key_init(key, lbrkey, offsetof(struct scoutfs_link_backref_key,
					       name[name_len]));
}

static struct scoutfs_key_buf *alloc_link_backref_key(struct super_block *sb,
						      u64 ino, u64 dir_ino,
						      char *name,
						      unsigned name_len)
{
	struct scoutfs_link_backref_key *lbkey;
	struct scoutfs_key_buf *key;

	key = scoutfs_key_alloc(sb, offsetof(struct scoutfs_link_backref_key,
					     name[name_len]));
	if (key) {
		lbkey = key->data;
		init_link_backref_key(key, lbkey, ino, dir_ino,
				      name, name_len);
	}

	return key;
}

static struct dentry *scoutfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_key_buf *key = NULL;
	struct scoutfs_dirent dent;
	struct scoutfs_lock *dir_lock = NULL;
	SCOUTFS_DECLARE_KVEC(val);
	struct inode *inode;
	u64 ino = 0;
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	ret = alloc_dentry_info(dentry);
	if (ret)
		goto out;

	key = alloc_dirent_key(sb, dir, dentry);
	if (!key) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_PR, scoutfs_ino(dir),
				     &dir_lock);
	if (ret)
		goto out;

	scoutfs_kvec_init(val, &dent, sizeof(dent));

	ret = scoutfs_item_lookup_exact(sb, key, val, sizeof(dent),
					dir_lock->end);
	if (ret == -ENOENT) {
		ino = 0;
		ret = 0;
	} else if (ret == 0) {
		ino = le64_to_cpu(dent.ino);
		update_dentry_info(dentry, &dent);
	}
out:
	if (ret < 0)
		inode = ERR_PTR(ret);
	else if (ino == 0)
		inode = NULL;
	else
		inode = scoutfs_iget(sb, ino);

	scoutfs_unlock(sb, dir_lock, DLM_LOCK_PR);

	scoutfs_key_free(sb, key);

	return d_splice_alias(inode, dentry);
}

/* this exists upstream so we can just delete it in a forward port */
static int dir_emit_dots(struct file *file, void *dirent, filldir_t filldir)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct inode *parent = dentry->d_parent->d_inode;

	if (file->f_pos == 0) {
		if (filldir(dirent, ".", 1, 1, scoutfs_ino(inode), DT_DIR))
			return 0;
		file->f_pos = 1;
	}

	if (file->f_pos == 1) {
		if (filldir(dirent, "..", 2, 1, scoutfs_ino(parent), DT_DIR))
			return 0;
		file->f_pos = 2;
	}

	return 1;
}

static void init_readdir_key(struct scoutfs_key_buf *key,
			     struct scoutfs_readdir_key *rkey,
			     struct inode *inode, loff_t pos)
{
	rkey->zone = SCOUTFS_FS_ZONE;
	rkey->ino = cpu_to_be64(scoutfs_ino(inode));
	rkey->type = SCOUTFS_READDIR_TYPE;
	rkey->pos = cpu_to_be64(pos);

	scoutfs_key_init(key, rkey, sizeof(struct scoutfs_readdir_key));
}

/*
 * readdir simply iterates over the dirent items for the dir inode and
 * uses their offset as the readdir position.
 *
 * It will need to be careful not to read past the region of the dirent
 * hash offset keys that it has access to.
 */
static int scoutfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_dirent *dent;
	struct scoutfs_key_buf key;
	struct scoutfs_key_buf last_key;
	struct scoutfs_readdir_key rkey;
	struct scoutfs_readdir_key last_rkey;
	struct scoutfs_lock *dir_lock;
	SCOUTFS_DECLARE_KVEC(val);
	unsigned int item_len;
	unsigned int name_len;
	u64 pos;
	int ret;

	if (!dir_emit_dots(file, dirent, filldir))
		return 0;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_PR, scoutfs_ino(inode),
				     &dir_lock);
	if (ret)
		return ret;

	init_readdir_key(&last_key, &last_rkey, inode, SCOUTFS_DIRENT_LAST_POS);

	item_len = offsetof(struct scoutfs_dirent, name[SCOUTFS_NAME_LEN]);
	dent = kmalloc(item_len, GFP_KERNEL);
	if (!dent) {
		ret = -ENOMEM;
		goto out;
	}

	for (;;) {
		init_readdir_key(&key, &rkey, inode, file->f_pos);

		scoutfs_kvec_init(val, dent, item_len);
		ret = scoutfs_item_next_same_min(sb, &key, &last_key, val,
				offsetof(struct scoutfs_dirent, name[1]),
						 dir_lock->end);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		name_len = ret - sizeof(struct scoutfs_dirent);
		pos = be64_to_cpu(rkey.pos);

		if (filldir(dirent, dent->name, name_len, pos,
			    le64_to_cpu(dent->ino), dentry_type(dent->type))) {
			ret = 0;
			break;
		}

		file->f_pos = pos + 1;
	}

out:
	scoutfs_unlock(sb, dir_lock, DLM_LOCK_PR);

	kfree(dent);
	return ret;
}

static int add_entry_items(struct inode *dir, struct scoutfs_lock *dir_lock,
			   struct dentry *dentry, struct inode *inode,
			   struct scoutfs_lock *inode_lock)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(dir);
	struct dentry_info *di = dentry->d_fsdata;
	struct super_block *sb = dir->i_sb;
	struct scoutfs_key_buf *ent_key = NULL;
	struct scoutfs_key_buf *lb_key = NULL;
	struct scoutfs_key_buf *del_keys[3];
	struct scoutfs_key_buf *end_keys[3];
	struct scoutfs_key_buf rdir_key;
	struct scoutfs_readdir_key rkey;
	struct scoutfs_dirent dent;
	SCOUTFS_DECLARE_KVEC(val);
	int del = 0;
	u64 pos;
	int ret;
	int err;

	/* caller should have allocated the dentry info */
	if (WARN_ON_ONCE(di == NULL))
		return -EINVAL;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_dirty_inode_item(dir, dir_lock->end);
	if (ret)
		return ret;

	/* initialize the dent */
	pos = si->next_readdir_pos++;
	dent.ino = cpu_to_le64(scoutfs_ino(inode));
	dent.readdir_pos = cpu_to_le64(pos);
	dent.type = mode_to_type(inode->i_mode);

	/* dirent item for lookup */
	ent_key = alloc_dirent_key(sb, dir, dentry);
	if (!ent_key)
		return -ENOMEM;

	scoutfs_kvec_init(val, &dent, sizeof(dent));

	ret = scoutfs_item_create(sb, ent_key, val);
	if (ret)
		goto out;
	del_keys[del++] = ent_key;
	end_keys[del] = dir_lock->end;

	/* readdir item for .. readdir */
	init_readdir_key(&rdir_key, &rkey, dir, pos);
	scoutfs_kvec_init(val, &dent, sizeof(dent),
			  (void *)dentry->d_name.name, dentry->d_name.len);

	ret = scoutfs_item_create(sb, &rdir_key, val);
	if (ret)
		goto out;
	del_keys[del++] = &rdir_key;
	end_keys[del] = dir_lock->end;

	/* link backref item for inode to path resolution */
	lb_key = alloc_link_backref_key(sb, scoutfs_ino(inode),
					scoutfs_ino(dir),
					(void *)dentry->d_name.name,
					dentry->d_name.len);
	if (!lb_key) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_item_create(sb, lb_key, NULL);
	if (ret)
		goto out;
	del_keys[del++] = lb_key;
	end_keys[del] = inode_lock->end;

	update_dentry_info(dentry, &dent);
	ret = 0;
out:
	while (ret < 0 && --del >= 0) {
		err = scoutfs_item_delete(sb, del_keys[del], end_keys[del]);
		/* can always delete dirty while holding */
		BUG_ON(err);
	}

	scoutfs_key_free(sb, ent_key);
	scoutfs_key_free(sb, lb_key);

	return ret;
}

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	DECLARE_ITEM_COUNT(cnt);
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	ret = alloc_dentry_info(dentry);
	if (ret)
		return ret;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(dir),
				     &dir_lock);
	if (ret)
		return ret;

	scoutfs_count_mknod(&cnt, dentry->d_name.len);
	ret = scoutfs_hold_trans(sb, &cnt);
	if (ret)
		goto out_unlock;

	inode = scoutfs_new_inode(sb, dir, mode, rdev);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	/* Now that we have ino from scoutfs_new_inode, allocate a lock */
	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(inode),
				     &inode_lock);
	if (ret)
		goto out;

	ret = add_entry_items(dir, dir_lock, dentry, inode, inode_lock);
	if (ret)
		goto out;

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	inode->i_mtime = inode->i_atime = inode->i_ctime = dir->i_mtime;

	if (S_ISDIR(mode)) {
		inc_nlink(inode);
		inc_nlink(dir);
	}

	scoutfs_update_inode_item(inode);
	scoutfs_update_inode_item(dir);

	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
out_unlock:
	scoutfs_unlock(sb, dir_lock, DLM_LOCK_EX);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_EX);
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
	DECLARE_ITEM_COUNT(cnt);
	int ret;

	if (inode->i_nlink >= SCOUTFS_LINK_MAX)
		return -EMLINK;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(dir),
				     &dir_lock);
	if (ret)
		return ret;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(inode),
				     &inode_lock);
	if (ret)
		goto out_unlock;

	ret = alloc_dentry_info(dentry);
	if (ret)
		goto out_unlock;

	scoutfs_count_link(&cnt, dentry->d_name.len);
	ret = scoutfs_hold_trans(sb, &cnt);
	if (ret)
		goto out_unlock;

	ret = add_entry_items(dir, dir_lock, dentry, inode, inode_lock);
	if (ret)
		goto out;

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	inode->i_ctime = dir->i_mtime;
	inc_nlink(inode);

	scoutfs_update_inode_item(inode);
	scoutfs_update_inode_item(dir);

	atomic_inc(&inode->i_count);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
out_unlock:
	scoutfs_unlock(sb, dir_lock, DLM_LOCK_EX);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_EX);
	return ret;
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
	struct scoutfs_key_buf *keys[3] = {NULL,};
	struct scoutfs_key_buf *ends[3] = {NULL,};
	struct scoutfs_key_buf rdir_key;
	struct scoutfs_readdir_key rkey;
	DECLARE_ITEM_COUNT(cnt);
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	int ret = 0;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode))
		return -ENOTEMPTY;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(dir),
				     &dir_lock);
	if (ret)
		return ret;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(inode),
				     &inode_lock);
	if (ret)
		goto out;

	keys[0] = alloc_dirent_key(sb, dir, dentry);
	if (!keys[0]) {
		ret = -ENOMEM;
		goto out;
	}
	ends[0] = dir_lock->end;

	init_readdir_key(&rdir_key, &rkey, dir, dentry_info_pos(dentry));
	keys[1] = &rdir_key;
	ends[1] = dir_lock->end;

	keys[2] = alloc_link_backref_key(sb, scoutfs_ino(inode),
					 scoutfs_ino(dir),
					 (void *)dentry->d_name.name,
					 dentry->d_name.len);
	if (!keys[2]) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_count_unlink(&cnt, dentry->d_name.len);
	ret = scoutfs_hold_trans(sb, &cnt);
	if (ret)
		goto out;

	ret = scoutfs_dirty_inode_item(dir, dir_lock->end) ?:
		scoutfs_dirty_inode_item(inode, inode_lock->end);
	if (ret)
		goto out_trans;

	ret = scoutfs_item_delete_many(sb, keys, ARRAY_SIZE(keys), ends);
	if (ret)
		goto out_trans;

	if ((inode->i_nlink == 1) ||
	    (S_ISDIR(inode->i_mode) && inode->i_nlink == 2)) {
		/*
		 * Insert the orphan item before we modify any inode
		 * metadata so we can gracefully exit should it
		 * fail.
		 */
		ret = scoutfs_orphan_inode(inode);
		if (ret)
			goto out_trans;
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
	scoutfs_update_inode_item(inode);
	scoutfs_update_inode_item(dir);

out_trans:
	scoutfs_release_trans(sb);
out:
	scoutfs_key_free(sb, keys[0]);
	scoutfs_key_free(sb, keys[2]);
	scoutfs_unlock(sb, dir_lock, DLM_LOCK_EX);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_EX);
	return ret;
}

static void init_symlink_key(struct scoutfs_key_buf *key,
			     struct scoutfs_symlink_key *skey, u64 ino, u8 nr)
{
	skey->zone = SCOUTFS_FS_ZONE;
	skey->ino = cpu_to_be64(ino);
	skey->type = SCOUTFS_SYMLINK_TYPE;
	skey->nr = nr;

	scoutfs_key_init(key, skey, sizeof(struct scoutfs_symlink_key));
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
	struct scoutfs_symlink_key skey;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	unsigned bytes;
	unsigned nr;
	int ret;
	int i;

	if (WARN_ON_ONCE(size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE ||
		         op > SYM_DELETE))
		return -EINVAL;

	nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);
	for (i = 0; i < nr; i++) {

		init_symlink_key(&key, &skey, ino, i);
		bytes = min(size, SCOUTFS_MAX_VAL_SIZE);
		scoutfs_kvec_init(val, (void *)target, bytes);

		if (op == SYM_CREATE)
			ret = scoutfs_item_create(sb, &key, val);
		else if (op == SYM_LOOKUP)
			ret = scoutfs_item_lookup_exact(sb, &key, val, bytes,
							lock->end);
		else if (op == SYM_DELETE)
			ret = scoutfs_item_delete(sb, &key, lock->end);
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
	loff_t size = i_size_read(inode);
	char *path;
	int ret;

	/* XXX corruption */
	if (size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE)
		return ERR_PTR(-EIO);

	/* unlikely, but possible I suppose */
	if (size > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_PR, scoutfs_ino(inode),
				     &inode_lock);
	if (ret)
		return ERR_PTR(ret);

	path = kmalloc(size, GFP_NOFS);
	if (!path) {
		path = ERR_PTR(-ENOMEM);
		goto out;
	}

	ret = symlink_item_ops(sb, SYM_LOOKUP, scoutfs_ino(inode), inode_lock,
			       path, size);

	/* XXX corruption: missing items or not null term */
	if (ret == -ENOENT || (ret == 0 && path[size - 1]))
		ret = -EIO;

	if (ret < 0) {
		kfree(path);
		path = ERR_PTR(ret);
	} else {
		nd_set_link(nd, path);
	}
out:
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
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
	struct scoutfs_lock *dir_lock;
	struct scoutfs_lock *inode_lock = NULL;
	DECLARE_ITEM_COUNT(cnt);
	int ret;

	/* path_max includes null as does our value for nd_set_link */
	if (name_len > PATH_MAX || name_len > SCOUTFS_SYMLINK_MAX_SIZE)
		return -ENAMETOOLONG;

	ret = alloc_dentry_info(dentry);
	if (ret)
		return ret;

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(dir),
				     &dir_lock);
	if (ret)
		return ret;

	scoutfs_count_symlink(&cnt, dentry->d_name.len, name_len);
	ret = scoutfs_hold_trans(sb, &cnt);
	if (ret)
		goto out_unlock;

	inode = scoutfs_new_inode(sb, dir, S_IFLNK|S_IRWXUGO, 0);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(inode),
				     &inode_lock);
	if (ret)
		goto out;

	ret = symlink_item_ops(sb, SYM_CREATE, scoutfs_ino(inode), inode_lock,
			       symname, name_len);
	if (ret)
		goto out;

	ret = add_entry_items(dir, dir_lock, dentry, inode, inode_lock);
	if (ret)
		goto out;

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

	inode->i_ctime = dir->i_mtime;
	i_size_write(inode, name_len);

	scoutfs_update_inode_item(inode);
	scoutfs_update_inode_item(dir);

	insert_inode_hash(inode);
	/* XXX need to set i_op/fop before here for sec callbacks */
	d_instantiate(dentry, inode);
out:
	if (ret < 0) {
		if (!IS_ERR_OR_NULL(inode))
			iput(inode);

		symlink_item_ops(sb, SYM_DELETE, scoutfs_ino(inode), inode_lock,
				 NULL, name_len);
	}

	scoutfs_release_trans(sb);
out_unlock:
	scoutfs_unlock(sb, dir_lock, DLM_LOCK_EX);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_EX);
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
 * given dir inode and null terminated name.  If we find a backref item
 * we add an allocated copy of it to the head of the caller's list.
 *
 * Returns 0 if we added an entry, -ENOENT if we didn't, and -errno for
 * search errors.
 */
static int add_next_linkref(struct super_block *sb, u64 ino,
			    u64 dir_ino, char *name, unsigned int name_len,
			    struct list_head *list)
{
	struct scoutfs_link_backref_key last_lbkey;
	struct scoutfs_link_backref_entry *ent;
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	int len;
	int ret;

	ent = kmalloc(offsetof(struct scoutfs_link_backref_entry,
			       lbkey.name[SCOUTFS_NAME_LEN + 1]), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	INIT_LIST_HEAD(&ent->head);

	/* put search key in ent */
	init_link_backref_key(&key, &ent->lbkey, ino, dir_ino, name, name_len);
	/* we actually have room for a full backref item */
	scoutfs_key_init_buf_len(&key, key.data, key.key_len,
				 offsetof(struct scoutfs_link_backref_key,
					  name[SCOUTFS_NAME_LEN + 1]));

	/* small last key to avoid full name copy, XXX enforce no U64_MAX ino */
	init_link_backref_key(&last, &last_lbkey, ino, U64_MAX, NULL, 0);

	/* next backref key is now in ent */
	ret = scoutfs_item_next(sb, &key, &last, NULL, NULL);
	trace_printk("ino %llu dir_ino %llu ret %d key_len %u\n",
		      ino, dir_ino, ret, key.key_len);
	if (ret < 0)
		goto out;


	len = (int)key.key_len - sizeof(struct scoutfs_link_backref_key);
	/* XXX corruption */
	if (len < 1 || len > SCOUTFS_NAME_LEN) {
		ret = -EIO;
		goto out;
	}

	ent->name_len = len;
	list_add(&ent->head, list);
	ret = 0;
out:
	if (list_empty(&ent->head))
		kfree(ent);
	return ret;
}

static u64 first_backref_dir_ino(struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;

	ent = list_first_entry(list, struct scoutfs_link_backref_entry, head);
	return be64_to_cpu(ent->lbkey.dir_ino);
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
				 char *name, u16 name_len,
				 struct list_head *list)
{
	u64 par_ino;
	int ret;

retry:
	/* get the next link name to the given inode */
	ret = add_next_linkref(sb, ino, dir_ino, name, name_len, list);
	if (ret < 0)
		goto out;

	/* then get the names of all the parent dirs */
	par_ino = first_backref_dir_ino(list);
	while (par_ino != SCOUTFS_ROOT_INO) {

		ret = add_next_linkref(sb, par_ino, 0, NULL, 0, list);
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

const struct file_operations scoutfs_dir_fops = {
	.readdir	= scoutfs_readdir,
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
	.setxattr	= scoutfs_setxattr,
	.getxattr	= scoutfs_getxattr,
	.listxattr	= scoutfs_listxattr,
	.removexattr	= scoutfs_removexattr,
	.symlink	= scoutfs_symlink,
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
