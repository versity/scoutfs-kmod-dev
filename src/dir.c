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
#include "key.h"
#include "super.h"
#include "btree.h"
#include "trans.h"
#include "name.h"
#include "xattr.h"
#include "kvec.h"
#include "item.h"

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

static struct dentry *scoutfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_dirent_key dkey;
	struct scoutfs_dirent dent;
	SCOUTFS_DECLARE_KVEC(key);
	SCOUTFS_DECLARE_KVEC(val);
	struct inode *inode;
	u64 ino = 0;
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	dkey.type = SCOUTFS_DIRENT_KEY;
	dkey.ino = cpu_to_be64(scoutfs_ino(dir));
	scoutfs_kvec_init(key, &dkey, sizeof(dkey),
			  (void *)dentry->d_name.name, dentry->d_name.len);

	scoutfs_kvec_init(val, &dent, sizeof(dent));

	ret = scoutfs_item_lookup_exact(sb, key, val, sizeof(dent));
	if (ret == -ENOENT) {
		ino = 0;
		ret = 0;
	} else if (ret == 0) {
		ino = le64_to_cpu(dent.ino);
	}

out:
	if (ret < 0)
		inode = ERR_PTR(ret);
	else if (ino == 0)
		inode = NULL;
	else
		inode = scoutfs_iget(sb, ino);

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
	struct scoutfs_readdir_key rkey;
	struct scoutfs_readdir_key last_rkey;
	SCOUTFS_DECLARE_KVEC(key);
	SCOUTFS_DECLARE_KVEC(last_key);
	SCOUTFS_DECLARE_KVEC(val);
	unsigned int item_len;
	unsigned int name_len;
	u64 pos;
	int ret;

	if (!dir_emit_dots(file, dirent, filldir))
		return 0;

	rkey.type = SCOUTFS_READDIR_KEY;
	rkey.ino = cpu_to_be64(scoutfs_ino(inode));
	/* pos set in each loop */
	scoutfs_kvec_init(key, &rkey, sizeof(rkey));

	last_rkey.type = SCOUTFS_READDIR_KEY;
	last_rkey.ino = cpu_to_be64(scoutfs_ino(inode));
	last_rkey.pos = cpu_to_be64(SCOUTFS_DIRENT_LAST_POS);
	scoutfs_kvec_init(last_key, &last_rkey, sizeof(last_rkey));

	item_len = offsetof(struct scoutfs_dirent, name[SCOUTFS_NAME_LEN]);
	dent = kmalloc(item_len, GFP_KERNEL);
	if (!dent)
		return -ENOMEM;

	for (;;) {
		rkey.pos = cpu_to_be64(file->f_pos);
		scoutfs_kvec_init(val, dent, item_len);
		ret = scoutfs_item_next_same_min(sb, key, last_key, val,
				offsetof(struct scoutfs_dirent, name[1]));
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

	kfree(dent);
	return ret;
}

#if 0
static void set_lref_key(struct scoutfs_key *key, u64 ino, u64 ctr)
{
	scoutfs_set_key(key, ino, SCOUTFS_LINK_BACKREF_KEY, ctr);
}

static int update_lref_item(struct super_block *sb, struct scoutfs_key *key,
			    u64 dir_ino, u64 dir_off, bool update)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_link_backref lref;
	struct scoutfs_btree_val val;
	int ret;

	lref.ino = cpu_to_le64(dir_ino);
	lref.offset = cpu_to_le64(dir_off);

	scoutfs_btree_init_val(&val, &lref, sizeof(lref));

	if (update)
		ret = scoutfs_btree_update(sb, meta, key, &val);
	else
		ret = scoutfs_btree_insert(sb, meta, key, &val);

	return ret;
}
#endif

static int add_entry_items(struct inode *dir, struct dentry *dentry,
			   struct inode *inode)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_dirent_key dkey;
	struct scoutfs_dirent dent;
	SCOUTFS_DECLARE_KVEC(key);
	SCOUTFS_DECLARE_KVEC(val);
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_dirty_inode_item(dir);
	if (ret)
		return ret;

	/* dirent item for lookup */
	dkey.type = SCOUTFS_DIRENT_KEY;
	dkey.ino = cpu_to_be64(scoutfs_ino(dir));
	scoutfs_kvec_init(key, &dkey, sizeof(dkey),
			  (void *)dentry->d_name.name, dentry->d_name.len);

	dent.ino = cpu_to_le64(scoutfs_ino(inode));
	dent.type = mode_to_type(inode->i_mode);
	scoutfs_kvec_init(val, &dent, sizeof(dent));

	ret = scoutfs_item_create(sb, key, val);
	if (ret)
		return ret;

#if 0
	struct scoutfs_inode_info *si = SCOUTFS_I(dir);

	/* readdir item for .. readdir */
	si->readdir_pos++;
	rkey.type = SCOUTFS_READDIR_KEY;
	rkey.ino = cpu_to_le64(scoutfs_ino(dir));
	rkey.pos = cpu_to_le64(si->readdir_pos);
	scoutfs_kvec_init(key, &rkey, sizeof(rkey));

	scoutfs_kvec_init(val, &dent, sizeof(dent),
			dentry->d_name.name, dentry->d_name.len);

	ret = scoutfs_item_create(sb, key, val);
	if (ret)
		goto out_dent;

	/* backref item for inode to path resolution */
	lrkey.type = SCOUTFS_LINK_BACKREF_KEY;
	lrey.ino = cpu_to_le64(scoutfs_ino(inode));
	lrey.dir = cpu_to_le64(scoutfs_ino(dir));
	scoutfs_kvec_init(key, &lrkey, sizeof(lrkey),
			  dentry->d_name.name, dentry->d_name.len);

	ret = scoutfs_item_create(sb, key, NULL);
	if (ret) {
		scoutfs_kvec_init(key, &rkey, sizeof(rkey));
		scoutfs_item_delete(sb, key);
out_dent:
		scoutfs_kvec_init(key, &dkey, sizeof(dkey),
			  dentry->d_name.name, dentry->d_name.len);
		scoutfs_item_delete(sb, key);
	}
#endif

	return ret;
}

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	int ret;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	inode = scoutfs_new_inode(sb, dir, mode, rdev);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	ret = add_entry_items(dir, dentry, inode);
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
	/* XXX delete the inode item here */
	if (ret && !IS_ERR_OR_NULL(inode))
		iput(inode);
	scoutfs_release_trans(sb);
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
	int ret;

	if (inode->i_nlink >= SCOUTFS_LINK_MAX)
		return -EMLINK;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	ret = add_entry_items(dir, dentry, inode);
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
	struct scoutfs_dirent_key dkey;
	SCOUTFS_DECLARE_KVEC(key);
	int ret = 0;

	/* will need to add deletion items */
	return -EINVAL;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode))
		return -ENOTEMPTY;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	ret = scoutfs_dirty_inode_item(dir) ?:
	      scoutfs_dirty_inode_item(inode);
	if (ret)
		goto out;

	/* XXX same items as add_entry_items */
	dkey.type = SCOUTFS_DIRENT_KEY;
	dkey.ino = cpu_to_be64(scoutfs_ino(dir));
	scoutfs_kvec_init(key, &dkey, sizeof(dkey),
			  (void *)dentry->d_name.name, dentry->d_name.len);

	ret = scoutfs_item_delete(sb, key);
	if (ret)
		goto out;

	if ((inode->i_nlink == 1) ||
	    (S_ISDIR(inode->i_mode) && inode->i_nlink == 2)) {
		/*
		 * Insert the orphan item before we modify any inode
		 * metadata so we can gracefully exit should it
		 * fail.
		 */
		ret = scoutfs_orphan_inode(inode);
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
	scoutfs_update_inode_item(inode);
	scoutfs_update_inode_item(dir);

out:
	scoutfs_release_trans(sb);
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
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	loff_t size = i_size_read(inode);
	struct scoutfs_btree_val val;
	struct scoutfs_key key;
	char *path;
	int bytes;
	int off;
	int ret;
	int k;

	/* update for kvec items */
	return ERR_PTR(-EINVAL);

	/* XXX corruption */
	if (size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE)
		return ERR_PTR(-EIO);

	/* unlikely, but possible I suppose */
	if (size > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	path = kmalloc(size, GFP_NOFS);
	if (!path)
		return ERR_PTR(-ENOMEM);

	for (off = 0, k = 0; off < size ; k++) {
		scoutfs_set_key(&key, scoutfs_ino(inode),
				SCOUTFS_SYMLINK_KEY, k);
		bytes = min_t(int, size - off, SCOUTFS_MAX_ITEM_LEN);
		scoutfs_btree_init_val(&val, path + off, bytes);
		val.check_size_eq = 1;

		ret = scoutfs_btree_lookup(sb, meta, &key, &val);
		if (ret < 0) {
			/* XXX corruption */
			if (ret == -ENOENT)
				ret = -EIO;
			break;
		}

		off += bytes;
		ret = 0;
	}

	/* XXX corruption */
	if (ret == 0 && (off != size || path[off - 1] != '\0'))
		ret = -EIO;

	if (ret) {
		kfree(path);
		path = ERR_PTR(ret);
	} else {
		nd_set_link(nd, path);
	}

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
 * Symlink target paths can be annoyingly huge.  We don't want large
 * items gumming up the btree so we store relatively rare large paths in
 * multiple items.
 */
static int scoutfs_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct inode *inode = NULL;
	struct scoutfs_key key;
	const int name_len = strlen(symname) + 1;
	int off;
	int bytes;
	int ret;
	int k = 0;

	/* update for kvec items */
	return -EINVAL;

	/* path_max includes null as does our value for nd_set_link */
	if (name_len > PATH_MAX || name_len > SCOUTFS_SYMLINK_MAX_SIZE)
		return -ENAMETOOLONG;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	inode = scoutfs_new_inode(sb, dir, S_IFLNK|S_IRWXUGO, 0);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	for (k = 0, off = 0; off < name_len; off += bytes, k++) {
		scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_SYMLINK_KEY,
				k);
		bytes = min(name_len - off, SCOUTFS_MAX_ITEM_LEN);

		scoutfs_btree_init_val(&val, (char *)symname + off, bytes);

		ret = scoutfs_btree_insert(sb, meta, &key, &val);
		if (ret)
			goto out;
	}

	ret = add_entry_items(dir, dentry, inode);
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

		while (k--) {
			scoutfs_set_key(&key, scoutfs_ino(inode),
					SCOUTFS_SYMLINK_KEY, k);
			scoutfs_btree_delete(sb, meta, &key);
		}
	}

	scoutfs_release_trans(sb);
	return ret;
}

/*
 * Delete all the symlink items.  There should only ever be a handful of
 * these that contain the target path of the symlink.
 */
int scoutfs_symlink_drop(struct super_block *sb, u64 ino)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_key key;
	int ret;
	int nr;
	int k;

	nr = DIV_ROUND_UP(SCOUTFS_SYMLINK_MAX_SIZE, SCOUTFS_MAX_ITEM_LEN);

	for (k = 0; k < nr; k++) {
		scoutfs_set_key(&key, ino, SCOUTFS_SYMLINK_KEY, k);

		ret = scoutfs_btree_delete(sb, meta, &key);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}
	}

	return ret;
}

/*
 * Store the null terminated path component that links to the inode at
 * the given counter in the callers buffer.
 *
 * This is implemented by searching for link backrefs on the inode
 * starting from the given counter.  Those contain references to the
 * parent directory and dirent key offset that contain the link to the
 * inode.
 *
 * The caller holds no locks that protect components in the path.  We
 * search the link backref to find the parent dir then acquire it's
 * i_mutex to make sure that its entries and backrefs are stable.  If
 * the next backref points to a different dir after we acquire the lock
 * we bounce off and retry.
 *
 * Backref counters are never reused and rename only modifies the
 * existing backref counter under the dir's mutex.
 */
static int append_linkref_name(struct super_block *sb, u64 *dir_ino, u64 ino,
			       u64 *ctr, char *path, unsigned int bytes)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_link_backref lref;
	struct scoutfs_btree_val val;
	struct scoutfs_dirent dent;
	struct inode *inode = NULL;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key key;
	u64 retried = 0;
	u64 off;
	int len;
	int ret;

retry:
	scoutfs_set_key(&first, ino, SCOUTFS_LINK_BACKREF_KEY, *ctr);
	scoutfs_set_key(&last, ino, SCOUTFS_LINK_BACKREF_KEY, ~0ULL);

	scoutfs_btree_init_val(&val, &lref, sizeof(lref));
	val.check_size_eq = 1;

	ret = scoutfs_btree_next(sb, meta, &first, &last, &key, &val);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	*dir_ino = le64_to_cpu(lref.ino),
	off = le64_to_cpu(lref.offset);
	*ctr = scoutfs_key_offset(&key);

	trace_printk("ino %llu ctr %llu dir_ino %llu off %llu\n",
		     ino, *ctr, *dir_ino, off);

	/* XXX corruption, should never be key == U64_MAX */
	if (*ctr == U64_MAX) {
		ret = -EIO;
		goto out;
	}

	/* XXX should verify ino and offset, too */

	if (inode && scoutfs_ino(inode) != *dir_ino) {
		mutex_unlock(&inode->i_mutex);
		iput(inode);
		inode = NULL;
	}

	if (!inode) {
		inode = scoutfs_iget(sb, *dir_ino);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			inode = NULL;
			if (ret == -ENOENT && retried != *dir_ino) {
				retried = *dir_ino;
				goto retry;
			}
			goto out;
		}

		mutex_lock(&inode->i_mutex);
		goto retry;
	}

	scoutfs_set_key(&key, *dir_ino, SCOUTFS_DIRENT_KEY, off);
	scoutfs_btree_init_val(&val, &dent, sizeof(dent), path, bytes - 1);
	val.check_size_lte = 1;

	ret = scoutfs_btree_lookup(sb, meta, &key, &val);
	if (ret < 0) {
		/* XXX corruption, should always have dirent for backref */
		if (ret == -ENOENT)
			ret = -EIO;
		else if (ret == -EOVERFLOW)
			ret = -ENAMETOOLONG;
		goto out;
	}

	/* XXX corruption */
	if (ret <= sizeof(dent)) {
		ret = -EIO;
		goto out;
	}

	len = ret - sizeof(dent); /* just name len, no null term */

	/* XXX corruption */
	if (len > SCOUTFS_NAME_LEN || le64_to_cpu(dent.ino) != ino) {
		ret = -EIO;
		goto out;
	}

	trace_printk("dent ino %llu len %d\n", le64_to_cpu(dent.ino), len);

	(*ctr)++;
	path[len] = '\0';
	ret = len + 1;
out:
	if (inode) {
		mutex_unlock(&inode->i_mutex);
		iput(inode);
	}

	return ret;
}

/*
 * Fill the caller's buffer with the null terminated path components
 * from the target inode to the root.  These will be in the opposite
 * order of a typical slash delimited path.  The caller's ctr gives the
 * specific link to start from.
 *
 * This is racing with modification of components in the path.  We can
 * traverse a partial path only to find that it's been blown away
 * entirely.  If we see a component go missing we retry.  The removal of
 * the final link to the inode should prevent repeatedly traversing
 * paths that no longer exist.
 *
 * Returns > 0 and *ctr is updated if a full path from the link to the
 * root dir was filled, 0 if no name past *ctr was found, or -errno on
 * errors.
 */
int scoutfs_dir_get_ino_path(struct super_block *sb, u64 ino, u64 *ctr,
			     char *path, unsigned int bytes)
{
	u64 final_ctr;
	u64 par_ctr;
	u64 par_ino;
	int ret;
	int nr;

	/* update for kvec items */
	return -EINVAL;

	if (*ctr == U64_MAX)
		return 0;

retry:
	final_ctr = *ctr;
	ret = 0;

	/* get the next link name to the given inode */
	nr = append_linkref_name(sb, &par_ino, ino, &final_ctr, path, bytes);
	if (nr <= 0) {
		ret = nr;
		goto out;
	}
	ret += nr;

	/* then get the names of all the parent dirs */
	while (par_ino != SCOUTFS_ROOT_INO) {
		par_ctr = 0;
		nr = append_linkref_name(sb, &par_ino, par_ino, &par_ctr,
					 path + ret, bytes - ret);
		if (nr < 0) {
			ret = nr;
			goto out;
		}

		/* restart if there was no parent component */
		if (nr == 0)
			goto retry;

		ret += nr;
	}

out:
	*ctr = final_ctr;
	return ret;
}

const struct file_operations scoutfs_dir_fops = {
	.readdir	= scoutfs_readdir,
	.fsync		= scoutfs_file_fsync,
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
