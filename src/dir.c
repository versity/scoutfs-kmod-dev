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

#include "format.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "super.h"
#include "btree.h"
#include "trans.h"
#include "name.h"
#include "xattr.h"

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
 * XXX This crc nonsense is a quick hack.  We'll want something a
 * lot stronger like siphash.
 */
static u32 name_hash(const char *name, unsigned int len, u32 salt)
{
	u32 h = crc32c(salt, name, len) & SCOUTFS_DIRENT_OFF_MASK;

	return max_t(u32, 2, min_t(u32, h, SCOUTFS_DIRENT_LAST_POS));
}

static unsigned int dent_bytes(unsigned int name_len)
{
	return sizeof(struct scoutfs_dirent) + name_len;
}

static unsigned int item_name_len(struct scoutfs_btree_cursor *curs)
{
	return curs->val_len - sizeof(struct scoutfs_dirent);
}

/*
 * Each dirent stores the values that are needed to build the keys of
 * the items that are removed on unlink so that we don't to search through
 * items on unlink.
 */
struct dentry_info {
	u64 lref_counter;
	u32 hash;
};

static struct kmem_cache *scoutfs_dentry_cachep;

static void scoutfs_d_release(struct dentry *dentry)
{
	struct dentry_info *di = dentry->d_fsdata;

	if (di) {
		kmem_cache_free(scoutfs_dentry_cachep, di);
		dentry->d_fsdata = NULL;
	}
}

static const struct dentry_operations scoutfs_dentry_ops = {
	.d_release = scoutfs_d_release,
};

static struct dentry_info *alloc_dentry_info(struct dentry *dentry)
{
	struct dentry_info *di;

	/* XXX read mb? */
	if (dentry->d_fsdata)
		return dentry->d_fsdata;

	di = kmem_cache_zalloc(scoutfs_dentry_cachep, GFP_NOFS);
	if (!di)
		return ERR_PTR(-ENOMEM);

	spin_lock(&dentry->d_lock);
	if (!dentry->d_fsdata) {
		dentry->d_fsdata = di;
		d_set_d_op(dentry, &scoutfs_dentry_ops);
	}

	spin_unlock(&dentry->d_lock);

	if (di != dentry->d_fsdata)
		kmem_cache_free(scoutfs_dentry_cachep, di);

	return dentry->d_fsdata;
}

static void update_dentry_info(struct dentry_info *di, struct scoutfs_key *key,
			       struct scoutfs_dirent *dent)
{
	di->lref_counter = le64_to_cpu(dent->counter);
	di->hash = scoutfs_key_offset(key);
}

static u64 last_dirent_key_offset(u32 h)
{
	return min_t(u64, (u64)h + SCOUTFS_DIRENT_COLL_NR - 1,
			  SCOUTFS_DIRENT_LAST_POS);
}

/*
 * Lookup searches for an entry for the given name amongst the entries
 * stored in the item at the name's hash. 
 */
static struct dentry *scoutfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(dir);
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct super_block *sb = dir->i_sb;
	struct scoutfs_dirent *dent;
	struct dentry_info *di;
	struct scoutfs_key first;
	struct scoutfs_key last;
	unsigned int name_len;
	struct inode *inode;
	u64 ino = 0;
	u32 h = 0;
	int ret;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di)) {
		ret = PTR_ERR(di);
		goto out;
	}

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	h = name_hash(dentry->d_name.name, dentry->d_name.len, si->salt);

	scoutfs_set_key(&first, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);
	scoutfs_set_key(&last, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY,
			last_dirent_key_offset(h));

	while ((ret = scoutfs_btree_next(sb, &first, &last, &curs)) > 0) {

		/* XXX verify */

		dent = curs.val;
		name_len = item_name_len(&curs);
		if (scoutfs_names_equal(dentry->d_name.name, dentry->d_name.len,
					dent->name, name_len)) {
			ino = le64_to_cpu(dent->ino);
			update_dentry_info(di, curs.key, dent);
			break;
		}
	}

	scoutfs_btree_release(&curs);

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
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_dirent *dent;
	struct scoutfs_key first;
	struct scoutfs_key last;
	unsigned int name_len;
	int ret;
	u32 pos;

	if (!dir_emit_dots(file, dirent, filldir))
		return 0;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_DIRENT_KEY,
			file->f_pos);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_DIRENT_KEY,
			SCOUTFS_DIRENT_LAST_POS);

	while ((ret = scoutfs_btree_next(sb, &first, &last, &curs)) > 0) {
		dent = curs.val;
		name_len = item_name_len(&curs);
		pos = scoutfs_key_offset(curs.key);

		if (filldir(dirent, dent->name, name_len, pos,
			    le64_to_cpu(dent->ino), dentry_type(dent->type))) {
			ret = 0;
			break;
		}

		file->f_pos = pos + 1;
	}

	scoutfs_btree_release(&curs);

	return ret;
}

static void set_lref_key(struct scoutfs_key *key, u64 ino, u64 ctr)
{
	scoutfs_set_key(key, ino, SCOUTFS_LINK_BACKREF_KEY, ctr);
}

static int update_lref_item(struct super_block *sb, struct scoutfs_key *key,
			    u64 dir_ino, u64 dir_off, bool update)
{
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_link_backref *lref;
	int ret;

	if (update)
		ret = scoutfs_btree_update(sb, key, &curs);
	else
		ret = scoutfs_btree_insert(sb, key, sizeof(*lref), &curs);

	/* XXX verify size */
	if (ret == 0) {
		lref = curs.val;
		lref->ino = cpu_to_le64(dir_ino);
		lref->offset = cpu_to_le64(dir_off);
		scoutfs_btree_release(&curs);
	}

	return ret;
}

static int add_entry_items(struct inode *dir, struct dentry *dentry,
			   struct inode *inode)
{
	struct dentry_info *di = dentry->d_fsdata;
	struct super_block *sb = dir->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(dir);
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_dirent *dent;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct scoutfs_key lref_key;
	int bytes;
	int ret;
	u64 h;

	/* caller should have allocated the dentry info */
	if (WARN_ON_ONCE(di == NULL))
		return -EINVAL;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_dirty_inode_item(dir);
	if (ret)
		goto out;

	bytes = dent_bytes(dentry->d_name.len);
	h = name_hash(dentry->d_name.name, dentry->d_name.len, si->salt);
	scoutfs_set_key(&first, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);
	scoutfs_set_key(&last, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY,
			last_dirent_key_offset(h));

	ret = scoutfs_btree_hole(sb, &first, &last, &key);
	if (ret)
		goto out;

	set_lref_key(&lref_key, scoutfs_ino(inode),
		     atomic64_inc_return(&SCOUTFS_I(inode)->link_counter));
	ret = update_lref_item(sb, &lref_key, scoutfs_ino(dir),
			       scoutfs_key_offset(&key), false);
	if (ret)
		goto out;

	ret = scoutfs_btree_insert(sb, &key, bytes, &curs);
	if (ret) {
		scoutfs_btree_delete(sb, &lref_key);
		goto out;
	}

	dent = curs.val;
	dent->ino = cpu_to_le64(scoutfs_ino(inode));
	dent->counter = lref_key.offset;
	dent->type = mode_to_type(inode->i_mode);
	memcpy(dent->name, dentry->d_name.name, dentry->d_name.len);
	update_dentry_info(di, &key, dent);

	scoutfs_btree_release(&curs);
out:
	return ret;
}

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct dentry_info *di;
	int ret;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di))
		return PTR_ERR(di);

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
	struct dentry_info *di;
	int ret;

	if (inode->i_nlink >= SCOUTFS_LINK_MAX)
		return -EMLINK;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di))
		return PTR_ERR(di);

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
	struct dentry_info *di;
	struct scoutfs_key key;
	struct scoutfs_key lref_key;
	int ret = 0;

	if (WARN_ON_ONCE(!dentry->d_fsdata))
		return -EINVAL;
	di = dentry->d_fsdata;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode))
		return -ENOTEMPTY;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	set_lref_key(&lref_key, scoutfs_ino(inode), di->lref_counter);

	ret = scoutfs_dirty_inode_item(dir) ?:
	      scoutfs_dirty_inode_item(inode) ?:
	      scoutfs_btree_dirty(sb, &lref_key);
	if (ret)
		goto out;

	scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, di->hash);

	ret = scoutfs_btree_delete(sb, &key);
	if (ret)
		goto out;

	scoutfs_btree_delete(sb, &lref_key);

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
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	loff_t size = i_size_read(inode);
	struct scoutfs_key first;
	struct scoutfs_key last;
	char *path;
	int off;
	int ret;
	int k;

	/* XXX corruption */
	if (size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE)
		return ERR_PTR(-EIO);

	/* unlikely, but possible I suppose */
	if (size > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	path = kmalloc(size, GFP_NOFS);
	if (!path)
		return ERR_PTR(-ENOMEM);

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_SYMLINK_KEY, 0);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_SYMLINK_KEY, ~0ULL);

	off = 0;
	k = 0;
	while ((ret = scoutfs_btree_next(sb, &first, &last, &curs)) > 0) {
		if (scoutfs_key_offset(curs.key) != k ||
		    off + curs.val_len > size) {
			/* XXX corruption */
			scoutfs_btree_release(&curs);
			ret = -EIO;
			break;
		}

		memcpy(path + off, curs.val, curs.val_len);

		off += curs.val_len;
		k++;
	}

	/* XXX corruption */
	if (ret == 0 && (off != size || path[off - 1] != '\0'))
		ret = -EIO;

	if (ret) {
		kfree(path);
		path = ERR_PTR(ret);
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
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct inode *inode = NULL;
	struct scoutfs_key key;
	struct dentry_info *di;
	const int name_len = strlen(symname) + 1;
	int off;
	int bytes;
	int ret;
	int k = 0;

	/* path_max includes null as does our value for nd_set_link */
	if (name_len > PATH_MAX || name_len > SCOUTFS_SYMLINK_MAX_SIZE)
		return -ENAMETOOLONG;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di))
		return PTR_ERR(di);

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
		bytes = min(name_len, SCOUTFS_MAX_ITEM_LEN);

		ret = scoutfs_btree_insert(sb, &key, bytes, &curs);
		if (ret)
			goto out;

		memcpy(curs.val, symname + off, bytes);
		scoutfs_btree_release(&curs);
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
			scoutfs_btree_delete(sb, &key);
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
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key key;
	int ret;

	scoutfs_set_key(&first, ino, SCOUTFS_SYMLINK_KEY, 0);
	scoutfs_set_key(&last, ino, SCOUTFS_SYMLINK_KEY, ~0ULL);

	while ((ret = scoutfs_btree_next(sb, &first, &last, &curs)) > 0) {
		key = *curs.key;
		first = *curs.key;
		scoutfs_inc_key(&first);
		scoutfs_btree_release(&curs);

		ret = scoutfs_btree_delete(sb, &key);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Add an allocated path component to the callers list which links to
 * the target inode at a counter past the given counter.
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
static int add_linkref_name(struct super_block *sb, u64 *dir_ino, u64 ino,
			    u64 *ctr, struct list_head *list)
{
	struct scoutfs_path_component *comp;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_link_backref *lref;
	struct scoutfs_dirent *dent;
	struct inode *inode = NULL;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key key;
	u64 retried = 0;
	u64 off;
	int len;
	int ret;

	comp = kmalloc(sizeof(struct scoutfs_path_component), GFP_KERNEL);
	if (!comp)
		return -ENOMEM;

retry:
	scoutfs_set_key(&first, ino, SCOUTFS_LINK_BACKREF_KEY, *ctr);
	scoutfs_set_key(&last, ino, SCOUTFS_LINK_BACKREF_KEY, ~0ULL);

	ret = scoutfs_btree_next(sb, &first, &last, &curs);
	if (ret <= 0)
		goto out;

	lref = curs.val;
	*dir_ino = le64_to_cpu(lref->ino),
	off = le64_to_cpu(lref->offset);
	*ctr = scoutfs_key_offset(curs.key);

	trace_printk("ino %llu ctr %llu dir_ino %llu off %llu\n",
		     ino, *ctr, *dir_ino, off);

	scoutfs_btree_release(&curs);

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

	ret = scoutfs_btree_lookup(sb, &key, &curs);
	if (ret < 0) {
		/* XXX corruption, should always have dirent for backref */
		if (ret == -ENOENT)
			ret = -EIO;
		goto out;
	}

	dent = curs.val;
	len = item_name_len(&curs);

	trace_printk("dent ino %llu len %d\n", le64_to_cpu(dent->ino), len);

	/* XXX corruption */
	if (len < 1 || len > SCOUTFS_NAME_LEN) {
		ret = -EIO;
		goto out;
	}

	/* XXX corruption, dirents should always match link backref */
	if (le64_to_cpu(dent->ino) != ino) {
		ret = -EIO;
		goto out;
	}

	(*ctr)++;
	comp->len = len;
	memcpy(comp->name, dent->name, len);
	list_add(&comp->head, list);
	comp = NULL; /* won't be freed */

	scoutfs_btree_release(&curs);
	ret = 1;
out:
	if (inode) {
		mutex_unlock(&inode->i_mutex);
		iput(inode);
	}

	kfree(comp);
	return ret;
}

void scoutfs_dir_free_path(struct list_head *list)
{
	struct scoutfs_path_component *comp;
	struct scoutfs_path_component *tmp;

	list_for_each_entry_safe(comp, tmp, list, head) {
		list_del_init(&comp->head);
		kfree(comp);
	}
}

/*
 * Fill the list with the allocated path components that link the root
 * to the target inode.  The caller's ctr gives the link counter to
 * start from.
 *
 * This is racing with modification of components in the path.  We can
 * traverse a partial path only to find that it's been blown away
 * entirely.  If we see a component go missing we retry.  The removal of
 * the final link to the inode should prevent repeatedly traversing
 * paths that no longer exist.
 *
 * Returns > 0 and *ctr is updated if an allocated name was added to the
 * list, 0 if no name past *ctr was found, or -errno on errors.
 */
int scoutfs_dir_next_path(struct super_block *sb, u64 ino, u64 *ctr,
			  struct list_head *list)
{
	u64 our_ctr;
	u64 par_ctr;
	u64 par_ino;
	int ret;

	if (*ctr == U64_MAX)
		return 0;

retry:
	our_ctr = *ctr;
	/* get the next link name to the given inode */
	ret = add_linkref_name(sb, &par_ino, ino, &our_ctr, list);
	if (ret <= 0)
		goto out;

	/* then get the names of all the parent dirs */
	while (par_ino != SCOUTFS_ROOT_INO) {
		par_ctr = 0;
		ret = add_linkref_name(sb, &par_ino, par_ino, &par_ctr, list);
		if (ret < 0)
			goto out;

		/* restart if there was no parent component */
		if (ret == 0) {
			scoutfs_dir_free_path(list);
			goto retry;
		}
	}

out:
	if (ret > 0)
		*ctr = our_ctr;
	return ret;
}

const struct file_operations scoutfs_dir_fops = {
	.readdir	= scoutfs_readdir,
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
	if (scoutfs_dentry_cachep) {
		kmem_cache_destroy(scoutfs_dentry_cachep);
		scoutfs_dentry_cachep = NULL;
	}
}

int scoutfs_dir_init(void)
{
	scoutfs_dentry_cachep = kmem_cache_create("scoutfs_dentry_info",
						  sizeof(struct dentry_info), 0,
						  SLAB_RECLAIM_ACCOUNT, NULL);
	if (!scoutfs_dentry_cachep)
		return -ENOMEM;

	return 0;
}
