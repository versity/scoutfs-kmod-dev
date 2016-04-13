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

#include "format.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "super.h"
#include "btree.h"

/*
 * Directory entries are stored in entries with offsets calculated from
 * the hash of their entry name.
 *
 * The upside of having a single namespace of items used for both lookup
 * and readdir iteration reduces the storage overhead of directories.
 * The downside is that dirent operations produce random item access
 * patterns.
 *
 * Hash values are limited to 31 bits to avoid bugs from use of 31 bit
 * signed offsets.  We also avoid bugs in network protocols limited to
 * 32 bit directory positions.
 *
 * We have to worry about collisions because we're using the hash of the
 * name.  We simply allow a name to be stored at multiple hash value
 * locations.  Create iterates until it finds an unused value and lookup
 * iterates until it finds an entry at a hash that matches the name.  We
 * can store the max iteration used during create in the directory to
 * limit the number of values we'll check in lookup.  With 31bit hash
 * values we can get tens of thousands of entries before we use two
 * hashes, hundreds for three, millions for four, and so on.  The vast
 * majority of directories will use one hash value.
 *
 * This would be a crazy design in systems where dirent lookups perform
 * dependent block reads down a radix or btree structure for each hash
 * value.  scoutfs makes this a lot cheaper by using the bloom filters
 * in the log segments to short circuit negative item lookups. 
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

static int names_equal(const char *name_a, int len_a, const char *name_b,
		       int len_b)
{
	return (len_a == len_b) && !memcmp(name_a, name_b, len_a);
}

/*
 * Return the offset portion of a dirent key from the hash of the name.
 * The hash can't be 0 or 1 for . and .. and we chose to limit the max
 * file->f_pos.
 *
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
 * Store the dirent item hash in the dentry so that we don't have to
 * calculate and search to remove the item. 
 */
struct dentry_info {
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
	struct scoutfs_key key;
	unsigned int name_len;
	struct inode *inode;
	u64 ino = 0;
	u32 h = 0;
	int ret;
	int i;

	if (si->max_dirent_hash_nr == 0) {
		ret = -ENOENT;
		goto out;
	}

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di)) {
		ret = PTR_ERR(di);
		goto out;
	}

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	h = si->salt;
	for (i = 0; i < si->max_dirent_hash_nr; i++) {
		h = name_hash(dentry->d_name.name, dentry->d_name.len, h);
		scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);

		scoutfs_btree_release(&curs);
		ret = scoutfs_btree_lookup(sb, &key, &curs);
		if (ret == -ENOENT)
			continue;
		if (ret < 0)
			break;

		dent = curs.val;
		name_len = item_name_len(&curs);
		if (names_equal(dentry->d_name.name, dentry->d_name.len,
				dent->name, name_len)) {
			ino = le64_to_cpu(dent->ino);
			ret = 0;
			break;
		} else {
			ret = -ENOENT;
		}
	}

	scoutfs_btree_release(&curs);
out:
	if (ret == -ENOENT) {
		inode = NULL;
	} else if (ret) {
		inode = ERR_PTR(ret);
	} else {
		di->hash = h;
		inode = scoutfs_iget(sb, ino);
	}

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
 * readdir finds the next entry at or past the hash|coll_nr stored in
 * the current file position.
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

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(dir);
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct inode *inode = NULL;
	struct scoutfs_dirent *dent;
	struct dentry_info *di;
	struct scoutfs_key key;
	int bytes;
	int ret;
	u64 h;
	int i;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di))
		return PTR_ERR(di);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_dirty_inode_item(dir);
	if (ret)
		return ret;

	inode = scoutfs_new_inode(sb, dir, mode, rdev);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	bytes = dent_bytes(dentry->d_name.len);

	h = si->salt;
	for (i = 0; i < SCOUTFS_MAX_DENT_HASH_NR; i++) {
		h = name_hash(dentry->d_name.name, dentry->d_name.len, h);
		scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);

		ret = scoutfs_btree_insert(sb, &key, bytes, &curs);
		if (ret != -EEXIST)
			break;
	}
	if (ret) {
		if (ret == -EEXIST)
			ret = -ENOSPC;
		goto out;
	}

	dent = curs.val;
	dent->ino = cpu_to_le64(scoutfs_ino(inode));
	dent->type = mode_to_type(inode->i_mode);
	memcpy(dent->name, dentry->d_name.name, dentry->d_name.len);
	di->hash = h;

	scoutfs_btree_release(&curs);

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	si->max_dirent_hash_nr = max_t(int, i + 1, si->max_dirent_hash_nr);
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
	int ret = 0;

	if (WARN_ON_ONCE(!dentry->d_fsdata))
		return -EINVAL;
	di = dentry->d_fsdata;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode))
		return -ENOTEMPTY;

	ret = scoutfs_dirty_inode_item(dir) ?:
	      scoutfs_dirty_inode_item(inode);
	if (ret)
		return ret;

	scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, di->hash);

	ret = scoutfs_btree_delete(sb, &key);
	if (ret)
		goto out;

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
	.unlink		= scoutfs_unlink,
	.rmdir		= scoutfs_unlink,
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
