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
#include "segment.h"
#include "super.h"

/*
 * Directory entries are stored in items whose offset is determined by
 * the hash of the entry's name.  This was primarily chosen to minimize
 * the amount of data stored for each entry.
 *
 * Because we're hashing the name we need to worry about collisions.  We
 * store all the entries with the same hash value in the item.  This was
 * done so that create works with one specific item.
 *
 * readdir iterates over these items in hash order.  The high bits of
 * the entry's readdir f_pos come from the item offset while the low
 * bits come from a collision number in the entry.
 *
 * The full readdir position, and thus the absolute max number of
 * entries in a directory, is limited to 2^31 to avoid the risk of
 * breaking legacy environments.  Even with a relatively small 27bit
 * item offset allowing 16 colliding entries gets well into hundreds of
 * millions of entries before an item fills up and we return a premature
 * ENOSPC.  Hundreds of millions in a single dir ought to be, wait for
 * it, good enough for anybody.
 *
 * Each item's contents are protected by the dir inode's i_mutex that
 * callers acquire before calling our dir operations.  If we wanted more
 * fine grained concurrency, and we might, we'd have to be careful to
 * manage the shared items.
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
 *
 * XXX This crc nonsense is a quick hack.  We'll want something a
 * lot stronger like siphash.
 */
static u32 name_hash(struct inode *dir, const char *name, unsigned int len)
{
	struct scoutfs_inode_info *ci = SCOUTFS_I(dir);

	return crc32c(ci->salt, name, len) >> (32 - SCOUTFS_DIRENT_OFF_BITS);
}

static unsigned int dent_bytes(unsigned int name_len)
{
	return sizeof(struct scoutfs_dirent) + name_len;
}

static unsigned int dent_val_off(struct scoutfs_item_ref *ref,
				 struct scoutfs_dirent *dent)
{
	return (char *)dent - (char *)ref->val;
}

static inline struct scoutfs_dirent *next_dent(struct scoutfs_item_ref *ref,
					       struct scoutfs_dirent *dent)
{
	unsigned int next_off;

	next_off = dent_val_off(ref, dent) + dent_bytes(dent->name_len);
	if (next_off == ref->val_len)
		return NULL;

	return ref->val + next_off;
}

#define for_each_item_dent(ref, dent) \
	for (dent = (ref)->val; dent; dent = next_dent(ref, dent))

struct dentry_info {
	/*
	 * The key offset and collision nr are stored so that we don't
	 * have to either hash the name to find the item or compare
	 * names to find the dirent in the item.
	 */
	u32 key_offset;
	u8 coll_nr;
};

static struct kmem_cache *scoutfs_dentry_cachep;

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
	if (!dentry->d_fsdata)
		dentry->d_fsdata = di;
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
	struct super_block *sb = dir->i_sb;
	struct scoutfs_dirent *dent;
	struct dentry_info *di;
	struct scoutfs_key key;
	struct inode *inode;
	DECLARE_SCOUTFS_ITEM_REF(ref);
	u64 ino = 0;
	u32 h = 0;
	u32 nr = 0;
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

	h = name_hash(dir, dentry->d_name.name, dentry->d_name.len);
	scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);

	ret = scoutfs_read_item(sb, &key, &ref);
	if (ret)
		goto out;

	ret = -ENOENT;
	for_each_item_dent(&ref, dent) {
		if (names_equal(dentry->d_name.name, dentry->d_name.len,
				dent->name, dent->name_len)) {
			ino = le64_to_cpu(dent->ino);
			nr = dent->coll_nr;
			ret = 0;
			break;
		}
	}

	scoutfs_put_ref(&ref);
out:
	if (ret == -ENOENT) {
		inode = NULL;
	} else if (ret) {
		inode = ERR_PTR(ret);
	} else {
		di->key_offset = h;
		di->coll_nr = nr;
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
	DECLARE_SCOUTFS_ITEM_REF(ref);
	struct scoutfs_dirent *dent;
	struct scoutfs_key first;
	struct scoutfs_key last;
	LIST_HEAD(iter_list);
	int ret = 0;
	u32 off;
	u32 pos;
	u32 nr;

	if (!dir_emit_dots(file, dirent, filldir))
		return 0;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_DIRENT_KEY,
			file->f_pos >> SCOUTFS_DIRENT_COLL_BITS);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_DIRENT_KEY,
			SCOUTFS_DIRENT_OFF_MASK);

	for(;;) {
		scoutfs_put_ref(&ref);
		ret = scoutfs_next_item(sb, &first, &last, &iter_list, &ref);
		if (ret)
			break;

		/* start from first collision if we're in a new item */
		if (scoutfs_key_offset(&first) == scoutfs_key_offset(ref.key))
			nr = file->f_pos & SCOUTFS_DIRENT_COLL_MASK;
		else
			nr = 0;

		off = scoutfs_key_offset(ref.key) << SCOUTFS_DIRENT_COLL_BITS;
		for_each_item_dent(&ref, dent) {
			if (dent->coll_nr < nr)
				continue;

			pos = off | dent->coll_nr;

			if (filldir(dirent, dent->name, dent->name_len, pos,
				    le64_to_cpu(dent->ino),
				    dentry_type(dent->type)))
				break;

			file->f_pos = pos + 1;
		}
		/* done if filldir broke the loop */
		if (dent)
			break;

		first = *ref.key;
		scoutfs_inc_key(&first);
	}

	scoutfs_put_ref(&ref);
	scoutfs_put_iter_list(&iter_list);

	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

static int scoutfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	struct scoutfs_dirent *dent;
	DECLARE_SCOUTFS_ITEM_REF(ref);
	struct dentry_info *di;
	struct scoutfs_key key;
	int bytes;
	int ret;
	u64 nr;
	u64 h;

	di = alloc_dentry_info(dentry);
	if (IS_ERR(di))
		return PTR_ERR(di);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	inode = scoutfs_new_inode(sb, dir, mode, rdev);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	h = name_hash(dir, dentry->d_name.name, dentry->d_name.len);
	scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY, h);
	bytes = dent_bytes(dentry->d_name.len);

	ret = scoutfs_read_item(sb, &key, &ref);
	if (ret != -ENOENT) {
		/* XXX implement many hashes, not coll nr */
		if (WARN_ON_ONCE(!ret)) {
			scoutfs_put_ref(&ref);
			ret = -ENOSPC;
		}
		goto out;
	}

	ret = scoutfs_create_item(sb, &key, bytes, &ref);
	if (ret)
		goto out;

	dent = ref.val;
	nr = 0;
	dent->ino = cpu_to_le64(scoutfs_ino(inode));
	dent->type = mode_to_type(inode->i_mode);
	dent->coll_nr = nr;
	dent->name_len = dentry->d_name.len;
	memcpy(dent->name, dentry->d_name.name, dent->name_len);
	di->key_offset = h;
	di->coll_nr = nr;

	scoutfs_put_ref(&ref);

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
	DECLARE_SCOUTFS_ITEM_REF(ref);
	struct dentry_info *di;
	struct scoutfs_key key;
	int ret = 0;

	if (WARN_ON_ONCE(!dentry->d_fsdata))
		return -EINVAL;
	di = dentry->d_fsdata;

	trace_printk("dir size %llu entry k_off nr %u %u\n",
		     i_size_read(inode), di->key_offset, di->coll_nr);

	if (S_ISDIR(inode->i_mode) && i_size_read(inode))
		return -ENOTEMPTY;

	scoutfs_set_key(&key, scoutfs_ino(dir), SCOUTFS_DIRENT_KEY,
			di->key_offset);

	ret = scoutfs_read_item(sb, &key, &ref);
	if (ret)
		goto out;

	ret = scoutfs_delete_item(sb, &ref);
	scoutfs_put_ref(&ref);
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
