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
#include <linux/dcache.h>
#include <linux/xattr.h>

#include "format.h"
#include "inode.h"
#include "key.h"
#include "super.h"
#include "btree.h"
#include "trans.h"
#include "name.h"
#include "xattr.h"

/*
 * xattrs are stored in items with offsets set to the hash of their
 * name.  The item's value contains the xattr name and value.
 *
 * We reserve a few low bits of the key offset for hash collisions.
 * Lookup walks collisions looking for an xattr with its name and create
 * looks for a hole in the colliding key space for the new xattr.
 *
 * Usually btree block locking would protect the atomicity of xattr
 * value updates.  Lookups would have to wait for modification to
 * finish.  But the collision items are updated with multiple btree
 * operations.  And we insert new items before deleting the old so that
 * we can always unwind on errors.  This means that there can be
 * multiple versions of an xattr in the btree.  So we add an inode rw
 * semaphore around xattr operations.
 *
 * XXX
 *  - add acl support and call generic xattr->handlers for SYSTEM
 *  - remove all xattrs on unlink
 */

/* the value immediately follows the name and there is no null termination */
static char *xat_value(struct scoutfs_xattr *xat)
{
	return &xat->name[xat->name_len];
}

static unsigned int xat_bytes(unsigned int name_len, unsigned int value_len)
{
	return offsetof(struct scoutfs_xattr, name[name_len + value_len]);
}

/*
 * The caller provides an initialized cursor.
 *
 * If we return > 0 then the cursor points to an xattr with the given
 * name and the caller must clean up the cursor.
 *
 * Returns 0 when no matching xattr is found or -errno on error.
 */
static int lookup_xattr(struct inode *inode, const char *name,
			unsigned int name_len,
			struct scoutfs_btree_cursor *curs)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_xattr *xat;
	int ret;
	u64 h;

	if (name_len > SCOUTFS_MAX_XATTR_NAME_LEN)
		return -EINVAL;

	/* XXX could be a lookup helper? */
	h = scoutfs_name_hash(name, name_len) & ~SCOUTFS_XATTR_HASH_MASK;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, h);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_XATTR_KEY,
			h | SCOUTFS_XATTR_HASH_MASK);

	while ((ret = scoutfs_btree_next(sb, &first, &last, curs)) > 0) {
		xat = curs->val;

		if (scoutfs_names_equal(name, name_len, xat->name,
					xat->name_len))
			break;
	}

	if (ret <= 0)
		scoutfs_btree_release(curs);

	return ret;
}

/*
 * Insert a new xattr and set the caller's key to the key that we used.
 * The caller is responsible for managing transactions and locking.
 */
static int insert_xattr(struct inode *inode, const char *name,
			unsigned int name_len, const void *value, size_t size,
			struct scoutfs_key *key)
{
	struct super_block *sb = inode->i_sb;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_xattr *xat;
	struct scoutfs_key first;
	struct scoutfs_key last;
	int ret;
	u64 h;

	if (name_len > SCOUTFS_MAX_XATTR_NAME_LEN ||
	    size > SCOUTFS_MAX_XATTR_NAME_LEN)
		return -EINVAL;

	/* XXX could be a lookup helper? */
	h = scoutfs_name_hash(name, name_len) & ~SCOUTFS_XATTR_HASH_MASK;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, h);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_XATTR_KEY,
			h | SCOUTFS_XATTR_HASH_MASK);

	/* find the first unoccupied key offset after the hashed name */
	ret = scoutfs_btree_hole(sb, &first, &last, key);
	if (ret)
		return ret;

	ret = scoutfs_btree_insert(sb, key, xat_bytes(name_len, size), &curs);
	if (!ret) {
		xat = curs.val;
		xat->name_len = name_len;
		xat->value_len = size;
		memcpy(xat->name, name, name_len);
		memcpy(xat_value(xat), value, size);

		scoutfs_btree_release(&curs);
	}

	return ret;
}

/*
 * This will grow to have all the supported prefixes (then will turn
 * into xattr_handlers with prefixes upstream).
 */
static int unknown_prefix(const char *name)
{
	return strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);
}

ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	size_t name_len = strlen(name);
	struct scoutfs_xattr *xat;
	int ret;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	down_read(&si->xattr_rwsem);

	ret = lookup_xattr(inode, name, name_len, &curs);
	if (ret == 0) {
		ret = -ENODATA;
	} else if (ret > 0) {
		xat = curs.val;

		ret = xat->value_len;
		if (buffer) {
			if (ret <= size)
				memcpy(buffer, xat_value(xat), ret);
			else
				ret = -ERANGE;
		}
		scoutfs_btree_release(&curs);
	}

	up_read(&si->xattr_rwsem);

	return ret;
}

/*
 * Set the xattr with the given name to the given value.  The value can
 * have a size of 0.  A null value pointer indicates that we should
 * delete the xattr.
 */
static int scoutfs_xattr_set(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags)

{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	size_t name_len = strlen(name);
	struct scoutfs_key old_key;
	struct scoutfs_key new_key;
	bool old;
	int ret;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	ret = scoutfs_dirty_inode_item(inode);
	if (ret)
		goto out;

	down_write(&si->xattr_rwsem);

	ret = lookup_xattr(inode, name, name_len, &curs);
	if (ret > 0) {
		old = true;
		old_key = *curs.key;
		scoutfs_btree_release(&curs);
	} else if (ret == 0) {
		old = false;
	} else {
		goto out;
	}

	if (old && (flags & XATTR_CREATE)) {
		ret = -EEXIST;
		goto out;
	}
	if (!old && (flags & XATTR_REPLACE)) {
		ret = -ENODATA;
		goto out;
	}

	if (value) {
		ret = insert_xattr(inode, name, name_len, value, size,
				   &new_key);
		if (ret)
			goto out;
	}

	if (old) {
		ret = scoutfs_btree_delete(sb, &old_key);
		if (ret) {
			scoutfs_btree_delete(sb, &new_key);
			goto out;
		}
	}

	inode_inc_iversion(inode);
	inode->i_ctime = CURRENT_TIME;
	scoutfs_update_inode_item(inode);
	ret = 0;
out:
	up_write(&si->xattr_rwsem);
	scoutfs_release_trans(sb);
	return ret;
}

int scoutfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{
	if (size == 0)
		value = ""; /* set empty value */

	return scoutfs_xattr_set(dentry, name, value, size, 0);
}

int scoutfs_removexattr(struct dentry *dentry, const char *name)
{
	return scoutfs_xattr_set(dentry, name, NULL, 0, XATTR_REPLACE);
}

ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct scoutfs_xattr *xat;
	struct scoutfs_key first;
	struct scoutfs_key last;
	ssize_t total;
	int ret;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, 0);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, ~0ULL);

	down_read(&si->xattr_rwsem);

	total = 0;
	while ((ret = scoutfs_btree_next(sb, &first, &last, &curs)) > 0) {
		xat = curs.val;

		total += xat->name_len + 1;
		if (!size)
			continue;
		if (!buffer || total > size) {
			ret = -ERANGE;
			break;
		}

		memcpy(buffer, xat->name, xat->name_len);
		buffer += xat->name_len;
		*(buffer++) = '\0';
	}

	scoutfs_btree_release(&curs);

	up_read(&si->xattr_rwsem);

	return ret < 0 ? ret : total;
}
