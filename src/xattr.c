/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <linux/crc32c.h>

#include "format.h"
#include "inode.h"
#include "key.h"
#include "super.h"
#include "kvec.h"
#include "forest.h"
#include "trans.h"
#include "xattr.h"
#include "lock.h"
#include "hash.h"
#include "scoutfs_trace.h"

/*
 * Extended attributes are packed into multiple smaller file system
 * items.  The common case only uses one item.
 *
 * The xattr keys contain the hash of the xattr name and a unique
 * identifier used to differentiate xattrs whose names hash to the same
 * value.  xattr lookup has to walk all the xattrs with the matching
 * name hash to compare the names.
 *
 * We use a rwsem in the inode to serialize modification of multiple
 * items to make sure that we don't let readers race and see an
 * inconsistent mix of the items that make up xattrs.
 *
 * XXX
 *  - add acl support and call generic xattr->handlers for SYSTEM
 */

static u32 xattr_name_hash(const char *name, unsigned int name_len)
{
	return crc32c(U32_MAX, name, name_len);
}

/* only compare names if the lens match, callers might not have both names */
static u32 xattr_names_equal(const char *a_name, unsigned int a_len,
			     const char *b_name, unsigned int b_len)
{
	return a_len == b_len && memcmp(a_name, b_name, a_len) == 0;
}

static unsigned int xattr_full_bytes(struct scoutfs_xattr *xat)
{
	return offsetof(struct scoutfs_xattr,
		        name[xat->name_len + le16_to_cpu(xat->val_len)]);
}

static unsigned int xattr_nr_parts(struct scoutfs_xattr *xat)
{
	return SCOUTFS_XATTR_NR_PARTS(xat->name_len,
				      le16_to_cpu(xat->val_len));
}

static void init_xattr_key(struct scoutfs_key *key, u64 ino, u32 name_hash,
			   u64 id)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skx_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_XATTR_TYPE,
		.skx_name_hash = cpu_to_le64(name_hash),
		.skx_id = cpu_to_le64(id),
		.skx_part = 0,
	};
}

#define SCOUTFS_XATTR_PREFIX		"scoutfs."
#define SCOUTFS_XATTR_PREFIX_LEN	(sizeof(SCOUTFS_XATTR_PREFIX) - 1)

static int unknown_prefix(const char *name)
{
	return strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
	       strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) &&
	       strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) &&
	       strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)&&
	       strncmp(name, SCOUTFS_XATTR_PREFIX, SCOUTFS_XATTR_PREFIX_LEN);
}

struct prefix_tags {
	unsigned long hide:1,
		      srch:1;
};

#define HIDE_TAG	"hide."
#define SRCH_TAG	"srch."
#define TAG_LEN		(sizeof(HIDE_TAG) - 1)

static int parse_tags(const char *name, unsigned int name_len,
		      struct prefix_tags *tgs)
{
	bool found;

	memset(tgs, 0, sizeof(struct prefix_tags));

	if ((name_len < (SCOUTFS_XATTR_PREFIX_LEN + TAG_LEN + 1)) ||
	    strncmp(name, SCOUTFS_XATTR_PREFIX, SCOUTFS_XATTR_PREFIX_LEN))
		return 0;
	name += SCOUTFS_XATTR_PREFIX_LEN;

	found = false;
	for (;;) {
		if (!strncmp(name, HIDE_TAG, TAG_LEN)) {
			if (++tgs->hide == 0)
				return -EINVAL;
		} else if (!strncmp(name, SRCH_TAG, TAG_LEN)) {
			if (++tgs->srch == 0)
				return -EINVAL;
		} else {
			/* only reason to use scoutfs. is tags */
			if (!found)
				return -EINVAL;
			break;
		}
		name += TAG_LEN;
		found = true;
	}

	return 0;
}

void scoutfs_xattr_index_key(struct scoutfs_key *key,
			     u64 hash, u64 ino, u64 id)
{
	scoutfs_key_set_zeros(key);
	key->sk_zone = SCOUTFS_XATTR_INDEX_ZONE;
	key->skxi_hash = cpu_to_le64(hash);
	key->sk_type = SCOUTFS_XATTR_INDEX_NAME_TYPE;
	key->skxi_ino = cpu_to_le64(ino);
	key->skxi_id = cpu_to_le64(id);
}

/*
 * Find the next xattr and copy the key, xattr header, and as much of
 * the name and value into the callers buffer as we can.  Returns the
 * number of bytes copied which include the header, name, and value and
 * can be limited by the xattr length or the callers buffer.  The caller
 * is responsible for comparing their lengths, the header, and the
 * returned length before safely using the xattr.
 *
 * If a name is provided then we'll iterate over items with a matching
 * name_hash until we find a matching name.  If we don't find a matching
 * name then we return -ENOENT.
 *
 * If a name isn't provided then we'll return the next xattr from the
 * given name_hash and id position.
 *
 * Returns -ENOENT if it didn't find a next item.
 */
static int get_next_xattr(struct inode *inode, struct scoutfs_key *key,
			  struct scoutfs_xattr *xat, unsigned int bytes,
			  const char *name, unsigned int name_len,
			  u64 name_hash, u64 id, struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key last;
	struct kvec val;
	u8 last_part;
	int total;
	u8 part;
	int ret;

	/* need to be able to see the name we're looking for */
	if (WARN_ON_ONCE(name_len > 0 && bytes < offsetof(struct scoutfs_xattr,
							  name[name_len])))
		return -EINVAL;

	if (name_len)
		name_hash = xattr_name_hash(name, name_len);

	init_xattr_key(key, scoutfs_ino(inode), name_hash, id);
	init_xattr_key(&last, scoutfs_ino(inode), U32_MAX, U64_MAX);

	last_part = 0;
	part = 0;
	total = 0;

	for (;;) {
		key->skx_part = part;
		kvec_init(&val, (void *)xat + total, bytes - total);
		ret = scoutfs_forest_next(sb, key, &last, &val, lock);
		if (ret < 0) {
			/* XXX corruption, ran out of parts */
			if (ret == -ENOENT && part > 0)
				ret = -EIO;
			break;
		}

		trace_scoutfs_xattr_get_next_key(sb, key);

		/* XXX corruption */
		if (key->skx_part != part) {
			ret = -EIO;
			break;
		}

		/*
		 * XXX corruption: We should have seen a valid header in
		 * the first part and if the next xattr name fits in our
		 * buffer then the item must have included it.
		 */
		if (part == 0 &&
		    (ret < sizeof(struct scoutfs_xattr) ||
		     (xat->name_len <= name_len &&
		      ret < offsetof(struct scoutfs_xattr,
				     name[xat->name_len])) ||
		     xat->name_len > SCOUTFS_XATTR_MAX_NAME_LEN ||
		     le16_to_cpu(xat->val_len) > SCOUTFS_XATTR_MAX_VAL_LEN)) {
			ret = -EIO;
			break;
		}

		if (part == 0 && name_len) {
			/* ran out of names that could match */
			if (le64_to_cpu(key->skx_name_hash) != name_hash) {
				ret = -ENOENT;
				break;
			}

			/* keep looking for our name */
			if (!xattr_names_equal(name, name_len,
					       xat->name, xat->name_len)) {
				part = 0;
				le64_add_cpu(&key->skx_id, 1);
				continue;
			}

			/* use the matching name we found */
			last_part = xattr_nr_parts(xat) - 1;
		}

		total += ret;
		if (total == bytes || part == last_part) {
			/* copied as much as we could */
			ret = total;
			break;
		}
		part++;
	}

	return ret;
}

/*
 * Create all the items associated with the given xattr.  If this
 * returns an error it will have already cleaned up any items it created
 * before seeing the error.
 */
static int create_xattr_items(struct inode *inode, u64 id,
			      struct scoutfs_xattr *xat, unsigned int bytes,
			      struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	unsigned int part_bytes;
	unsigned int total;
	struct kvec val;
	int ret;

	init_xattr_key(&key, scoutfs_ino(inode),
		       xattr_name_hash(xat->name, xat->name_len), id);

	total = 0;
	ret = 0;
	while (total < bytes) {
		part_bytes = min_t(unsigned int, bytes - total,
				   SCOUTFS_XATTR_MAX_PART_SIZE);
		kvec_init(&val, (void *)xat + total, part_bytes);

		ret = scoutfs_forest_create(sb, &key, &val, lock);
		if (ret) {
			while (key.skx_part-- > 0)
				scoutfs_forest_delete_dirty(sb, &key);
			break;
		}

		total += part_bytes;
		key.skx_part++;
	}

	return ret;
}

/*
 * Delete and save the items that make up the given xattr.  If this
 * returns an error then the deleted and saved items are left on the
 * list for the caller to restore.
 */
static int delete_xattr_items(struct inode *inode, u32 name_hash, u64 id,
			      u8 nr_parts, struct list_head *list,
			      struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	int ret;

	init_xattr_key(&key, scoutfs_ino(inode), name_hash, id);

	do {
		ret = scoutfs_forest_delete_save(sb, &key, list, lock);
	} while (ret == 0 && ++key.skx_part < nr_parts);

	return ret;
}

/*
 * Copy the value for the given xattr name into the caller's buffer, if it
 * fits.  Return the bytes copied or -ERANGE if it doesn't fit.
 */
ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	struct scoutfs_key key;
	unsigned int bytes;
	size_t name_len;
	int ret;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	name_len = strlen(name);
	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN)
		return -ENODATA;

	/* only need enough for caller's name and value sizes */
	bytes = sizeof(struct scoutfs_xattr) + name_len + size;
	xat = kmalloc(bytes, GFP_NOFS);
	if (!xat)
		return -ENOMEM;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	ret = get_next_xattr(inode, &key, xat, bytes,
			     name, name_len, 0, 0, lck);

	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_READ);

	if (ret < 0) {
		if (ret == -ENOENT)
			ret = -ENODATA;
		goto out;
	}

	/* the caller just wants to know the size */
	if (size == 0) {
		ret = le16_to_cpu(xat->val_len);
		goto out;
	}

	/* the caller's buffer wasn't big enough */
	if (size < le16_to_cpu(xat->val_len)) {
		ret = -ERANGE;
		goto out;
	}

	/* XXX corruption, the items didn't match the header */
	if (ret < xattr_full_bytes(xat)) {
		ret = -EIO;
		goto out;
	}

	ret = le16_to_cpu(xat->val_len);
	memcpy(buffer, &xat->name[xat->name_len], ret);
out:
	kfree(xat);
	return ret;
}

/*
 * The confusing swiss army knife of creating, modifying, and deleting
 * xattrs.
 *
 * This always removes the old existing xattr items.
 *
 * If the value pointer is set then we're adding a new xattr.  The flags
 * cause creation to fail if the xattr already exists (_CREATE) or
 * doesn't already exist (_REPLACE).  xattrs can have a zero length
 * value.
 */
static int scoutfs_xattr_set(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	size_t name_len = strlen(name);
	struct scoutfs_key key;
	struct prefix_tags tgs;
	bool undo_srch = false;
	LIST_HEAD(ind_locks);
	LIST_HEAD(saved);
	u8 found_parts;
	unsigned int bytes;
	u64 ind_seq;
	u64 hash = 0;
	u64 id = 0;
	int ret;
	int err;

	trace_scoutfs_xattr_set(sb, name_len, value, size, flags);

	/* mirror the syscall's errors for large names and values */
	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN)
		return -ERANGE;
	if (value && size > SCOUTFS_XATTR_MAX_VAL_LEN)
		return -E2BIG;

	if (((flags & XATTR_CREATE) && (flags & XATTR_REPLACE)) ||
	    (flags & ~(XATTR_CREATE | XATTR_REPLACE)))
		return -EINVAL;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	if (parse_tags(name, name_len, &tgs) != 0)
		return -EINVAL;

	if ((tgs.hide || tgs.srch) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	bytes = sizeof(struct scoutfs_xattr) + name_len + size;
	xat = kmalloc(bytes, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lck);
	if (ret)
		goto out;

	down_write(&si->xattr_rwsem);

	/* find an existing xattr to delete */
	ret = get_next_xattr(inode, &key, xat,
			     sizeof(struct scoutfs_xattr) + name_len,
			     name, name_len, 0, 0, lck);
	if (ret < 0 && ret != -ENOENT)
		goto unlock;

	/* check existence constraint flags */
	if (ret == -ENOENT && (flags & XATTR_REPLACE)) {
		ret = -ENODATA;
		goto unlock;
	} else if (ret >= 0 && (flags & XATTR_CREATE)) {
		ret = -EEXIST;
		goto unlock;
	}

	/* not an error to delete something that doesn't exist */
	if (ret == -ENOENT && !value) {
		ret = 0;
		goto unlock;
	}

	/* found fields in key will also be used */
	found_parts = ret >= 0 ? xattr_nr_parts(xat) : 0;

	/* prepare our xattr */
	if (value) {
		id = si->next_xattr_id++;
		xat->name_len = name_len;
		xat->val_len = cpu_to_le16(size);
		memcpy(xat->name, name, name_len);
		memcpy(&xat->name[xat->name_len], value, size);
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq,
						SIC_XATTR_SET(found_parts,
							      value != NULL,
							      name_len, size,
							      tgs.srch));
	if (ret > 0)
		goto retry;
	if (ret)
		goto unlock;

	ret = scoutfs_dirty_inode_item(inode, lck);
	if (ret < 0)
		goto release;

	if (tgs.srch && !(found_parts && value)) {
		if (found_parts)
			id = le64_to_cpu(key.skx_id);
		hash = scoutfs_hash64(name, name_len);
		ret = scoutfs_forest_srch_add(sb, hash, ino, id);
		if (ret < 0)
			goto release;
		undo_srch = true;
	}

	ret = 0;
	if (found_parts)
		ret = delete_xattr_items(inode, le64_to_cpu(key.skx_name_hash),
					 le64_to_cpu(key.skx_id), found_parts,
					 &saved, lck);
	if (value && ret == 0)
		ret = create_xattr_items(inode, id, xat, bytes, lck);
	if (ret < 0) {
		scoutfs_forest_restore(sb, &saved, lck);
		goto release;
	}
	scoutfs_forest_free_batch(sb, &saved);

	/* XXX do these want i_mutex or anything? */
	inode_inc_iversion(inode);
	inode->i_ctime = CURRENT_TIME;
	scoutfs_update_inode_item(inode, lck, &ind_locks);
	ret = 0;

release:
	if (ret < 0 && undo_srch) {
		err = scoutfs_forest_srch_add(sb, hash, ino, id);
		BUG_ON(err);
	}

	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
unlock:
	up_write(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_WRITE);
out:
	kfree(xat);

	return ret;
}

int scoutfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{
	if (size == 0)
		value = ""; /* set empty value */

	return scoutfs_xattr_set(dentry, name, value, size, flags);
}

int scoutfs_removexattr(struct dentry *dentry, const char *name)
{
	return scoutfs_xattr_set(dentry, name, NULL, 0, XATTR_REPLACE);
}

ssize_t scoutfs_list_xattrs(struct inode *inode, char *buffer,
			    size_t size, __u32 *hash_pos, __u64 *id_pos,
			    bool e_range, bool show_hidden)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	struct scoutfs_key key;
	struct prefix_tags tgs;
	unsigned int bytes;
	ssize_t total = 0;
	u32 name_hash = 0;
	bool is_hidden;
	u64 id = 0;
	int ret;

	if (hash_pos)
		name_hash = *hash_pos;
	if (id_pos)
		id = *id_pos;

	/* need a buffer large enough for all possible names */
	bytes = sizeof(struct scoutfs_xattr) + SCOUTFS_XATTR_MAX_NAME_LEN;
	xat = kmalloc(bytes, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	for (;;) {
		ret = get_next_xattr(inode, &key, xat, bytes,
				     NULL, 0, name_hash, id, lck);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = total;
			break;
		}

		is_hidden = parse_tags(xat->name, xat->name_len, &tgs) == 0 &&
			    tgs.hide;

		if (show_hidden == is_hidden) {
			if (size) {
				if ((total + xat->name_len + 1) > size) {
					if (e_range)
						ret = -ERANGE;
					else
						ret = total;
					break;
				}

				memcpy(buffer, xat->name, xat->name_len);
				buffer += xat->name_len;
				*(buffer++) = '\0';
			}

			total += xat->name_len + 1;
		}

		name_hash = le64_to_cpu(key.skx_name_hash);
		id = le64_to_cpu(key.skx_id) + 1;
	}

	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_READ);
out:
	kfree(xat);

	if (hash_pos)
		*hash_pos = name_hash;
	if (id_pos)
		*id_pos = id;

	return ret;
}

ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;

	return scoutfs_list_xattrs(inode, buffer, size,
				   NULL, NULL, true, false);
}

/*
 * Delete all the xattr items associated with this inode.  The inode is
 * dead so we don't need the xattr rwsem.
 */
int scoutfs_xattr_drop(struct super_block *sb, u64 ino,
		       struct scoutfs_lock *lock)
{
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct prefix_tags tgs;
	bool release = false;
	unsigned int bytes;
	struct kvec val;
	u64 hash;
	int ret;

	/* need a buffer large enough for all possible names */
	bytes = sizeof(struct scoutfs_xattr) + SCOUTFS_XATTR_MAX_NAME_LEN;
	xat = kmalloc(bytes, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	init_xattr_key(&key, ino, 0, 0);
	init_xattr_key(&last, ino, U32_MAX, U64_MAX);

	for (;;) {
		kvec_init(&val, (void *)xat, bytes);
		ret = scoutfs_forest_next(sb, &key, &last, &val, lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		if (key.skx_part != 0 ||
		    parse_tags(xat->name, xat->name_len, &tgs) != 0)
			memset(&tgs, 0, sizeof(tgs));

		ret = scoutfs_hold_trans(sb, SIC_EXACT(2, 0));
		if (ret < 0)
			break;
		release = true;

		ret = scoutfs_forest_delete(sb, &key, lock);
		if (ret < 0)
			break;

		if (tgs.srch) {
			hash = scoutfs_hash64(xat->name, xat->name_len);
			ret = scoutfs_forest_srch_add(sb, hash, ino,
						      le64_to_cpu(key.skx_id));
		       if (ret < 0)
			       break;
		}

		scoutfs_release_trans(sb);
		release = false;

		/* don't need to inc, next won't see deleted item */
	}

	if (release)
		scoutfs_release_trans(sb);
	kfree(xat);
out:
	return ret;
}
