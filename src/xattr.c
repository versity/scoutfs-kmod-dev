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
#include "kvec.h"
#include "item.h"
#include "trans.h"
#include "xattr.h"
#include "lock.h"

/*
 * In the simple case an xattr is stored in a single item whose key and
 * value contain the key and value from the xattr.
 *
 * But xattr values can be larger than our max item value length.  In
 * that case the rest of the xattr value is stored in additional items.
 * Each item key contains a footer struct after the name which
 * identifies the position of the item in the series that make up the
 * total xattr.
 *
 * That xattrs are then spread out across multiple items does mean that
 * we need locking other than the item cache locking which only protects
 * each item call, the i_mutex which isn't held on getxattr, and cluster
 * locking which doesn't serialize local matches on the same node.  We
 * use a rwsem in the inode.
 *
 * XXX
 *  - add acl support and call generic xattr->handlers for SYSTEM
 */

/*
 * We have a static full xattr name with all 1s so that we can construct
 * precise final keys for the range of items that cover all the xattrs
 * on an inode.  We could instead construct a smaller last key for the
 * next inode with a null name but that could be accidentally create
 * lock contention with that next inode.  We want lock ranges to be as
 * precise as possible.
 */
static char last_xattr_name[SCOUTFS_XATTR_MAX_NAME_LEN];

/* account for the footer after the name */
static unsigned xattr_key_bytes(unsigned name_len)
{
	return offsetof(struct scoutfs_xattr_key, name[name_len]) +
	       sizeof(struct scoutfs_xattr_key_footer);
}

static unsigned xattr_key_name_len(struct scoutfs_key_buf *key)
{
	return key->key_len - xattr_key_bytes(0);
}

static struct scoutfs_xattr_key_footer *
xattr_key_footer(struct scoutfs_key_buf *key)
{
	return key->data + key->key_len -
	       sizeof(struct scoutfs_xattr_key_footer);
}

static struct scoutfs_key_buf *alloc_xattr_key(struct super_block *sb,
					       u64 ino, const char *name,
					       unsigned int name_len, u8 part)
{
	struct scoutfs_xattr_key_footer *foot;
	struct scoutfs_xattr_key *xkey;
	struct scoutfs_key_buf *key;

	key = scoutfs_key_alloc(sb, xattr_key_bytes(name_len));
	if (key) {
		xkey = key->data;
		foot = xattr_key_footer(key);

		xkey->zone = SCOUTFS_FS_ZONE;
		xkey->ino = cpu_to_be64(ino);
		xkey->type = SCOUTFS_XATTR_TYPE;

		if (name && name_len)
			memcpy(xkey->name, name, name_len);

		foot->null = '\0';
		foot->part = part;
	}

	return key;
}

static void set_xattr_key_part(struct scoutfs_key_buf *key, u8 part)
{
	struct scoutfs_xattr_key_footer *foot = xattr_key_footer(key);

	foot->part = part;
}

/*
 * This walks the keys and values for the items that make up the xattr
 * items that describe the value in the caller's buffer.  The caller is
 * responsible for breaking out when it hits an existing final item that
 * hasn't consumed the buffer.
 *
 * Each iteration sets the val header in case the caller is writing
 * items.  If they're reading items they'll just overwrite it.
 */
#define for_each_xattr_item(key, val, vh, buffer, size, part, off, bytes)    \
	for (part = 0, off = 0;						     \
	     ((off < size) || (part == 0 && size == 0)) &&		     \
		(bytes = min_t(size_t, SCOUTFS_XATTR_PART_SIZE, size - off), \
		 set_xattr_key_part(key, part),				     \
		 (vh)->part_len = cpu_to_le16(bytes),			     \
		 (vh)->last_part = off + bytes == size ? 1 : 0,		     \
		 scoutfs_kvec_init(val, vh,				     \
			           sizeof(struct scoutfs_xattr_val_header),  \
				   buffer + off, bytes),		     \
		 1);							     \
	     part++, off += bytes)

static int unknown_prefix(const char *name)
{
	return strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
	       strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) &&
	       strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) &&
	       strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN);
}

/*
 * Copy the value for the given xattr name into the caller's buffer, if it
 * fits.  Return the bytes copied or -ERANGE if it doesn't fit.
 */
ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_xattr_val_header vh;
	struct scoutfs_key_buf *key = NULL;
	struct scoutfs_key_buf *last = NULL;
	SCOUTFS_DECLARE_KVEC(val);
	struct scoutfs_lock *lck;
	unsigned int total;
	unsigned int bytes;
	unsigned int off;
	size_t name_len;
	u8 part;
	int ret;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	name_len = strlen(name);
	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN)
		return -ENODATA;

	/* honestly, userspace, just alloc a max size buffer */
	if (size == 0)
		return SCOUTFS_XATTR_MAX_SIZE;

	key = alloc_xattr_key(sb, scoutfs_ino(inode), name, name_len, 0);
	last = alloc_xattr_key(sb, scoutfs_ino(inode), name, name_len, 0xff);
	if (!key || !last) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_PR, scoutfs_ino(inode), &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	total = 0;
	vh.last_part = 0;

	for_each_xattr_item(key, val, &vh, buffer, size, part, off, bytes) {

		ret = scoutfs_item_lookup(sb, key, val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = -EIO;
			break;
		}

		/* XXX corruption: no header, more val than header len */
		ret -= sizeof(struct scoutfs_xattr_val_header);
		if (ret < 0 || ret > le16_to_cpu(vh.part_len)) {
			ret = -EIO;
			break;
		}

		/* not enough buffer if we didn't copy the part */
		if (ret < le16_to_cpu(vh.part_len)) {
			ret = -ERANGE;
			break;
		}

		total += ret;

		/* XXX corruption: total xattr val too long */
		if (total > SCOUTFS_XATTR_MAX_SIZE) {
			ret = -EIO;
			break;
		}

		/* done if we fully copied last part */
		if (vh.last_part) {
			ret = total;
			break;
		}
	}

	/* not enough buffer if we didn't see last */
	if (ret >= 0 && !vh.last_part)
		ret = -ERANGE;

	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck);

out:
	scoutfs_key_free(sb, key);
	scoutfs_key_free(sb, last);
	return ret;
}

/*
 * The confusing swiss army knife of creating, modifying, and deleting
 * xattrs.
 *
 * This always removes the old existing xattr.  If value is set then
 * we're replacing it with a new xattr.  The flags cause creation to
 * fail if the xattr already exists (_CREATE) or doesn't already exist
 * (_REPLACE).  xattrs can have a zero length value.
 *
 * To modify xattrs built of individual items we use the batch
 * interface.  It provides atomic transitions from one group of items to
 * another.
 */
static int scoutfs_xattr_set(struct dentry *dentry, const char *name,

			     const void *value, size_t size, int flags)

{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key_buf *last;
	struct scoutfs_key_buf *key;
	struct scoutfs_xattr_val_header vh;
	size_t name_len = strlen(name);
	SCOUTFS_DECLARE_KVEC(val);
	DECLARE_ITEM_COUNT(cnt);
	struct scoutfs_lock *lck;
	unsigned int bytes;
	unsigned int off;
	LIST_HEAD(list);
	u8 part;
	int sif;
	int ret;

	trace_printk("name_len %zu value %p size %zu flags 0x%x\n",
		     name_len, value, size, flags);

	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN ||
	    (value && size > SCOUTFS_XATTR_MAX_SIZE))
		return -EINVAL;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	key = alloc_xattr_key(sb, scoutfs_ino(inode), name, name_len, 0);
	last = alloc_xattr_key(sb, scoutfs_ino(inode), name, name_len, 0xff);
	if (!key || !last) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, scoutfs_ino(inode), &lck);
	if (ret)
		goto out;

	/* build up batch of new items for the new xattr */
	if (value) {
		for_each_xattr_item(key, val, &vh, (void *)value, size,
				    part, off, bytes) {

			ret = scoutfs_item_add_batch(sb, &list, key, val);
			if (ret)
				goto unlock;
		}
	}

	/* XXX could add range deletion items around xattr items here */

	/* reset key to first */
	set_xattr_key_part(key, 0);

	if (flags & XATTR_CREATE)
		sif = SIF_EXCLUSIVE;
	else if (flags & XATTR_REPLACE)
		sif = SIF_REPLACE;
	else
		sif = 0;

	scoutfs_count_xattr_set(&cnt, name_len, size);
	ret = scoutfs_hold_trans(sb, &cnt);
	if (ret)
		goto unlock;

	down_write(&si->xattr_rwsem);

	ret = scoutfs_dirty_inode_item(inode) ?:
	      scoutfs_item_set_batch(sb, &list, key, last, sif);
	if (ret == 0) {
		/* XXX do these want i_mutex or anything? */
		inode_inc_iversion(inode);
		inode->i_ctime = CURRENT_TIME;
		scoutfs_update_inode_item(inode);
	}

	up_write(&si->xattr_rwsem);
	scoutfs_release_trans(sb);

unlock:
	scoutfs_unlock(sb, lck);

out:
	scoutfs_item_free_batch(sb, &list);
	scoutfs_key_free(sb, key);
	scoutfs_key_free(sb, last);

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
	struct scoutfs_xattr_key_footer *foot;
	struct scoutfs_xattr_key *xkey;
	struct scoutfs_key_buf *key;
	struct scoutfs_key_buf *last;
	struct scoutfs_lock *lck;
	ssize_t total;
	int name_len;
	int ret;

	key = alloc_xattr_key(sb, scoutfs_ino(inode),
			      NULL, SCOUTFS_XATTR_MAX_NAME_LEN, 0);
	last = alloc_xattr_key(sb, scoutfs_ino(inode), last_xattr_name,
			       SCOUTFS_XATTR_MAX_NAME_LEN, 0xff);
	if (!key || !last) {
		ret = -ENOMEM;
		goto out;
	}

	xkey = key->data;
	xkey->name[0] = '\0';

	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_PR, scoutfs_ino(inode), &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	total = 0;
	for (;;) {
		ret = scoutfs_item_next(sb, key, last, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = total;
			break;
		}

		/* not used until we verify key len */
		foot = xattr_key_footer(key);

		/* XXX corruption */
		if (key->key_len < xattr_key_bytes(1) ||
		    foot->null != '\0' || foot->part != 0) {
			ret = -EIO;
			break;
		}

		name_len = xattr_key_name_len(key);

		/* XXX corruption? */
		if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN) {
			ret = -EIO;
			break;
		}

		total += name_len + 1;

		if (size) {
			if (total > size) {
				ret = -ERANGE;
				break;
			}

			memcpy(buffer, xkey->name, name_len);
			buffer += name_len;
			*(buffer++) = '\0';
		}

		set_xattr_key_part(key, 0xff);
	}

	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck);
out:
	scoutfs_key_free(sb, key);
	scoutfs_key_free(sb, last);

	return ret;
}

/*
 * Delete all the xattr items associated with this inode.  The caller
 * holds a transaction.
 *
 * XXX This isn't great because it reads in all the items so that it can
 * create deletion items for each.  It would be better to have the
 * caller create range deletion items for all the items covered by the
 * inode.  That wouldn't require reading at all.
 */
int scoutfs_xattr_drop(struct super_block *sb, u64 ino)
{
	struct scoutfs_key_buf *key;
	struct scoutfs_key_buf *last;
	struct scoutfs_lock *lck;
	int ret;

	key = alloc_xattr_key(sb, ino, NULL, SCOUTFS_XATTR_MAX_NAME_LEN, 0);
	last = alloc_xattr_key(sb, ino, last_xattr_name,
			       SCOUTFS_XATTR_MAX_NAME_LEN, 0xff);
	if (!key || !last) {
		ret = -ENOMEM;
		goto out;
	}

	/* while we read to delete we need to writeback others */
	ret = scoutfs_lock_ino_group(sb, DLM_LOCK_EX, ino, &lck);
	if (ret)
		goto out;

	/* the inode is dead so we don't need the xattr sem */

	for (;;) {
		ret = scoutfs_item_next(sb, key, last, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ret = scoutfs_item_delete(sb, key);
		if (ret)
			break;

		/* don't need to increment past deleted key */
	}

	scoutfs_unlock(sb, lck);

out:
	scoutfs_key_free(sb, key);
	scoutfs_key_free(sb, last);

	return ret;
}

int scoutfs_xattr_init(void)
{
	memset(last_xattr_name, 0xff, sizeof(last_xattr_name));

	return 0;
}
