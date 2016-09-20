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
 * We support ioctls which find inodes that may contain xattrs with
 * either a given name or value.  A name hash item is created for a
 * given hash value with no collision bits as long as there are any
 * names at that hash value.  A value hash item is created but it
 * contains a refcount in its value to track the number of values with
 * that hash value because we can't use the xattr keys to determine if
 * there are matching values or not.
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

static void set_xattr_keys(struct inode *inode, struct scoutfs_key *first,
			   struct scoutfs_key *last, const char *name,
			   unsigned int name_len)
{
	u64 h = scoutfs_name_hash(name, name_len) &
		~SCOUTFS_XATTR_NAME_HASH_MASK;

	scoutfs_set_key(first, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, h);
	scoutfs_set_key(last, scoutfs_ino(inode), SCOUTFS_XATTR_KEY,
			h | SCOUTFS_XATTR_NAME_HASH_MASK);
}

static void set_name_val_keys(struct scoutfs_key *name_key,
			      struct scoutfs_key *val_key,
			      struct scoutfs_key *key, u64 val_hash)
{
	u64 h = scoutfs_key_offset(key) & ~SCOUTFS_XATTR_NAME_HASH_MASK;

	scoutfs_set_key(name_key, h, SCOUTFS_XATTR_NAME_HASH_KEY,
			scoutfs_key_inode(key));

	scoutfs_set_key(val_key, val_hash, SCOUTFS_XATTR_VAL_HASH_KEY,
			scoutfs_key_inode(key));
}

/*
 * Before insertion we perform a pretty through search of the xattr
 * items whose offset collides with the name to be inserted.
 *
 * We try to find the item with the matching item so it can be removed.
 * We notice if there are other colliding names so that the caller can
 * correctly maintain the name hash items.  We calculate the value hash
 * of the existing item so that the caller can maintain the value hash
 * items.  And we notice if there are any free colliding items that are
 * available for new item insertion.
 */
struct xattr_search_results {
	bool found;
	bool other_coll;
	struct scoutfs_key key;
	u64 val_hash;
	bool found_hole;
	struct scoutfs_key hole_key;
};

static int search_xattr_items(struct inode *inode, const char *name,
			      unsigned int name_len,
			      struct xattr_search_results *res)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct scoutfs_xattr *xat;
	struct scoutfs_key last;
	struct scoutfs_key key;
	unsigned int max_len;
	int ret;

	max_len = xat_bytes(SCOUTFS_MAX_XATTR_LEN, SCOUTFS_MAX_XATTR_LEN),
	xat = kmalloc(max_len, GFP_KERNEL);
	if (!xat)
		return -ENOMEM;

	set_xattr_keys(inode, &key, &last, name, name_len);
	scoutfs_btree_init_val(&val, xat, max_len);

	res->found = false;
	res->other_coll = false;
	res->found_hole = false;
	res->hole_key = key;

	for (;;) {
		ret = scoutfs_btree_next(sb, meta, &key, &last, &key, &val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		/* XXX corruption */
		if (ret < sizeof(struct scoutfs_xattr) ||
		    ret != xat_bytes(xat->name_len, xat->value_len)) {
			ret = -EIO;
			break;
		}

		/* found a hole when we skip past next expected key */
		if (!res->found_hole &&
		    scoutfs_key_cmp(&res->hole_key, &key) < 0)
			res->found_hole = true;

		/* keep searching for a hole past this key */
		if (!res->found_hole) {
			res->hole_key = key;
			scoutfs_inc_key(&res->hole_key);
		}

		/* only compare the names until we find our given name */
		if (!res->found &&
		    scoutfs_names_equal(name, name_len, xat->name,
				        xat->name_len)) {
			res->found = true;
			res->key = key;
			res->val_hash = scoutfs_name_hash(xat_value(xat),
							  xat->value_len);
		} else {
			res->other_coll = true;
		}

		/* finished once we have all the caller needs */
		if (res->found && res->other_coll && res->found_hole) {
			ret = 0;
			break;
		}

		scoutfs_inc_key(&key);
	}

	kfree(xat);
	return ret;
}

/*
 * Inset a new xattr item, updating the name and value hash items as
 * needed.  The caller is responsible for managing transactions and
 * locking.  If this returns an error then no changes will have been
 * made.
 */
static int insert_xattr(struct inode *inode, const char *name,
			unsigned int name_len, const void *value, size_t size,
			struct scoutfs_key *key, bool other_coll,
			u64 val_hash)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	bool inserted_name_hash_item = false;
	struct scoutfs_btree_val val;
	__le64 refcount;
	struct scoutfs_key name_key;
	struct scoutfs_key val_key;
	struct scoutfs_xattr xat;
	int ret;

	/* insert the main xattr item */
	set_name_val_keys(&name_key, &val_key, key, val_hash);
	scoutfs_btree_init_val(&val, &xat, sizeof(xat), (void *)name, name_len,
			       (void *)value, size);

	xat.name_len = name_len;
	xat.value_len = size;

	ret = scoutfs_btree_insert(sb, meta, key, &val);
	if (ret)
		return ret;

	/* insert the name hash item for find_xattr if we're first */
	if (!other_coll) {
		ret = scoutfs_btree_insert(sb, meta, &name_key, NULL);
		/* XXX eexist would be corruption */
		if (ret)
			goto out;
		inserted_name_hash_item = true;
	}

	/* increment the val hash item for find_xattr, inserting if first */
	scoutfs_btree_init_val(&val, &refcount, sizeof(refcount));

	ret = scoutfs_btree_lookup(sb, meta, &val_key, &val);
	if (ret < 0 && ret != -ENOENT)
		goto out;

	if (ret == -ENOENT) {
		refcount = cpu_to_le64(1);
		ret = scoutfs_btree_insert(sb, meta, &val_key, &val);
	} else {
		/* XXX corruption */
		if (ret != sizeof(refcount)) {
			ret = -EIO;
			goto out;
		}

		le64_add_cpu(&refcount, 1);
		ret = scoutfs_btree_update(sb, meta, &val_key, &val);
	}
out:
	if (ret) {
		scoutfs_btree_delete(sb, meta, key);
		if (inserted_name_hash_item)
			scoutfs_btree_delete(sb, meta, &name_key);
	}
	return ret;
}

/*
 * Remove an xattr.  Remove the name hash item if there are no more xattrs
 * in the inode that hash to the name's hash value.  Remove the value hash
 * item if there are no more xattr values in the inode with this value
 * hash.
 */
static int delete_xattr(struct super_block *sb, struct scoutfs_key *key,
			bool other_coll, u64 val_hash)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct scoutfs_key name_key;
	struct scoutfs_key val_key;
	__le64 refcount;
	int ret;

	set_name_val_keys(&name_key, &val_key, key, val_hash);

	/* update the val_hash refcount, making sure it's not nonsense */
	scoutfs_btree_init_val(&val, &refcount, sizeof(refcount));
	ret = scoutfs_btree_lookup(sb, meta, &val_key, &val);
	if (ret < 0)
		goto out;

	/* XXX corruption */
	if (ret != sizeof(refcount)) {
		ret = -EIO;
		goto out;
	}

	le64_add_cpu(&refcount, -1ULL);

	/* ensure that we can update and delete name_ and val_ keys */
	if (!other_coll) {
		ret = scoutfs_btree_dirty(sb, meta, &name_key);
		if (ret)
			goto out;
	}
	ret = scoutfs_btree_dirty(sb, meta, &val_key);
	if (ret)
		goto out;

	ret = scoutfs_btree_delete(sb, meta, key);
	if (ret)
		goto out;

	if (!other_coll)
		scoutfs_btree_delete(sb, meta, &name_key);

	if (refcount)
		scoutfs_btree_update(sb, meta, &val_key, &val);
	else
		scoutfs_btree_delete(sb, meta, &val_key);
	ret = 0;
out:
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

/*
 * Look up an xattr matching the given name.  We walk our xattr items stored
 * at the hashed name.  We'll only be able to copy out a value that fits
 * in the callers buffer.
 */
ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	size_t name_len = strlen(name);
	struct scoutfs_btree_val val;
	struct scoutfs_xattr *xat;
	struct scoutfs_key key;
	struct scoutfs_key last;
	unsigned int item_len;
	int ret;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	/* make sure we don't allocate an enormous item */
	if (name_len > SCOUTFS_MAX_XATTR_LEN)
		return -ENODATA;
	size = min_t(size_t, size, SCOUTFS_MAX_XATTR_LEN);

	item_len = xat_bytes(name_len, size);
	xat = kmalloc(item_len, GFP_KERNEL);
	if (!xat)
		return -ENOMEM;

	set_xattr_keys(inode, &key, &last, name, name_len);
	scoutfs_btree_init_val(&val, xat, item_len);

	down_read(&si->xattr_rwsem);

	for (;;) {
		ret = scoutfs_btree_next(sb, meta, &key, &last, &key, &val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = -ENODATA;
			break;
		}

		/* XXX corruption */
		if (ret < sizeof(struct scoutfs_xattr)) {
			ret = -EIO;
			break;
		}

		if (!scoutfs_names_equal(name, name_len, xat->name,
					 xat->name_len)) {
			scoutfs_inc_key(&key);
			continue;
		}

		ret = xat->value_len;
		if (buffer) {
			if (ret <= size)
				memcpy(buffer, xat_value(xat), ret);
			else
				ret = -ERANGE;
		}
		break;
	}

	up_read(&si->xattr_rwsem);

	kfree(xat);
	return ret;
}

/*
 * The confusing swiss army knife of creating, modifying, and deleting
 * xattrs.
 *
 * If the value pointer is non-null then we always create a new item.  The
 * value can have a size of 0.  We create a new item before possibly
 * deleting an old item.
 *
 * We always delete the old xattr item.  If we have a null value then we're
 * deleting the xattr.  If there's a value then we're effectively updating
 * the xattr by deleting old and creating new.
 */
static int scoutfs_xattr_set(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags)

{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct xattr_search_results old = {0,};
	size_t name_len = strlen(name);
	u64 new_val_hash = 0;
	int ret;

	if (name_len > SCOUTFS_MAX_XATTR_LEN ||
	    (value && size > SCOUTFS_MAX_XATTR_LEN))
		return -EINVAL;

	if (unknown_prefix(name))
		return -EOPNOTSUPP;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	ret = scoutfs_dirty_inode_item(inode);
	if (ret)
		goto out;

	/* might as well do this outside locking */
	if (value)
		new_val_hash = scoutfs_name_hash(value, size);

	down_write(&si->xattr_rwsem);

	/*
	 * The presence of other colliding names is a little tricky.
	 * Searching will set it if there are other non-matching names.
	 * It will be false if we only found the old matching name. That
	 * old match is also considered a collision for later insertion.
	 * Then *that* insertion is considered a collision for deletion
	 * of the existing old matching name.
	 */
	ret = search_xattr_items(inode, name, name_len, &old);
	if (ret)
		goto out;

	if (old.found && (flags & XATTR_CREATE)) {
		ret = -EEXIST;
		goto out;
	}
	if (!old.found && (flags & XATTR_REPLACE)) {
		ret = -ENODATA;
		goto out;
	}

	if (value) {
		ret = insert_xattr(inode, name, name_len, value, size,
				   &old.hole_key, old.other_coll || old.found,
				   new_val_hash);
		if (ret)
			goto out;
	}

	if (old.found) {
		ret = delete_xattr(sb, &old.key, old.other_coll || value,
				   old.val_hash);
		if (ret) {
			if (value)
				delete_xattr(sb, &old.hole_key, true,
					     new_val_hash);
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
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct scoutfs_xattr *xat;
	struct scoutfs_key key;
	struct scoutfs_key last;
	unsigned int item_len;
	ssize_t total;
	int ret;

	item_len = xat_bytes(SCOUTFS_MAX_XATTR_LEN, 0);
	xat = kmalloc(item_len, GFP_KERNEL);
	if (!xat)
		return -ENOMEM;

	scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, 0);
	scoutfs_set_key(&last, scoutfs_ino(inode), SCOUTFS_XATTR_KEY, ~0ULL);
	scoutfs_btree_init_val(&val, xat, item_len);

	down_read(&si->xattr_rwsem);

	total = 0;
	for (;;) {
		ret = scoutfs_btree_next(sb, meta, &key, &last, &key, &val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		/* XXX corruption */
		if (ret < sizeof(struct scoutfs_xattr)) {
			ret = -EIO;
			break;
		}

		total += xat->name_len + 1;

		if (size) {
			if (!buffer || total > size) {
				ret = -ERANGE;
				break;
			}

			memcpy(buffer, xat->name, xat->name_len);
			buffer += xat->name_len;
			*(buffer++) = '\0';
		}

		scoutfs_inc_key(&key);
	}

	up_read(&si->xattr_rwsem);

	kfree(xat);

	return ret < 0 ? ret : total;
}

/*
 * Delete all the xattr items associted with this inode.  The caller
 * holds a transaction.
 *
 * The name and value hashes are sorted by the hash value instead of the
 * inode so we have to use the inode's xattr items to find them.  We
 * only remove the xattr item once the hash items are removed.
 *
 * Hash items can be shared amongst xattrs whose names or values hash to
 * the same hash value.  We don't bother trying to remove the hash items
 * as the last xattr is removed.  We always try to remove them and allow
 * failure when we try to remove a hash item that wasn't found.
 */
int scoutfs_xattr_drop(struct super_block *sb, u64 ino)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct scoutfs_xattr *xat;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct scoutfs_key name_key;
	struct scoutfs_key val_key;
	unsigned int item_len;
	u64 val_hash;
	int ret;

	scoutfs_set_key(&key, ino, SCOUTFS_XATTR_KEY, 0);
	scoutfs_set_key(&last, ino, SCOUTFS_XATTR_KEY, ~0ULL);

	item_len = xat_bytes(SCOUTFS_MAX_XATTR_LEN, SCOUTFS_MAX_XATTR_LEN),
	xat = kmalloc(item_len, GFP_KERNEL);
	if (!xat)
		return -ENOMEM;

	scoutfs_btree_init_val(&val, xat, item_len);

	for (;;) {
		ret = scoutfs_btree_next(sb, meta, &key, &last, &key, &val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		/* XXX corruption */
		if (ret < sizeof(struct scoutfs_xattr) ||
		    ret != xat_bytes(xat->name_len, xat->value_len)) {
			ret = -EIO;
			break;
		}

		val_hash = scoutfs_name_hash(xat_value(xat), xat->value_len);
		set_name_val_keys(&name_key, &val_key, &key, val_hash);

		ret = scoutfs_btree_delete(sb, meta, &name_key);
		if (ret && ret != -ENOENT)
			break;

		ret = scoutfs_btree_delete(sb, meta, &val_key);
		if (ret && ret != -ENOENT)
			break;

		ret = scoutfs_btree_delete(sb, meta, &key);
		if (ret && ret != -ENOENT)
			break;

		scoutfs_inc_key(&key);
	}

	kfree(xat);

	return ret;
}
