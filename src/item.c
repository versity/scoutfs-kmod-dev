/*
 * Copyright (C) 2015 Versity Software, Inc.  All rights reserved.
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
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#include "super.h"
#include "key.h"
#include "item.h"
#include "segment.h"

/*
 * describe:
 *  - tracks per-item dirty state for writing
 *  - decouples vfs cache lifetimes from item lifetimes
 *  - item-granular cache for things vfs doesn't cache (readdir, xattr)
 *
 * XXX:
 *  - warnings for invalid keys/lens
 *  - memory pressure
 */

enum {
	ITW_NEXT = 1,
	ITW_PREV,
};

static inline struct scoutfs_item *node_item(struct super_block *sb,
					     struct rb_root *root,
					     struct rb_node *node)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	unsigned long off;

	if (root == &sbi->item_root)
		off = offsetof(struct scoutfs_item, node);
	else
		off = offsetof(struct scoutfs_item, dirty_node);

	return (void *)((char *)node - off);
}

static inline struct rb_node *item_node(struct super_block *sb,
					struct rb_root *root,
					struct scoutfs_item *item)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	unsigned long off;

	if (root == &sbi->item_root)
		off = offsetof(struct scoutfs_item, node);
	else
		off = offsetof(struct scoutfs_item, dirty_node);

	return (void *)((char *)item + off);
}

/*
 * Insert a new item in the tree.  The caller must have done a lookup to
 * ensure that the key is not already present.
 */
static void insert_item(struct super_block *sb, struct rb_root *root,
			struct scoutfs_item *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_item *item;
	int cmp;

	while (*node) {
		parent = *node;
		item = node_item(sb, root, *node);

		cmp = scoutfs_key_cmp(&ins->key, &item->key);
		BUG_ON(cmp == 0);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(item_node(sb, root, ins), parent, node);
	rb_insert_color(item_node(sb, root, ins), root);
}

enum {
	FI_NEXT = 1,
	FI_PREV,
};

/*
 * Walk the tree looking for an item.
 *
 * If NEXT or PREV are specified then those will be returned
 * if the specific item isn't found.
 */
static struct scoutfs_item *find_item(struct super_block *sb,
				      struct rb_root *root,
				      struct scoutfs_key *key, int np)
{
	struct rb_node *node = root->rb_node;
	struct scoutfs_item *found = NULL;
	struct scoutfs_item *item;
	int cmp;

	while (node) {
		item = node_item(sb, root, node);

		cmp = scoutfs_key_cmp(key, &item->key);
		if (cmp < 0) {
			if (np == FI_NEXT)
				found = item;
			node = node->rb_left;
		} else if (cmp > 0) {
			if (np == FI_PREV)
				found = item;
			node = node->rb_right;
		} else {
			found = item;
			break;
		}
	}

	return found;
}

static struct scoutfs_item *alloc_item(struct scoutfs_key *key,
				       unsigned int val_len)
{
	struct scoutfs_item *item;
	void *val;

	item = kmalloc(sizeof(struct scoutfs_item), GFP_NOFS);
	val = kmalloc(val_len, GFP_NOFS);
	if (!item || !val) {
		kfree(item);
		kfree(val);
		return ERR_PTR(-ENOMEM);
	}

	RB_CLEAR_NODE(&item->node);
	RB_CLEAR_NODE(&item->dirty_node);
	atomic_set(&item->refcount, 1);
	item->key = *key;
	item->val_len = val_len;
	item->val = val;

	return item;
}

static struct scoutfs_item *create_item(struct super_block *sb,
					struct scoutfs_key *key,
					unsigned int val_len, bool dirty)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_item *existing;
	struct scoutfs_item *item;
	unsigned long flags;

	item = alloc_item(key, val_len);
	if (IS_ERR(item))
		return item;

	spin_lock_irqsave(&sbi->item_lock, flags);

	existing = find_item(sb, &sbi->item_root, key, 0);
	if (!existing) {
		insert_item(sb, &sbi->item_root, item);
		atomic_inc(&item->refcount);
		if (dirty) {
			insert_item(sb, &sbi->dirty_item_root, item);
			atomic_inc(&item->refcount);
		}

	}
	spin_unlock_irqrestore(&sbi->item_lock, flags);

	if (existing) {
		scoutfs_item_put(item);
		item = ERR_PTR(-EEXIST);
	}

	trace_printk("item %p key "CKF" val_len %d\n", item, CKA(key), val_len);

	return item;
}

/*
 * Create a new item stored at the given key.  Return it with a reference.
 * return an ERR_PTR with ENOMEM or EEXIST.
 *
 * The caller is responsible for initializing the item's value.
 */
struct scoutfs_item *scoutfs_item_create(struct super_block *sb,
					 struct scoutfs_key *key,
					 unsigned int val_len)
{
	return create_item(sb, key, val_len, true);
}

/*
 * Allocate a new clean item in the cache for the caller to fill.  If the
 * item already exists then -EEXIST is returned.
 */
struct scoutfs_item *scoutfs_clean_item(struct super_block *sb,
				        struct scoutfs_key *key,
				        unsigned int val_len)
{
	return create_item(sb, key, val_len, false);
}

/*
 * The caller is still responsible for unlocking and putting the item.
 *
 * We don't try and optimize away the lock for items that are already
 * removed from the tree.  The caller's locking and item behaviour means
 * that racing to remove an item is extremely rare.
 *
 * XXX for now we're just removing it from the rbtree.  We'd need to leave
 * behind a deletion record for lsm.
 */
void scoutfs_item_delete(struct super_block *sb, struct scoutfs_item *item)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	unsigned long flags;

	spin_lock_irqsave(&sbi->item_lock, flags);

	if (!RB_EMPTY_NODE(&item->dirty_node)) {
		rb_erase(&item->dirty_node, &sbi->dirty_item_root);
		RB_CLEAR_NODE(&item->dirty_node);
		scoutfs_item_put(item);
	}

	if (!RB_EMPTY_NODE(&item->node)) {
		rb_erase(&item->node, &sbi->item_root);
		RB_CLEAR_NODE(&item->node);
		scoutfs_item_put(item);
	}

	spin_unlock_irqrestore(&sbi->item_lock, flags);
}

/*
 * Find an item in the cache.  If it isn't present then we try to read
 * it from log segements.
 */
static struct scoutfs_item *item_lookup(struct super_block *sb,
					struct scoutfs_key *key, int np)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_item *item;
	unsigned long flags;
	unsigned retried = 0;
	int ret;

	do {
		spin_lock_irqsave(&sbi->item_lock, flags);

		item = find_item(sb, &sbi->item_root, key, np);
		if (item)
			atomic_inc(&item->refcount);

		spin_unlock_irqrestore(&sbi->item_lock, flags);
		if (!item) {
			if (np == FI_NEXT)
				ret = scoutfs_read_next_item(sb, key);
			else
				ret = scoutfs_read_item(sb, key);
			if (ret)
				item = ERR_PTR(ret);
		}
	} while (!item && !retried++);

	if (!item)
		item = ERR_PTR(-ENOENT);

	return item;
}

struct scoutfs_item *scoutfs_item_lookup(struct super_block *sb,
					 struct scoutfs_key *key)
{
	return item_lookup(sb, key, 0);
}

struct scoutfs_item *scoutfs_item_next(struct super_block *sb,
				       struct scoutfs_key *key)
{
	return item_lookup(sb, key, FI_NEXT);
}

struct scoutfs_item *scoutfs_item_prev(struct super_block *sb,
				       struct scoutfs_key *key)
{
	return item_lookup(sb, key, FI_PREV);
}

/*
 * Expand the item's value by inserting bytes at the given offset.  The
 * new bytes are not initialized.
 */
int scoutfs_item_expand(struct scoutfs_item *item, int off, int bytes)
{
	void *val;

	/* XXX bytes too big */
	if (WARN_ON_ONCE(off < 0 || off > item->val_len))
		return -EINVAL;

	val = kmalloc(item->val_len + bytes, GFP_NOFS);
	if (!val)
		return -ENOMEM;

	memcpy(val, item->val, off);
	memcpy(val + off + bytes, item->val + off, item->val_len - off);

	kfree(item->val);
	item->val = val;
	item->val_len += bytes;

	return 0;
}

/*
 * Shrink the item's value by remove bytes at the given offset.
 */
int scoutfs_item_shrink(struct scoutfs_item *item, int off, int bytes)
{
	void *val;

	if (WARN_ON_ONCE(off < 0 || off >= item->val_len ||
		         bytes <= 0 || (off + bytes) > item->val_len ||
		         bytes == item->val_len))
		return -EINVAL;

	val = kmalloc(item->val_len - bytes, GFP_NOFS);
	if (!val)
		return -ENOMEM;

	memcpy(val, item->val, off);
	memcpy(val + off, item->val + off + bytes,
	       item->val_len - (off + bytes));

	kfree(item->val);
	item->val = val;
	item->val_len -= bytes;

	return 0;
}

void scoutfs_item_mark_dirty(struct super_block *sb, struct scoutfs_item *item)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	unsigned long flags;

	spin_lock_irqsave(&sbi->item_lock, flags);

	if (RB_EMPTY_NODE(&item->dirty_node)) {
		insert_item(sb, &sbi->dirty_item_root, item);
		atomic_inc(&item->refcount);
	}

	spin_unlock_irqrestore(&sbi->item_lock, flags);
}

/*
 * Mark all the dirty items clean by emptying the dirty rbtree.  The
 * caller should be preventing writes from dirtying new items.
 *
 * We erase leaf nodes with no children to minimize rotation
 * overhead during erase.  Dirty items must be in the main rbtree if
 * they're in the dirty rbtree so the puts here shouldn't free the
 * items.
 */
void scoutfs_item_all_clean(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct rb_root *root = &sbi->dirty_item_root;
	struct scoutfs_item *item;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&sbi->item_lock, flags);

	node = sbi->dirty_item_root.rb_node;
	while (node) {
		if (node->rb_left)
			node = node->rb_left;
		else if (node->rb_right)
			node = node->rb_right;
		else {
			item = node_item(sb, root, node);
			node = rb_parent(node);

			trace_printk("item %p key "CKF"\n",
				     item, CKA(&item->key));
			rb_erase(&item->dirty_node, root);
			RB_CLEAR_NODE(&item->dirty_node);
			scoutfs_item_put(item);
		}
	}

	spin_unlock_irqrestore(&sbi->item_lock, flags);
}

/*
 * If the item is null then the first dirty item is returned.  If an
 * item is given then the next dirty item is returned.  NULL is returned
 * if there are no more dirty items.
 *
 * The caller is given a reference that it has to put.  The given item
 * will always have its item dropped including if it returns NULL.
 */
struct scoutfs_item *scoutfs_item_next_dirty(struct super_block *sb,
					     struct scoutfs_item *item)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_item *next_item;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&sbi->item_lock, flags);

	if (item)
		node = rb_next(&item->dirty_node);
	else
		node = rb_first(&sbi->dirty_item_root);

	if (node) {
		next_item = node_item(sb, &sbi->dirty_item_root, node);
		atomic_inc(&next_item->refcount);
	} else {
		next_item = NULL;
	}

	spin_unlock_irqrestore(&sbi->item_lock, flags);

	scoutfs_item_put(item);

	return next_item;
}

void scoutfs_item_put(struct scoutfs_item *item)
{
	if (!IS_ERR_OR_NULL(item) && atomic_dec_and_test(&item->refcount)) {
		WARN_ON_ONCE(!RB_EMPTY_NODE(&item->node));
		WARN_ON_ONCE(!RB_EMPTY_NODE(&item->dirty_node));
		kfree(item);
	}
}
