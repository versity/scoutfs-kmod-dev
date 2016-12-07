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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/rbtree_augmented.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "manifest.h"
#include "item.h"
#include "seg.h"

struct item_cache {
	spinlock_t lock;
	struct rb_root root;

	unsigned long nr_dirty_items;
	unsigned long dirty_key_bytes;
	unsigned long dirty_val_bytes;
};

/*
 * The dirty bits track if the given item is dirty and if its child
 * subtrees contain any dirty items.
 */
struct cached_item {
	struct rb_node node;
	long dirty;

	SCOUTFS_DECLARE_KVEC(key);
	SCOUTFS_DECLARE_KVEC(val);
};

static struct cached_item *find_item(struct rb_root *root, struct kvec *key)
{
	struct rb_node *node = root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_item *item;
	int cmp;

	while (node) {
		parent = node;
		item = container_of(node, struct cached_item, node);

		cmp = scoutfs_kvec_memcmp(key, item->key);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return item;
	}

	return NULL;
}

/*
 * We store the dirty bits in a single value so that the simple
 * augmented rbtree implementation gets a single scalar value to compare
 * and store.
 */
#define ITEM_DIRTY 0x1
#define LEFT_DIRTY 0x2
#define RIGHT_DIRTY 0x4

/*
 * Return the given dirty bit if the item with the given node is dirty
 * or has dirty children.
 */
static long node_dirty_bit(struct rb_node *node, long dirty)
{
	struct cached_item *item;

	if (node) {
		item = container_of(node, struct cached_item, node);
		if (item->dirty)
			return dirty;
	}

	return 0;
}

static long compute_item_dirty(struct cached_item *item)
{
	return (item->dirty & ITEM_DIRTY) |
	       node_dirty_bit(item->node.rb_left, LEFT_DIRTY) |
	       node_dirty_bit(item->node.rb_right, RIGHT_DIRTY);
}

RB_DECLARE_CALLBACKS(static, scoutfs_item_rb_cb, struct cached_item, node,
		     long, dirty, compute_item_dirty);

/*
 * Always insert the given item.  If there's an existing item it is
 * returned.  This can briefly leave duplicate items in the tree until
 * the caller removes the existing item.
 */
static struct cached_item *insert_item(struct rb_root *root,
				       struct cached_item *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_item *existing = NULL;
	struct cached_item *item;
	int cmp;

	while (*node) {
		parent = *node;
		item = container_of(*node, struct cached_item, node);

		cmp = scoutfs_kvec_memcmp(ins->key, item->key);
		if (cmp < 0) {
			if (ins->dirty)
				item->dirty |= LEFT_DIRTY;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			if (ins->dirty)
				item->dirty |= RIGHT_DIRTY;
			node = &(*node)->rb_right;
		} else {
			existing = item;
			break;
		}
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_augmented(&ins->node, root, &scoutfs_item_rb_cb);

	return existing;
}

/*
 * Find an item with the given key and copy its value into the caller's
 * value vector.  The amount of bytes copied is returned which can be
 * 0 or truncated if the caller's buffer isn't big enough.
 */
int scoutfs_item_lookup(struct super_block *sb, struct kvec *key,
			struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(&cac->root, key);
		if (item)
			ret = scoutfs_kvec_memcpy(val, item->val);
		else
			ret = -ENOENT;

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (!item && ((ret = scoutfs_manifest_read_items(sb, key)) == 0));

	trace_printk("ret %d\n", ret);

	return ret;
}

/*
 * This requires that the item at the specified key has a value of the
 * same length as the specified value.  Callers are asserting that
 * mismatched size are corruption so it returns -EIO if the sizes don't
 * match.  This isn't the fast path so we don't mind the copying
 * overhead that comes from only detecting the size mismatch after the
 * copy by reusing the more permissive _lookup().
 *
 * Returns 0 or -errno.
 */
int scoutfs_item_lookup_exact(struct super_block *sb, struct kvec *key,
			      struct kvec *val, int size)
{
	int ret;

	ret = scoutfs_item_lookup(sb, key, val);
	if (ret == size)
		ret = 0;
	else if (ret >= 0)
		ret = -EIO;

	return ret;
}

/*
 * Return the next cached item starting with the given key.
 *
 * -ENOENT is returned if there are no cached items past the given key.
 * If the last key is specified then -ENOENT is returned if there are no
 * cached items up until that last key, inclusive.
 *
 * The found key is copied to the caller's key.  -ENOBUFS is returned if
 * the found key didn't fit in the caller's key.
 *
 * The found value is copied into the callers value.  The number of
 * value bytes copied is returned.  The copied value can be truncated by
 * the caller's value buffer length.
 */
int scoutfs_item_next(struct super_block *sb, struct kvec *key,
		      struct kvec *last, struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	/*
	 * This partial copy and paste of lookup is stubbed out for now.
	 * we'll want the negative caching fixes to be able to iterate
	 * without constantly searching the manifest between cached
	 * items.
	 */
	return -EINVAL;

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(&cac->root, key);
		if (!item) {
			ret = -ENOENT;
		} else if (scoutfs_kvec_length(item->key) >
			   scoutfs_kvec_length(key)) {
			ret = -ENOBUFS;
		} else {
			scoutfs_kvec_memcpy_truncate(key, item->key);
			if (val)
				ret = scoutfs_kvec_memcpy(val, item->val);
			else
				ret = 0;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (!item && ((ret = scoutfs_manifest_read_items(sb, key)) == 0));

	trace_printk("ret %d\n", ret);

	return ret;
}

/*
 * Like _next but requires that the found keys be the same length as the
 * search key and that values be of at least a minimum size.  It treats
 * size mismatches as a sign of corruption.  A found key larger than the
 * found key buffer gives -ENOBUFS and is a sign of corruption.
 */
int scoutfs_item_next_same_min(struct super_block *sb, struct kvec *key,
			       struct kvec *last, struct kvec *val, int len)
{
	int key_len = scoutfs_kvec_length(key);
	int ret;

	trace_printk("key len %u min val len %d\n", key_len, len);

	if (WARN_ON_ONCE(!val || scoutfs_kvec_length(val) < len))
		return -EINVAL;

	ret = scoutfs_item_next(sb, key, last, val);
	if (ret == -ENOBUFS ||
	    (ret >= 0 && (scoutfs_kvec_length(key) != key_len || ret < len)))
		ret = -EIO;

	trace_printk("ret %d\n", ret);

	return ret;
}

static void free_item(struct cached_item *item)
{
	if (!IS_ERR_OR_NULL(item)) {
		scoutfs_kvec_kfree(item->val);
		scoutfs_kvec_kfree(item->key);
		kfree(item);
	}
}

/*
 * The caller might have modified the item's dirty flags.  Ascend
 * through parents updating their dirty flags until there's no change.
 */
static void update_dirty_parents(struct cached_item *item)
{
	struct cached_item *parent;
	struct rb_node *node;
	long dirty;

	while ((node = rb_parent(&item->node))) {
		parent = container_of(node, struct cached_item, node);
		dirty = compute_item_dirty(parent);

		if (parent->dirty == dirty)
			break;

		parent->dirty = dirty;
		item = parent;
	}
}

static void mark_item_dirty(struct item_cache *cac,
			    struct cached_item *item)
{
	if (WARN_ON_ONCE(RB_EMPTY_NODE(&item->node)))
		return;

	if (item->dirty & ITEM_DIRTY)
		return;

	item->dirty |= ITEM_DIRTY;
	cac->nr_dirty_items++;
	cac->dirty_key_bytes += scoutfs_kvec_length(item->key);
	cac->dirty_val_bytes += scoutfs_kvec_length(item->val);

	update_dirty_parents(item);
}

static void clear_item_dirty(struct item_cache *cac,
			     struct cached_item *item)
{
	if (WARN_ON_ONCE(RB_EMPTY_NODE(&item->node)))
		return;

	if (!(item->dirty & ITEM_DIRTY))
		return;

	item->dirty &= ~ITEM_DIRTY;
	cac->nr_dirty_items--;
	cac->dirty_key_bytes -= scoutfs_kvec_length(item->key);
	cac->dirty_val_bytes -= scoutfs_kvec_length(item->val);

	update_dirty_parents(item);
}

/*
 * Add an item with the key and value to the item cache.  The new item
 * is clean.  Any existing item at the key will be removed and freed.
 */
static int add_item(struct super_block *sb, struct kvec *key, struct kvec *val,
		    bool dirty)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *existing;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	item = kzalloc(sizeof(struct cached_item), GFP_NOFS);
	if (!item)
		return -ENOMEM;

	ret = scoutfs_kvec_dup_flatten(item->key, key) ?:
	      scoutfs_kvec_dup_flatten(item->val, val);
	if (ret) {
		free_item(item);
		return ret;
	}

	spin_lock_irqsave(&cac->lock, flags);
	existing = insert_item(&cac->root, item);
	if (existing) {
		clear_item_dirty(cac, existing);
		rb_erase_augmented(&item->node, &cac->root,
				   &scoutfs_item_rb_cb);
	}
	mark_item_dirty(cac, item);
	spin_unlock_irqrestore(&cac->lock, flags);
	free_item(existing);

	return 0;
}

/*
 * Add a clean item to the cache.  This is used to populate items while
 * reading segments.
 */
int scoutfs_item_insert(struct super_block *sb, struct kvec *key,
		        struct kvec *val)
{
	return add_item(sb, key, val, false);
}

/*
 * Create a new dirty item in the cache.
 */
int scoutfs_item_create(struct super_block *sb, struct kvec *key,
		        struct kvec *val)
{
	return add_item(sb, key, val, true);
}

/*
 * If the item with the key exists make sure it's cached and dirty.  -ENOENT
 * will be returned if it doesn't exist.
 */
int scoutfs_item_dirty(struct super_block *sb, struct kvec *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(&cac->root, key);
		if (item) {
			mark_item_dirty(cac, item);
			ret = 0;
		} else {
			ret = -ENOENT;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (!item && ((ret = scoutfs_manifest_read_items(sb, key)) == 0));

	trace_printk("ret %d\n", ret);

	return ret;
}

/*
 * Set the value of an existing item in the tree.  The item is marked dirty
 * and the previous value is freed.  The provided value may be null.
 *
 * Returns -ENOENT if the item doesn't exist.
 */
int scoutfs_item_update(struct super_block *sb, struct kvec *key,
			struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	SCOUTFS_DECLARE_KVEC(up_val);
	struct cached_item *item;
	unsigned long flags;
	int ret;

	if (val) {
		ret = scoutfs_kvec_dup_flatten(up_val, val);
		if (ret)
			return -ENOMEM;
	} else {
		scoutfs_kvec_init_null(up_val);
	}

	spin_lock_irqsave(&cac->lock, flags);

	/* XXX update seq */
	item = find_item(&cac->root, key);
	if (item) {
		scoutfs_kvec_swap(up_val, item->val);
		mark_item_dirty(cac, item);
	} else {
		ret = -ENOENT;
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	scoutfs_kvec_kfree(up_val);

	trace_printk("ret %d\n", ret);

	return ret;
}

/*
 * XXX how nice, it'd just creates a cached deletion item.  It doesn't
 * have to read.
 */
int scoutfs_item_delete(struct super_block *sb, struct kvec *key)
{
	return WARN_ON_ONCE(-EINVAL);
}

/*
 * Return the first dirty node in the subtree starting at the given node.
 */
static struct cached_item *first_dirty(struct rb_node *node)
{
	struct cached_item *ret = NULL;
	struct cached_item *item;

	while (node) {
		item = container_of(node, struct cached_item, node);

		if (item->dirty & LEFT_DIRTY) {
			node = item->node.rb_left;
		} else if (item->dirty & ITEM_DIRTY) {
			ret = item;
			break;
		} else if (item->dirty & RIGHT_DIRTY) {
			node = item->node.rb_right;
		}
	}

	return ret;
}

/*
 * Find the next dirty item after a given item.  First we see if we have
 * a dirty item in our right subtree.  If not we ascend through parents
 * skipping those that are less than us.  If we find a parent that's
 * greater than us then we see if it's dirty, if not we start the search
 * all over again by checking its right subtree then ascending.
 */
static struct cached_item *next_dirty(struct cached_item *item)
{
	struct rb_node *parent;
	struct rb_node *node;

	while (item) {
		if (item->dirty & RIGHT_DIRTY)
			return first_dirty(item->node.rb_right);

		/* find next greatest parent */
		node = &item->node;
		while ((parent = rb_parent(node)) && parent->rb_right == node)
			node = parent;
		if (!parent)
			break;

		/* done if our next greatest parent itself is dirty */
		item = container_of(parent, struct cached_item, node);
		if (item->dirty & ITEM_DIRTY)
			return item;

		/* continue to check right subtree */
	}

	return NULL;
}

/*
 * The total number of bytes that will be stored in segments if we were
 * to write out all the currently dirty items.
 *
 * XXX this isn't strictly correct because item's aren't of a uniform
 * size.  We might need more segments when large items leave gaps at the
 * tail of each segment as it is filled with sorted items.  It's close
 * enough for now.
 */
long scoutfs_item_dirty_bytes(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	unsigned long flags;
	long bytes;

	spin_lock_irqsave(&cac->lock, flags);

	bytes = (cac->nr_dirty_items * sizeof(struct scoutfs_segment_item)) +
	         cac->dirty_key_bytes + cac->dirty_val_bytes;

	spin_unlock_irqrestore(&cac->lock, flags);

	bytes += DIV_ROUND_UP(bytes, sizeof(struct scoutfs_segment_block)) *
			sizeof(struct scoutfs_segment_block);

	return bytes;
}

/*
 * Find the initial sorted dirty items that will fit in a segment.  Give
 * the caller the number of items and the total bytes of their keys.
 */
static void count_seg_items(struct item_cache *cac, u32 *nr_items,
			    u32 *key_bytes)
{
	struct cached_item *item;
	u32 total;

	*nr_items = 0;
	*key_bytes = 0;
	total = sizeof(struct scoutfs_segment_block);

	for (item = first_dirty(cac->root.rb_node); item;
	     item = next_dirty(item)) {

		total += sizeof(struct scoutfs_segment_item) +
			 scoutfs_kvec_length(item->key) +
			 scoutfs_kvec_length(item->val);

		if (total > SCOUTFS_SEGMENT_SIZE)
			break;

		(*nr_items)++;
		(*key_bytes) += scoutfs_kvec_length(item->key);
	}
}

/*
 * Fill the given segment with sorted dirty items.
 *
 * The caller is responsible for the consistency of the dirty items once
 * they're in its seg.  We can consider them clean once we store them.
 */
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	u32 key_bytes;
	u32 nr_items;

	count_seg_items(cac, &nr_items, &key_bytes);
	if (nr_items) {
		item = first_dirty(cac->root.rb_node);
		scoutfs_seg_first_item(sb, seg, item->key, item->val,
				       nr_items, key_bytes);
		clear_item_dirty(cac, item);

		while ((item = next_dirty(item))) {
			scoutfs_seg_append_item(sb, seg, item->key, item->val);
			clear_item_dirty(cac, item);
		}
	}

	return 0;
}

int scoutfs_item_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac;

	cac = kzalloc(sizeof(struct item_cache), GFP_KERNEL);
	if (!cac)
		return -ENOMEM;
	sbi->item_cache = cac;

	spin_lock_init(&cac->lock);
	cac->root = RB_ROOT;

	return 0;
}

void scoutfs_item_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	struct rb_node *node;

	if (cac) {
		for (node = rb_first(&cac->root); node; ) {
			item = container_of(node, struct cached_item, node);
			node = rb_next(node);
			free_item(item);
		}

		kfree(cac);
	}
}
