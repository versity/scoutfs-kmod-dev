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
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * A simple rbtree of cached items isolates the item API callers from
 * the relatively expensive segment searches.
 *
 * The item cache uses an rbtree of key ranges to record regions of keys
 * that are completely described by the items.  This lets it return
 * negative lookups cache hits for items that don't exist without having
 * to constantly perform expensive segment searches.
 */

struct item_cache {
	spinlock_t lock;
	struct rb_root items;
	struct rb_root ranges;

	long nr_dirty_items;
	long dirty_key_bytes;
	long dirty_val_bytes;
};

/*
 * The dirty bits track if the given item is dirty and if its child
 * subtrees contain any dirty items.
 *
 * The entry is only used when the items are in a private batch list
 * before insertion.
 */
struct cached_item {
	union {
		struct rb_node node;
		struct list_head entry;
	};
	long dirty;

	struct scoutfs_key_buf *key;

	SCOUTFS_DECLARE_KVEC(val);
};

struct cached_range {
	struct rb_node node;

	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
};

/*
 * Walk the item rbtree and return the item found and the next and
 * prev items.
 */
static struct cached_item *walk_items(struct rb_root *root,
				      struct scoutfs_key_buf *key,
				      struct cached_item **prev,
				      struct cached_item **next)
{
	struct rb_node *node = root->rb_node;
	struct cached_item *item;
	int cmp;

	*prev = NULL;
	*next = NULL;

	while (node) {
		item = container_of(node, struct cached_item, node);

		cmp = scoutfs_key_compare(key, item->key);
		if (cmp < 0) {
			*next = item;
			node = node->rb_left;
		} else if (cmp > 0) {
			*prev = item;
			node = node->rb_right;
		} else {
			return item;
		}
	}

	return NULL;
}

static struct cached_item *find_item(struct super_block *sb,
				     struct rb_root *root,
				     struct scoutfs_key_buf *key)
{
	struct cached_item *prev;
	struct cached_item *next;
	struct cached_item *item;

	item = walk_items(root, key, &prev, &next);

	if (item)
		scoutfs_inc_counter(sb, item_lookup_hit);
	else
		scoutfs_inc_counter(sb, item_lookup_miss);

	return item;
}

static struct cached_item *next_item(struct rb_root *root,
				     struct scoutfs_key_buf *key)
{
	struct cached_item *prev;
	struct cached_item *next;

	return walk_items(root, key, &prev, &next) ?: next;
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

static void scoutfs_item_rb_propagate(struct rb_node *node,
				      struct rb_node *stop)
{
	struct cached_item *item;
	long dirty;

	while (node != stop) {
		item = container_of(node, struct cached_item, node);
		dirty = compute_item_dirty(item);

		if (item->dirty == dirty)
			break;

		item->dirty = dirty;
		node = rb_parent(&item->node);
	}
}

static void scoutfs_item_rb_copy(struct rb_node *old, struct rb_node *new)
{
	struct cached_item *o = container_of(old, struct cached_item, node);
	struct cached_item *n = container_of(new, struct cached_item, node);

	n->dirty = o->dirty;
}

/* calculate the new parent last as it depends on the old parent */
static void scoutfs_item_rb_rotate(struct rb_node *old, struct rb_node *new)
{
	struct cached_item *o = container_of(old, struct cached_item, node);
	struct cached_item *n = container_of(new, struct cached_item, node);

	BUG_ON(rb_parent(old) != new);

	o->dirty = compute_item_dirty(o);
	n->dirty = compute_item_dirty(n);
}

/*
 * The generic RB_DECLARE_CALLBACKS() helpers are built for augmented
 * values that are simple commutative function of the left and right
 * children's augmented values.  During rotation the new parent just
 * gets the old parent's augmented value and then the old parent's value
 * is calculated.
 *
 * Our dirty bits don't work that way.  They are not just an or of the
 * child's bits, the bits depend on the left and right children
 * specifically.  During rotation both parents need to be specifically
 * recalculated.  (They could be masked and asigned based on the
 * direction of the rotation but that's annoying, let's just
 * recalculate.)
 */
static const struct rb_augment_callbacks scoutfs_item_rb_cb  = {
	.propagate = scoutfs_item_rb_propagate,
	.copy = scoutfs_item_rb_copy,
	.rotate = scoutfs_item_rb_rotate,
};

/*
 * Try to insert the given item.  If there's already an item with the
 * insertion key then return -EEXIST.
 */
static int insert_item(struct rb_root *root, struct cached_item *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_item *item;
	int cmp;

	while (*node) {
		parent = *node;
		item = container_of(*node, struct cached_item, node);

		cmp = scoutfs_key_compare(ins->key, item->key);
		if (cmp < 0) {
			if (ins->dirty)
				item->dirty |= LEFT_DIRTY;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			if (ins->dirty)
				item->dirty |= RIGHT_DIRTY;
			node = &(*node)->rb_right;
		} else {
			return -EEXIST;
		}
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_augmented(&ins->node, root, &scoutfs_item_rb_cb);

	return 0;
}

/*
 * Return true if the given key is covered by a cached range.  end is
 * set to the end of the cached range.
 *
 * Return false if the given key isn't covered by a cached range and is
 * instead in an uncached hole.  end is set to the start of the next
 * cached range.
 */
static bool check_range(struct super_block *sb, struct rb_root *root,
			struct scoutfs_key_buf *key,
			struct scoutfs_key_buf *end)
{
	struct rb_node *node = root->rb_node;
	struct cached_range *next = NULL;
	struct cached_range *rng;
	int cmp;

	while (node) {
		rng = container_of(node, struct cached_range, node);

		cmp = scoutfs_key_compare_ranges(key, key,
						 rng->start, rng->end);
		if (cmp < 0) {
			next = rng;
			node = node->rb_left;
		} else if (cmp > 0) {
			node = node->rb_right;
		} else {
			scoutfs_key_copy(end, rng->end);
			scoutfs_inc_counter(sb, item_range_hit);
			return true;
		}
	}

	if (next)
		scoutfs_key_copy(end, next->start);
	else
		scoutfs_key_set_max(end);

	scoutfs_inc_counter(sb, item_range_miss);
	return false;
}

static void free_range(struct super_block *sb, struct cached_range *rng)
{
	if (!IS_ERR_OR_NULL(rng)) {
		scoutfs_key_free(sb, rng->start);
		scoutfs_key_free(sb, rng->end);
		kfree(rng);
	}
}

/*
 * Insert a new cached range.  It might overlap with any number of
 * existing cached ranges.  As we descend we combine with and free any
 * overlapping ranges before restarting the descent.
 *
 * We're responsible for the ins allocation.  We free it if we don't
 * insert it in the tree.
 */
static void insert_range(struct super_block *sb, struct rb_root *root,
			 struct cached_range *ins)
{
	struct cached_range *rng;
	struct rb_node *parent;
	struct rb_node **node;
	int start_cmp;
	int end_cmp;
	int cmp;

	scoutfs_inc_counter(sb, item_range_insert);

restart:
	parent = NULL;
	node = &root->rb_node;
	while (*node) {
		parent = *node;
		rng = container_of(*node, struct cached_range, node);

		cmp = scoutfs_key_compare_ranges(ins->start, ins->end,
						 rng->start, rng->end);
		/* simple iteration until we overlap */
		if (cmp < 0) {
			node = &(*node)->rb_left;
			continue;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
			continue;
		}

		start_cmp = scoutfs_key_compare(ins->start, rng->start);
		end_cmp = scoutfs_key_compare(ins->end, rng->end);

		/* free our insertion if we're entirely within an existing */
		if (start_cmp >= 0 && end_cmp <= 0) {
			free_range(sb, ins);
			return;
		}

		/* expand to cover partial overlap before freeing */
		if (start_cmp < 0 && end_cmp < 0)
			swap(ins->end, rng->end);
		else if (start_cmp > 0 && end_cmp > 0)
			swap(ins->start, rng->start);

		/* remove and free all overlaps and restart the descent */
		rb_erase(&rng->node, root);
		free_range(sb, rng);
		goto restart;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

/*
 * Find an item with the given key and copy its value into the caller's
 * value vector.  The amount of bytes copied is returned which can be 0
 * or truncated if the caller's buffer isn't big enough.
 */
int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *end;
	struct cached_item *item;
	unsigned long flags;
	int ret;

//	trace_scoutfs_item_lookup(sb, key, val);

	end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!end) {
		ret = -ENOMEM;
		goto out;
	}

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item)
			ret = scoutfs_kvec_memcpy(val, item->val);
		else if (check_range(sb, &cac->ranges, key, end))
			ret = -ENOENT;
		else
			ret = -ENODATA;

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);

	scoutfs_key_free(sb, end);
out:
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
int scoutfs_item_lookup_exact(struct super_block *sb,
			      struct scoutfs_key_buf *key, struct kvec *val,
			      int size)
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
 * Return the next item starting with the given key, returning the last
 * key at the most.
 *
 * -ENOENT is returned if there are no items between the given and last
 * keys.
 *
 * The next item's key is copied to the caller's key.  The caller is
 * responsible for dealing with key lengths and truncation.
 *
 * The next item's value is copied into the callers value.  The number
 * of value bytes copied is returned.  The copied value can be truncated
 * by the caller's value buffer length.
 */
int scoutfs_item_next(struct super_block *sb, struct scoutfs_key_buf *key,
		      struct scoutfs_key_buf *last, struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *read_start = NULL;
	struct scoutfs_key_buf *read_end = NULL;
	struct scoutfs_key_buf *range_end = NULL;
	struct cached_item *item;
	unsigned long flags;
	bool cached;
	int ret;

	/* convenience to avoid searching if caller iterates past their last */
	if (scoutfs_key_compare(key, last) > 0) {
		ret = -ENOENT;
		goto out;
	}

	read_start = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	read_end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	range_end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!read_start || !read_end || !range_end) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&cac->lock, flags);

	for(;;) {
		/* see if we have a usable item in cache and before last */
		cached = check_range(sb, &cac->ranges, key, range_end);

		if (cached && (item = next_item(&cac->items, key)) &&
		    scoutfs_key_compare(item->key, range_end) <= 0 &&
		    scoutfs_key_compare(item->key, last) <= 0) {

			scoutfs_key_copy(key, item->key);
			if (val)
				ret = scoutfs_kvec_memcpy(val, item->val);
			else
				ret = 0;
			break;
		}

		if (!cached) {
			/* missing cache starts at key */
			scoutfs_key_copy(read_start, key);
			scoutfs_key_copy(read_end, range_end);

		} else if (scoutfs_key_compare(range_end, last) < 0) {
			/* missing cache starts at range_end */
			scoutfs_key_copy(read_start, range_end);
			scoutfs_key_copy(read_end, last);

		} else {
			/* no items and we have cache between key and last */
			ret = -ENOENT;
			break;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

		ret = scoutfs_manifest_read_items(sb, read_start, read_end);

		spin_lock_irqsave(&cac->lock, flags);
		if (ret)
			break;
	}

	spin_unlock_irqrestore(&cac->lock, flags);
out:
	scoutfs_key_free(sb, read_start);
	scoutfs_key_free(sb, read_end);
	scoutfs_key_free(sb, range_end);

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Like _next but requires that the found keys be the same length as the
 * search key and that values be of at least a minimum size.  It treats
 * size mismatches as a sign of corruption.  A found key larger than the
 * found key buffer gives -ENOBUFS and is a sign of corruption.
 */
int scoutfs_item_next_same_min(struct super_block *sb,
			       struct scoutfs_key_buf *key,
			       struct scoutfs_key_buf *last,
			       struct kvec *val, int len)
{
	int key_len = key->key_len;
	int ret;

	trace_printk("key len %u min val len %d\n", key_len, len);

	if (WARN_ON_ONCE(!val || scoutfs_kvec_length(val) < len))
		return -EINVAL;

	ret = scoutfs_item_next(sb, key, last, val);
	if (ret >= 0 && (key->key_len != key_len || ret < len))
		ret = -EIO;

	trace_printk("ret %d\n", ret);

	return ret;
}

static void free_item(struct super_block *sb, struct cached_item *item)
{
	if (!IS_ERR_OR_NULL(item)) {
		scoutfs_key_free(sb, item->key);
		scoutfs_kvec_kfree(item->val);
		kfree(item);
	}
}

/*
 * The caller has changed an item's dirty bit.  Its child dirty bits are
 * still consistent.  But its parent's bits might need to be updated.
 * Its bits are consistent so we don't propagate from the node itself
 * because it would immediately terminate.
 */
static void update_dirty_parents(struct cached_item *item)
{
	scoutfs_item_rb_propagate(rb_parent(&item->node), NULL);
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
	cac->dirty_key_bytes += item->key->key_len;
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
	cac->dirty_key_bytes -= item->key->key_len;
	cac->dirty_val_bytes -= scoutfs_kvec_length(item->val);

	WARN_ON_ONCE(cac->nr_dirty_items < 0 || cac->dirty_key_bytes < 0 ||
		     cac->dirty_val_bytes < 0);

	update_dirty_parents(item);
}

static struct cached_item *alloc_item(struct super_block *sb,
				      struct scoutfs_key_buf *key,
				      struct kvec *val)
{
	struct cached_item *item;

	item = kzalloc(sizeof(struct cached_item), GFP_NOFS);
	if (item) {
		item->key = scoutfs_key_dup(sb, key);
		if (!item->key || scoutfs_kvec_dup_flatten(item->val, val)) {
			free_item(sb, item);
			item = NULL;
		}
	}

	return item;
}

/*
 * Create a new dirty item in the cache.  Returns -EEXIST if an item
 * already exists with the given key.
 *
 * XXX but it doesn't read.. is that weird?  Seems weird.
 */
int scoutfs_item_create(struct super_block *sb, struct scoutfs_key_buf *key,
		        struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	item = alloc_item(sb, key, val);
	if (!item)
		return -ENOMEM;

	spin_lock_irqsave(&cac->lock, flags);
	ret = insert_item(&cac->items, item);
	if (!ret) {
		scoutfs_inc_counter(sb, item_create);
		mark_item_dirty(cac, item);
	}
	spin_unlock_irqrestore(&cac->lock, flags);

	if (ret)
		free_item(sb, item);

	return ret;
}

/*
 * Allocate an item with the key and value and add it to the list of
 * items to be inserted as a batch later.  The caller adds in sort order
 * and we add with _tail to maintain that order.
 */
int scoutfs_item_add_batch(struct super_block *sb, struct list_head *list,
			   struct scoutfs_key_buf *key, struct kvec *val)
{
	struct cached_item *item;
	int ret;

	item = alloc_item(sb, key, val);
	if (item) {
		list_add_tail(&item->entry, list);
		ret = 0;
	} else {
		ret = -ENOMEM;
	}

	return ret;
}


/*
 * Insert a batch of clean read items from segments into the item cache.
 *
 * The caller hasn't been locked so the cached items could have changed
 * since they were asked to read.  If there are duplicates in the item
 * cache they might be newer than what was read so we must drop them on
 * the floor.
 *
 * The batch atomically adds the items and updates the cached range to
 * include the callers range that covers the items.
 *
 * It's safe to re-add items to the batch list after they aren't
 * inserted because _safe iteration will always be past the head entry
 * that will be inserted.
 */
int scoutfs_item_insert_batch(struct super_block *sb, struct list_head *list,
			      struct scoutfs_key_buf *start,
			      struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_range *rng;
	struct cached_item *item;
	struct cached_item *tmp;
	unsigned long flags;
	int ret;

//	trace_scoutfs_item_insert_batch(sb, start, end);

	if (WARN_ON_ONCE(scoutfs_key_compare(start, end) > 0))
		return -EINVAL;

	rng = kzalloc(sizeof(struct cached_range), GFP_NOFS);
	if (rng) {
	       rng->start = scoutfs_key_dup(sb, start);
	       rng->end = scoutfs_key_dup(sb, end);
	}
	if (!rng || !rng->start || !rng->end) {
		free_range(sb, rng);
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&cac->lock, flags);

	insert_range(sb, &cac->ranges, rng);

	list_for_each_entry_safe(item, tmp, list, entry) {
		list_del(&item->entry);
		if (insert_item(&cac->items, item))
			list_add(&item->entry, list);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	ret = 0;
out:
	scoutfs_item_free_batch(sb, list);
	return ret;
}

void scoutfs_item_free_batch(struct super_block *sb, struct list_head *list)
{
	struct cached_item *item;
	struct cached_item *tmp;

	list_for_each_entry_safe(item, tmp, list, entry) {
		list_del_init(&item->entry);
		free_item(sb, item);
	}
}


/*
 * If the item exists make sure it's dirty and pinned.  It can be read
 * if it wasn't cached.  -ENOENT is returned if the item doesn't exist.
 */
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key_buf *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *end;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!end) {
		ret = -ENOMEM;
		goto out;
	}

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item) {
			mark_item_dirty(cac, item);
			ret = 0;
		} else if (check_range(sb, &cac->ranges, key, end)) {
			ret = -ENOENT;
		} else {
			ret = -ENODATA;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);

	scoutfs_key_free(sb, end);
out:
	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Set the value of an existing item in the tree.  The item is marked dirty
 * and the previous value is freed.  The provided value may be null.
 *
 * Returns -ENOENT if the item doesn't exist.
 */
int scoutfs_item_update(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *end;
	SCOUTFS_DECLARE_KVEC(up_val);
	struct cached_item *item;
	unsigned long flags;
	int ret;

	end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!end) {
		ret = -ENOMEM;
		goto out;
	}

	if (val) {
		ret = scoutfs_kvec_dup_flatten(up_val, val);
		if (ret)
			goto out;
	} else {
		scoutfs_kvec_init_null(up_val);
	}

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item) {
			clear_item_dirty(cac, item);
			scoutfs_kvec_swap(up_val, item->val);
			mark_item_dirty(cac, item);
			ret = 0;
		} else if (check_range(sb, &cac->ranges, key, end)) {
			ret = -ENOENT;
		} else {
			ret = -ENODATA;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);
out:
	scoutfs_key_free(sb, end);
	scoutfs_kvec_kfree(up_val);

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * XXX how nice, it'd just creates a cached deletion item.  It doesn't
 * have to read.
 */
int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key_buf *key)
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
		} else {
			break;
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

bool scoutfs_item_has_dirty(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	unsigned long flags;
	bool has;

	spin_lock_irqsave(&cac->lock, flags);
	has = cac->nr_dirty_items != 0;
	spin_unlock_irqrestore(&cac->lock, flags);

	return has;
}

/*
 * Returns true if adding more items with the given count, keys, and values
 * still fits in a single item along with the current dirty items.
 */
bool scoutfs_item_dirty_fits_single(struct super_block *sb, u32 nr_items,
			            u32 key_bytes, u32 val_bytes)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	unsigned long flags;
	bool fits;

	spin_lock_irqsave(&cac->lock, flags);
	fits = scoutfs_seg_fits_single(nr_items + cac->nr_dirty_items,
				       key_bytes + cac->dirty_key_bytes,
				       val_bytes + cac->dirty_val_bytes);
	spin_unlock_irqrestore(&cac->lock, flags);

	return fits;
}

/*
 * Find the initial sorted dirty items that will fit in a segment.  Give
 * the caller the number of items and the total bytes of their keys.
 */
static void count_seg_items(struct item_cache *cac, u32 *nr_items,
			    u32 *key_bytes)
{
	struct cached_item *item;
	u32 items = 0;
	u32 keys = 0;
	u32 vals = 0;

	*nr_items = 0;
	*key_bytes = 0;

	for (item = first_dirty(cac->items.rb_node); item;
	     item = next_dirty(item)) {

		items++;
		keys += item->key->key_len;
		vals += scoutfs_kvec_length(item->val);

		if (!scoutfs_seg_fits_single(items, keys, vals))
			break;

		*nr_items = items;
		*key_bytes = keys;
	}
}

/*
 * Fill the given segment with sorted dirty items.
 *
 * The caller is responsible for the consistency of the dirty items once
 * they're in its seg.  We can consider them clean once we store them.
 *
 * Today entering a transaction doesn't ensure that there's never more
 * than a segment's worth of dirty items.  As we release a trans we kick
 * off an async sync.  By the time we get here we can have a lot more
 * than a segments worth of dirty items.
 *
 * XXX This is unacceptable because multiple segment writes are not
 * atomic.  We can have the items that make up an atomic change span
 * segments and can be partially visible if we only write the first
 * segment.  We probably want to throttle trans enters once we have as
 * many dirty items as our atomic segment updates can write.
 */
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	u32 key_bytes;
	u32 nr_items;

	count_seg_items(cac, &nr_items, &key_bytes);

	item = first_dirty(cac->items.rb_node);
	if (item) {
		scoutfs_seg_first_item(sb, seg, item->key, item->val,
				       nr_items, key_bytes);
		clear_item_dirty(cac, item);
		nr_items--;
	}

	while (nr_items-- && (item = next_dirty(item))) {
		scoutfs_seg_append_item(sb, seg, item->key, item->val);
		clear_item_dirty(cac, item);
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
	cac->items = RB_ROOT;
	cac->ranges = RB_ROOT;

	return 0;
}

void scoutfs_item_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	struct cached_range *rng;
	struct rb_node *node;

	if (cac) {
		for (node = rb_first(&cac->items); node; ) {
			item = container_of(node, struct cached_item, node);
			node = rb_next(node);
			rb_erase(&item->node, &cac->items);
			free_item(sb, item);
		}

		for (node = rb_first(&cac->ranges); node; ) {
			rng = container_of(node, struct cached_range, node);
			node = rb_next(node);
			rb_erase(&rng->node, &cac->items);
			free_range(sb, rng);
		}

		kfree(cac);
	}
}
