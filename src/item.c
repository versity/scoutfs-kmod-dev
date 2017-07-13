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
#include "trans.h"

/*
 * A simple rbtree of cached items isolates the item API callers from
 * the relatively expensive segment searches.
 *
 * The item cache uses an rbtree of key ranges to record regions of keys
 * that are completely described by the items.  This lets it return
 * negative lookups cache hits for items that don't exist without having
 * to constantly perform expensive segment searches.
 *
 * Deletions are recorded with items in the rbtree which record the key
 * of the deletion.  They're removed once they're written to a level0
 * segment.  While they're present in the cache we have to be careful to
 * clobber them in creation and skip them in lookups.
 */

static bool invalid_key_val(struct scoutfs_key_buf *key, struct kvec *val)
{
	return WARN_ON_ONCE(key->key_len > SCOUTFS_MAX_KEY_SIZE ||
	        (val && (scoutfs_kvec_length(val) > SCOUTFS_MAX_VAL_SIZE)));
}

static bool invalid_flags(int sif)
{
	return (sif & SIF_EXCLUSIVE) && (sif & SIF_REPLACE);
}

struct item_cache {
	struct super_block *sb;

	spinlock_t lock;
	struct rb_root items;
	struct rb_root ranges;

	long nr_dirty_items;
	long dirty_key_bytes;
	long dirty_val_bytes;

	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long lru_nr;
};

/*
 * The dirty bits track if the given item is dirty and if its child
 * subtrees contain any dirty items.
 *
 * The entry list_head typically stores clean items on an lru for shrinking.
 * It's also briefly used to track items in a batch after they're
 * allocated but before they're inserted for the first time.
 */
struct cached_item {
	struct rb_node node;
	struct list_head entry;

	long dirty;
	unsigned deletion:1;

	struct scoutfs_key_buf *key;

	SCOUTFS_DECLARE_KVEC(val);
};

struct cached_range {
	struct rb_node node;

	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
};

static u8 item_flags(struct cached_item *item)
{
	return item->deletion ? SCOUTFS_ITEM_FLAG_DELETION : 0;
}

static void free_item(struct super_block *sb, struct cached_item *item)
{
	if (!IS_ERR_OR_NULL(item)) {
		WARN_ON_ONCE(!list_empty(&item->entry));
		WARN_ON_ONCE(!RB_EMPTY_NODE(&item->node));
		scoutfs_key_free(sb, item->key);
		scoutfs_kvec_kfree(item->val);
		kfree(item);
	}
}

static struct cached_item *alloc_item(struct super_block *sb,
				      struct scoutfs_key_buf *key,
				      struct kvec *val)
{
	struct cached_item *item;

	item = kzalloc(sizeof(struct cached_item), GFP_NOFS);
	if (item) {
		RB_CLEAR_NODE(&item->node);
		INIT_LIST_HEAD(&item->entry);

		if (!val)
			scoutfs_kvec_init_null(item->val);

		item->key = scoutfs_key_dup(sb, key);
		if (!item->key ||
		    (val && scoutfs_kvec_dup_flatten(item->val, val))) {
			free_item(sb, item);
			item = NULL;
		}
	}

	return item;
}

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

/*
 * Look for the item with the given key.  Callers of this are looking
 * for existing items.  They would just return -ENOENT from a deletion
 * item if we gave it to them so we return null for deletion items.
 * Callers that would remove a deletion item before inserting a new
 * version of the item do so by having insert_item() replace existing
 * deleted items on their behalf.
 */
static struct cached_item *find_item(struct super_block *sb,
				     struct rb_root *root,
				     struct scoutfs_key_buf *key)
{
	struct cached_item *prev;
	struct cached_item *next;
	struct cached_item *item;

	item = walk_items(root, key, &prev, &next);

	if (item && item->deletion)
		item = NULL;

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
	struct cached_item *n = container_of(new, struct cached_item, node);

	n->dirty = compute_item_dirty(n);
}

/* calculate the new parent last as it depends on the old parent */
static void scoutfs_item_rb_rotate(struct rb_node *old, struct rb_node *new)
{
	struct cached_item *o = container_of(old, struct cached_item, node);
	struct cached_item *n = container_of(new, struct cached_item, node);

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
 * The caller has changed an item's dirty bit.  Its child dirty bits are
 * still consistent.  But its parent's bits might need to be updated.
 * Its bits are consistent so we don't propagate from the node itself
 * because it would immediately terminate.
 */
static void update_dirty_parents(struct cached_item *item)
{
	scoutfs_item_rb_propagate(rb_parent(&item->node), NULL);
}

static void mark_item_dirty(struct super_block *sb, struct item_cache *cac,
			    struct cached_item *item)
{
	if (WARN_ON_ONCE(RB_EMPTY_NODE(&item->node)))
		return;

	if (item->dirty & ITEM_DIRTY)
		return;

	item->dirty |= ITEM_DIRTY;
	list_del_init(&item->entry);
	cac->lru_nr--;

	cac->nr_dirty_items++;
	cac->dirty_key_bytes += item->key->key_len;
	cac->dirty_val_bytes += scoutfs_kvec_length(item->val);

	scoutfs_trans_track_item(sb, 1, item->key->key_len,
				 scoutfs_kvec_length(item->val));

	update_dirty_parents(item);
}

static void clear_item_dirty(struct super_block *sb, struct item_cache *cac,
			     struct cached_item *item)
{
	if (WARN_ON_ONCE(RB_EMPTY_NODE(&item->node)))
		return;

	if (!(item->dirty & ITEM_DIRTY))
		return;

	item->dirty &= ~ITEM_DIRTY;
	list_add_tail(&item->entry, &cac->lru_list);
	cac->lru_nr++;

	cac->nr_dirty_items--;
	cac->dirty_key_bytes -= item->key->key_len;
	cac->dirty_val_bytes -= scoutfs_kvec_length(item->val);

	scoutfs_trans_track_item(sb, -1, -item->key->key_len,
				 -scoutfs_kvec_length(item->val));

	WARN_ON_ONCE(cac->nr_dirty_items < 0 || cac->dirty_key_bytes < 0 ||
		     cac->dirty_val_bytes < 0);

	update_dirty_parents(item);
}

static void item_referenced(struct item_cache *cac, struct cached_item *item)
{
	if (!item->dirty)
		list_move_tail(&item->entry, &cac->lru_list);
}

/*
 * Safely erase an item from the tree.  Make sure to remove its dirty
 * accounting, use the augmented erase, and free it.
 */
static void erase_item(struct super_block *sb, struct item_cache *cac,
		       struct cached_item *item)
{
	trace_printk("erasing item %p\n", item);

	clear_item_dirty(sb, cac, item);
	rb_erase_augmented(&item->node, &cac->items, &scoutfs_item_rb_cb);
	RB_CLEAR_NODE(&item->node);
	if (!list_empty(&item->entry)) {
		list_del_init(&item->entry);
		cac->lru_nr--;
	}
	free_item(sb, item);
}

/*
 * Turn an item that the caller has found while holding the lock into a
 * deletion item.  The caller will free whatever we put in the deletion
 * value after releasing the lock.
 */
static void become_deletion_item(struct super_block *sb,
				 struct item_cache *cac,
				 struct cached_item *item,
				 struct kvec *del_val)
{
	clear_item_dirty(sb, cac, item);
	scoutfs_kvec_clone(del_val, item->val);
	scoutfs_kvec_init_null(item->val);
	item->deletion = 1;
	mark_item_dirty(sb, cac, item);
	scoutfs_inc_counter(sb, item_delete);
}

/*
 * Try to add an item to the cache.  The caller is responsible for
 * marking the newly inserted item dirty.
 *
 * We distinguish between callers seeing trying to insert a new logical
 * item and others trying to populate the cache.
 *
 * New logical item creaters have made sure the items are participating
 * in consistent locking.  It's safe for them to clobber dirty deletion
 * items with a new version of the item.
 *
 * Cache readers can only populate items that weren't present already.
 * In particular, they absolutely cannot replace dirty old inode index items
 * with the old version that was just deleted (outside of range caching and
 * locking consistency).
 */
static int insert_item(struct super_block *sb, struct item_cache *cac,
		       struct cached_item *ins, bool logical_overwrite,
		       bool cache_populate)
{
	struct rb_root *root = &cac->items;
	struct cached_item *item;
	struct rb_node *parent;
	struct rb_node **node;
	int cmp;

restart:
	node = &root->rb_node;
	parent = NULL;
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
			if (cache_populate ||
			    (!item->deletion && !logical_overwrite))
				return -EEXIST;

			/* sadly there's no augmented replace */
			erase_item(sb, cac, item);
			goto restart;
		}
	}

	trace_scoutfs_item_insertion(sb, ins->key);

	rb_link_node(&ins->node, parent, node);
	rb_insert_augmented(&ins->node, root, &scoutfs_item_rb_cb);

	BUG_ON(ins->dirty & ITEM_DIRTY);
	list_add_tail(&ins->entry, &cac->lru_list);
	cac->lru_nr++;

	return 0;
}

static struct cached_range *rb_first_rng(struct rb_root *root)
{
	struct rb_node *node;

	if ((node = rb_first(root)))
		return container_of(node, struct cached_range, node);

	return NULL;
}

static struct cached_range *rb_next_rng(struct cached_range *rng)
{
	struct rb_node *node;

	if (rng && (node = rb_next(&rng->node)))
		return container_of(node, struct cached_range, node);

	return NULL;
}

static struct cached_range *walk_ranges(struct rb_root *root,
					struct scoutfs_key_buf *key,
					struct cached_range **prev,
					struct cached_range **next)
{
	struct rb_node *node = root->rb_node;
	struct cached_range *rng;
	int cmp;

	if (prev)
		*prev = NULL;
	if (next)
		*next = NULL;

	while (node) {
		rng = container_of(node, struct cached_range, node);

		cmp = scoutfs_key_compare_ranges(key, key,
						 rng->start, rng->end);
		if (cmp < 0) {
			if (next)
				*next = rng;
			node = node->rb_left;
		} else if (cmp > 0) {
			if (prev)
				*prev = rng;
			node = node->rb_right;
		} else {
			return rng;
		}
	}

	return NULL;
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
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_range *next;
	struct cached_range *rng;

	rng = walk_ranges(&cac->ranges, key, NULL, &next);
	if (rng) {
		scoutfs_inc_counter(sb, item_range_hit);
		if (end)
			scoutfs_key_copy(end, rng->end);
		return true;
	}

	if (end) {
		if (next)
			scoutfs_key_copy(end, next->start);
		else
			scoutfs_key_set_max(end);
	}

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
 * Remove a given cached range.  The caller has already removed all the
 * items that fell within the range.  There can be any number of
 * existing cached ranges that overlap with the range that should be
 * removed.
 *
 * The caller's range has full precision keys that specify the endpoints
 * that will not be considered cached.  If we use them to set the new
 * bounds of existing ranges then we have to dec/inc them into the range
 * to have them represent the last/first valid key, not the first/last
 * key to be removed.
 *
 * Like insert_, we're responsible for freeing the caller's range.  We
 * might insert it into the tree to track the other half of a range
 * that's split by the removal.
 */
static void remove_range(struct super_block *sb, struct rb_root *root,
			 struct cached_range *rem)
{
	struct cached_range *rng;
	struct rb_node *parent;
	struct rb_node **node;
	bool insert = false;
	int start_cmp;
	int end_cmp;
	int cmp;

restart:
	parent = NULL;
	node = &root->rb_node;
	while (*node) {
		parent = *node;
		rng = container_of(*node, struct cached_range, node);

		cmp = scoutfs_key_compare_ranges(rem->start, rem->end,
						 rng->start, rng->end);
		/* simple iteration until we overlap */
		if (cmp < 0) {
			node = &(*node)->rb_left;
			continue;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
			continue;
		}

		start_cmp = scoutfs_key_compare(rem->start, rng->start);
		end_cmp = scoutfs_key_compare(rem->end, rng->end);

		/* remove the middle of an existing range, insert other half */
		if (start_cmp > 0 && end_cmp < 0) {
			swap(rng->end, rem->start);
			scoutfs_key_dec(rng->end);

			swap(rem->start, rem->end);
			scoutfs_key_inc(rem->start);
			insert = true;
			goto restart;
		}

		/* remove partial overlap from existing */
		if (start_cmp < 0 && end_cmp < 0) {
			swap(rem->end, rng->start);
			scoutfs_key_inc(rng->start);
			continue;
		}

		if (start_cmp > 0 && end_cmp > 0) {
			swap(rem->start, rng->end);
			scoutfs_key_dec(rng->end);
			continue;
		}

		/* erase and free existing surrounded by removal */
		rb_erase(&rng->node, root);
		free_range(sb, rng);
		goto restart;
	}

	if (insert) {
		rb_link_node(&rem->node, parent, node);
		rb_insert_color(&rem->node, root);
	} else {
		free_range(sb, rem);
	}
}

/*
 * Find an item with the given key and copy its value into the caller's
 * value vector.  The amount of bytes copied is returned which can be 0
 * or truncated if the caller's buffer isn't big enough.
 *
 * The end key limits how many keys after the search key can be read
 * and inserted into the cache.
 */
int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val, struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	trace_scoutfs_item_lookup(sb, key);

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item) {
			item_referenced(cac, item);
			ret = scoutfs_kvec_memcpy(val, item->val);
		} else if (check_range(sb, &cac->ranges, key, NULL)) {
			ret = -ENOENT;
		} else {
			ret = -ENODATA;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);

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
 * The end key limits how many keys after the search key can be read
 * and inserted into the cache.
 *
 * Returns 0 or -errno.
 */
int scoutfs_item_lookup_exact(struct super_block *sb,
			      struct scoutfs_key_buf *key, struct kvec *val,
			      int size, struct scoutfs_key_buf *end)
{
	int ret;

	ret = scoutfs_item_lookup(sb, key, val, end);
	if (ret == size)
		ret = 0;
	else if (ret >= 0)
		ret = -EIO;

	return ret;
}

/*
 * Return the next linked node in the tree that isn't a deletion item
 * and which is still within the last allowed key value.
 */
static struct cached_item *next_item_node(struct rb_root *root,
					  struct cached_item *item,
					  struct scoutfs_key_buf *last)
{
	struct rb_node *node;

	while (item) {
		node = rb_next(&item->node);
		if (!node) {
			item = NULL;
			break;
		}

		item = container_of(node, struct cached_item, node);

		if (scoutfs_key_compare(item->key, last) > 0) {
			item = NULL;
			break;
		}

		if (!item->deletion)
			break;
	}

	return item;
}

/*
 * Find the next item to return from the "_next" item interface.  It's the
 * next item from the key that isn't a deletion item and is within the
 * bounds of the end of the cache and the caller's last key.
 */
static struct cached_item *item_for_next(struct rb_root *root,
				         struct scoutfs_key_buf *key,
					 struct scoutfs_key_buf *range_end,
					 struct scoutfs_key_buf *last)
{
	struct cached_item *item;

	/* limit by the lesser of the two */
	if (range_end && scoutfs_key_compare(range_end, last) < 0)
		last = range_end;

	item = next_item(root, key);
	if (item) {
		if (scoutfs_key_compare(item->key, last) > 0)
			item = NULL;
		else if (item->deletion)
			item = next_item_node(root, item, last);
	}

	return item;
}

/*
 * Return the next item starting with the given key, returning the last
 * key at the most.
 *
 * While iteration stops the last key we can cache up to the end key so
 * that a sequence of small iterations covered by one lock are satisfied
 * with a large read of items from segments into the cache.
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
		      struct scoutfs_key_buf *last, struct kvec *val,
		      struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *read_start = NULL;
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
	range_end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!read_start || !range_end) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&cac->lock, flags);

	for(;;) {
		/* see if we have a usable item in cache and before last */
		cached = check_range(sb, &cac->ranges, key, range_end);

		if (cached && (item = item_for_next(&cac->items, key,
						    range_end, last))) {
			scoutfs_key_copy(key, item->key);
			if (val) {
				item_referenced(cac, item);
				ret = scoutfs_kvec_memcpy(val, item->val);
			} else {
				ret = 0;
			}
			break;
		}

		if (!cached) {
			/* missing cache starts at key */
			scoutfs_key_copy(read_start, key);

		} else if (scoutfs_key_compare(range_end, last) < 0) {
			/* missing cache starts at range_end */
			scoutfs_key_copy(read_start, range_end);

		} else {
			/* no items and we have cache between key and last */
			ret = -ENOENT;
			break;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

		ret = scoutfs_manifest_read_items(sb, read_start, end);

		spin_lock_irqsave(&cac->lock, flags);
		if (ret)
			break;
	}

	spin_unlock_irqrestore(&cac->lock, flags);
out:
	scoutfs_key_free(sb, read_start);
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
			       struct kvec *val, int len,
			       struct scoutfs_key_buf *end)
{
	int key_len = key->key_len;
	int ret;

	trace_printk("key len %u min val len %d\n", key_len, len);

	if (WARN_ON_ONCE(!val || scoutfs_kvec_length(val) < len))
		return -EINVAL;

	ret = scoutfs_item_next(sb, key, last, val, end);
	if (ret >= 0 && (key->key_len != key_len || ret < len))
		ret = -EIO;

	trace_printk("ret %d\n", ret);

	return ret;
}

/*
 * Like _next but requires that the found keys be the same length as the
 * search key.  It treats size mismatches as a sign of corruption.
 */
int scoutfs_item_next_same(struct super_block *sb, struct scoutfs_key_buf *key,
			   struct scoutfs_key_buf *last, struct kvec *val,
			   struct scoutfs_key_buf *end)
{
	int key_len = key->key_len;
	int ret;

	trace_printk("key len %u\n", key_len);

	ret = scoutfs_item_next(sb, key, last, val, end);
	if (ret >= 0 && (key->key_len != key_len))
		ret = -EIO;

	trace_printk("ret %d\n", ret);

	return ret;
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

	if (invalid_key_val(key, val))
		return -EINVAL;

	item = alloc_item(sb, key, val);
	if (!item)
		return -ENOMEM;

	spin_lock_irqsave(&cac->lock, flags);
	ret = insert_item(sb, cac, item, false, false);
	if (!ret) {
		scoutfs_inc_counter(sb, item_create);
		mark_item_dirty(sb, cac, item);
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

	if (invalid_key_val(key, val))
		return -EINVAL;

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

	trace_scoutfs_item_insert_batch(sb, start, end);

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
		list_del_init(&item->entry);
		if (insert_item(sb, cac, item, false, true))
			list_add(&item->entry, list);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	ret = 0;
out:
	scoutfs_item_free_batch(sb, list);
	return ret;
}

/*
 * Atomically set the caller's items to be the only cached items in the
 * caller's range.  Any existing items that overlap with the caller's
 * items are replaced.  Any existing items in the range that aren't in
 * the caller's list will be replaced with deletion items.  The deletion
 * items and the caller's inserted items will all be marked dirty.
 *
 * In practice this is used for relatively few items at a time, at most
 * on the order of 16.  So we're not too worried with it walking a small
 * number of items a few times when the caller provides flags that have
 * to check for existing items.
 *
 * Returns -ENODATA if SIF_REPLACE is set and a batch item doesn't have
 * a matching existing item or -EEXIST if SIF_EXCLUSIVE is set and a
 * batch item does have an existing item.
 */
int scoutfs_item_set_batch(struct super_block *sb, struct list_head *list,
			   struct scoutfs_key_buf *first,
			   struct scoutfs_key_buf *last, int sif,
			   struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *range_end;
	SCOUTFS_DECLARE_KVEC(del_val);
	struct cached_item *exist;
	struct cached_item *item;
	struct cached_item *tmp;
	unsigned long flags;
	int cmp;
	int ret;

	if (WARN_ON_ONCE(invalid_flags(sif)))
		return -EINVAL;

	list_for_each_entry(item, list, entry) {
		if (invalid_key_val(item->key, item->val))
			return -EINVAL;
	}

	trace_scoutfs_item_set_batch(sb, first, last);

	if (WARN_ON_ONCE(scoutfs_key_compare(first, last) > 0) ||
	    WARN_ON_ONCE(scoutfs_key_compare(end, last) < 0))
		return -EINVAL;

	range_end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!range_end)
		return -ENOMEM;

	spin_lock_irqsave(&cac->lock, flags);

	/* make sure all of first through last are cached */
	scoutfs_key_copy(range_end, first);
	for (;;) {
		if (check_range(sb, &cac->ranges, range_end, range_end)) {
			if (scoutfs_key_compare(range_end, last) >= 0)
				break;
			/* start reading from hole starting at range_end */
		} else {
			scoutfs_key_copy(range_end, first);
		}

		spin_unlock_irqrestore(&cac->lock, flags);
		ret = scoutfs_manifest_read_items(sb, range_end, end);
		spin_lock_irqsave(&cac->lock, flags);

		if (ret)
			goto out;
	}

	/* check for _EXCLUSIVE or _REPLACE errors before destroying items */
	if (!list_empty(list) && (sif & (SIF_EXCLUSIVE | SIF_REPLACE))) {

		item = list_first_entry(list, struct cached_item, entry);
		exist = item_for_next(&cac->items, first, NULL, last);

		while (item) {
			/* compare keys, with bias to finding _REPLACE err */
			if (exist)
				cmp = scoutfs_key_compare(item->key,
							  exist->key);
			else
				cmp = -1;

			if (cmp < 0) {
				if (sif & SIF_REPLACE) {
					ret = -ENODATA;
					goto out;
				}
				if (item->entry.next != list)
					item = list_next_entry(item, entry);
				else
					item = NULL;

			} else if (cmp > 0) {
				exist = next_item_node(&cac->items, exist, last);

			} else {
				/* cmp == 0 */
				if (sif & SIF_EXCLUSIVE) {
					ret = -EEXIST;
					goto out;
				}
			}
		}

	}

	/* delete everything in the range */
	for (exist = item_for_next(&cac->items, first, NULL, last);
	     exist; exist = next_item_node(&cac->items, exist, last)) {

		scoutfs_kvec_init_null(del_val);
		become_deletion_item(sb, cac, exist, del_val);
		scoutfs_kvec_kfree(del_val);
	}

	/* insert the caller's items, overwriting any existing */
	list_for_each_entry_safe(item, tmp, list, entry) {
		list_del_init(&item->entry);
		insert_item(sb, cac, item, true, false);
		mark_item_dirty(sb, cac, item);
	}

	ret = 0;
out:
	spin_unlock_irqrestore(&cac->lock, flags);
	scoutfs_key_free(sb, range_end);

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
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key_buf *key,
		       struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item) {
			mark_item_dirty(sb, cac, item);
			ret = 0;
		} else if (check_range(sb, &cac->ranges, key, NULL)) {
			ret = -ENOENT;
		} else {
			ret = -ENODATA;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);

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
			struct kvec *val, struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	SCOUTFS_DECLARE_KVEC(up_val);
	struct cached_item *item;
	unsigned long flags;
	int ret;

	if (invalid_key_val(key, val))
		return -EINVAL;

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
			clear_item_dirty(sb, cac, item);
			scoutfs_kvec_swap(up_val, item->val);
			mark_item_dirty(sb, cac, item);
			ret = 0;
		} else if (check_range(sb, &cac->ranges, key, NULL)) {
			ret = -ENOENT;
		} else {
			ret = -ENODATA;
		}

		spin_unlock_irqrestore(&cac->lock, flags);

	} while (ret == -ENODATA &&
		 (ret = scoutfs_manifest_read_items(sb, key, end)) == 0);
out:
	scoutfs_kvec_kfree(up_val);

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Delete an existing item with the given key.
 *
 * If a non-deletion item is present then we mark it dirty and deleted
 * and free it's value.
 *
 * Returns -ENOENT if an item doesn't exist at the key.  This forces us
 * to read the item before creating a deletion item for it.  XXX If we
 * relaxed this we'd need to see if callers make use of -ENOENT and if
 * there are any ways for userspace to overwhelm the system with
 * deletion items for items that didn't exist in the first place.
 */
int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key_buf *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *end;
	struct cached_item *item;
	SCOUTFS_DECLARE_KVEC(del_val);
	unsigned long flags;
	int ret;

	scoutfs_kvec_init_null(del_val);

	end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	if (!end) {
		ret = -ENOMEM;
		goto out;
	}

	do {
		spin_lock_irqsave(&cac->lock, flags);

		item = find_item(sb, &cac->items, key);
		if (item) {
			become_deletion_item(sb, cac, item, del_val);
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
	scoutfs_kvec_kfree(del_val);
out:
	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Delete an item that the caller knows must be dirty because they hold
 * locks and the transaction and have created or dirtied it.  This can't
 * fail.
 */
void scoutfs_item_delete_dirty(struct super_block *sb,
			       struct scoutfs_key_buf *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	SCOUTFS_DECLARE_KVEC(del_val);
	struct cached_item *item;
	unsigned long flags;

	scoutfs_kvec_init_null(del_val);

	spin_lock_irqsave(&cac->lock, flags);

	item = find_item(sb, &cac->items, key);
	if (item)
		become_deletion_item(sb, cac, item, del_val);

	spin_unlock_irqrestore(&cac->lock, flags);

	scoutfs_kvec_kfree(del_val);
}

/*
 * A helper that deletes a set of items.  It first dirties the items
 * will be pinned so that deletion won't fail as it tries to read and
 * populate the items.
 *
 * It's a little cleaner to have this helper than have the caller
 * iterate, but it could also give us the opportunity to reduce item
 * searches if we remembered the items we dirtied.
 */
int scoutfs_item_delete_many(struct super_block *sb,
			     struct scoutfs_key_buf **keys, unsigned nr,
			     struct scoutfs_key_buf *end)
{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		ret = scoutfs_item_dirty(sb, keys[i], end);
		if (ret)
			goto out;
	}

	for (i = 0; i < nr; i++)
		scoutfs_item_delete_dirty(sb, keys[i]);

out:
	trace_printk("ret %d\n", ret);
	return ret;
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
 * Fill the given segment with sorted dirty items.
 *
 * The caller is responsible for the consistency of the dirty items once
 * they're in its seg.  We can consider them clean once we store them.
 *
 * XXX this first/append pattern will go away once we can write a stream
 * of items to a segment without needing to know the item count to
 * find the starting key and value offsets.
 */
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	__le32 *links[SCOUTFS_MAX_SKIP_LINKS];
	struct cached_item *item = NULL;
	struct cached_item *del;
	unsigned long flags;
	bool appended;

	spin_lock_irqsave(&cac->lock, flags);

	item = first_dirty(cac->items.rb_node);
	while (item) {
		appended = scoutfs_seg_append_item(sb, seg, item->key, item->val,
						   item_flags(item), links);
		/* trans reservation should have limited dirty */
		BUG_ON(!appended);

		clear_item_dirty(sb, cac, item);

		del = item;
		item = next_dirty(item);

		if (del->deletion)
			erase_item(sb, cac, del);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	return 0;
}

/*
 * The caller wants us to write out any dirty items within the given
 * range.  We look for any dirty items within the range and if we find
 * any we issue a sync which writes out all the dirty items.
 */
int scoutfs_item_writeback(struct super_block *sb,
			   struct scoutfs_key_buf *start,
			   struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	unsigned long flags;
	bool sync = false;
	int ret = 0;

	/* XXX think about racing with trans write */

	spin_lock_irqsave(&cac->lock, flags);

	if (cac->nr_dirty_items) {
		item = next_item(&cac->items, start);
		if (item && !(item->dirty & ITEM_DIRTY))
			item = next_dirty(item);
		if (item && scoutfs_key_compare(item->key, end) <= 0)
			sync = true;
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	if (sync)
		ret = scoutfs_sync_fs(sb, 1);

	return ret;
}

/*
 * The caller wants us to drop any items within the range on the floor.
 * They should have ensured that items in this range won't be dirty.
 */
int scoutfs_item_invalidate(struct super_block *sb,
			    struct scoutfs_key_buf *start,
			    struct scoutfs_key_buf *end)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_range *rng;
	struct cached_item *next;
	struct cached_item *item;
	struct rb_node *node;
	unsigned long flags;
	int ret;

	/* XXX think about racing with trans write */

	rng = kzalloc(sizeof(struct cached_range), GFP_NOFS);
	if (rng) {
	       rng->start = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	       rng->end = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	}
	if (!rng || !rng->start || !rng->end) {
		free_range(sb, rng);
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_key_copy(rng->start, start);
	scoutfs_key_copy(rng->end, end);

	spin_lock_irqsave(&cac->lock, flags);

	for (item = next_item(&cac->items, start);
	     item && scoutfs_key_compare(item->key, end) <= 0;
	     item = next) {

		/* XXX seems like this should be a helper? */
		node = rb_next(&item->node);
		if (node)
			next = container_of(node, struct cached_item, node);
		else
			next = NULL;

		WARN_ON_ONCE(item->dirty & ITEM_DIRTY);
		erase_item(sb, cac, item);
	}

	remove_range(sb, &cac->ranges, rng);

	spin_unlock_irqrestore(&cac->lock, flags);

	ret = 0;
out:
	return ret;
}

static struct cached_item *rb_next_item(struct cached_item *item)
{
	struct rb_node *node;

	if (item && (node = rb_next(&item->node)))
		return container_of(node, struct cached_item, node);

	return NULL;
}

/*
 * Shrink the item cache.
 *
 * Unfortunately this is complicated by the rbtree of ranges that track
 * the validity of the cache.  If we free items we have to make sure
 * they're not covered by ranges or else they'd be considered a valid
 * negative cache hit.  We don't want to allocate more memory for new
 * range entries that would be required to poke holes int he cached
 * range.
 *
 * So instead of just freeing the oldest item we shrink the range that
 * contains the oldest item.  We bias towards freeing the lesser side of
 * the range.
 *
 * Instead of allocating a new range start key we use the key of the
 * item we're removing.  We have to increment it past the removed key
 * value.  That increment can move it past the next key in the range if
 * the next key is of higher precision.  This will be rare and can't go
 * on indefinitely so we keep searching until we can inc a key and not
 * extend past the next item.  Eventually we have a range of items to
 * free.
 *
 * During all of this, we chose to abort if we see dirty items.  They
 * won't be dirty forever and the mm can call back in.
 *
 * We can also hit items in the lru which aren't covered by ranges.  We
 * just free them straight away.  And finally if we're completely out of
 * items we walk and free the ranges.
 */
static int item_lru_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
	struct item_cache *cac = container_of(shrink, struct item_cache,
					      shrinker);
	struct super_block *sb = cac->sb;
	struct cached_range *rng;
	struct cached_item *item;
	struct cached_item *next;
	struct cached_item *begin;
	struct cached_item *end;
	unsigned long flags;
	unsigned long nr;

	nr = sc->nr_to_scan;
	if (nr == 0)
		goto out;

	spin_lock_irqsave(&cac->lock, flags);

	while (nr > 0) {
		item = list_first_entry_or_null(&cac->lru_list,
						struct cached_item, entry);

		/* no lru items, if no items at all then free ranges */
		if (!item) {
			if (!RB_EMPTY_ROOT(&cac->items)) {
				scoutfs_inc_counter(sb, item_shrink_dirty_abort);
				goto abort;
			}
			rng = rb_first_rng(&cac->ranges);
			if (!rng)
				break;
			scoutfs_inc_counter(sb, item_shrink_no_items);
			begin = NULL;
			end = NULL;
			goto free;
		}

		/* can't have dirty items on the lru */
		BUG_ON(item->dirty & ITEM_DIRTY);

		/* if we're not in a range just shrink the item */
		rng = walk_ranges(&cac->ranges, item->key, NULL, NULL);
		if (!rng) {
			begin = item;
			end = item;
			scoutfs_inc_counter(sb, item_shrink_outside);
			goto free;
		}

		/* find the string of items to free, ending with range start */
		item = next_item(&cac->items, rng->start);
		begin = item;
		end = item;

		while (item) {
			/* can't if it's dirty :( */
			if (item->dirty & ITEM_DIRTY) {
				scoutfs_inc_counter(sb, item_shrink_dirty_abort);
				goto abort;
			}

			/* we're going to free this item now */
			end = item;

			/* free items and range if we exhausted the range */
			next = rb_next_item(item);
			if (!next || scoutfs_key_compare(next->key, rng->end) > 0)
				break;

			/* truncate range using after our key as start, if safe */
			scoutfs_key_inc_cur_len(item->key);
			if (scoutfs_key_compare(item->key, next->key) <= 0) {
				trace_scoutfs_item_shrink(sb, item->key);
				scoutfs_key_free(sb, rng->start);
				rng->start = item->key;
				item->key = NULL;
				rng = NULL;
				break;
			}
			scoutfs_key_dec_cur_len(item->key);

			/* keep searching for valid range start key */
			scoutfs_inc_counter(sb, item_shrink_skip_inced);
			item = next;
		}

free:
		if (rng) {
			trace_scoutfs_item_shrink_range(sb, rng->start, rng->end);
			scoutfs_inc_counter(sb, item_shrink_range);
			rb_erase(&rng->node, &cac->ranges);
			free_range(sb, rng);
		}

		/* free items from begin to end */
		for (item = begin;
		     item && (next = item == end ? NULL : rb_next_item(item), 1);
		     item = next) {
			if (item->key)
				trace_scoutfs_item_shrink(sb, item->key);
			scoutfs_inc_counter(sb, item_shrink);
			erase_item(sb, cac, item);
		}

		nr--;
	}

abort:
	spin_unlock_irqrestore(&cac->lock, flags);

out:
	return min_t(unsigned long, cac->lru_nr, INT_MAX);
}

static void *copy_key_with_len(void *data, struct scoutfs_key_buf *key)
{
	u16 len = key->key_len;

	memcpy(data, &len, sizeof(len));
	data += sizeof(len);
	memcpy(data, key->data, len);

	return data + len;
}

/*
 * Copy the next cached ranges starting with the key into the caller's
 * buffer.  Each range copied by storing each keys size in a u16
 * followed by the binary key data.  The number of bytes of full copied
 * ranges is returned.  The caller's key is incremented past the last
 * key returned so that they can iterate without worrying about
 * examining the returned keys.
 */
int scoutfs_item_copy_range_keys(struct super_block *sb,
				 struct scoutfs_key_buf *key, void *data,
				 unsigned len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct rb_node *node = cac->ranges.rb_node;
	struct cached_range *next = NULL;
	struct scoutfs_key_buf *last = NULL;
	struct cached_range *rng;
	unsigned long flags;
	unsigned bytes;
	int ret = 0;
	int cmp;

	spin_lock_irqsave(&cac->lock, flags);

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
			next = rng;
			break;
		}
	}

	for (rng = next; rng; rng = rb_next_rng(rng)) {
		bytes = 2 + rng->start->key_len + 2 + rng->end->key_len;
		if (len < bytes)
			break;

		data = copy_key_with_len(data, rng->start);
		data = copy_key_with_len(data, rng->end);
		len -= bytes;
		ret += bytes;

		last = rng->end;
	}

	if (last) {
		scoutfs_key_copy(key, last);
		scoutfs_key_inc(key);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	return ret;
}

/* like copy_range_keys, but for present items */
int scoutfs_item_copy_keys(struct super_block *sb, struct scoutfs_key_buf *key,
			   void *data, unsigned len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct scoutfs_key_buf *last = NULL;
	struct cached_item *item = NULL;
	unsigned long flags;
	unsigned bytes;
	int ret = 0;

	spin_lock_irqsave(&cac->lock, flags);

	for (item = next_item(&cac->items, key); item; item = rb_next_item(item)) {
		if (item->deletion)
			continue;

		bytes = 2 + item->key->key_len;
		if (len < bytes)
			break;

		data = copy_key_with_len(data, item->key);
		len -= bytes;
		ret += bytes;

		last = item->key;
	}

	if (last) {
		scoutfs_key_copy(key, last);
		scoutfs_key_inc(key);
	}

	spin_unlock_irqrestore(&cac->lock, flags);

	return ret;
}

int scoutfs_item_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac;

	cac = kzalloc(sizeof(struct item_cache), GFP_KERNEL);
	if (!cac)
		return -ENOMEM;
	sbi->item_cache = cac;

	cac->sb = sb;
	spin_lock_init(&cac->lock);
	cac->items = RB_ROOT;
	cac->ranges = RB_ROOT;
	cac->shrinker.shrink = item_lru_shrink;
	cac->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&cac->shrinker);
	INIT_LIST_HEAD(&cac->lru_list);

	return 0;
}

/*
 * There's no more users of the items and ranges at this point.  We can
 * destroy them without locking and ignoring augmentation.
 */
void scoutfs_item_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *item;
	struct cached_item *pos_item;
	struct cached_range *rng;
	struct cached_range *pos_rng;

	if (cac) {
		if (cac->shrinker.shrink == item_lru_shrink)
			unregister_shrinker(&cac->shrinker);

		rbtree_postorder_for_each_entry_safe(item, pos_item,
						     &cac->items, node) {
			RB_CLEAR_NODE(&item->node);
			INIT_LIST_HEAD(&item->entry);
			free_item(sb, item);
		}

		rbtree_postorder_for_each_entry_safe(rng, pos_rng,
						     &cac->ranges, node) {
			free_range(sb, rng);
		}

		kfree(cac);
	}
}
