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

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "manifest.h"
#include "item.h"

struct item_cache {
	spinlock_t lock;
	struct rb_root root;
};

struct cached_item {
	struct rb_node node;

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

static struct cached_item *insert_item(struct rb_root *root,
				       struct cached_item *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_item *found = NULL;
	struct cached_item *item;
	int cmp;

	while (*node) {
		parent = *node;
		item = container_of(*node, struct cached_item, node);

		cmp = scoutfs_kvec_memcmp(ins->key, item->key);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			rb_replace_node(&item->node, &ins->node, root);
			found = item;
			break;
		}
	}

	if (!found) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
	}

	return found;
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
	else if (ret >= 0 && ret != size)
		ret = -EIO;

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
 * Add an item with the key and value to the item cache.  The new item
 * is clean.  Any existing item at the key will be removed and freed.
 */
int scoutfs_item_insert(struct super_block *sb, struct kvec *key,
		        struct kvec *val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache *cac = sbi->item_cache;
	struct cached_item *found;
	struct cached_item *item;
	unsigned long flags;
	int ret;

	item = kmalloc(sizeof(struct cached_item), GFP_NOFS);
	if (!item)
		return -ENOMEM;

	ret = scoutfs_kvec_dup_flatten(item->key, key) ?:
	      scoutfs_kvec_dup_flatten(item->val, val);
	if (ret) {
		free_item(item);
		return ret;
	}

	spin_lock_irqsave(&cac->lock, flags);
	found = insert_item(&cac->root, item);
	spin_unlock_irqrestore(&cac->lock, flags);
	free_item(found);

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
	struct rb_node *node;
	struct cached_item *item;

	if (cac) {
		for (node = rb_first(&cac->root); node; ) {
			item = container_of(node, struct cached_item, node);
			node = rb_next(node);
			free_item(item);
		}

		kfree(cac);
	}

}
