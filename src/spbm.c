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
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/bitmap.h>
#include <linux/rbtree.h>

#include "spbm.h"

#define SPBM_BITS	128
#define SPBM_SHIFT	ilog2(SPBM_BITS)
#define SPBM_MASK	((u64)SPBM_BITS - 1)
#define SPBM_LONGS	(SPBM_BITS / BITS_PER_LONG)

/*
 * Maintain a sparse bitmap in an rbtree.  Setting bits can allocate and
 * fail but clearing will always succeed.  Locking is left up to the
 * caller.
 */

struct spbm_node {
	struct rb_node node;
	u64 index;
	unsigned long bits[SPBM_LONGS];
};

void scoutfs_spbm_init(struct scoutfs_spbm *spbm)
{
	BUILD_BUG_ON(!is_power_of_2(SPBM_BITS));

	spbm->root = RB_ROOT;
}

enum {
	/* if a node isn't found then return an allocated new node */
	SPBM_FIND_ALLOC = 0x1,
};
static struct spbm_node *find_node(struct scoutfs_spbm *spbm, u64 index,
				   int flags)
{
	struct rb_node *parent;
	struct rb_node **node;
	struct spbm_node *sn;

	node = &spbm->root.rb_node;
	parent = NULL;
	sn = NULL;
	while (*node) {
		parent = *node;
		sn = container_of(*node, struct spbm_node, node);

		if (index < sn->index) {
			node = &(*node)->rb_left;
		} else if (index > sn->index) {
			node = &(*node)->rb_right;
		} else {
			break;
		}

		sn = NULL;
	}

	if (!sn && (flags & SPBM_FIND_ALLOC)) {
		sn = kzalloc(sizeof(struct spbm_node), GFP_NOFS);
		if (sn) {
			sn->index = index;
			rb_link_node(&sn->node, parent, node);
			rb_insert_color(&sn->node, &spbm->root);
		}
	}

	return sn;
}

static void calc_index_nr(u64 *index, int *nr, u64 bit)
{
	*index = bit >> SPBM_SHIFT;
	*nr = bit & SPBM_MASK;
}

int scoutfs_spbm_set(struct scoutfs_spbm *spbm, u64 bit)
{
	struct spbm_node *sn;
	u64 index;
	int nr;

	calc_index_nr(&index, &nr, bit);

	sn = find_node(spbm, index, SPBM_FIND_ALLOC);
	if (!sn)
		return -ENOMEM;

	set_bit(nr, sn->bits);

	return 0;
}

int scoutfs_spbm_test(struct scoutfs_spbm *spbm, u64 bit)
{
	struct spbm_node *sn;
	u64 index;
	int nr;

	calc_index_nr(&index, &nr, bit);

	sn = find_node(spbm, index, 0);
	if (sn)
		return !!test_bit(nr, sn->bits);

	return 0;
}

static void free_node(struct scoutfs_spbm *spbm, struct spbm_node *sn)
{
	rb_erase(&sn->node, &spbm->root);
	kfree(sn);
}

void scoutfs_spbm_clear(struct scoutfs_spbm *spbm, u64 bit)
{
	struct spbm_node *sn;
	u64 index;
	int nr;

	calc_index_nr(&index, &nr, bit);

	sn = find_node(spbm, index, 0);
	if (sn) {
		clear_bit(nr, sn->bits);
		if (bitmap_empty(sn->bits, SPBM_BITS))
			free_node(spbm, sn);
	}
}

void scoutfs_spbm_destroy(struct scoutfs_spbm *spbm)
{
	struct spbm_node *sn;
	struct spbm_node *pos;

	rbtree_postorder_for_each_entry_safe(sn, pos, &spbm->root, node)
		free_node(spbm, sn);
}
