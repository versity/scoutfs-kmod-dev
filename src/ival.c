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

#include "rbtree_aug.h"

#include "format.h"
#include "key.h"
#include "ival.h"

/*
 * scoutfs wants to store overlapping key ranges and find intersections
 * for tracking both segments in level 0 and granting access ranges.
 *
 * We use a simple augmented rbtree of key intervals that tracks the
 * greatest end value of all the intervals in a node's subtree.  Wikipedia
 * data structures 101.
 *
 * Unfortunately the augmented rbtree callbacks need a tweak to compare
 * our key structs.  But we don't want to mess around with updating
 * distro kernels.  So we backport the augmented rbtree code from
 * mainline in a private copy.  This'll vanish when we bring scoutfs up
 * to mainline.
 */

static struct scoutfs_key *node_subtree_end(struct rb_node *node)
{
	struct scoutfs_ival *ival;
	static struct scoutfs_key static_zero = {0,};

	if (!node)
		return &static_zero;

	ival = container_of(node, struct scoutfs_ival, node);
	return &ival->subtree_end;
}

static struct scoutfs_key compute_subtree_end(struct scoutfs_ival *ival)
{
	return *scoutfs_max_key(node_subtree_end(ival->node.rb_left),
			        node_subtree_end(ival->node.rb_right));
}

RB_DECLARE_CALLBACKS(static, ival_rb_cb, struct scoutfs_ival, node,
		     struct scoutfs_key, subtree_end, compute_subtree_end)

void scoutfs_insert_ival(struct scoutfs_ival_tree *tree,
			 struct scoutfs_ival *ins)
{
	struct rb_node **node = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_ival *ival;

	giant_rbtree_hack_build_bugs();

	while (*node) {
		parent = *node;
		ival = container_of(*node, struct scoutfs_ival, node);

		/* extend traversed subtree end to cover inserted end */
		ival->subtree_end = *scoutfs_max_key(&ival->subtree_end,
						     &ins->end);

		if (scoutfs_key_cmp(&ins->start, &ival->start) < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	ins->subtree_end = ins->end;
	rb_link_node(&ins->node, parent, node);
	rb_insert_augmented(&ins->node, &tree->root, &ival_rb_cb);
}

void scoutfs_remove_ival(struct scoutfs_ival_tree *tree,
			 struct scoutfs_ival *ival)
{
	if (!RB_EMPTY_NODE(&ival->node)) {
		rb_erase_augmented(&ival->node, &tree->root, &ival_rb_cb);
		RB_CLEAR_NODE(&ival->node);
	}
}

/*
 * Find the interval in the tree with the lowest start value that
 * intersects the search range.
 */
static struct scoutfs_ival *first_ival(struct scoutfs_ival_tree *tree,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end)
{
	struct rb_node *node = tree->root.rb_node;
	struct scoutfs_ival *ival;

	while (node) {
		ival = container_of(node, struct scoutfs_ival, node);

		if (scoutfs_key_cmp(node_subtree_end(ival->node.rb_left),
				    start) >= 0)
			node = node->rb_left;
		else if (!scoutfs_cmp_key_ranges(start, end,
						 &ival->start, &ival->end))
			return ival;
		else if (scoutfs_key_cmp(end, &ival->start) < 0)
			break;
		else
			node = node->rb_right;
	}

	return NULL;
}

/*
 * Find the next interval sorted by the start value which intersect the
 * given search range.  ival is null to first return the intersection
 * with the lowest start value.  The caller must serialize access while
 * iterating.
 */
struct scoutfs_ival *scoutfs_next_ival(struct scoutfs_ival_tree *tree,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end,
				       struct scoutfs_ival *ival)
{
	struct rb_node *node;

	if (!ival)
		return first_ival(tree, start, end);

	while ((node = rb_next(&ival->node))) {
		ival = container_of(node, struct scoutfs_ival, node);

		if (scoutfs_cmp_key_ranges(start, end,
					   &ival->start, &ival->end))
			ival = NULL;
		break;
	}

	return ival;
}
