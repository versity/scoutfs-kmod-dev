/*
 * Copyright (C) 2020 Versity Software, Inc.  All rights reserved.
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

#include "format.h"
#include "avl.h"

/*
 * We use a simple avl to index items in btree blocks.  The interface
 * looks a bit like the kernel rbtree interface in that the caller
 * manages locking and storage for the nodes.  Node references are
 * stored as byte offsets from the root so that the implementation
 * doesn't have to know anything about the caller's container. 
 *
 * We store the full height in each node, rather than just 2 bits for
 * the balance, so that we can use the extra redundancy to verify the
 * integrity of the tree.
 */

static struct scoutfs_avl_node *node_ptr(struct scoutfs_avl_root *root,
					 __le16 off)
{
	return off ? (void *)root + le16_to_cpu(off) : NULL;
}

static __le16 node_off(struct scoutfs_avl_root *root,
		       struct scoutfs_avl_node *node)
{
	return node ? cpu_to_le16((void *)node - (void *)root) : 0;
}

static __u8 node_height(struct scoutfs_avl_node *node)
{
	return node ? node->height : 0;
}

struct scoutfs_avl_node *
scoutfs_avl_search(struct scoutfs_avl_root *root,
		   scoutfs_avl_compare_t compare, void *arg, int *cmp_ret,
		   struct scoutfs_avl_node **par,
		   struct scoutfs_avl_node **next,
		   struct scoutfs_avl_node **prev)
{
	struct scoutfs_avl_node *node = node_ptr(root, root->node);
	int cmp;

	if (cmp_ret)
		*cmp_ret = -1;
	if (par)
		*par = NULL;
	if (next)
		*next = NULL;
	if (prev)
		*prev = NULL;

	while (node) {
		cmp = compare(arg, node);
		if (par)
			*par = node;
		if (cmp_ret)
			*cmp_ret = cmp;
		if (cmp < 0) {
			if (next)
				*next = node;
			node = node_ptr(root, node->left);
		} else if (cmp > 0) {
			if (prev)
				*prev = node;
			node = node_ptr(root, node->right);
		} else {
			return node;
		}
	}

	return NULL;
}

struct scoutfs_avl_node *scoutfs_avl_first(struct scoutfs_avl_root *root)
{
	struct scoutfs_avl_node *node = node_ptr(root, root->node);

	while (node && node->left)
		node = node_ptr(root, node->left);

	return node;
}

struct scoutfs_avl_node *scoutfs_avl_last(struct scoutfs_avl_root *root)
{
	struct scoutfs_avl_node *node = node_ptr(root, root->node);

	while (node && node->right)
		node = node_ptr(root, node->right);

	return node;
}

struct scoutfs_avl_node *scoutfs_avl_next(struct scoutfs_avl_root *root,
					  struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *parent;

	if (node->right) {
		node = node_ptr(root, node->right);
		while (node->left)
			node = node_ptr(root, node->left);
		return node;
	}

	while ((parent = node_ptr(root, node->parent)) &&
	       node == node_ptr(root, parent->right))
		node = parent;

	return parent;
}

struct scoutfs_avl_node *scoutfs_avl_prev(struct scoutfs_avl_root *root,
					  struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *parent;

	if (node->left) {
		node = node_ptr(root, node->left);
		while (node->right)
			node = node_ptr(root, node->right);
		return node;
	}

	while ((parent = node_ptr(root, node->parent)) &&
	       node == node_ptr(root, parent->left))
		node = parent;

	return parent;
}

static void set_parent_left_right(struct scoutfs_avl_root *root,
				  struct scoutfs_avl_node *parent,
				  struct scoutfs_avl_node *old,
				  struct scoutfs_avl_node *new)
{
	__le16 *off;

	if (parent == NULL)
		off = &root->node;
	else if (parent->left == node_off(root, old))
		off = &parent->left;
	else
		off = &parent->right;

	*off = node_off(root, new);
}

static void set_height(struct scoutfs_avl_root *root,
		       struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *left = node_ptr(root, node->left);
	struct scoutfs_avl_node *right = node_ptr(root, node->right);

	node->height = 1 + max(node_height(left), node_height(right));
}

static int node_balance(struct scoutfs_avl_root *root,
		        struct scoutfs_avl_node *node)
{
	if (node == NULL)
		return 0;

	return (int)node_height(node_ptr(root, node->right)) -
	       (int)node_height(node_ptr(root, node->left));
}

/*
 *     d                         b
 *    / \    rotate right ->    / \
 *   b   e                     a   d
 *  / \      <- rotate left       / \
 * a   c                         c   e
 *
 * The rotate functions are always called with the higher node as the
 * earlier argument.  Links to a and e are constant.  We have to update
 * the forward and back refs between parents and nodes for the three links
 * along root->[db]->[bd]->c.
 */
static void rotate_right(struct scoutfs_avl_root *root,
			 struct scoutfs_avl_node *d)
{
	struct scoutfs_avl_node *gpa = node_ptr(root, d->parent);
	struct scoutfs_avl_node *b = node_ptr(root, d->left);
	struct scoutfs_avl_node *c = node_ptr(root, b->right);

	set_parent_left_right(root, gpa, d, b);
	b->parent = node_off(root, gpa);

	b->right = node_off(root, d);
	d->parent = node_off(root, b);

	d->left = node_off(root, c);
	if (c)
		c->parent = node_off(root, d);

	set_height(root, d);
	set_height(root, b);
}

static void rotate_left(struct scoutfs_avl_root *root,
			struct scoutfs_avl_node *b)
{
	struct scoutfs_avl_node *gpa = node_ptr(root, b->parent);
	struct scoutfs_avl_node *d = node_ptr(root, b->right);
	struct scoutfs_avl_node *c = node_ptr(root, d->left);

	set_parent_left_right(root, gpa, b, d);
	d->parent = node_off(root, gpa);

	d->left = node_off(root, b);
	b->parent = node_off(root, d);

	b->right = node_off(root, c);
	if (c)
		c->parent = node_off(root, b);

	set_height(root, b);
	set_height(root, d);
}

/*
 * Check the balance factor for the given node and perform rotations if
 * its two child subtrees are too far out of balance.  Return either the
 * node again or the root of the newly balanced subtree.
 */
static struct scoutfs_avl_node *
rotate_imbalance(struct scoutfs_avl_root *root, struct scoutfs_avl_node *node)
{
	int bal = node_balance(root, node);
	struct scoutfs_avl_node *child;

	if (bal >= -1 && bal <= 1)
		return node;

	if (bal > 0) {
		/* turn right-left case into right-right */
		child = node_ptr(root, node->right);
		if (node_balance(root, child) < 0)
			rotate_right(root, child);
		/* rotate left to address right-right */
		rotate_left(root, node);

	} else {
		/* or do the mirror for the left- cases */
		child = node_ptr(root, node->left);
		if (node_balance(root, child) > 0)
			rotate_left(root, child);
		rotate_right(root, node);
	}

	return node_ptr(root, node->parent);
}

void scoutfs_avl_insert(struct scoutfs_avl_root *root,
			struct scoutfs_avl_node *parent,
			struct scoutfs_avl_node *node, int cmp)
{
	node->parent = 0;
	node->left = 0;
	node->right = 0;
	set_height(root, node);

	if (parent == NULL) {
		root->node = node_off(root, node);
		node->parent = 0;
		return;
	}

	if (cmp < 0)
		parent->left = node_off(root, node);
	else
		parent->right = node_off(root, node);
	node->parent = node_off(root, parent);

	while (parent) {
		set_height(root, parent);
		parent = rotate_imbalance(root, parent);
		parent = node_ptr(root, parent->parent);
	}
}

static struct scoutfs_avl_node *avl_successor(struct scoutfs_avl_root *root,
					      struct scoutfs_avl_node *node)
{
	node = node_ptr(root, node->right);
	while (node->left)
		node = node_ptr(root, node->left);

	return node;
}

/*
 * Find a node next successor and then swap the positions of the two
 * nodes with each other in the tree.  This is only tricky because the
 * successor can be a direct child of the node and if we weren't careful
 * we'd be modifying each of the nodes through the pointers between
 * them.
 */
static void swap_with_successor(struct scoutfs_avl_root *root,
				struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *succ = avl_successor(root, node);
	struct scoutfs_avl_node *succ_par = node_ptr(root, succ->parent);
	struct scoutfs_avl_node *succ_right = node_ptr(root, succ->right);
	struct scoutfs_avl_node *parent;
	struct scoutfs_avl_node *left;
	struct scoutfs_avl_node *right;

	/* Link old node's parent and left child with the successor */
	succ->parent = node->parent;
	parent = node_ptr(root, succ->parent);
	set_parent_left_right(root, parent, node, succ);
	succ->left = node->left;
	left = node_ptr(root, succ->left);
	if (left)
		left->parent = node_off(root, succ);

	/*
	 * Link the old node's right with successor and the old
	 * successor's parent with the node, they could have pointed to
	 * each other.
	 */
	if (succ_par == node) {
		succ->right = node_off(root, node);
		node->parent = node_off(root, succ);
	} else {
		succ->right = node->right;
		right = node_ptr(root, succ->right);
		if (right)
			right->parent = node_off(root, succ);
		set_parent_left_right(root, succ_par, succ, node);
		node->parent = node_off(root, succ_par);
	}

	/* Link the old successor's right with the node, it can't have left */
	node->right = node_off(root, succ_right);
	if (succ_right)
		succ_right->parent = node_off(root, node);
	node->left = 0;

	swap(node->height, succ->height);
}

void scoutfs_avl_delete(struct scoutfs_avl_root *root,
			struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *parent;
	struct scoutfs_avl_node *child;

	if (node->left && node->right)
		swap_with_successor(root, node);

	parent = node_ptr(root, node->parent);
	child = node_ptr(root, node->left ?: node->right);

	set_parent_left_right(root, parent, node, child);
	if (child)
		child->parent = node->parent;

	while (parent) {
		set_height(root, parent);
		parent = rotate_imbalance(root, parent);
		parent = node_ptr(root, parent->parent);
	}
}

/*
 * Move the contents of a node to a new node location in memory.  The
 * logical position of the node in the tree does not change.
 */
void scoutfs_avl_relocate(struct scoutfs_avl_root *root,
			  struct scoutfs_avl_node *to,
			  struct scoutfs_avl_node *from)
{
	struct scoutfs_avl_node *parent = node_ptr(root, from->parent);
	struct scoutfs_avl_node *left = node_ptr(root, from->left);
	struct scoutfs_avl_node *right = node_ptr(root, from->right);

	set_parent_left_right(root, parent, from, to);
	to->parent = from->parent;
	to->left = from->left;
	if (left)
		left->parent = node_off(root, to);
	to->right = from->right;
	if (right)
		right->parent = node_off(root, to);
	to->height = from->height;
}
