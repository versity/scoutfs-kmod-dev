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
#include <linux/random.h>

#include "format.h"
#include "treap.h"

/*
 * Implement a simple treap in memory.  The caller is responsible for
 * allocating and freeing roots and nodes.  This only performs the tree
 * operations on them.
 *
 * Node references are stored as byte offsets from the root to the node.
 * As long as we have the root the byte offsets or node pointers are
 * interchangeable.  The code tries to prefer to use pointers to be
 * slightly easier to read.
 *
 * The caller is responsible for locking access to the tree.
 */

/*
 * treap nodes are embedded in btree items.  Their offset is relative to
 * the treap root which is embedded in the btree block header.  Their
 * offset can't have the item overlap the btree block header, nor can
 * the item fall off the end of the block.
 */
static void bug_on_bad_node_off(u16 off)
{
	BUG_ON(off < (sizeof(struct scoutfs_btree_block) -
		      offsetof(struct scoutfs_btree_block, treap) +
		      offsetof(struct scoutfs_btree_item, tnode)));
	BUG_ON(off > (SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_item) +
		      offsetof(struct scoutfs_btree_item, tnode)));
}

static struct scoutfs_treap_node *off_node(struct scoutfs_treap_root *root,
					   __le16 off)
{
	if (!off)
		return NULL;

	bug_on_bad_node_off(le16_to_cpu(off));

	return (void *)root + le16_to_cpu(off);
}

static __le16 node_off(struct scoutfs_treap_root *root,
			struct scoutfs_treap_node *node)
{
	u16 off;

	if (!node)
		return 0;

	off = (char *)node - (char *)root;
	bug_on_bad_node_off(off);

	return cpu_to_le16(off);
}

/*
 * Walk the tree looking for a node that matches a node in the tree.
 * Return the found node or the last node traversed.  Set the caller's
 * cmp to the comparison between the key and the returned node.  The
 * caller can ask that we set their pointers to the most recently
 * traversed node before or after the returned node.
 */
static struct scoutfs_treap_node *descend(struct scoutfs_treap_root *root,
					  scoutfs_treap_cmp_t cmp_func,
					  struct scoutfs_treap_node *key,
					  int *cmp,
					  struct scoutfs_treap_node **before,
					  struct scoutfs_treap_node **after)
{
	struct scoutfs_treap_node *node = NULL;
	__le16 off = root->off;

	*cmp = -1;
	if (before)
		*before = NULL;
	if (after)
		*after = NULL;

	while (off) {
		node = off_node(root, off);
		*cmp = cmp_func(key, node);
		if (*cmp < 0) {
			if (after)
				*after = node;
			off = node->left;
		} else if (*cmp > 0) {
			if (before)
				*before = node;
			off = node->right;
		} else {
			break;
		}
	}

	return node;
}

/*
 * Link the two nodes together by setting their child and parent pointers
 * as needed.  Both parent and child can be null.
 */
static void set_links(struct scoutfs_treap_root *root,
		      struct scoutfs_treap_node *parent, bool left,
		      struct scoutfs_treap_node *child)
{
	if (!parent)
		root->off = node_off(root, child);
	else if (left)
		parent->left = node_off(root, child);
	else
		parent->right = node_off(root, child);

	if (child)
		child->parent = node_off(root, parent);
}

/*
 * Perform a tree rotation.  The node pointer names describe their
 * relationships before the rotation.  We use the relationship between
 * the node and its child to determine the direction of the rotation.
 * After the rotation the child will be higher than the node.  Only the
 * node and child must exist.
 *
 * Here's a right rotation:
 *
 *      parent		parent
 *        |		  |
 *       node		 child
 *       / \ 		 / \
 *   child  a		b  node
 *    / \		   /   \
 *   b  gr_chi		gr_chi  a
 *
 */
static void rotation(struct scoutfs_treap_root *root,
		     struct scoutfs_treap_node *node,
		     struct scoutfs_treap_node *child)
{
	struct scoutfs_treap_node *parent = off_node(root, node->parent);
	struct scoutfs_treap_node *grand_child;
	bool right;

	if (node->left == node_off(root, child)) {
		right = true;
		grand_child = off_node(root, child->right);
	} else {
		right = false;
		grand_child = off_node(root, child->left);
	}

	set_links(root, parent,
		  parent && (parent->left == node_off(root, node)), child);
	set_links(root, node, right, grand_child);
	set_links(root, child, !right, node);
}

/*
 * Insertion links a node in at a leaf and then rotates it up the
 * tree until its parent has a higher priority.
 */
int scoutfs_treap_insert(struct scoutfs_treap_root *root,
		         scoutfs_treap_cmp_t cmp_func,
			 struct scoutfs_treap_node *ins)
{
	struct scoutfs_treap_node *parent;
	int cmp;

	ins->prio = cpu_to_le32(get_random_int());
	ins->parent = 0;
	ins->left = 0;
	ins->right = 0;

	parent = descend(root, cmp_func, ins, &cmp, NULL, NULL);
	if (cmp == 0)
		return -EEXIST;

	set_links(root, parent, cmp < 0, ins);

	while (ins->parent) {
		parent = off_node(root, ins->parent);
		if (le32_to_cpu(ins->prio) < le32_to_cpu(parent->prio))
			break;

		rotation(root, parent, ins);
	}

	return 0;
}

/*
 * Deletion rotates the node down the tree until it doesn't have two
 * children so that it can be unlinked by pointing its parent at its
 * child, if it has one.
 */
void scoutfs_treap_delete(struct scoutfs_treap_root *root,
			  struct scoutfs_treap_node *node)
{
	struct scoutfs_treap_node *left;
	struct scoutfs_treap_node *right;
	struct scoutfs_treap_node *child;
	struct scoutfs_treap_node *parent;

	while (node->left && node->right) {
		left = off_node(root, node->left);
		right = off_node(root, node->right);

		if (le32_to_cpu(left->prio) > le32_to_cpu(right->prio))
			rotation(root, node, left);
		else
			rotation(root, node, right);
	}

	parent = off_node(root, node->parent);

	if (node->left)
		child = off_node(root, node->left);
	else
		child = off_node(root, node->right);

	set_links(root, parent,
		  parent && parent->left == node_off(root, node), child);
}

struct scoutfs_treap_node *scoutfs_treap_lookup(struct scoutfs_treap_root *root,
						scoutfs_treap_cmp_t cmp_func,
						struct scoutfs_treap_node *key)
{
	struct scoutfs_treap_node *node;
	int cmp;

	node = descend(root, cmp_func, key, &cmp, NULL, NULL);
	if (cmp != 0)
		return NULL;

	return node;
}

/* return the first node in the tree */
struct scoutfs_treap_node *scoutfs_treap_first(struct scoutfs_treap_root *root)
{
	struct scoutfs_treap_node *node = off_node(root, root->off);

	while (node && node->left)
		node = off_node(root, node->left);

	return node;
}

/* return the last node in the tree */
struct scoutfs_treap_node *scoutfs_treap_last(struct scoutfs_treap_root *root)
{
	struct scoutfs_treap_node *node = off_node(root, root->off);

	while (node && node->right)
		node = off_node(root, node->right);

	return node;
}

/* return the last node whose key is less than or equal to the key */
struct scoutfs_treap_node *scoutfs_treap_before(struct scoutfs_treap_root *root,
						scoutfs_treap_cmp_t cmp_func,
						struct scoutfs_treap_node *key)
{
	struct scoutfs_treap_node *before;
	struct scoutfs_treap_node *node;
	int cmp;

	node = descend(root, cmp_func, key, &cmp, &before, NULL);
	if (cmp == 0)
		return node;

	return before;
}

/* return the first node whose key is greater than or equal to the key */
struct scoutfs_treap_node *scoutfs_treap_after(struct scoutfs_treap_root *root,
					       scoutfs_treap_cmp_t cmp_func,
					       struct scoutfs_treap_node *key)
{
	struct scoutfs_treap_node *after;
	struct scoutfs_treap_node *node;
	int cmp;

	node = descend(root, cmp_func, key, &cmp, NULL, &after);
	if (cmp == 0)
		return node;

	return after;
}

/*
 * The usual BST iteration: either the least descendant or the first
 * ancestor in the direction of the iteration.
 */
struct scoutfs_treap_node *scoutfs_treap_next(struct scoutfs_treap_root *root,
					      struct scoutfs_treap_node *node)
{
	struct scoutfs_treap_node *parent;

	if (node->right) {
		node = off_node(root, node->right);
		while (node->left)
			node = off_node(root, node->left);
		return node;
	}

	while ((parent = off_node(root, node->parent)) &&
	        parent->right == node_off(root, node)) {
		node = parent;
	}

	return parent;
}

struct scoutfs_treap_node *scoutfs_treap_prev(struct scoutfs_treap_root *root,
					      struct scoutfs_treap_node *node)
{
	struct scoutfs_treap_node *parent;

	if (node->left) {
		node = off_node(root, node->left);
		while (node->right)
			node = off_node(root, node->right);
		return node;
	}

	while ((parent = off_node(root, node->parent)) &&
	        parent->left == node_off(root, node)) {
		node = parent;
	}

	return parent;
}

static void update_relative(struct scoutfs_treap_root *root, __le16 node_off,
			    __le16 from_off, __le16 to_off)
{
	struct scoutfs_treap_node *node = off_node(root, node_off);

	if (node) {
		if (node->parent == from_off)
			node->parent = to_off;
		else if (node->left == from_off)
			node->left = to_off;
		else if (node->right == from_off)
			node->right = to_off;
	}
}

/*
 * A node has moved from one storage location to another.  Update the
 * nodes that refer to it.  The from pointer can only be used to
 * determine the old offset.  Its contents are undefined.
 */
void scoutfs_treap_move(struct scoutfs_treap_root *root,
		        struct scoutfs_treap_node *from,
		        struct scoutfs_treap_node *to)
{
	__le16 from_off = node_off(root, from);
	__le16 to_off = node_off(root, to);

	if (root->off == from_off)
		root->off = to_off;
	else
		update_relative(root, to->parent, from_off, to_off);

	update_relative(root, to->left, from_off, to_off);
	update_relative(root, to->right, from_off, to_off);
}
