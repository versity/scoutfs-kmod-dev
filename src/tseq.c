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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/rbtree_augmented.h>

#include "tseq.h"

/*
 * This trivial seq file wrapper takes care of the details of displaying
 * a set of objects in seq file output.  We use an augmented rbtree to
 * add new objects at the next free file position.  The caller takes
 * care of the object life times, only debugfs file creation can fail.
 */

static loff_t tseq_node_total(struct rb_node *node)
{
	struct scoutfs_tseq_entry *ent;

	if (node == NULL)
		return 0;

	ent = rb_entry(node, struct scoutfs_tseq_entry, node);
	return ent->total;
}

static struct scoutfs_tseq_entry *tseq_rb_next(struct scoutfs_tseq_entry *ent)
{
	struct rb_node *node = rb_next(&ent->node);

	if (node == NULL)
		return NULL;

	return rb_entry(node, struct scoutfs_tseq_entry, node);
}

static loff_t tseq_compute_total(struct scoutfs_tseq_entry *ent)
{
	return 1 + tseq_node_total(ent->node.rb_left) +
	       tseq_node_total(ent->node.rb_right);
}

RB_DECLARE_CALLBACKS(static, tseq_rb_callbacks, struct scoutfs_tseq_entry,
		     node, loff_t, total, tseq_compute_total)

void scoutfs_tseq_tree_init(struct scoutfs_tseq_tree *tree,
			    scoutfs_tseq_show_t show)
{
	spin_lock_init(&tree->lock);
	tree->root = RB_ROOT;
	tree->show = show;
}

/*
 * Descend towards the leaf node that should be the parent for inserting
 * a new entry.
 *
 * We use the augmented subtree totals to see when a left subtree has
 * fewer entries than the current entry's pos which tells us that there
 * is a lesser free pos.
 *
 * If there isn't a lesser free pos then we descend to the right and set
 * the minimum possible pos to the pos after the entry we're traversing.
 */
void scoutfs_tseq_add(struct scoutfs_tseq_tree *tree,
		      struct scoutfs_tseq_entry *ins)
{
	struct scoutfs_tseq_entry *ent;
	struct rb_node *parent;
	struct rb_node **node;
	loff_t min_pos;

	spin_lock(&tree->lock);

	node = &tree->root.rb_node;
	parent = NULL;
	min_pos = 0;

	while (*node) {
		parent = *node;
		ent = rb_entry(*node, struct scoutfs_tseq_entry, node);

		ent->total++;

		if (min_pos + tseq_node_total(ent->node.rb_left) < ent->pos) {
			node = &ent->node.rb_left;
		} else {
			min_pos = ent->pos + 1;
			node = &ent->node.rb_right;
		}
	}

	ins->pos = min_pos;
	ins->total = 1;
	rb_link_node(&ins->node, parent, node);
	rb_insert_augmented(&ins->node, &tree->root, &tseq_rb_callbacks);

	spin_unlock(&tree->lock);
}

static struct scoutfs_tseq_entry *tseq_pos_next(struct scoutfs_tseq_tree *tree,
					        loff_t pos)
{
	struct scoutfs_tseq_entry *next;
	struct scoutfs_tseq_entry *ent;
	struct rb_node *node;

	assert_spin_locked(&tree->lock);

	node = tree->root.rb_node;
	next = NULL;

	while (node) {
		ent = rb_entry(node, struct scoutfs_tseq_entry, node);

		if (pos < ent->pos) {
			next = ent;
			node = ent->node.rb_left;
		} else if (pos > ent->pos) {
			node = ent->node.rb_right;
		} else {
			return ent;
		}
	}

	return next;
}

void scoutfs_tseq_del(struct scoutfs_tseq_tree *tree,
		      struct scoutfs_tseq_entry *ent)
{
	spin_lock(&tree->lock);
	rb_erase_augmented(&ent->node, &tree->root, &tseq_rb_callbacks);
	RB_CLEAR_NODE(&ent->node);
	spin_unlock(&tree->lock);
}

/* _stop is always called no matter what start returns */
static void *scoutfs_tseq_seq_start(struct seq_file *m, loff_t *pos)
	__acquires(tree->lock)
{
	struct scoutfs_tseq_tree *tree = m->private;

	spin_lock(&tree->lock);

	return tseq_pos_next(tree, *pos);
}

static void *scoutfs_tseq_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct scoutfs_tseq_entry *ent = v;

	ent = tseq_rb_next(ent);
	if (ent)
		*pos = ent->pos;
	return ent;
}

static void scoutfs_tseq_seq_stop(struct seq_file *m, void *v)
	__releases(tree->lock)
{
	struct scoutfs_tseq_tree *tree = m->private;

	spin_unlock(&tree->lock);
}

static int scoutfs_tseq_seq_show(struct seq_file *m, void *v)
{
	struct scoutfs_tseq_tree *tree = m->private;
	struct scoutfs_tseq_entry *ent = v;

	tree->show(m, ent);
	return 0;
}

static const struct seq_operations scoutfs_tseq_seq_ops = {
	.start =	scoutfs_tseq_seq_start,
	.next =		scoutfs_tseq_seq_next,
	.stop =		scoutfs_tseq_seq_stop,
	.show =		scoutfs_tseq_seq_show,
};

static int scoutfs_tseq_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &scoutfs_tseq_seq_ops);
	if (ret == 0) {
		m = file->private_data;
		m->private = inode->i_private;
	}
	return ret;
}

static const struct file_operations scoutfs_tseq_fops = {
	.open =		scoutfs_tseq_open,
	.release =	seq_release,
	.read =		seq_read,
	.llseek =	seq_lseek,
};

/*
 * This doesn't create any additional state so the returned dentry
 * can be destroyed with the usual debugfs file calls.
 */
struct dentry *scoutfs_tseq_create(const char *name, struct dentry *parent,
				   struct scoutfs_tseq_tree *tree)
{
	return debugfs_create_file(name, S_IFREG|S_IRUSR, parent, tree,
				   &scoutfs_tseq_fops);
}
