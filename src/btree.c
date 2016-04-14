/*
 * Copyright (C) 2016 Zach Brown.  All rights reserved.
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
#include <linux/rwsem.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "key.h"
#include "treap.h"
#include "btree.h"

/*
 * scoutfs stores file system metadata in btrees whose items have fixed
 * sized keys and variable length values.
 *
 * Items are stored as a small header with the key followed by the
 * value.  New items are appended to the end of the block.  Free space
 * is not indexed.  Deleted items can be reclaimed by walking all the
 * items from the front of the block and moving later live items onto
 * earlier deleted items.
 *
 * The items are kept in a treap sorted by their keys.  Using a dynamic
 * structure keeps the modification costs low.  Modifying persistent
 * structures avoids translation to and from run-time structures around
 * read and write.  The treap was chosen because it's very simple to
 * implement and has some cool merging and splitting functions that we
 * could make use of.  The treap has parent pointers so that we can
 * perform operations relative to a node without having to keep a record
 * of the path down the tree.
 *
 * Parent blocks in the btree have the same format as leaf blocks.
 * There's one key for every child reference instead of having separator
 * keys between child references.  The key in a child reference contains
 * the largest key that may be found in the child subtree.  The right
 * spine of the tree has maximal keys so that they don't have to be
 * updated if we insert an item with a key greater than everything in
 * the tree.
 *
 * Operations are performed in one pass down the tree.  This lets us
 * cascade locks from the root down to the leaves and avoids having to
 * maintain a record of the path down the tree.  Splits and merges are
 * performed as we descend.
 *
 * XXX
 *  - actually free blknos
 *  - do we want a level in the btree header?  seems like we would?
 *  - validate structures on read?
 */

/* size of the item with a value of the given length */
static inline unsigned int val_bytes(unsigned int val_len)
{
	return sizeof(struct scoutfs_btree_item) + val_len;
}

static inline unsigned int item_bytes(struct scoutfs_btree_item *item)
{
	return val_bytes(le16_to_cpu(item->val_len));
}

static inline unsigned int used_total(struct scoutfs_btree_block *bt)
{
	return SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block) -
	       le16_to_cpu(bt->total_free);
}

static int cmp_tnode_items(struct scoutfs_treap_node *A,
			   struct scoutfs_treap_node *B)
{
	struct scoutfs_btree_item *a;
	struct scoutfs_btree_item *b;

	a = container_of(A, struct scoutfs_btree_item, tnode);
	b = container_of(B, struct scoutfs_btree_item, tnode);

	return scoutfs_key_cmp(&a->key, &b->key);
}

/* A bunch of wrappers for navigating items through treap nodes. */

#define BT_TREAP_KEY_WRAPPER(which)					\
static struct scoutfs_btree_item *bt_##which(struct scoutfs_btree_block *bt, \
					     struct scoutfs_key *key)	\
{									\
	struct scoutfs_btree_item dummy = { .key = *key };		\
	struct scoutfs_treap_node *node;				\
									\
	node = scoutfs_treap_##which(&bt->treap, cmp_tnode_items,	\
				     &dummy.tnode);			\
	if (!node)							\
		return NULL;						\
									\
	return container_of(node, struct scoutfs_btree_item, tnode);	\
}

BT_TREAP_KEY_WRAPPER(lookup)
/* BT_TREAP_KEY_WRAPPER(before) */
BT_TREAP_KEY_WRAPPER(after)

#define BT_TREAP_ROOT_WRAPPER(which)					\
static struct scoutfs_btree_item *bt_##which(struct scoutfs_btree_block *bt) \
{									\
	struct scoutfs_treap_node *node;				\
									\
	node = scoutfs_treap_##which(&bt->treap);			\
	if (!node)							\
		return NULL;						\
									\
	return container_of(node, struct scoutfs_btree_item, tnode);	\
}

BT_TREAP_ROOT_WRAPPER(first)
BT_TREAP_ROOT_WRAPPER(last)

#define BT_TREAP_NODE_WRAPPER(which)					\
static struct scoutfs_btree_item *bt_##which(struct scoutfs_btree_block *bt, \
					     struct scoutfs_btree_item *item)\
{									\
	struct scoutfs_treap_node *node;				\
									\
	node = scoutfs_treap_##which(&bt->treap, &item->tnode);		\
	if (!node)							\
		return NULL;						\
									\
	return container_of(node, struct scoutfs_btree_item, tnode);	\
}

BT_TREAP_NODE_WRAPPER(next)
BT_TREAP_NODE_WRAPPER(prev)

static inline struct scoutfs_key *least_key(struct scoutfs_btree_block *bt)
{
	return &bt_first(bt)->key;
}

static inline struct scoutfs_key *greatest_key(struct scoutfs_btree_block *bt)
{
	return &bt_last(bt)->key;
}

/*
 * Allocate and insert a new item into the block.
 *
 * The caller has made sure that there's room for everything.
 *
 * The caller is responsible for initializing the value.
 */
static struct scoutfs_btree_item *create_item(struct scoutfs_btree_block *bt,
					      struct scoutfs_key *key,
					      unsigned int val_len)
{
	unsigned int bytes = val_bytes(val_len);
	struct scoutfs_btree_item *item;

	item = (void *)((char *)bt + SCOUTFS_BLOCK_SIZE -
				le16_to_cpu(bt->tail_free));
	le16_add_cpu(&bt->tail_free, -bytes);
	le16_add_cpu(&bt->total_free, -bytes);
	le16_add_cpu(&bt->nr_items, 1);

	item->key = *key;
	item->val_len = cpu_to_le16(val_len);

	scoutfs_treap_insert(&bt->treap, cmp_tnode_items, &item->tnode);

	return item;
}

#define MAGIC_DELETED_PARENT cpu_to_le16(1)

/*
 * Delete an item from a btree block.  We set the deleted item's parent
 * treap offset to a magic value for compaction.
 */
static void delete_item(struct scoutfs_btree_block *bt,
			struct scoutfs_btree_item *item)
{
	scoutfs_treap_delete(&bt->treap, &item->tnode);
	item->tnode.parent = MAGIC_DELETED_PARENT;

	le16_add_cpu(&bt->total_free, item_bytes(item));
	le16_add_cpu(&bt->nr_items, -1);
}

/*
 * Move items from a source block to a destination block.  The caller
 * tells us if we're moving from the tail of the source block right to
 * the head of the destination block, or vice versa.  We stop moving
 * once we've moved enough bytes of items.
 *
 * XXX This could use fancy treap splitting and merging.  We don't need
 * to go there yet.
 */
static void move_items(struct scoutfs_btree_block *dst,
		       struct scoutfs_btree_block *src, bool move_right,
		       int to_move)
{
	struct scoutfs_btree_item *from;
	struct scoutfs_btree_item *del;
	struct scoutfs_btree_item *to;
	unsigned int val_len;

	if (move_right)
		from = bt_last(src);
	else
		from = bt_first(src);

	while (from && to_move > 0) {
		val_len = le16_to_cpu(from->val_len);

		to = create_item(dst, &from->key, val_len);
		memcpy(to->val, from->val, val_len);

		del = from;
		if (move_right)
			from = bt_prev(src, from);
		else
			from = bt_next(src, from);

		delete_item(src, del);
		to_move -= item_bytes(to);
	}
}

/*
 * As items are deleted they create fragmented free space.  Even if we
 * indexed free space in the block it could still get sufficiently
 * fragmented to force a split on insertion even though the two
 * resulting blocks would have less than the minimum space consumed by
 * items.
 *
 * We don't bother implementing free space indexing and addressing that
 * corner case.  Instead we track the number of total free bytes in the
 * block.  If free space needed is available in the block but is not
 * available at the end of the block then we reclaim the fragmented free
 * space by compacting the items.
 *
 * We move the free space to the tail of the block by walk forward
 * through the items in allocated order moving live items back in to
 * free space.
 *
 * Compaction is only attempted during descent as we find a block that
 * needs more or less free space.  The caller has the parent locked for
 * writing and there are no references to the items at this point so
 * it's safe to scramble the block contents.
 */
static void compact_items(struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_item *from = (void *)(bt + 1);
	struct scoutfs_btree_item *to = from;
	unsigned int bytes;
	unsigned int i;

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		bytes = item_bytes(from);

		if (from->tnode.parent != MAGIC_DELETED_PARENT) {
			if (from != to) {
				memmove(to, from, bytes);
				scoutfs_treap_move(&bt->treap, &from->tnode,
						   &to->tnode);
			}
			to = (void *)to + bytes;
		} else {
			i--;
		}

		from = (void *)from + bytes;
	}

	bytes = SCOUTFS_BLOCK_SIZE - ((char *)to - (char *)bt);
	bt->tail_free = cpu_to_le16(bytes);
}

/*
 * Allocate and initialize a new tree block. The caller adds references
 * to it.
 */
static struct scoutfs_block *alloc_tree_block(struct super_block *sb)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;

	bl = scoutfs_alloc_block(sb);
	if (!IS_ERR(bl)) {
		bt = bl->data;

		bt->treap.off = 0;
		bt->total_free = cpu_to_le16(SCOUTFS_BLOCK_SIZE -
					sizeof(struct scoutfs_btree_block));
		bt->tail_free = bt->total_free;
		bt->nr_items = 0;
	}

	return bl;
}

/*
 * Allocate a new tree block and point the root at it.  The caller
 * is responsible for the items in the new root block.
 */
static struct scoutfs_block *grow_tree(struct super_block *sb,
				       struct scoutfs_btree_root *root)
{
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *bl;

	bl = alloc_tree_block(sb);
	if (!IS_ERR(bl)) {
		hdr = bl->data;

		root->height++;
		root->ref.blkno = hdr->blkno;
		root->ref.seq = hdr->seq;
	}

	return bl;
}

/*
 * Create a new item in the parent which references the child.  The caller
 * specifies the key in the item that describes the items in the child.
 */
static void create_parent_item(struct scoutfs_btree_block *parent,
			       struct scoutfs_btree_block *child,
			       struct scoutfs_key *key)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_block_ref ref = {
		.blkno = child->hdr.blkno,
		.seq = child->hdr.seq,
	};

	item = create_item(parent, key, sizeof(ref));
	memcpy(&item->val, &ref, sizeof(ref));
}

/*
 * See if we need to split this block while descending for insertion so
 * that we have enough space to insert.
 *
 * Parent blocks need enough space for a new item and child ref if a
 * child block splits.  Leaf blocks need enough space to insert the new
 * item with its value.
 *
 * We split to the left so that the greatest key in the existing block
 * doesn't change so we don't have to update the key in its parent item.
 *
 * If the search key falls in the new split block then we return it
 * to the caller to walk through.
 *
 * The locking in the case where we add the first parent is a little wonky.
 * We're creating a parent block that the walk doesn't know about.  It
 * holds the tree mutex while we add the parent ref and then will lock
 * the child that we return.  It's skipping locking the new parent as it
 * descends but that's fine.
 */
static struct scoutfs_block *try_split(struct super_block *sb,
				       struct scoutfs_btree_root *root,
				       int level, struct scoutfs_key *key,
				       unsigned int val_len,
				       struct scoutfs_btree_block *parent,
				       struct scoutfs_btree_item *par_item,
				       struct scoutfs_block *right_bl)
{
	struct scoutfs_btree_block *right = right_bl->data;
	struct scoutfs_btree_block *left;
	struct scoutfs_block *left_bl;
	struct scoutfs_block *par_bl = NULL;
	unsigned int bytes;

	if (level)
		val_len = sizeof(struct scoutfs_block_ref);
	bytes = val_bytes(val_len);

	if (le16_to_cpu(right->tail_free) >= bytes)
		return right_bl;

	if (le16_to_cpu(right->total_free) >= bytes) {
		compact_items(right);
		return right_bl;
	}

	if (!parent) {
		par_bl = grow_tree(sb, root);
		if (IS_ERR(par_bl)) {
			scoutfs_put_block(right_bl);
			return par_bl;
		}

		parent = par_bl->data;
	}

	left_bl = alloc_tree_block(sb);
	if (IS_ERR(left_bl)) {
		/* XXX free parent block? */
		scoutfs_put_block(par_bl);
		scoutfs_put_block(right_bl);
		return left_bl;
	}
	left = left_bl->data;

	/* only grow the tree once we have the split neighbour */
	if (par_bl) {
		struct scoutfs_key ones;
		memset(&ones, 0xff, sizeof(ones));
		create_parent_item(parent, right, &ones);
	}

	move_items(left, right, false, used_total(right) / 2);
	create_parent_item(parent, left, greatest_key(left));

	if (scoutfs_key_cmp(key, greatest_key(left)) <= 0) {
		/* insertion will go to the new left block */
		scoutfs_put_block(right_bl);
		right_bl = left_bl;
	} else {
		/* insertion will still go through us, might need to compact */
		scoutfs_put_block(left_bl);

		if (le16_to_cpu(right->tail_free) < bytes)
			compact_items(right);
	}

	scoutfs_put_block(par_bl);

	return right_bl;
}

/*
 * This is called during descent for deletion when we have a parent and
 * might need to merge items from a sibling block if this block has too
 * much free space.  Eventually we'll be able to fit all of the
 * sibling's items in our free space which lets us delete the sibling
 * block.
 *
 * The error handling here is a little weird.  We're returning an
 * ERR_PTR buffer to match splitting so that the walk can handle errors
 * from both easily.  We have to unlock and release our buffer to return
 * an error.
 *
 * The caller only has the parent locked.  They'll lock whichever
 * block we return.
 *
 * XXX this could more cleverly chose a merge candidate sibling
 */
static struct scoutfs_block *try_merge(struct super_block *sb,
				     struct scoutfs_btree_root *root,
				     struct scoutfs_btree_block *parent,
				     struct scoutfs_btree_item *par_item,
				     struct scoutfs_block *bl)
{
	struct scoutfs_btree_block *bt = bl->data;
	struct scoutfs_btree_block *sib_bt;
	struct scoutfs_block *sib_bl;
	struct scoutfs_btree_item *sib_item;
	int to_move;
	bool move_right;

	if (le16_to_cpu(bt->total_free) <= SCOUTFS_BTREE_FREE_LIMIT)
		return bl;

	/* move items right into our block if we have a left sibling */
	sib_item = bt_prev(parent, par_item);
	if (sib_item) {
		move_right = false;
	} else {
		sib_item = bt_next(parent, par_item);
		move_right = true;
	}

	sib_bl = scoutfs_dirty_ref(sb, (void *)sib_item->val);
	if (IS_ERR(sib_bl)) {
		/* XXX do we need to unlock this?  don't think so */
		scoutfs_put_block(bl);
		return sib_bl;
	}
	sib_bt = sib_bl->data;

	if (used_total(sib_bt) <= le16_to_cpu(bt->total_free))
		to_move = used_total(sib_bt);
	else
		to_move = le16_to_cpu(bt->total_free) -
			  SCOUTFS_BTREE_FREE_LIMIT;

	if (le16_to_cpu(bt->tail_free) < to_move)
		compact_items(bt);

	move_items(bt, sib_bt, move_right, to_move);

	/* update our parent's ref if we changed our greatest key */
	if (!move_right)
		par_item->key = *greatest_key(bt);

	/* delete an empty sib or update if we changed its greatest key */
	if (sib_bt->nr_items == 0) {
		delete_item(parent, sib_item);
		/* XXX free sib block */
	} else if (move_right) {
		sib_item->key = *greatest_key(sib_bt);
	}

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le16_to_cpu(parent->nr_items) == 1) {
		root->height--;
		root->ref.blkno = bt->hdr.blkno;
		root->ref.seq = bt->hdr.seq;
		/* XXX free block */
	}

	return bl;
}

enum {
	WALK_INSERT = 1,
	WALK_DELETE,
	WALK_NEXT,
	WALK_PREV,
	WALK_DIRTY,
};

/*
 * Usually we descend to a leaf that contains the key.  But if we're
 * searching for a next or previous item then we might hit a leaf block
 * that contains the key but no items in the direction of the search.
 * We might need to ascend and continue the search in the next block.
 *
 * The caller has just descended to a leaf and is asking us to discover
 * this case.  We set the parent item and return true to tell the caller
 * to read the new parent item's referenced block.
 *
 * XXX I don't think this can see bts with 0 items?  would need to verify?
 */
static bool next_leaf(struct scoutfs_btree_block *parent,
		     struct scoutfs_btree_item **par_item,
		     struct scoutfs_btree_block *bt, int op, int level,
		     struct scoutfs_key *key)
{
	struct scoutfs_btree_item *nei;

	if (level > 0 || !parent || le16_to_cpu(parent->nr_items) < 2)
		return false;

	if (op == WALK_NEXT) {
		nei = bt_next(parent, *par_item);
		if (nei && (scoutfs_key_cmp(key, greatest_key(bt)) > 0)) {
			*par_item = nei;
			return true;
		}
	}

	if (op == WALK_PREV) {
		nei = bt_prev(parent, *par_item);
		if (nei && (scoutfs_key_cmp(key, least_key(bt)) < 0)) {
			*par_item = nei;
			return true;
		}
	}

	return false;
}

/*
 * As we descend we lock parent blocks (or the root), then lock the child,
 * then unlock the parent.
 */
static void lock_block(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl,
		       bool dirty)
{
	struct rw_semaphore *rwsem;

	if (bl == NULL)
		rwsem = &sbi->btree_rwsem;
	else
		rwsem = &bl->rwsem;

	if (dirty)
		down_write(rwsem);
	else
		down_read(rwsem);
}

static void unlock_block(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl,
		         bool dirty)
{
	struct rw_semaphore *rwsem;

	if (bl == NULL)
		rwsem = &sbi->btree_rwsem;
	else
		rwsem = &bl->rwsem;

	if (dirty)
		up_write(rwsem);
	else
		up_read(rwsem);
}


/*
 * Return the leaf block that should contain the given key.  The caller
 * is responsible for searching the leaf block and performing their
 * operation.  The block is returned locked for either reading or writing
 * depending on the operation.
 */
static struct scoutfs_block *btree_walk(struct super_block *sb,
					struct scoutfs_key *key,
					unsigned int val_len, int op)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_btree_block *parent = NULL;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_root *root;
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_item *item = NULL;
	struct scoutfs_block_ref *ref;
	unsigned int level;
	const bool dirty = op == WALK_INSERT || op == WALK_DELETE ||
			   op == WALK_DIRTY;

	lock_block(sbi, par_bl, dirty);

	/* XXX one for now */
	root = &sbi->super.btree_root;
	ref = &root->ref;
	level = root->height;

	if (!root->height) {
		if (op == WALK_INSERT) {
			bl = ERR_PTR(-ENOENT);
		} else {
			bl = grow_tree(sb, root);
			if (!IS_ERR(bl))
				lock_block(sbi, bl, dirty);
		}
		unlock_block(sbi, par_bl, dirty);
		return bl;
	}

	while (level--) {
		/* XXX hmm, need to think about retry */
		if (dirty) {
			bl = scoutfs_dirty_ref(sb, ref);
		} else {
			bl = scoutfs_read_ref(sb, ref);
		}
		if (IS_ERR(bl))
			break;
		bt = bl->data;

		/* see if a search needs to move to the next parent ref */
		if (next_leaf(parent, &item, bt, op, level, key)) {
			ref = (void *)item->val;
			level++;
			scoutfs_put_block(bl);
			continue;
		}

		if (op == WALK_INSERT)
			bl = try_split(sb, root, level, key, val_len, parent,
				       item, bl);
		if ((op == WALK_DELETE) && parent)
			bl = try_merge(sb, root, parent, item, bl);
		if (IS_ERR(bl))
			break;

		lock_block(sbi, bl, dirty);

		if (!level)
			break;

		/* unlock parent before searching so others can use it */
		unlock_block(sbi, par_bl, dirty);
		scoutfs_put_block(par_bl);
		par_bl = bl;
		parent = bt;

		/* there should always be a parent item */
		item = bt_after(parent, key);
		if (!item) {
			/* current block dropped as parent below */
			bl = ERR_PTR(-EIO);
			break;
		}

		/* XXX verify sane length */
		ref = (void *)item->val;
	}

	unlock_block(sbi, par_bl, dirty);
	scoutfs_put_block(par_bl);

	return bl;
}

static void set_cursor(struct scoutfs_btree_cursor *curs,
		       struct scoutfs_block *bl,
		       struct scoutfs_btree_item *item, bool write)
{
	curs->bl = bl;
	curs->item = item;
	curs->key = &item->key;
	curs->val = item->val;
	curs->val_len = le16_to_cpu(item->val_len);
	curs->write = !!write;
}

/*
 * Point the caller's cursor at the item if it's found.  It can't be
 * modified.  -ENOENT is returned if the key isn't found in the tree.
 */
int scoutfs_btree_lookup(struct super_block *sb, struct scoutfs_key *key,
			 struct scoutfs_btree_cursor *curs)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_block *bl;
	int ret;

	BUG_ON(curs->bl);

	bl = btree_walk(sb, key, 0, 0);
	if (IS_ERR(bl))
		return PTR_ERR(bl);

	item = bt_lookup(bl->data, key);
	if (item) {
		set_cursor(curs, bl, item, false);
		ret = 0;
	} else {
		up_read(&bl->rwsem);
		scoutfs_put_block(bl);
		ret = -ENOENT;
	}

	return ret;
}

/*
 * Insert a new item in the tree and point the caller's cursor at it.
 * The caller is responsible for setting the value.
 *
 * -EEXIST is returned if the key is already present in the tree.
 *
 * XXX this walks the treap twice, which isn't great
 */
int scoutfs_btree_insert(struct super_block *sb, struct scoutfs_key *key,
			 unsigned int val_len,
			 struct scoutfs_btree_cursor *curs)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	BUG_ON(curs->bl);

	bl = btree_walk(sb, key, val_len, WALK_INSERT);
	if (IS_ERR(bl))
		return PTR_ERR(bl);
	bt = bl->data;

	/* XXX should this return -eexist? */
	item = bt_lookup(bt, key);
	if (!item) {
		item = create_item(bt, key, val_len);
		set_cursor(curs, bl, item, true);
		ret = 0;
	} else {
		up_write(&bl->rwsem);
		scoutfs_put_block(bl);
		ret = -ENOENT;
	}

	return ret;
}

/*
 * Delete an item from the tree.  -ENOENT is returned if the key isn't
 * found.
 */
int scoutfs_btree_delete(struct super_block *sb, struct scoutfs_key *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	bl = btree_walk(sb, key, 0, WALK_DELETE);
	if (IS_ERR(bl))
		return PTR_ERR(bl);
	bt = bl->data;

	item = bt_lookup(bt, key);
	if (item) {
		delete_item(bt, item);
		ret = 0;

		/* XXX this locking is broken.. hold root rwsem? */

		/* delete the final block in the tree */
		if (bt->nr_items == 0) {
			memset(&sbi->super.btree_root, 0,
			       sizeof(struct scoutfs_btree_root));
			/* XXX free block */
		}
	} else {
		ret = -ENOENT;
	}

	up_write(&bl->rwsem);
	scoutfs_put_block(bl);

	return ret;
}

/*
 * The caller initializes the cursor and first and last keys and then
 * gets the cursor set to each item within those keys.
 *
 * The btree walk takes care of advancing past interior leaves that
 * don't contain items past the key.  Our job is to find the next item
 * after the key.  If that next item's key is past the caller's last key
 * then the iteration is done.
 *
 * returns 0 if no next, > 0 when curs contains next, < 0 on error
 */
int scoutfs_btree_next(struct super_block *sb, struct scoutfs_key *first,
		       struct scoutfs_key *last,
		       struct scoutfs_btree_cursor *curs)
{
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	struct scoutfs_key key = *first;
	int ret;

	trace_printk("first "CKF" last "CKF" %d curs "CKF"\n",
		CKA(first), CKA(last),
		!!curs->bl, CKA(curs->bl ? curs->key : &key));

	/* find the next item after the cursor, releasing if we're done */
	if (curs->bl) {
		key = curs->item->key;
		scoutfs_inc_key(&key);

		curs->item = bt_next(curs->bl->data, curs->item);
		trace_printk("next %p\n", curs->item);
		if (curs->item)
			set_cursor(curs, curs->bl, curs->item, curs->write);
		else
			scoutfs_btree_release(curs);
	}

	/* walk the tree to find the key, can be first or later */
	if (!curs->bl) {
		bl = btree_walk(sb, &key, 0, WALK_NEXT);
		if (IS_ERR(bl))
			return PTR_ERR(bl);
		bt = bl->data;

		curs->item = bt_after(bl->data, &key);
		trace_printk("after %p\n", curs->item);
		if (curs->item) {
			set_cursor(curs, bl, curs->item, false);
		} else {
			up_read(&bl->rwsem);
			scoutfs_put_block(bl);
		}
	}

	/* only return the next item if it's within last */
	if (curs->item && scoutfs_key_cmp(curs->key, last) <= 0) {
		ret = 1;
	} else {
		scoutfs_btree_release(curs);
		ret = 0;
	}

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Ensure that the blocks that lead to the item with the given key are
 * dirty.  caller can hold a transaction to pin the dirty blocks and
 * guarantee that later updates of the item will succeed.
 *
 * <0 is returned on error, including -ENOENT if the key isn't present.
 */
int scoutfs_btree_dirty(struct super_block *sb, struct scoutfs_key *key)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_block *bl;
	int ret;

	bl = btree_walk(sb, key, 0, WALK_DIRTY);
	if (IS_ERR(bl))
		return PTR_ERR(bl);

	item = bt_lookup(bl->data, key);
	if (item) {
		ret = 0;
	} else {
		ret = -ENOENT;
	}

	up_write(&bl->rwsem);
	scoutfs_put_block(bl);

	return ret;
}

/*
 * For this to be safe the caller has to have pinned the dirty blocks
 * for the item in their transaction.
 */
void scoutfs_btree_update(struct super_block *sb, struct scoutfs_key *key,
			  struct scoutfs_btree_cursor *curs)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_block *bl;

	BUG_ON(curs->bl);

	bl = btree_walk(sb, key, 0, WALK_DIRTY);
	BUG_ON(IS_ERR(bl));

	item = bt_lookup(bl->data, key);
	BUG_ON(!item);

	set_cursor(curs, bl, item, true);
}

void scoutfs_btree_release(struct scoutfs_btree_cursor *curs)
{
	if (curs->bl) {
		if (curs->write)
			up_write(&curs->bl->rwsem);
		else
			up_read(&curs->bl->rwsem);
		scoutfs_put_block(curs->bl);
	}
	curs->bl = NULL;
}
