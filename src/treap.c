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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/crc32c.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "bio.h"
#include "treap.h"
#include "scoutfs_trace.h"

/*
 * scoutfs builds a consistent file system out of segments by describing
 * them all with the manifest.  Typically the manifest will fit in
 * memory but in the pathological case it can be much larger.  Our task
 * is to index the manifest such that the pathological case is possible
 * but the typical case isn't unreasonably penalized by the IO cost of
 * maintaining the index.
 *
 * We chose to index the manifest by storing entries in treap nodes in a
 * static ring.  Updates are large contiguous writes to the ring with
 * low amplification.  Incremental updates can similarly read-ahead
 * large chunks of the ring.  Entirely cold reads end up issuing lots of
 * small dependent random IOs.
 *
 * The nodes in the ring are loaded into native copies in memory.
 * Having native allocated nodes lets us do things that would be
 * unreasonable if we only traversed persistent structures in cached
 * blocks: pointers to nodes in memory instead of indirecting through
 * block cache lookups, parent pointers for trivial iteration but which
 * would would rule out cow updates, and per-node lru tracking so that
 * we can reclaim from the leaves of the tree up to the root without
 * false pinning based on which nodes happen to share blocks.
 *
 * As nodes are modified or inserted they're marked dirty.  Eventually
 * all the dirty nodes are written to the tail of the ring.  We ensure
 * that new nodes written at the tail never overwrite old live nodes by
 * using a large ring and constantly also migrating old nodes in the
 * ring to the tail.
 *
 * Nodes don't span 4k blocks so there will always be at least a node
 * struct's worth of blank space in each block, more typically half the
 * average item length, and at worst the max item length.
 *
 * The tree is augmented to enable searches by more than the primary
 * sort keys of the tree.  The treap itself maintains augmentation in
 * memory to track dirty nodes and in the persistent nodes to track old
 * nodes for migration.  Callers get callbacks to maintain their own
 * augmentation in the node payloads.
 *
 * Each dirty node gets a generation number that is incremented for each
 * version of the tree that is written to the tail of the ring.  This
 * lets traverse cached nodes without needing strong cache coherence
 * with other node writers.  With the byte offset and generation of root
 * node we can traverse our cached nodes and retry the walk when our
 * nodes are stale.
 *
 * XXX
 *  - add lru list, nodes to tail during walk, shrink from head
 *  - stale walking needs work: restart walk, get new root sample
 *  - lru would need to reclaim nodes orphaned by new root ref walk
 */

/*
 * We preallocate sufficient pages to write all the treap nodes to write
 * a transactoin.
 *
 * XXX Today we only ever write a l0 segment or update the manifest and
 * allocator for a single compaction.  Those events are *well* less than
 * the number of pages that make up a large segment.  We'll want this to
 * be more careful in the future as we batch up updates from lots of
 * writers.
 */
struct treap_info {
	/* static, derived from the super */
	u64 last_ring_off;

	/* temporarily assigned to each dirty node */
	u64 dirty_off;
	u64 dirty_gen;

	/* used to write nodes to the ring */
	struct page *pages[SCOUTFS_SEGMENT_PAGES];
	u64 pages_off;
	u64 ring_off;
	unsigned int nr_blocks;
	unsigned block_space;
};

#define DECLARE_TREAP_INFO(sb, name) \
	struct treap_info *name = SCOUTFS_SB(sb)->treap_info

struct treap_ref {
	struct treap_node *node;
	u64 off;
	u64 gen;
	u8 aug_bits;
};

struct scoutfs_treap {
	struct super_block *sb;
	struct scoutfs_super_block *super;
	struct scoutfs_treap_ops *ops;
	struct treap_ref root_ref;
	bool dirty;
	u64 dirty_bytes;
};

/*
 * The in-memory node differs in that it uses native endian fields, has
 * a parent pointer, and (will some day have) an lru for reclaiming from
 * the leaves up.
 *
 * The data is long aligned so that callers can use native longs to
 * manipulate bitmaps in the data.
 */
struct treap_node {
	u64 off;
	u64 gen;
	u64 prio;
	u16 bytes;

	struct treap_node *parent;

	struct treap_ref left;
	struct treap_ref right;

	u8 data[0] __aligned(sizeof(long));
};

#if 0
static void print_treap_node(struct treap_ref *ref, u64 loc)
{
	struct treap_node *node = ref->node;

	if (!node)
		return;

	printk("loc %llx node %p: off %llu gen %llu prio %016llx bytes %u\n",
		loc, node, node->off, node->gen, node->prio, node->bytes);
	printk("    left: off %llu gen %llu aug %u node %p\n",
		node->left.off, node->left.gen, node->left.aug_bits,
		node->left.node);
	printk("    right: off %llu gen %llu aug %u node %p\n",
		node->right.off, node->right.gen, node->right.aug_bits,
		node->right.node);

	print_treap_node(&node->left, (loc << 4) | 1);
	print_treap_node(&node->right, (loc << 4) | 2);
}
#endif

static struct treap_ref *parent_ref(struct scoutfs_treap *treap,
				    struct treap_node *node)
{
	if (!node->parent)
		return &treap->root_ref;
	if (node->parent->left.node == node)
		return &node->parent->left;
	return &node->parent->right;
}

static u8 off_aug_bit(struct scoutfs_treap *treap, u64 off)
{
	u64 blocks = le64_to_cpu(treap->super->ring_blocks);
	u64 mid = (blocks << SCOUTFS_BLOCK_SHIFT) / 2;

	return off < mid ? SCOUTFS_TREAP_AUG_LESSER :
			   SCOUTFS_TREAP_AUG_GREATER;
}

static u8 old_aug_bit(struct scoutfs_treap *treap)
{
	DECLARE_TREAP_INFO(treap->sb, tinf);

	return off_aug_bit(treap, tinf->dirty_off) ^ SCOUTFS_TREAP_AUG_HALVES;
}

/*
 * Return the aug bits that'll be used to refer to the given node.
 * We calculate the bits for the node itself and then or those with the
 * bits in its references to its children.
 */
static u8 node_aug_bits(struct scoutfs_treap *treap, struct treap_node *node)
{
	DECLARE_TREAP_INFO(treap->sb, tinf);

	return (node->off == tinf->dirty_off ? SCOUTFS_TREAP_AUG_DIRTY : 0) |
	        off_aug_bit(treap, node->off) |
	        node->left.aug_bits |
		node->right.aug_bits;
}

/*
 * Update the treap augmentation until its back in sync.  We can be
 * called with a null node to repair a non-existing parent and we just
 * have to clear the root aug_bits in that case.
 */
static void update_internal_aug(struct scoutfs_treap *treap,
				struct treap_node *node)
{
	struct treap_ref *ref;
	u8 bits;

	if (!node)
		treap->root_ref.aug_bits = 0;

	while (node) {
		bits = node_aug_bits(treap, node);
		ref = parent_ref(treap, node);
		trace_printk("node %p bits %x parent %p ref bits %x\n",
				node, bits, node->parent, ref->aug_bits);
		if (ref->aug_bits == bits)
			break;
		ref->aug_bits = bits;
		node = node->parent;
	}
}

static bool ops_update_aug(struct scoutfs_treap *treap,
			   struct treap_node *parent, struct treap_node *node)
{
	if (!treap->ops->update_aug)
		return false;

	return treap->ops->update_aug(parent->data, parent->left.node == node,
				     node->data);
}

/*
 * Update the tree's augmentation stored in the data payloads.  The caller
 * sets the left or right aug in the parent to match the node.
 */
static void update_data_aug(struct scoutfs_treap *treap,
			  struct treap_node *node)
{
	struct treap_node *parent;

	while (node && (parent = node->parent)) {
		if (!ops_update_aug(treap, parent, node))
			break;
		node = node->parent;
	}
}

/*
 *   G       G
 *   |       |
 *   P       N
 *  /   ->    \
 * N           P
 *  \         /
 *
 * parent->left = node->right;
 * node->right = parent;
 * grand->(left|right) = node
 *
 * The rotation has the following effect on augmentation:
 *  - parent ref's aug bits have the same population, no change
 *  - node left's unchanged
 *  - parent right's unchanged
 *  - parent's left just set to the node's right
 *  - node right's recalculated based on parent
 */
static void rotate_right(struct scoutfs_treap *treap,
			 struct treap_node *parent, struct treap_node *node)
{
	struct treap_ref *grand_ref;
	struct treap_node *grand;

	/* get grandparent ref before clobbering parent */
	grand = parent->parent;
	if (grand) {
		if (grand->left.node == parent)
			grand_ref = &grand->left;
		else
			grand_ref = &grand->right;
	} else {
		grand_ref = &treap->root_ref;
	}

	/* parent rotates down and points to node's child */
	parent->left = node->right;
	if (parent->left.node)
		parent->left.node->parent = parent;

	/* node rotates up and points to parent */
	node->right.node = parent;
	node->right.off = parent->off;
	node->right.gen = parent->gen;
	node->right.aug_bits = node_aug_bits(treap, parent);
	parent->parent = node;

	/* grand parent points to node */
	grand_ref->node = node;
	grand_ref->off = node->off;
	grand_ref->gen = node->gen;
	grand_ref->aug_bits = node_aug_bits(treap, node);
	node->parent = grand;

	ops_update_aug(treap, node, parent);
}

/* see above: swap left/right */
static void rotate_left(struct scoutfs_treap *treap,
			struct treap_node *parent, struct treap_node *node)
{
	struct treap_ref *grand_ref;
	struct treap_node *grand;

	grand = parent->parent;
	if (grand) {
		if (grand->right.node == parent)
			grand_ref = &grand->right;
		else
			grand_ref = &grand->left;
	} else {
		grand_ref = &treap->root_ref;
	}

	parent->right = node->left;
	if (parent->right.node)
		parent->right.node->parent = parent;

	node->left.node = parent;
	node->left.off = parent->off;
	node->left.gen = parent->gen;
	node->left.aug_bits = node_aug_bits(treap, parent);
	parent->parent = node;

	grand_ref->node = node;
	grand_ref->off = node->off;
	grand_ref->gen = node->gen;
	grand_ref->aug_bits = node_aug_bits(treap, node);
	node->parent = grand;

	ops_update_aug(treap, node, parent);
}

/*
 * Rebalance the tree by rotating the parent and child as long as the
 * child has a higher random priority.
 */
static void rebalance(struct scoutfs_treap *treap, struct treap_node *node)
{
	struct treap_node *parent;

	while (node && (parent = node->parent) && node->prio > parent->prio) {
		if (parent->left.node == node)
			rotate_right(treap, parent, node);
		else
			rotate_left(treap, parent, node);
	}
}


/*
 * The caller has mucked with a node.  We make sure all of our internal
 * augmentation, the op data's augmentation, and the treap prio balance
 * is repaired.
 */
static void repair(struct scoutfs_treap *treap, struct treap_node *node)
{
	update_internal_aug(treap, node);
	update_data_aug(treap, node);
	rebalance(treap, node);

	trace_printk("treap %p root aug %x\n",
		     treap, treap->root_ref.aug_bits);
}

static struct treap_node *alloc_node(u16 bytes)
{
	struct treap_node *node;

	node = kmalloc(offsetof(struct treap_node, data[bytes]), GFP_NOFS);
	if (node)
		memset(node, 0, offsetof(struct treap_node, data));

	return node;
}

/*
 * bytes in the persistent ring taken up by a node with the given number
 * of data bytes.
 */
static unsigned node_ring_bytes(struct treap_node *node)
{
	return offsetof(struct scoutfs_treap_node, data[node->bytes]);
}

static bool dirty_node(struct scoutfs_treap *treap, struct treap_node *node)
{
	DECLARE_TREAP_INFO(treap->sb, tinf);

	return node->off == tinf->dirty_off;
}

/*
 * Ensure that the given node is dirty.  If it isn't we need to mark it
 * dirty and augment the tree.  Transaction limits and preallocation
 * make sure that we always have resources to write nodes that are
 * dirtied.
 *
 * When we dirty old nodes we temporarily set their offset to the
 * current half of the ring so that they won't show up in augmented
 * searches for old nodes.
 */
static bool mark_node_dirty(struct scoutfs_treap *treap, struct treap_ref *ref,
			    struct treap_node *node)
{
	DECLARE_TREAP_INFO(treap->sb, tinf);

	if (dirty_node(treap, node))
		return false;

	trace_printk("node %p off %llu gen %llu now dirty\n",
		     node, node->off, node->gen);

	treap->dirty_bytes += node_ring_bytes(node);
	treap->dirty = true;

	node->off = tinf->dirty_off;
	node->gen = tinf->dirty_gen;
	ref->off = node->off;
	ref->gen = node->gen;
	repair(treap, node);

	return true;
}

static int dirty_old_nodes(struct scoutfs_treap *treap, unsigned old_target,
			   unsigned dirty_limit);

static struct scoutfs_treap_node *read_ring_node(struct scoutfs_treap *treap,
					         u64 off)
{
	struct address_space *mapping = treap->sb->s_bdev->bd_inode->i_mapping;
	struct scoutfs_treap_node *tnode = NULL;
	struct page *page = NULL;
	unsigned pg_off;
	unsigned bytes;
	pgoff_t pg_ind;
	int ret;

	off += le64_to_cpu(treap->super->ring_blkno) << SCOUTFS_BLOCK_SHIFT;
	pg_ind = off >> PAGE_CACHE_SHIFT;
	pg_off = off & ~PAGE_CACHE_MASK;

	if (pg_off + sizeof(struct scoutfs_treap_node) > PAGE_CACHE_SIZE) {
		ret = -EIO;
		goto out;
	}

retry:
	page = find_or_create_page(mapping, pg_ind, GFP_NOFS);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	tnode = page_address(page) + pg_off;

	if (PageUptodate(page)) {
		unlock_page(page);
		ret = 0;
		goto out;
	}

	ClearPageError(page);
	ret = mapping->a_ops->readpage(NULL, page);
	if (ret) {
		if (ret == AOP_TRUNCATED_PAGE) {
			page_cache_release(page);
			goto retry;
		}
		goto out;
	}

	wait_on_page_locked(page);
	if (!PageUptodate(page)) {
		if (page->mapping != mapping) {
			page_cache_release(page);
			goto retry;
		}
		ret = -EIO;
		goto out;
	} else {
		ret = 0;
	}

	bytes = le16_to_cpu(tnode->bytes);

	if (pg_off + offsetof(struct scoutfs_treap_node, data[bytes]) >
	    PAGE_CACHE_SIZE) {
		ret = -EIO;
	}

out:
	if (ret) {
		if (page)
			page_cache_release(page);
		return ERR_PTR(ret);
	}

	return tnode;
}

static void release_ring_node(struct scoutfs_treap_node *tnode)
{
	if (!IS_ERR_OR_NULL(tnode))
		page_cache_release(virt_to_page(tnode));
}

/*
 * We write to ring blocks from preallocated private pages with bios but read
 * through the bdev page cache.  Invalidate the blocks we're about to write
 * so we'll read them later.
 */
static void invalidate_blocks(struct super_block *sb, u64 blkno, u64 nr)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	loff_t lstart = blkno << SCOUTFS_BLOCK_SHIFT;
	loff_t lend = lstart + (nr << SCOUTFS_BLOCK_SHIFT) - 1;

	truncate_inode_pages_range(mapping, lstart, lend);
}

static void invalidate_ring_block(struct scoutfs_treap *treap, u64 off)
{
	invalidate_blocks(treap->sb, le64_to_cpu(treap->super->ring_blkno) +
			  (off >> SCOUTFS_BLOCK_SHIFT), 1);
}

static __le32 tnode_crc(struct scoutfs_treap_node *tnode)
{
	u16 bytes = le16_to_cpu(tnode->bytes);
	unsigned skip = sizeof(tnode->crc);

	return cpu_to_le32(crc32c(~0, (void *)tnode + skip,
			   offsetof(struct scoutfs_treap_node,
				    data[bytes]) - skip));
}

/*
 * Give the caller the node pointed to by their reference.  If the node
 * isn't already in the tree then we link it in and update augmentation.
 *
 * XXX what's the consequence of failing to also dirty old ring nodes?
 * The ring gets out of balance but we do nothing about it.
 */
static struct treap_node *read_node(struct scoutfs_treap *treap,
				    struct treap_node *parent,
				    struct treap_ref *ref, bool dirty)
{
	struct scoutfs_treap_node *tnode = NULL;
	struct treap_node *node = NULL;
	unsigned retries = 3;
	u16 bytes;
	int ret;

	if (ref->node) {
		node = ref->node;
		ret = 0;
		goto out;
	}

retry:
	tnode = read_ring_node(treap, ref->off);
	if (IS_ERR(tnode)) {
		ret = PTR_ERR(tnode);
		goto out;
	}

	if (tnode->crc != tnode_crc(tnode) ||
	    le64_to_cpu(tnode->off) != ref->off ||
	    le64_to_cpu(tnode->gen) != ref->gen) {
		invalidate_ring_block(treap, ref->off);
		if (retries--) {
			/* XXX restart search, not just this read */
			release_ring_node(tnode);
			goto retry;
		} else {
			ret = -EIO;
			goto out;
		}
	}

	bytes = le16_to_cpu(tnode->bytes);

	node = alloc_node(bytes);
	if (!node) {
		ret = -ENOMEM;
		goto out;
	}

	node->off = le64_to_cpu(tnode->off);
	node->gen = le64_to_cpu(tnode->gen);
	node->prio = le64_to_cpu(tnode->prio);
	node->left.off = le64_to_cpu(tnode->left.off);
	node->left.gen = le64_to_cpu(tnode->left.gen);
	node->left.aug_bits = tnode->left.aug_bits;
	node->right.off = le64_to_cpu(tnode->right.off);
	node->right.gen = le64_to_cpu(tnode->right.gen);
	node->right.aug_bits = tnode->right.aug_bits;
	node->bytes = bytes;
	memcpy(node->data, tnode->data, bytes);

	node->parent = parent;
	ref->node = node;
	ret = 0;
out:
	release_ring_node(tnode);
	if (!ret && dirty && mark_node_dirty(treap, ref, node))
		ret = dirty_old_nodes(treap, node_ring_bytes(node), 0);
	if (ret)
		return ERR_PTR(ret);

	return node;
}

/*
 * Find nodes in the older half of the ring and mark them dirty.  Stop
 * when we don't have any more older nodes, after dirtying enough old
 * nodes, or before dirtying too many nodes.
 */
static int dirty_old_nodes(struct scoutfs_treap *treap, unsigned old_target,
			   unsigned dirty_limit)
{
	u8 bit = old_aug_bit(treap);
	struct treap_node *parent;
	struct treap_node *node;
	struct treap_ref *ref;
	unsigned dirty = 0;
	unsigned old = 0;
	unsigned bytes;
	int ret = 0;

restart:
	parent = NULL;
	ref = &treap->root_ref;

	while (ref->aug_bits & bit) {
		node = read_node(treap, parent, ref, false);
		if (IS_ERR(node)) {
			ret = PTR_ERR(node);
			break;
		}

		bytes = node_ring_bytes(node);

		if (!dirty_node(treap, node) && dirty_limit) {
			dirty += bytes;
			if (dirty > dirty_limit)
				break;
		}

		if (old_target && off_aug_bit(treap, node->off) == bit)
			old += bytes;

		/* sets dirty, sets current half aug bit, repairs */
		mark_node_dirty(treap, ref, node);

		if (old_target && old >= old_target)
			break;

		if (node->left.aug_bits & bit)
			ref = &node->left;
		else if (node->right.aug_bits & bit)
			ref = &node->right;
		else
			goto restart;
	}

	return ret;
}

/*
 * Return the dirty node identified by the given key, creating it if it
 * doesn't exist.
 *
 * Returns ERR -EEXIST if a node already exists at the given key.
 */
void *scoutfs_treap_insert(struct scoutfs_treap *treap, void *key, u16 bytes,
			   void *fill_arg)
{
	struct treap_ref *ref = &treap->root_ref;
	struct treap_node *parent = NULL;
	struct treap_node *node = NULL;
	int cmp;

	while (ref->gen) {
		node = read_node(treap, parent, ref, true);
		if (IS_ERR(node))
			goto out;

		cmp = treap->ops->compare(key, node->data);
		if (cmp < 0) {
			ref = &node->left;
		} else if (cmp > 0) {
			ref = &node->right;
		} else {
			node = ERR_PTR(-EEXIST);
			goto out;
		}

		parent = node;
		node = NULL;
	}

	node = alloc_node(bytes);
	if (!node) {
		node = ERR_PTR(-ENOMEM);
		goto out;
	}

	node->parent = parent;
	node->bytes = bytes;
	get_random_bytes_arch(&node->prio, sizeof(node->prio));

	ref->node = node;

	/* filling here instead of in caller for aug update in repair */
	treap->ops->fill(node->data, fill_arg);

	/* sets off and gen and repairs */
	mark_node_dirty(treap, ref, node);
out:
	if (IS_ERR(node))
		return ERR_CAST(node);

	return node->data;
}

/*
 * Delete a node with the given key.
 *
 * It's easy when the node doesn't have two children.  We remove the
 * node and point it's parent ref at either of the child's refs that
 * might have been populated.
 *
 * Deletion's a little tricker when we have both children.  We could
 * find an ancestor and swap but that's fiddly to get right with all our
 * rich node pointers.  Instead we can reuse rotation to rotate the node
 * down until it doesn't have both children.
 */
int scoutfs_treap_delete(struct scoutfs_treap *treap, void *key)
{
	struct treap_ref *ref = &treap->root_ref;
	struct treap_node *parent = NULL;
	struct treap_node *node = NULL;
	struct treap_ref *child_ref;
	struct treap_node *left;
	struct treap_node *right;
	int cmp;
	int ret;

	/* find node to delete */
	while (ref->gen) {
		node = read_node(treap, parent, ref, true);
		if (IS_ERR(node)) {
			ret = PTR_ERR(node);
			goto out;
		}

		cmp = treap->ops->compare(key, node->data);
		if (cmp < 0)
			ref = &node->left;
		else if (cmp > 0)
			ref = &node->right;
		else
			break;

		parent = node;
		node = NULL;
	}

	if (!node) {
		ret = -ENOENT;
		goto out;
	}

	/*
	 * Rotate the node down with its higher priority child until it
	 * doesn't have both children.  Dirtying tries to repair which
	 * can try to repair priority imbalance with rotation so we swap
	 * priorities first.  Unfortunately we need to read both
	 * children to get their priorities but we only try to dirty the
	 * rotation child.  It's messy but dirtying both can double
	 * write amplification.
	 */
	while (node->left.gen && node->right.gen) {
		left = read_node(treap, node, &node->left, false);
		right = read_node(treap, node, &node->right, false);
		if (IS_ERR(left) || IS_ERR(right)) {
			ret = IS_ERR(left) ? PTR_ERR(left) : PTR_ERR(right);
			goto out;
		}

		if (left->prio > right->prio) {
			left = read_node(treap, node, &node->left, true);
			if (IS_ERR(left)) {
				ret = IS_ERR(left);
				goto out;
			}
			swap(node->prio, left->prio);
			rotate_right(treap, node, left);
		} else {
			right = read_node(treap, node, &node->right, true);
			if (IS_ERR(right)) {
				ret = IS_ERR(right);
				goto out;
			}
			swap(node->prio, right->prio);
			rotate_left(treap, node, right);
		}

		parent = node->parent;
		ref = parent_ref(treap, node);
	}

	/* delete the node, might have to point parent at child */
	if (node->left.gen)
		child_ref = &node->left;
	else
		child_ref = &node->right;

	*ref = *child_ref;
	if (ref->node)
		ref->node->parent = parent;

	if (dirty_node(treap, node))
		treap->dirty_bytes -= node_ring_bytes(node);

	kfree(node);

	repair(treap, parent);
	ret = 0;
out:
	return ret;
}

enum {
	LU_DIRTY,
	LU_NEXT,
	LU_PREV,
};

static void *treap_lookup(struct scoutfs_treap *treap, void *key, int flags)
{
	struct treap_ref *ref = &treap->root_ref;
	struct treap_node *parent = NULL;
	struct treap_node *node = NULL;
	struct treap_node *prev = NULL;
	struct treap_node *next = NULL;
	int cmp;

	while (ref->gen) {
		node = read_node(treap, parent, ref, flags & LU_DIRTY);
		if (IS_ERR(node))
			break;

		cmp = treap->ops->compare(key, node->data);
		if (cmp < 0) {
			ref = &node->left;
			next = node;
		} else if (cmp > 0) {
			ref = &node->right;
			prev = node;
		} else {
			break;
		}

		parent = node;
		node = NULL;
	}

	if (!node && (flags & LU_PREV) && prev)
		node = prev;
	else if (!node && (flags & LU_NEXT) && next)
		node = next;

	if (IS_ERR(node))
		return ERR_CAST(node);
	if (node)
		return node->data;
	return NULL;
}

void *scoutfs_treap_lookup(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, 0);
}

void *scoutfs_treap_lookup_dirty(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, LU_DIRTY);
}

void *scoutfs_treap_lookup_next(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, LU_NEXT);
}

void *scoutfs_treap_lookup_next_dirty(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, LU_NEXT | LU_DIRTY);
}

void *scoutfs_treap_lookup_prev(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, LU_PREV);
}

void *scoutfs_treap_lookup_prev_dirty(struct scoutfs_treap *treap, void *key)
{
	return treap_lookup(treap, key, LU_PREV | LU_DIRTY);
}

void *scoutfs_treap_first(struct scoutfs_treap *treap)
{
	struct treap_ref *ref = &treap->root_ref;
	struct treap_node *parent = NULL;
	struct treap_node *node = NULL;

	while (ref->gen) {
		node = read_node(treap, parent, ref, false);
		if (IS_ERR(node))
			break;

		ref = &node->left;
		parent = node;
	}

	if (IS_ERR(node))
		return ERR_CAST(node);
	if (node)
		return node->data;
	return NULL;
}

void *scoutfs_treap_last(struct scoutfs_treap *treap)
{
	struct treap_ref *ref = &treap->root_ref;
	struct treap_node *parent = NULL;
	struct treap_node *node = NULL;

	while (ref->gen) {
		node = read_node(treap, parent, ref, false);
		if (IS_ERR(node))
			break;

		ref = &node->right;
		parent = node;
	}

	if (IS_ERR(node))
		return ERR_CAST(node);
	if (node)
		return node->data;
	return NULL;
}

void *scoutfs_treap_next(struct scoutfs_treap *treap, void *data)
{
	struct treap_node *node = container_of(data, struct treap_node, data);
	struct treap_node *parent;

	if (node->right.gen) {
		node = read_node(treap, node, &node->right, false);
		if (IS_ERR(node))
			goto out;

		while (node->left.gen) {
			node = read_node(treap, node, &node->left, false);
			if (IS_ERR(node))
				goto out;
		}

		goto out;
	}

	while (((parent = node->parent)) && node == parent->right.node)
		node = parent;
	node = parent;

out:
	if (IS_ERR(node))
		return ERR_CAST(node);
	if (node)
		return node->data;
	return NULL;
}

void *scoutfs_treap_prev(struct scoutfs_treap *treap, void *data)
{
	struct treap_node *node = container_of(data, struct treap_node, data);
	struct treap_node *parent;

	if (node->left.gen) {
		node = read_node(treap, node, &node->left, false);
		if (IS_ERR(node))
			goto out;

		while (node->right.gen) {
			node = read_node(treap, node, &node->right, false);
			if (IS_ERR(node))
				goto out;
		}

		goto out;
	}

	while (((parent = node->parent)) && node == parent->left.node)
		node = parent;
	node = parent;

out:
	if (IS_ERR(node))
		return ERR_CAST(node);
	if (node)
		return node->data;
	return NULL;
}

int scoutfs_treap_has_dirty(struct scoutfs_treap *treap)
{
	return treap->dirty;
}

static void *pages_off_ptr(struct treap_info *tinf)
{
	return page_address(tinf->pages[tinf->pages_off >> PAGE_SHIFT]) +
	       (tinf->pages_off % ~PAGE_MASK);
}

/*
 * The dirty offset is carefully chosen so that it will consider dirty
 * nodes part of the current half of the ring but is an offset that will
 * never be actually written.  That way it is overwritten as dirty nodes
 * are copied to the ring and get their final offset and aren't considered
 * dirty.  Nodes never span blocks so we set the dirty offset to the final
 * byte of the next block in the ring.
 */
static void init_writer(struct treap_info *tinf,
			struct scoutfs_super_block *super)
{
	tinf->ring_off = le64_to_cpu(super->ring_tail_block) <<
			 SCOUTFS_BLOCK_SHIFT;
	tinf->pages_off = 0;
	tinf->block_space = 0;
	tinf->nr_blocks = 0;

	tinf->dirty_gen = le64_to_cpu(super->ring_gen) + 1;
	tinf->dirty_off = tinf->ring_off + SCOUTFS_BLOCK_MASK;
}

static void try_zero_block_tail(struct treap_info *tinf)
{
	if (tinf->block_space != SCOUTFS_BLOCK_SIZE)
		memset(pages_off_ptr(tinf), 0, tinf->block_space);
}

/*
 * Copy the node to the page at the next free tail offset.  The
 * in-memory node's offset is set to its final ring offset and its
 * parent ref is updated.  Thus it will no longer have the magic dirty
 * offset and won't be considered dirty by the tree augmentation.
 */
static void copy_node_to_ring(struct scoutfs_treap *treap,
			      struct treap_node *node)
{
	DECLARE_TREAP_INFO(treap->sb, tinf);
	struct scoutfs_treap_node *tnode;
	u32 bytes = node_ring_bytes(node);
	u32 skip;

	if (tinf->block_space < bytes) {
		try_zero_block_tail(tinf);

		skip = ALIGN(tinf->ring_off, SCOUTFS_BLOCK_SIZE) -
		       tinf->ring_off;
		tinf->ring_off += skip;
		tinf->pages_off += skip;

		tinf->block_space = SCOUTFS_BLOCK_SIZE;
		tinf->nr_blocks++;

		/* see if we're wrapping */
		if (tinf->ring_off == tinf->last_ring_off)
			tinf->ring_off = 0;
	}

	node->off = tinf->ring_off;
	parent_ref(treap, node)->off = node->off;

	tnode = pages_off_ptr(tinf);
	tinf->ring_off += bytes;
	tinf->pages_off += bytes;
	tinf->block_space -= bytes;

	tnode->off = cpu_to_le64(node->off);
	tnode->gen = cpu_to_le64(node->gen);
	tnode->prio = cpu_to_le64(node->prio);
	tnode->left.off = cpu_to_le64(node->left.off);
	tnode->left.gen = cpu_to_le64(node->left.gen);
	tnode->left.aug_bits = node->left.aug_bits;
	tnode->right.off = cpu_to_le64(node->right.off);
	tnode->right.gen = cpu_to_le64(node->right.gen);
	tnode->right.aug_bits = node->right.aug_bits;
	tnode->bytes = cpu_to_le16(node->bytes);
	memcpy(tnode->data, node->data, node->bytes);

	tnode->crc = tnode_crc(tnode);
}

/*
 * Copy the currently dirty nodes into preallocated pages for writing.
 *
 * We can consider the nodes clean as we copy them to the pages.  The
 * caller is responsible for ensuring forward progress or aborting.
 *
 * As nodes are copied to the pages they are assigned their final offset
 * in the ring.  We have to update their parent refs with the new
 * offset.  (We also could have them cross a half ring, getting new off
 * aug bits that bubble up).
 *
 * All that means that we copy from the leaves up to the root so that we
 * capture the modifications to parents as we copy children.
 *
 * This is called for multiple treaps before the ring is written.
 */
int scoutfs_treap_dirty_ring(struct scoutfs_treap *treap,
			     struct scoutfs_treap_root *root)
{
	struct treap_node *node;
	unsigned bytes;
	int ret;

	/* first fill final partial block with old nodes */
	bytes = SCOUTFS_BLOCK_SIZE - (treap->dirty_bytes & SCOUTFS_BLOCK_MASK);
	if (bytes != SCOUTFS_BLOCK_SIZE) {
		ret = dirty_old_nodes(treap, 0, bytes);
		if (ret)
			goto out;
	}

	node = treap->root_ref.node;
	while (node) {
		/* follow dirty links first */
		if (node->left.aug_bits & SCOUTFS_TREAP_AUG_DIRTY) {
			node = node->left.node;
		} else if (node->right.aug_bits & SCOUTFS_TREAP_AUG_DIRTY) {
			node = node->right.node;
		} else {
			/* node doesn't have dirty children, append if dirty */
			if (dirty_node(treap, node)) {
				copy_node_to_ring(treap, node);
				repair(treap, node);
			}

			/* ascend back up through parents */
			node = node->parent;
		}
	}

	/* point the persistent super root at the treap we wrote to the ring */
	root->ref.off = cpu_to_le64(treap->root_ref.off);
	root->ref.gen = cpu_to_le64(treap->root_ref.gen);
	root->ref.aug_bits = treap->root_ref.aug_bits;

	treap->dirty_bytes = 0;
	treap->dirty = false;
	ret = 0;
out:
	return ret;
}

/*
 * Submit writes for all the dirty nodes that have been copied into the
 * preallocated pages.
 * entries were appended.  The dirty ring blocks are contiguous in the
 * page array but can wrap in the block ring on disk.
 *
 * If it wraps then we submit the earlier fragment at the head of the
 * ring first.
 *
 * The wrapped fragment starts at some block offset in the page array.
 * The hacky page array math only works when our fixed 4k block size ==
 * page_size.  To fix it we'd add a offset block to the bio submit loop
 * which could add an initial partial page vec to the bios.
 *
 * XXX figure out where to write.  I guess we have a write ring block
 * in the super?
 */
int scoutfs_treap_submit_write(struct super_block *sb,
			       struct scoutfs_bio_completion *comp)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_TREAP_INFO(sb, tinf);
	u64 head_blocks;
	u64 tail_blocks;
	u64 blkno;
	u64 tail;

	if (!tinf->nr_blocks)
		return 0;

	try_zero_block_tail(tinf);

	tail = le64_to_cpu(super->ring_tail_block);
	tail_blocks = min_t(u64, tinf->nr_blocks,
			    le64_to_cpu(super->ring_blocks) - tail);

	head_blocks = tinf->nr_blocks - tail_blocks;

	if (head_blocks) {
		BUILD_BUG_ON(SCOUTFS_BLOCK_SIZE != PAGE_SIZE);
		invalidate_blocks(sb, le64_to_cpu(super->ring_blkno),
				  head_blocks);
		scoutfs_bio_submit_comp(sb, WRITE, tinf->pages + tail_blocks,
					le64_to_cpu(super->ring_blkno),
					head_blocks, comp);
	}

	blkno = le64_to_cpu(super->ring_blkno) + tail;
	invalidate_blocks(sb, blkno, tail_blocks);
	scoutfs_bio_submit_comp(sb, WRITE, tinf->pages, blkno, tail_blocks,
				comp);

	/* record new tail index in super and reset for next trans */
	super->ring_tail_block = cpu_to_le64(tail + tail_blocks);
	if (super->ring_tail_block == super->ring_blocks)
		super->ring_tail_block = cpu_to_le64(head_blocks);

	super->ring_gen = cpu_to_le64(tinf->dirty_gen);

	init_writer(tinf, super);

	return 0;
}

struct scoutfs_treap *scoutfs_treap_alloc(struct super_block *sb,
					  struct scoutfs_treap_ops *ops,
					  struct scoutfs_treap_root *root)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_treap *treap;

	treap = kzalloc(sizeof(struct scoutfs_treap), GFP_NOFS);
	if (treap) {
		treap->sb = sb;
		treap->super = &sbi->super;
		treap->ops = ops;
		treap->root_ref.off = le64_to_cpu(root->ref.off);
		treap->root_ref.gen = le64_to_cpu(root->ref.gen);
		treap->root_ref.aug_bits = root->ref.aug_bits;
	}

	return treap;
}

/*
 * Free all the allocated nodes in the treap and clear the root.
 */
void scoutfs_treap_free(struct scoutfs_treap *treap)
{
	struct treap_node *node = treap->root_ref.node;
	struct treap_node *fre;

	while (node) {
		if (node->left.node) {
			node = node->left.node;
			node->parent->left.node = NULL;
		} if (node->right.node) {
			node = node->right.node;
			node->parent->right.node = NULL;
		} else {
			fre = node;
			node = node->parent;
			kfree(fre);
		}
	}

	kfree(treap);
}

int scoutfs_treap_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct treap_info *tinf;
	struct page *page;
	int i;

	BUILD_BUG_ON(offsetof(struct treap_node, data) & (sizeof(long) - 1));

	tinf = kzalloc(sizeof(struct treap_info), GFP_KERNEL);
	if (!tinf)
		return -ENOMEM;

	tinf->last_ring_off = le64_to_cpu(super->ring_blocks) <<
			      SCOUTFS_BLOCK_SHIFT;
	init_writer(tinf, super);

	for (i = 0; i < ARRAY_SIZE(tinf->pages); i++) {
		page = alloc_page(GFP_KERNEL);
		if (!page) {
			while (--i >= 0)
				__free_page(tinf->pages[i]);
			kfree(tinf);
			return -ENOMEM;
		}

		tinf->pages[i] = page;
	}

	sbi->treap_info = tinf;

	return 0;
}

void scoutfs_treap_destroy(struct super_block *sb)
{
	DECLARE_TREAP_INFO(sb, tinf);
	int i;

	if (tinf) {
		for (i = 0; i < ARRAY_SIZE(tinf->pages); i++)
			__free_page(tinf->pages[i]);

		kfree(tinf);
	}
}
