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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "counters.h"
#include "block.h"
#include "radix.h"
#include "scoutfs_trace.h"

/*
 * scoutfs uses bitmap blocks in cow radix trees to allocate free
 * blocks.  We like the radix trees because their stable structure lets
 * us easily build up the resources to make atomic changes, splice trees
 * around, and they have a respectable storage overhead when they're
 * highly fragmented.
 *
 * An allocator itself contains two trees: one for bits that were stable
 * at the start of a transaction and are available to satisfy
 * allocation, and one for bits that were freed during this transaction
 * which describe stable referenced blocks and can't be re-used to
 * satisfy allocations until the transaction is committed.
 *
 * Each allocator contains a mutex that protects its two trees.  It's
 * typical for callers to allocate by calling radix ops on one of the
 * alloc trees while providing the allocator to manage allocation of the
 * radix blocks themselves.  This is safe.  If the caller is operating
 * on other radix trees outside of the allocator struct (data
 * allocations, server manipulating client trees) it is responsible for
 * locking these external trees.
 *
 * The trees are updated by making cow copies of modified blocks and
 * writing them into free space.  The system does have a use for walking
 * the old stable version of a tree -- the server needs to merge stable
 * freed space back into its dirty available allocator tree while
 * avoiding new frees that are arriving as it cows blocks during the
 * merge process.
 *
 * Allocations search for the next free bit from a cursor that's stored
 * in the root of each tree.  We track the first set parent ref or leaf
 * bit in references to blocks to avoid searching entire blocks every
 * time.
 *
 * The radix isn't always fully populated.  References can contain
 * blknos with 0 or ~0 to indicate that its referenced subtree is either
 * entirely empty or full.  The counters that describe these stubbed out
 * subtrees will be correct as though all the blocks were populated.
 * Traversal instantiates initialized empty or full blocks as it
 * descends.  This lets mkfs initialize a tree with a large contigious
 * set region without having to populate all its blocks.
 *
 * The radix is used to allocate and free blocks when performing cow
 * updates of the blocks that make up radix itself.  Recursion is
 * carefully avoided by building up references to all the blocks needed
 * for the operation and then dirtying and modifying them all at once.
 *
 * Radix block references contain totals of bits set in its referenced
 * subtree.  This helps us balance the number of free bits stored across
 * multiple trees.
 *
 * The radix tracks large aligned regions of set bits that are used to
 * satisfy larger data extent allocations.  These large regions are also
 * tracked in the metadata allocator trees but aren't used.
 */

/*
 * We create temporary synthetic blocks past possible blocks to populate
 * stubbed out refs that reference entirely empty or full subtrees.
 * They're moved to properly allocated blknos.
 */
#define RADIX_SYNTH_BLKNO (SCOUTFS_BLOCK_LG_MAX + 1)

struct radix_path {
	struct rb_node node;
	struct list_head head;
	struct list_head alloc_head;
	u8 height;
	struct scoutfs_radix_root *root;
	u64 leaf_bit;
	/* path and index arrays indexed by level, [0] is leaf */
	struct scoutfs_block **bls;
	unsigned int *inds;
};

struct radix_change {
	struct list_head paths;
	struct list_head new_paths;
	struct list_head alloc_paths;
	struct rb_root rbroot;
	u64 block_allocs;
	u64 caller_allocs;
	u64 alloc_bits;
	u64 next_synth;
};

static struct radix_path *alloc_path(struct scoutfs_radix_root *root)
{
	struct radix_path *path;
	u8 height = root->height;

	path = kzalloc(sizeof(struct radix_path) +
		       (member_sizeof(struct radix_path, inds[0]) * height) +
		       (member_sizeof(struct radix_path, bls[0]) * height),
		       GFP_NOFS);
	if (path) {
		RB_CLEAR_NODE(&path->node);
		INIT_LIST_HEAD(&path->head);
		INIT_LIST_HEAD(&path->alloc_head);
		path->height = root->height;
		path->root = root;
		path->bls = (void *)(path + 1);
		path->inds = (void *)(&path->bls[height]);
	}
	return path;
}

/* Return a pointer to a reference in the path to a block at the given level. */
static struct scoutfs_radix_ref *path_ref(struct radix_path *path, int level)
{
	struct scoutfs_radix_block *rdx;

	BUG_ON(level < 0 || level >= path->height);

	if (level == path->height - 1) {
		return &path->root->ref;
	} else {
		rdx = path->bls[level + 1]->data;
		return &rdx->refs[path->inds[level + 1]];
	}
}

static bool paths_share_blocks(struct radix_path *a, struct radix_path *b)
{
	int i;

	for (i = 0; i < min(a->height, b->height); i++) {
		if (a->bls[i] == b->bls[i])
			return true;
	}

	return false;
}

/*
 * Drop a path's reference to blocks and free its memory.  If we still
 * have synthetic blocks then we reset their references to the original
 * empty or full blknos.  Ref sequence numbers aren't updated when we
 * initially reference synthetic blocks.
 */
static void free_path(struct super_block *sb, struct radix_path *path)
{
	struct scoutfs_radix_ref *ref;
	struct scoutfs_block *bl;
	__le64 orig;
	int i;

	if (!IS_ERR_OR_NULL(path)) {
		for (i = 0; i < path->height; i++) {
			bl = path->bls[i];
			if (bl == NULL)
				continue;

			if (bl->blkno >= RADIX_SYNTH_BLKNO) {
				ref = path_ref(path, i);
				if (bl->blkno & 1)
					orig = cpu_to_le64(U64_MAX);
				else
					orig = 0;

				if (ref->blkno != orig)
					ref->blkno = orig;
			}
			scoutfs_block_put(sb, bl);
		}
		kfree(path);
	}
}

static struct radix_change *alloc_change(void)
{
	struct radix_change *chg;

	chg = kzalloc(sizeof(struct radix_change), GFP_NOFS);
	if (chg) {
		INIT_LIST_HEAD(&chg->paths);
		INIT_LIST_HEAD(&chg->new_paths);
		INIT_LIST_HEAD(&chg->alloc_paths);
		chg->rbroot = RB_ROOT;
		chg->next_synth = RADIX_SYNTH_BLKNO;
	}
	return chg;
}

static void free_change(struct super_block *sb, struct radix_change *chg)
{
	struct radix_path *path;
	struct radix_path *tmp;

	if (!IS_ERR_OR_NULL(chg)) {
		list_splice_init(&chg->new_paths, &chg->paths);
		list_for_each_entry_safe(path, tmp, &chg->paths, head) {
			list_del_init(&path->head);
			free_path(sb, path);
		}
		kfree(chg);
	}
}

/*
 * We can use native longs to set full aligned regions, but we have to
 * use individual _le bit calls on leading and trailing partial regions.
 *
 * XXX these would be more efficient if we calculated masks for the
 * initial and final partial regions.
 */
static void bitmap_set_le(__le64 *map, int ind, int nbits)
{
	unsigned int full;

	while (ind & (BITS_PER_LONG - 1) && nbits-- > 0)
		set_bit_le(ind++, map);

	if (nbits >= BITS_PER_LONG) {
		full = round_down(nbits, BITS_PER_LONG);
		bitmap_set((long *)map, ind, full);
		ind += full;
		nbits -= full;
	}

	while (nbits-- > 0)
		set_bit_le(ind++, map);
}

/*
 * xor the destination bitmap with the source.  bitmap_xor() requires 2
 * const inputs so I'm not comfortable giving it the changing
 * destination pointer as one of the const input pointers.
 */
static void bitmap_xor_bitmap_le(__le64 *dst, __le64 *src, int nbits)
{
	int i;

	BUG_ON((unsigned long)src & 7);
	BUG_ON((unsigned long)dst & 7);
	BUG_ON(nbits & 63);

	for (i = 0; i < nbits; i += 64)
		*(dst++) ^= *(src++);
}

static void bitmap_clear_le(__le64 *map, int ind, int nbits)
{
	unsigned int full;

	while (ind & (BITS_PER_LONG - 1) && nbits-- > 0)
		clear_bit_le(ind++, map);

	if (nbits >= BITS_PER_LONG) {
		full = round_down(nbits, BITS_PER_LONG);
		bitmap_clear((long *)map, ind, full);
		ind += full;
		nbits -= full;
	}

	while (nbits-- > 0)
		clear_bit_le(ind++, map);
}

/* Returns true if the given region is all 0. */
static bool bitmap_empty_region_le(__le64 *map, int ind, int nbits)
{
	unsigned long size = ind + nbits;

	return find_next_bit_le(map, size, ind) >= size;
}

/* Returns true if the given region is all set. */
static bool bitmap_full_region_le(__le64 *map, int ind, int nbits)
{
	unsigned long size = ind + nbits;

	return find_next_zero_bit_le(map, size, ind) >= size;
}

/*
 * Return true if the large region containing the full precision small bit
 * index is full.
 */
static bool lg_is_full(__le64 *map, int ind)
{
	return bitmap_full_region_le(map, ind & ~SCOUTFS_RADIX_LG_MASK,
				     SCOUTFS_RADIX_LG_BITS);
}

/*
 * Count the number of bits set in the large regions that contain the input
 * bits.
 */
static u64 count_lg_bits(void *bits, int ind, int nbits)
{
	u64 count = 0;
	int end;
	int i;

	i = round_down(ind, SCOUTFS_RADIX_LG_BITS);
	end = round_up(ind + nbits, SCOUTFS_RADIX_LG_BITS);

	while (i < end) {
		if (lg_is_full(bits, i))
			count += SCOUTFS_RADIX_LG_BITS;
		i += SCOUTFS_RADIX_LG_BITS;
	}

	return count;
}

/*
 * For each of the large bit regions with bits set in the input bitmap,
 * count the number of bits in corresponding large regions that are
 * fully set in the result bitmap.
 */
static u64 count_lg_bitmap(void *result, void *input)
{
	u64 count = 0;
	int ind = 0;

	while ((ind = find_next_bit_le(input, SCOUTFS_RADIX_BITS, ind))
			< SCOUTFS_RADIX_BITS) {
		if (lg_is_full(result, ind))
			count += SCOUTFS_RADIX_LG_BITS;
		ind = round_up(ind + 1, SCOUTFS_RADIX_LG_BITS);
	}

	return count;
}


/* ind is a small full precision bit index, not in units of large regions */
static int find_next_lg(__le64 *map, int ind)
{
	for (ind = round_up(ind, SCOUTFS_RADIX_LG_BITS);
	     ind <= (SCOUTFS_RADIX_BITS - SCOUTFS_RADIX_LG_BITS);
	     ind += SCOUTFS_RADIX_LG_BITS) {
		if (test_bit_le(ind, map) && lg_is_full(map, ind))
			return ind;
	}

	return SCOUTFS_RADIX_BITS;
}

static u64 bit_from_inds(struct radix_path *path)
{
	u64 bit = path->inds[0];
	u64 mult = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i < path->height; i++) {
		bit += (u64)path->inds[i] * mult;
		mult *= SCOUTFS_RADIX_REFS;
	}

	return bit;
}

static u64 last_from_super(struct super_block *sb, bool meta)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	if (meta)
		return le64_to_cpu(super->last_meta_blkno);
	else
		return le64_to_cpu(super->last_data_blkno);
}

static u8 height_from_last(u64 last)
{
	u64 bit = SCOUTFS_RADIX_BITS - 1;
	u64 mult = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i <= U8_MAX; i++) {
		if (bit >= last)
			return i;

		bit += (u64)(SCOUTFS_RADIX_REFS - 1) * mult;
		mult *= SCOUTFS_RADIX_REFS;
	}

	return U8_MAX;
}

/* total number of bits set in a full subtree with first block at level */
static u64 full_subtree_total(int level)
{
	u64 total = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i <= level; i++)
		total *= SCOUTFS_RADIX_REFS;

	return total;
}

static void calc_level_inds(struct radix_path *path, u64 bit)
{
	u32 ind;
	int i;

	bit = div_u64_rem(bit, SCOUTFS_RADIX_BITS, &ind);
	path->inds[0] = ind;

	for (i = 1; i < path->height; i++) {
		bit = div_u64_rem(bit, SCOUTFS_RADIX_REFS, &ind);
		path->inds[i] = ind;
	}
}

static u64 calc_leaf_bit(u64 bit)
{
	u32 ind;
	div_u64_rem(bit, SCOUTFS_RADIX_BITS, &ind);

	return bit - ind;
}

static int compare_path(struct scoutfs_radix_root *root, u64 leaf_bit,
		        struct radix_path *path)
{
	return scoutfs_cmp((unsigned long)root, (unsigned long)path->root) ?:
	       scoutfs_cmp(leaf_bit, path->leaf_bit);
}

static struct radix_path *walk_paths(struct rb_root *rbroot,
				     struct scoutfs_radix_root *root,
				     u64 leaf_bit, struct radix_path *ins)
{
	struct rb_node **node = &rbroot->rb_node;
	struct rb_node *parent = NULL;
	struct radix_path *path;
	int cmp;

	while (*node) {
		parent = *node;
		path = container_of(*node, struct radix_path, node);

		cmp = compare_path(root, leaf_bit, path);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else if (cmp > 0)
			node = &(*node)->rb_right;
		else
			return path;
	}

	if (ins) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, rbroot);
		return ins;
	}

	return NULL;
}

/*
 * Make sure radix metadata is consistent.
 */
static void check_first_total(struct radix_path *path)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	int level;
	u64 st;
	u64 lt;
	u32 sf;
	u32 lf;
	int i;

	for (level = 0; level < path->height; level++) {
		rdx = path->bls[level]->data;
		ref = path_ref(path, level);

		if (level == 0) {
			st = bitmap_weight((long *)rdx->bits,
					   SCOUTFS_RADIX_BITS);
			lt = count_lg_bits(rdx->bits, 0, SCOUTFS_RADIX_BITS);

			sf = find_next_bit_le(rdx->bits, SCOUTFS_RADIX_BITS, 0);
			lf = find_next_lg(rdx->bits, 0);
		} else {
			st = 0;
			lt = 0;
			sf = SCOUTFS_RADIX_REFS;
			lf = SCOUTFS_RADIX_REFS;
			for (i = 0; i < SCOUTFS_RADIX_REFS; i++) {
				st += le64_to_cpu(rdx->refs[i].sm_total);
				lt += le64_to_cpu(rdx->refs[i].lg_total);
				if (rdx->refs[i].sm_total != 0 && i < sf)
					sf = i;
				if (rdx->refs[i].lg_total != 0 && i < lf)
					lf = i;
			}
		}

		if (le64_to_cpu(ref->sm_total) != st ||
		    le64_to_cpu(ref->lg_total) != lt ||
		    le32_to_cpu(rdx->sm_first) > sf ||
		    le32_to_cpu(rdx->lg_first) > lf) {
			printk("radix inconsistency: level %u calced sf %u st %llu lf %u lt %llu, stored sf %u st %llu lf %u lt %llu\n",
				level, sf, st, lf, lt,
				le32_to_cpu(rdx->sm_first), 
				le64_to_cpu(ref->sm_total), 
				le32_to_cpu(rdx->lg_first), 
				le64_to_cpu(ref->lg_total));
			BUG();
		}
	}
}

#define set_first_nonzero_ref(rdx, ind, first, total)			\
do {									\
	int _ind = min_t(u32, le32_to_cpu(rdx->first), (ind));		\
									\
	while (_ind < SCOUTFS_RADIX_REFS && rdx->refs[_ind].total == 0)	\
		_ind++;							\
									\
	rdx->first = cpu_to_le32(_ind);					\
} while (0)

/*
 * The caller has changed bits in a leaf block and updated the block's
 * first tracking.  We update the first tracking and totals in parent
 * blocks and refs up to the root ref.  We do this after modifying
 * leaves, instead of during descent, because we descend through clean
 * blocks and then dirty all he blocks in all the paths before modifying
 * leaves.
 */
static void fixup_parent_refs(struct radix_path *path,
			      s64 sm_delta, s64 lg_delta)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	int level;
	int ind;

	for (level = 0; level < path->height; level++) {
		rdx = path->bls[level]->data;
		ref = path_ref(path, level);

		le64_add_cpu(&ref->sm_total, sm_delta);
		le64_add_cpu(&ref->lg_total, lg_delta);
		if (level > 0) {
			ind = path->inds[level];
			set_first_nonzero_ref(rdx, ind, sm_first, sm_total);
			set_first_nonzero_ref(rdx, ind, lg_first, lg_total);
		}
	}

	if (0) /* expensive, would be nice to make conditional */
		check_first_total(path);
}

static void store_next_find_bit(struct super_block *sb, bool meta,
				struct scoutfs_radix_root *root, u64 bit)
{
	if (bit > last_from_super(sb, meta))
		bit = 0;
	root->next_find_bit = cpu_to_le64(bit);
}

/*
 * Allocate (clear and return) a region of bits from the leaf block of a
 * path.  The leaf walk has ensured that we have at least one block free.
 *
 * We always try to allocate smaller multi-block allocations from the
 * start of the small region.  This at least gets a single task extending
 * a file one large extent.  Multiple tasks extending writes will interleave.
 * It'll do for now.
 *
 * We always search for free bits from the start of the leaf.
 * This means that we can return recently freed blocks just behind the
 * next free cursor.  I'm not sure if that's much of a problem.
 */
static void alloc_leaf_bits(struct super_block *sb, bool meta,
			    struct radix_path *path,
			    int nbits, u64 *bit_ret, int *nbits_ret)
{
	struct scoutfs_radix_block *rdx = path->bls[0]->data;
	struct scoutfs_radix_ref *ref = path_ref(path, 0);
	u32 sm_first;
	u32 lg_first;
	int lg_nbits;
	int ind;
	int end;

	if (nbits >= SCOUTFS_RADIX_LG_BITS && ref->lg_total != 0) {
		/* always allocate large allocs from full large regions */
		ind = le32_to_cpu(rdx->lg_first);
		ind = find_next_lg(rdx->bits, ind);
		sm_first = le32_to_cpu(rdx->sm_first);
		lg_first = round_up(ind + nbits, SCOUTFS_RADIX_LG_BITS);

	} else {
		/* otherwise alloc as much as we can from the next small */
		ind = le32_to_cpu(rdx->sm_first);
		ind = find_next_bit_le(rdx->bits, SCOUTFS_RADIX_BITS, ind);

		if (nbits > 1) {
			end = find_next_zero_bit_le(rdx->bits, SCOUTFS_RADIX_BITS, ind);
			nbits = min(nbits, end - ind);
		}

		sm_first = ind + nbits;
		lg_first = le32_to_cpu(rdx->lg_first);
	}

	/* callers and structures should have ensured success */
	BUG_ON(ind >= SCOUTFS_RADIX_BITS);

	lg_nbits = count_lg_bits(rdx->bits, ind, nbits);
	bitmap_clear_le(rdx->bits, ind, nbits);

	/* always update the first we searched through */
	rdx->sm_first = cpu_to_le32(sm_first);
	rdx->lg_first = cpu_to_le32(lg_first);
	fixup_parent_refs(path, -nbits, -lg_nbits);

	*bit_ret = path->leaf_bit + ind;
	*nbits_ret = nbits;

	store_next_find_bit(sb, meta, path->root, path->leaf_bit + ind + nbits);
}

/*
 * Allocate a metadata blkno for the caller from the leaves of paths
 * which were stored in the change for metadata allocation.
 */
static u64 change_alloc_meta(struct super_block *sb, struct radix_change *chg)
{
	struct scoutfs_radix_ref *ref;
	struct radix_path *path;
	int nbits_ret;
	u64 bit;

	path = list_first_entry_or_null(&chg->alloc_paths, struct radix_path,
					alloc_head);
	BUG_ON(!path); /* shouldn't be possible */

	alloc_leaf_bits(sb, true, path, 1, &bit, &nbits_ret);

	/* remove the path from the alloc list once its empty */
	ref = path_ref(path, 0);
	if (ref->sm_total == 0)
		list_del_init(&path->alloc_head);

	return bit;
}

static void set_path_leaf_bits(struct super_block *sb, struct radix_path *path,
			       u64 bit, int nbits)
{
	struct scoutfs_radix_block *rdx;
	int lg_ind;
	int ind;

	BUG_ON(nbits <= 0);
	BUG_ON(calc_leaf_bit(bit) != calc_leaf_bit(bit + nbits - 1));
	BUG_ON(calc_leaf_bit(bit) != path->leaf_bit);

	rdx = path->bls[0]->data;
	ind = bit - path->leaf_bit;
	lg_ind = round_down(ind, SCOUTFS_RADIX_LG_BITS);

	/* should have returned an error if it was set while we got paths */
	BUG_ON(!bitmap_empty_region_le(rdx->bits, ind, nbits));
	bitmap_set_le(rdx->bits, ind, nbits);

	if (ind < le32_to_cpu(rdx->sm_first))
		rdx->sm_first = cpu_to_le32(ind);
	if (lg_ind < le32_to_cpu(rdx->lg_first) &&
	    lg_is_full(rdx->bits, lg_ind))
		rdx->lg_first = cpu_to_le32(lg_ind);
	fixup_parent_refs(path, nbits, count_lg_bits(rdx->bits, ind, nbits));

	trace_scoutfs_radix_set(sb, path->root, path->bls[0]->blkno,
				bit, ind, nbits);
}

/* Find the path for the root and bit in the change and set the region */
static void set_change_leaf_bits(struct super_block *sb,
				 struct radix_change *chg,
				 struct scoutfs_radix_root *root,
				 u64 bit, int nbits)
{
	struct radix_path *path;

	path = walk_paths(&chg->rbroot, root, calc_leaf_bit(bit), NULL);
	BUG_ON(!path); /* should have gotten paths for all leaves to set */
	set_path_leaf_bits(sb, path, bit, nbits);
}

/*
 * Initialize a reference to a block at the given level.
 */
static void init_ref(struct scoutfs_radix_ref *ref, int level, bool full)
{
	u64 tot;

	if (full) {
		tot = full_subtree_total(level);

		ref->blkno = cpu_to_le64(U64_MAX);
		ref->seq = cpu_to_le64(0);
		ref->sm_total = cpu_to_le64(tot);
		ref->lg_total = cpu_to_le64(tot);
	} else {

		ref->blkno = cpu_to_le64(0);
		ref->seq = cpu_to_le64(0);
		ref->sm_total = cpu_to_le64(0);
		ref->lg_total = cpu_to_le64(0);
	}
}

/* Initialize a new empty or full block at a given level. */
static void init_block(struct super_block *sb, struct scoutfs_radix_block *rdx,
		       u64 blkno, __le64 seq, int level, bool full)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_radix_ref ref;
	u32 first = full ? 0 : level ? SCOUTFS_RADIX_REFS : SCOUTFS_RADIX_BITS;
	int tail;
	int i;

	/* we use native long bitmap functions on the block bitmaps */
	BUILD_BUG_ON(offsetof(struct scoutfs_radix_block, bits) &
		     (sizeof(long) - 1));

	rdx->hdr.fsid = super->hdr.fsid;
	rdx->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_RADIX);
	rdx->hdr.blkno = cpu_to_le64(blkno);
	rdx->hdr.seq = seq;
	rdx->sm_first = cpu_to_le32(first);
	rdx->lg_first = cpu_to_le32(first);

	if (level == 0) {
		if (full)
			memset(rdx->bits, 0xff, SCOUTFS_RADIX_BITS_BYTES);
		else
			memset(rdx->bits, 0, SCOUTFS_RADIX_BITS_BYTES);

		tail = SCOUTFS_BLOCK_LG_SIZE -
		       offsetof(struct scoutfs_radix_block, bits) -
		       SCOUTFS_RADIX_BITS_BYTES;
	} else {
		init_ref(&ref, level - 1, full);

		for (i = 0; i < SCOUTFS_RADIX_REFS; i++)
			memcpy(&rdx->refs[i], &ref, sizeof(ref));

		tail = SCOUTFS_BLOCK_LG_SIZE -
		       offsetof(struct scoutfs_radix_block,
				refs[SCOUTFS_RADIX_REFS]);
	}

	/* make sure we don't write uninitialized tail kernel memory to disk */
	if (tail)
		memset((void *)rdx + SCOUTFS_BLOCK_LG_SIZE - tail, 0, tail);
}

/* get path flags */
enum {
	GPF_NEXT_SM	= (1 << 0),
	GPF_NEXT_LG	= (1 << 1),
};
/*
 * Give the caller an allocated path that holds references to the blocks
 * traversed to the leaf of the given root.
 */
static int get_path(struct super_block *sb, struct scoutfs_radix_root *root,
		    struct radix_change *chg, int gpf, u64 bit,
		    struct radix_path **path_ret)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	struct radix_path *path = NULL;
	struct scoutfs_block *bl;
	bool saw_inconsistent = false;
	u64 blkno;
	u64 synth;
	int level;
	int ind;
	int ret;
	int i;

	/* can't operate outside radix until we support growing devices */
	if (WARN_ON_ONCE(root->height < height_from_last(bit)) ||
	    WARN_ON_ONCE((gpf & GPF_NEXT_SM) && (gpf & GPF_NEXT_LG)))
		return -EINVAL;

	path = alloc_path(root);
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	/* switch to searching for small bits if no large found */
	if ((gpf & GPF_NEXT_LG) && le64_to_cpu(root->ref.lg_total) == 0)
		gpf ^= GPF_NEXT_LG | GPF_NEXT_SM;

	calc_level_inds(path, bit);

	for (level = root->height - 1; level >= 0; level--) {
		ref = path_ref(path, level);

		blkno = le64_to_cpu(ref->blkno);
		if (blkno == U64_MAX || blkno == 0) {
			synth = chg->next_synth++;
			if ((blkno & 1) != (synth & 1))
				synth = chg->next_synth++;
			/* careful not to go too high or wrap */
			if (synth == U64_MAX || synth < RADIX_SYNTH_BLKNO) {
				scoutfs_inc_counter(sb, radix_enospc_synth);
				ret = -ENOSPC;
				goto out;
			}
			bl = scoutfs_block_create(sb, synth);
			if (!IS_ERR_OR_NULL(bl)) {
				init_block(sb, bl->data, synth, ref->seq, level,
					   blkno == U64_MAX);
				ref->blkno = cpu_to_le64(bl->blkno);

			}
		} else {
			bl = scoutfs_block_read(sb, blkno);
		}
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}

		/*
		 * We can have a stale block in the cache but the tree
		 * shouldn't be changing under us.  We don't have to
		 * reread a root and restart descent.  If we don't get a
		 * consistent block after reading from the device then
		 * we've found corruption.
		 */
		if (!scoutfs_block_consistent_ref(sb, bl, ref->seq, ref->blkno,
						  SCOUTFS_BLOCK_MAGIC_RADIX)) {
			if (!saw_inconsistent) {
				scoutfs_block_invalidate(sb, bl);
				scoutfs_block_put(sb, bl);
				saw_inconsistent = true;
				level++;
				continue;
			}
			ret = -EIO;
			goto out;
		}
		saw_inconsistent = false;

		path->bls[level] = bl;
		if (level == 0) {
			/* path's leaf_bit is first in the leaf block */
			path->inds[0] = 0;
			break;
		}

		rdx = bl->data;
		ind = path->inds[level];

		/* search for a path to a leaf with a set large region */
		while ((gpf & GPF_NEXT_LG) && ind < SCOUTFS_RADIX_REFS &&
		       le64_to_cpu(rdx->refs[ind].lg_total) == 0) {
			if (ind < le32_to_cpu(rdx->lg_first))
				ind = le32_to_cpu(rdx->lg_first);
			else
				ind++;
		}

		/* search for a path to a leaf with a any bits set */
		while ((gpf & GPF_NEXT_SM) && ind < SCOUTFS_RADIX_REFS &&
		       le64_to_cpu(rdx->refs[ind].sm_total) == 0) {
			if (ind < le32_to_cpu(rdx->sm_first))
				ind = le32_to_cpu(rdx->sm_first);
			else
				ind++;
		}

		/*
		 * Didn't find a ref in the rest of the block at
		 * this level.  If we're the root block there's no
		 * more next bits to return.  If we're further down
		 * we bubble up a level and continue on a depth-first
		 * search.  We check the next ref from our parent and reset
		 * all the child inds to the left spine of the new
		 * subtree.
		 */
		if (ind >= SCOUTFS_RADIX_REFS) {
			if (level == root->height - 1) {
				ret = -ENOENT;
				goto out;
			}
			path->inds[level + 1]++;
			for (i = level; i >= 0; i--)
				path->inds[i] = 0;
			for (i = level; i <= level + 1; i++) {
				scoutfs_block_put(sb, path->bls[i]);
				path->bls[i] = NULL;
			}
			level += 2;
			continue;
		}

		/* reset all lower indices if we searched */
		if (ind != path->inds[level]) {
			for (i = level - 1; i >= 0; i--)
				path->inds[i] = 0;
			path->inds[level] = ind;
		}
	}

	path->leaf_bit = bit_from_inds(path);
	ret = 0;
out:
	if (ret < 0) {
		free_path(sb, path);
		path = NULL;
	}

	*path_ret = path;
	return ret;
}

/*
 * Get all the paths we're going to need to dirty all the blocks in all
 * the paths in the change.  The caller has added their path to the leaf
 * that they want to change to start the process off.
 *
 * For every clean block in paths we can have to set a bit in a leaf to
 * free the old blkno and clear a bit in a leaf to allocate a new dirty
 * blkno.  We keep checking new paths for clean blocks until eventually
 * all the paths only contain blocks whose blknos are in leaves that we
 * already have paths to.
 */
static int get_all_paths(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct radix_change *chg)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	struct scoutfs_block *bl;
	struct radix_path *path;
	struct radix_path *adding;
	struct radix_path *found;
	bool meta_wrapped;
	bool stable;
	u64 start_meta;
	u64 next_meta;
	u64 last_meta;
	u64 leaf_bit;
	int ind;
	int ret;
	int i;

	start_meta = calc_leaf_bit(le64_to_cpu(alloc->avail.next_find_bit));
	next_meta = start_meta;
	last_meta = le64_to_cpu(super->last_meta_blkno);
	meta_wrapped = false;

	do {
		stable = true;

		/* get paths to leaves to allocate dirty blknos from */
		if (chg->alloc_bits < chg->block_allocs + chg->caller_allocs) {
			stable = false;

			/* we're not modifying as we go, check for wrapping */
			if (next_meta >= start_meta && meta_wrapped) {
				scoutfs_inc_counter(sb, radix_enospc_paths);
				ret = -ENOSPC;
				break;
			}

			ret = get_path(sb, &alloc->avail, chg, GPF_NEXT_SM,
				       next_meta, &adding);
			if (ret < 0) {
				if (ret == -ENOENT) {
					meta_wrapped = true;
					next_meta = 0;
					continue;
				}
				break;
			}

			next_meta = adding->leaf_bit + SCOUTFS_RADIX_BITS;
			if (next_meta > last_meta) {
				meta_wrapped = true;
				next_meta = 0;
			}

			/* might already have path, maybe add it to alloc */
			found = walk_paths(&chg->rbroot, adding->root,
					   adding->leaf_bit, adding);
			if (found != adding) {
				free_path(sb, adding);
				adding = found;
			} else {
				list_add_tail(&adding->head, &chg->new_paths);
			}
			if (list_empty(&adding->alloc_head)) {
				ref = path_ref(adding, 0);
				chg->alloc_bits += le64_to_cpu(ref->sm_total);
				list_add_tail(&adding->alloc_head,
					      &chg->alloc_paths);
			}
		}

		if ((path = list_first_entry_or_null(&chg->new_paths,
						     struct radix_path,
						     head))) {
			list_move_tail(&path->head, &chg->paths);
			stable = false;

			/* check all the blocks in all new paths */
			for (i = path->height - 1; i >= 0; i--) {
				bl = path->bls[i];

				/* dirty are done, only visit each block once */
				if (scoutfs_block_writer_is_dirty(sb, bl) ||
				    scoutfs_block_tas_visited(sb, bl))
					continue;

				/* record the number of allocs we'll need */
				chg->block_allocs++;

				/* don't need to free synth blknos */
				if (bl->blkno >= RADIX_SYNTH_BLKNO)
					continue;

				/* see if we already a path to this leaf */
				leaf_bit = calc_leaf_bit(bl->blkno);
				if (walk_paths(&chg->rbroot, &alloc->freed,
					       leaf_bit, NULL))
					continue;

				/* get a new path to freed leaf to set */
				ret = get_path(sb, &alloc->freed, chg, 0,
					       bl->blkno, &adding);
				if (ret < 0)
					break;

				rdx = adding->bls[0]->data;
				ind = bl->blkno - adding->leaf_bit;
				if (test_bit_le(ind, rdx->bits)) {
					/* XXX corruption, bit already set? */
					ret = -EIO;
					break;
				}

				walk_paths(&chg->rbroot, adding->root,
					   adding->leaf_bit, adding);
				list_add_tail(&adding->head, &chg->new_paths);
			}
		}

		ret = 0;
	} while (!stable);

	return ret;
}

/*
 * We have pinned blocks in paths to all the leaves that we need to
 * modify to make a change to radix trees.  Walk through the paths
 * moving blocks to their new allocated blknos, freeing the old stable
 * blknos.
 */
static void dirty_all_path_blocks(struct super_block *sb,
				  struct scoutfs_radix_allocator *alloc,
				  struct scoutfs_block_writer *wri,
				  struct radix_change *chg)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	struct scoutfs_block *bl;
	struct radix_path *path;
	u64 blkno;
	int level;

	BUG_ON(!list_empty(&chg->new_paths));

	list_for_each_entry(path, &chg->paths, head) {

		for (level = path->height - 1; level >= 0; level--) {
			bl = path->bls[level];

			if (scoutfs_block_writer_is_dirty(sb, bl))
				continue;

			if (bl->blkno < RADIX_SYNTH_BLKNO)
				set_change_leaf_bits(sb, chg, &alloc->freed,
						     bl->blkno, 1);

			blkno = change_alloc_meta(sb, chg);
			scoutfs_block_clear_visited(sb, bl);
			scoutfs_block_move(sb, wri, bl, blkno);
			scoutfs_block_writer_mark_dirty(sb, wri, bl);

			rdx = bl->data;
			rdx->hdr.blkno = cpu_to_le64(bl->blkno);
			prandom_bytes(&rdx->hdr.seq, sizeof(rdx->hdr.seq));

			ref = path_ref(path, level);
			ref->blkno = rdx->hdr.blkno;
			ref->seq = rdx->hdr.seq;
		}
	}
}

static bool valid_free_bit_range(struct super_block *sb, bool meta,
				 u64 bit, int nbits)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	u64 last = bit + nbits - 1;

	return (nbits > 0) &&
	       (last >= bit) &&
	       (!meta || (bit >= le64_to_cpu(super->first_meta_blkno) &&
			  last <= le64_to_cpu(super->last_meta_blkno))) &&
	       (meta || (bit >= le64_to_cpu(super->first_data_blkno) &&
			  last <= le64_to_cpu(super->last_data_blkno)));
}

static int radix_free(struct super_block *sb,
		      struct scoutfs_radix_allocator *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_radix_root *root, bool meta,
		      u64 bit, int nbits)
{
	struct scoutfs_radix_block *rdx;
	struct radix_change *chg;
	struct radix_path *path;
	int ind;
	int ret;

	/* we only operate on one leaf */
	if (WARN_ON_ONCE(!valid_free_bit_range(sb, meta, bit, nbits)) ||
	    WARN_ON_ONCE(calc_leaf_bit(bit) != calc_leaf_bit(bit + nbits - 1)))
		return -EINVAL;

	mutex_lock(&alloc->mutex);

	chg = alloc_change();
	if (!chg) {
		ret = -ENOMEM;
		goto out;
	}

	ret = get_path(sb, root, chg, 0, bit, &path);
	if (ret < 0)
		goto out;
	list_add_tail(&path->head, &chg->new_paths);

	ind = bit - path->leaf_bit;
	rdx = path->bls[0]->data;
	if (!bitmap_empty_region_le(rdx->bits, ind, nbits)) {
		/* XXX corruption, trying to free set bits */
		ret = -EIO;
		goto out;
	}

	ret = get_all_paths(sb, alloc, chg);
	if (ret < 0)
		goto out;

	dirty_all_path_blocks(sb, alloc, wri, chg);
	set_path_leaf_bits(sb, path, bit, nbits);
	ret = 0;
out:
	free_change(sb, chg);
	mutex_unlock(&alloc->mutex);
	return ret;
}

/*
 * Return a single allocated metadata block for the caller.  We let the change
 * find a leaf in the metadata allocator for us.
 */
int scoutfs_radix_alloc(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri, u64 *blkno)
{
	struct radix_change *chg;
	int ret;

	mutex_lock(&alloc->mutex);

	chg = alloc_change();
	if (!chg) {
		ret = -ENOMEM;
		goto out;
	}

	chg->caller_allocs = 1;
	ret = get_all_paths(sb, alloc, chg);
	if (ret < 0)
		goto out;

	dirty_all_path_blocks(sb, alloc, wri, chg);
	*blkno = change_alloc_meta(sb, chg);
	ret = 0;
out:
	free_change(sb, chg);
	mutex_unlock(&alloc->mutex);

	return ret;
}

/*
 * Return an allocated data block extent by finding and clearing it from
 * the caller's tree.  The caller must protect access to their tree.  We
 * have to search in and allocate from the separate data allocator tree
 * ourselves.
 */
int scoutfs_radix_alloc_data(struct super_block *sb,
			     struct scoutfs_radix_allocator *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_radix_root *root,
			     int count, u64 *blkno_ret, int *count_ret)
{
	struct radix_change *chg;
	struct radix_path *path;
	u64 bit;
	int nbits;
	int gpf;
	int ret;

	*blkno_ret = 0;
	*count_ret = 0;

	if (WARN_ON_ONCE(count <= 0 || blkno_ret == NULL || count_ret == NULL))
		return -EINVAL;

	nbits = min(count, SCOUTFS_RADIX_LG_BITS);
	gpf = nbits > 1 ? GPF_NEXT_LG : GPF_NEXT_SM;

	mutex_lock(&alloc->mutex);

	chg = alloc_change();
	if (!chg) {
		ret = -ENOMEM;
		goto out;
	}

find_next:
	bit = le64_to_cpu(root->next_find_bit);
	ret = get_path(sb, root, chg, gpf, bit, &path);
	if (ret) {
		if (ret == -ENOENT) {
			if (root->next_find_bit != 0) {
				root->next_find_bit = 0;
				goto find_next;
			}
			scoutfs_inc_counter(sb, radix_enospc_data);
			ret = -ENOSPC;
		}
		goto out;
	}
	list_add_tail(&path->head, &chg->new_paths);

	ret = get_all_paths(sb, alloc, chg);
	if (ret < 0)
		goto out;

	dirty_all_path_blocks(sb, alloc, wri, chg);
	alloc_leaf_bits(sb, false, path, nbits, blkno_ret, count_ret);
	ret = 0;
out:
	free_change(sb, chg);
	mutex_unlock(&alloc->mutex);

	return ret;
}

/*
 * Free a single metadata block by adding it to the allocator's freed
 * tree.  Callers can trust our allocator to lock.
 */
int scoutfs_radix_free(struct super_block *sb,
		       struct scoutfs_radix_allocator *alloc,
		       struct scoutfs_block_writer *wri, u64 blkno)
{
	return radix_free(sb, alloc, wri, &alloc->freed, true, blkno, 1);
}

/*
 * Free a data block extent by setting it in the caller's tree.  The
 * caller must protect access to their tree.
 */
int scoutfs_radix_free_data(struct super_block *sb,
			    struct scoutfs_radix_allocator *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_radix_root *root,
			    u64 blkno, int count)
{
	return radix_free(sb, alloc, wri, root, false, blkno, count);
}

/*
 * Move bits between the source and destination trees.  The bits to move
 * are found in the input tree.
 *
 * Typically the input and source trees are the same.  We're careful to
 * modify the dst first because modifying src might also be modifying
 * inp.
 *
 * The input and source trees aren't the same when the caller is being
 * careful to use a read-only input tree because the source tree is
 * changing during the merge.  This happens when the server tries to
 * reclaim its freed tree by moving it into its avail.  Because our
 * dirtying actually moves clean blocks we need to be careful to not
 * reference dirty blocks from the input tree walk.  This is discovered
 * after dirtying the blocks.  The additional input walk will this time
 * read the old blocks.
 *
 * We can also be called with a src tree that is the current allocator
 * avail tree.  In this case dirtying the blocks in all the paths can
 * consume bits in the source tree.  We notice when dirtying allocation
 * empties the src block and we retry finding a new leaf to merge.
 *
 * The caller specifies the minimum count to move.  -ENOENT will be
 * returned if the source tree runs out of bits, potentially after
 * having already moved bits.  More than the minimum can be moved
 * because whole leaves worth of bits are moved.
 *
 * This is pretty expensive because it fully references full leaf blocks
 * a few times.  It could be more efficient if it short circuited walks
 * and spliced refs in parents when it finds that subtrees don't
 * intersect.
 */
int scoutfs_radix_merge(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_radix_root *dst,
			struct scoutfs_radix_root *src,
			struct scoutfs_radix_root *inp, bool meta, u64 count)
{
	struct scoutfs_radix_block *inp_rdx;
	struct scoutfs_radix_block *src_rdx;
	struct scoutfs_radix_block *dst_rdx;
	struct radix_change *chg = NULL;
	struct radix_path *inp_path = NULL;
	struct radix_path *src_path;
	struct radix_path *dst_path;
	s64 src_lg_delta;
	s64 dst_lg_delta;
	s64 sm_delta;
	u64 bit;
	int lg_ind;
	int ind;
	int ret;

	mutex_lock(&alloc->mutex);

	/* can't try to free too much when inp is read-only */
	if (inp != src &&
	    WARN_ON_ONCE(count > le64_to_cpu(inp->ref.sm_total))) {
		ret = -EINVAL;
		goto out;
	}

	while (count > 0) {

		chg = alloc_change();
		if (!chg) {
			ret = -ENOMEM;
			goto out;
		}

		bit = le64_to_cpu(src->next_find_bit);
wrapped:
		ret = get_path(sb, inp, chg, GPF_NEXT_SM, bit, &inp_path);
		if (ret < 0) {
			if (ret == -ENOENT) {
				if (bit != 0) {
					bit = 0;
					goto wrapped;
				} else {
					ret = -ENOSPC;
				}
			}
			goto out;
		}
		/* unique input is not modified, not stored in the change */
		bit = inp_path->leaf_bit;

		ret = get_path(sb, src, chg, 0, bit, &src_path);
		if (ret < 0)
			goto out;
		list_add_tail(&src_path->head, &chg->new_paths);

		ret = get_path(sb, dst, chg, 0, bit, &dst_path);
		if (ret < 0)
			goto out;
		list_add_tail(&dst_path->head, &chg->new_paths);

		ret = get_all_paths(sb, alloc, chg);
		if (ret < 0)
			goto out;

		/* this can modify src/dst when they're alloc trees */
		dirty_all_path_blocks(sb, alloc, wri, chg);

		inp_rdx = inp_path->bls[0]->data;
		src_rdx = src_path->bls[0]->data;
		dst_rdx = dst_path->bls[0]->data;

		sm_delta = le64_to_cpu(path_ref(inp_path, 0)->sm_total);
		ind = find_next_bit_le(inp_rdx->bits, SCOUTFS_RADIX_BITS,
				       le32_to_cpu(inp_rdx->sm_first));
		lg_ind = round_down(ind, SCOUTFS_RADIX_LG_BITS);

		/* back out and retry if no input left, or inp not ro */
		if (sm_delta == 0 ||
		    (inp != src && paths_share_blocks(inp_path, src_path))) {
			free_path(sb, inp_path);
			inp_path = NULL;
			free_change(sb, chg);
			chg = NULL;
			continue;
		}

		/* make sure all input bits are set in src */
		if (inp != src &&
		    !bitmap_subset((void *)inp_rdx->bits,
			    	   (void *)src_rdx->bits,
				   SCOUTFS_RADIX_BITS)) {
			ret = -EIO;
			goto out;
		}

		/* make sure all input bits are clear in dst */
		if (bitmap_intersects((void *)dst_rdx->bits,
				      (void *)inp_rdx->bits,
				      SCOUTFS_RADIX_BITS)) {
			ret = -EIO;
			goto out;
		}

		/* carefully modify src last, it might also be inp */
		bitmap_xor_bitmap_le(dst_rdx->bits, inp_rdx->bits,
				     SCOUTFS_RADIX_BITS);
		dst_lg_delta = count_lg_bitmap(dst_rdx->bits, inp_rdx->bits);

		src_lg_delta = count_lg_bitmap(src_rdx->bits, inp_rdx->bits);
		bitmap_xor_bitmap_le(src_rdx->bits, inp_rdx->bits,
				     SCOUTFS_RADIX_BITS);

		if (ind < le32_to_cpu(dst_rdx->sm_first))
			dst_rdx->sm_first = cpu_to_le32(ind);
		/* first doesn't have to be precise, search will cleanup */
		if (lg_ind < le32_to_cpu(dst_rdx->lg_first))
			dst_rdx->lg_first = cpu_to_le32(lg_ind);

		fixup_parent_refs(src_path, -sm_delta, -src_lg_delta);
		fixup_parent_refs(dst_path, sm_delta, dst_lg_delta);

		trace_scoutfs_radix_merge(sb, inp, inp_path->bls[0]->blkno,
					  src, src_path->bls[0]->blkno,
					  dst, dst_path->bls[0]->blkno, count,
					  bit, ind, sm_delta, src_lg_delta,
					  dst_lg_delta);

		free_path(sb, inp_path);
		inp_path = NULL;
		free_change(sb, chg);
		chg = NULL;

		store_next_find_bit(sb, meta, src, bit + SCOUTFS_RADIX_BITS);
		count -= min_t(u64, count, sm_delta);
	}

	ret = 0;
out:
	free_path(sb, inp_path);
	free_change(sb, chg);
	mutex_unlock(&alloc->mutex);

	return ret;
}

void scoutfs_radix_init_alloc(struct scoutfs_radix_allocator *alloc,
			      struct scoutfs_radix_root *avail,
			      struct scoutfs_radix_root *freed)
{
	mutex_init(&alloc->mutex);
	alloc->avail = *avail;
	alloc->freed = *freed;
}

/*
 * Initialize a root with an empty ref.  We set the height to the size
 * of the device and descent will fill in blocks.
 */
void scoutfs_radix_root_init(struct super_block *sb,
			     struct scoutfs_radix_root *root, bool meta)
{
	u64 last = last_from_super(sb, meta);

	root->height = height_from_last(last);
	root->next_find_bit = cpu_to_le64(0);
	init_ref(&root->ref, 0, false);
}

u64 scoutfs_radix_root_free_blocks(struct super_block *sb,
				   struct scoutfs_radix_root *root)
{
	return le64_to_cpu(root->ref.sm_total);
}

/*
 * The first bit nr in a leaf containing the bit, used by callers to
 * identify regions that span leafs and would need to be freed in
 * multiple calls.
 */
u64 scoutfs_radix_bit_leaf_nr(u64 bit)
{
	return calc_leaf_bit(bit);
}
