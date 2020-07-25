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
 * in the root of each tree.
 *
 * The radix isn't always fully populated.  References can contain
 * blknos with 0 or ~0 to indicate that its referenced subtree is either
 * entirely empty or full.  The counters that describe these stubbed out
 * subtrees will be correct as though all the blocks were populated.
 * Traversal instantiates initialized empty or full blocks as it
 * descends.  This lets mkfs initialize a tree with a large contigious
 * set region without having to populate all its blocks.
 *
 * The metadata allocator radix tree itself is used to allocate and free
 * its own blocks as it makes cow updates to itself.  Recursion is
 * avoided by tracking all the blocks we dirty with their parents,
 * making sure we have dirty leaves to record frees and allocs for all
 * the dirtied blocks, and using a read-only cursor to find blknos for
 * each new dirty block.  This lets us either atomically set and clear
 * all the leaf bits once we have all the dirty blocks or unwind all the
 * dirty blocks and restore their parent references.
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
 * This is just a sanity test at run time.  It's log base
 * SCOUTFS_RADIX_BITS of SCOUTFS_BLOCK_SM_MAX, but we can come close by
 * dividing bit widths by shifts if we under-estimate the number of bits
 * in a leaf by rounding it down to a power of two.  In practice the
 * trees are sized for the capacity of the device and are very short.
 */
#define RADIX_MAX_HEIGHT (((64 - SCOUTFS_BLOCK_SM_SHIFT) %	\
			   (SCOUTFS_BLOCK_LG_SHIFT + 2)) + 2)

/*
 * We create temporary synthetic blocks past possible blocks to populate
 * stubbed out refs that reference entirely empty or full subtrees.
 * They're moved to properly allocated blknos.
 */
#define RADIX_SYNTH_BLKNO (SCOUTFS_BLOCK_LG_MAX + 1)

static bool is_synth(u64 blkno)
{
	return blkno >= RADIX_SYNTH_BLKNO;
}

/* we use fake blknos to indicate subtrees either entirely empty or full */
static bool is_stub(u64 blkno)
{
	return blkno == 0 || blkno == U64_MAX;
}

struct radix_block_private {
	struct scoutfs_block *bl;
	struct list_head entry;
	struct list_head dirtied_entry;
	struct scoutfs_block *parent;
	struct scoutfs_radix_ref *ref;
	struct scoutfs_radix_ref orig_ref;
	struct scoutfs_block *blkno_bl;
	struct scoutfs_block *old_blkno_bl;
	int blkno_ind;
	int old_blkno_ind;
};

static bool was_dirtied(struct radix_block_private *priv)
{
	return !list_empty(&priv->dirtied_entry);
}

struct radix_change {
	struct scoutfs_radix_root *avail;
	struct list_head blocks;
	struct list_head dirtied_blocks;
	u64 next_synth;
	u64 next_find_bit;
	u64 first_free;
	struct scoutfs_block *free_bl;
	u64 free_leaf_bit;
	unsigned int free_ind;
};

#define DECLARE_RADIX_CHANGE(a) \
	struct radix_change a = {NULL, }

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
 * xor at least nbits total dst bits with set src bits, a full word at a
 * time, starting around the given starting index.  The src and dst
 * pointers can be to the same bitmap.  We might xor bits before the
 * starting index and might xor a bit more than nbits because we're
 * working an __le64 at a time.  Return the total amount xored and
 * set the caller's size that includes the last word we modified.
 */
static int bitmap_xor_bitmap_le(__le64 *dst, __le64 *src, int ind, int nbits,
				int *size)
{
	int xored = 0;
	int i;

	BUG_ON((unsigned long)src & 7);
	BUG_ON((unsigned long)dst & 7);

	while (xored < nbits &&
	       (ind = find_next_bit_le(src, SCOUTFS_RADIX_BITS, ind)) <
		SCOUTFS_RADIX_BITS) {
		i = ind / 64;
		xored += hweight64((u64 __force)src[i]);
		dst[i] = dst[i] ^ src[i];
		ind = round_up(ind + 1, 64);
		if (size)
			*size = ind;
	}

	return xored;
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
static u64 count_lg_from_set(void *result, void *input, int ind, int size)
{
	u64 count = 0;

	while ((ind = find_next_bit_le(input, size, ind)) < size) {
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

static u64 bit_from_inds(u32 *level_inds, u8 height)
{
	u64 bit = level_inds[0];
	u64 mult = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i < height; i++) {
		bit += (u64)level_inds[i] * mult;
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

static void calc_level_inds(u32 *level_inds, u8 height, u64 bit)
{
	u32 ind;
	int i;

	bit = div_u64_rem(bit, SCOUTFS_RADIX_BITS, &ind);
	level_inds[0] = ind;

	for (i = 1; i < height; i++) {
		bit = div_u64_rem(bit, SCOUTFS_RADIX_REFS, &ind);
		level_inds[i] = ind;
	}
}

static u64 calc_leaf_bit(u64 bit)
{
	u32 ind;
	div_u64_rem(bit, SCOUTFS_RADIX_BITS, &ind);

	return bit - ind;
}

/*
 * Make sure ref total tracking is correct after having modified a leaf
 * and updated all the parent refs.
 */
static void check_totals(struct scoutfs_block *leaf)
{
	struct radix_block_private *priv;
	struct scoutfs_block *bl = leaf;
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	int level;
	u64 st;
	u64 lt;
	int i;

	for (level = 0; bl; level++, bl = priv->parent) {
		priv = bl->priv;
		rdx = bl->data;
		ref = priv->ref;

		if (level == 0) {
			st = bitmap_weight((long *)rdx->bits,
					   SCOUTFS_RADIX_BITS);
			lt = count_lg_bits(rdx->bits, 0, SCOUTFS_RADIX_BITS);
		} else {
			st = 0;
			lt = 0;
			for (i = 0; i < SCOUTFS_RADIX_REFS; i++) {
				st += le64_to_cpu(rdx->refs[i].sm_total);
				lt += le64_to_cpu(rdx->refs[i].lg_total);
			}
		}

		if (le64_to_cpu(ref->sm_total) != st ||
		    le64_to_cpu(ref->lg_total) != lt) {
			printk("radix inconsistency: level %u calced st %llu lt %llu, stored st %llu lt %llu\n",
				level, st, lt,
				le64_to_cpu(ref->sm_total), 
				le64_to_cpu(ref->lg_total));
			BUG();
		}

		bl = priv->parent;
	}
}

/*
 * The caller has changed bits in a leaf block.  We update the totals in
 * rers up to the root ref.
 */
static void fixup_parent_refs(struct super_block *sb,
			      struct scoutfs_block *leaf,
			      s64 sm_delta, s64 lg_delta)
{
	struct radix_block_private *priv;
	struct scoutfs_radix_ref *ref;
	struct scoutfs_block *bl;

	for (bl = leaf; bl; bl = priv->parent) {
		priv = bl->priv;
		ref = priv->ref;

		le64_add_cpu(&ref->sm_total, sm_delta);
		le64_add_cpu(&ref->lg_total, lg_delta);
	}

	if (0) /* expensive, would be nice to make conditional */
		check_totals(leaf);
}

/* return 0 if the bit is past the last bit for the device */
static u64 wrap_bit(struct super_block *sb, bool meta, u64 bit)
{
	return bit > last_from_super(sb, meta) ? 0 : bit;
}

static void store_next_find_bit(struct super_block *sb, bool meta,
				struct scoutfs_radix_root *root, u64 bit)
{
	root->next_find_bit = cpu_to_le64(wrap_bit(sb, meta, bit));
}

static void bug_on_bad_bits(int ind, int nbits)
{
	BUG_ON(ind < 0 || ind > SCOUTFS_RADIX_BITS);
	BUG_ON(nbits < 0 || nbits > SCOUTFS_RADIX_BITS);
	BUG_ON(ind + nbits > SCOUTFS_RADIX_BITS);
}

static void set_leaf_bits(struct super_block *sb, struct scoutfs_block *bl,
			  int ind, int nbits)
{
	struct scoutfs_radix_block *rdx = bl->data;
	int lg_nbits;

	trace_scoutfs_radix_set_bits(sb, bl->blkno, ind, nbits);
	bug_on_bad_bits(ind, nbits);

	/* must never double-free bits */
	BUG_ON(!bitmap_empty_region_le(rdx->bits, ind, nbits));
	bitmap_set_le(rdx->bits, ind, nbits);
	lg_nbits = count_lg_bits(rdx->bits, ind, nbits);

	fixup_parent_refs(sb, bl, nbits, lg_nbits);
}

static void clear_leaf_bits(struct super_block *sb, struct scoutfs_block *bl,
			    int ind, int nbits)
{
	struct scoutfs_radix_block *rdx = bl->data;
	int lg_nbits;

	trace_scoutfs_radix_clear_bits(sb, bl->blkno, ind, nbits);
	bug_on_bad_bits(ind, nbits);

	/* must never alloc in-use bits */
	BUG_ON(!bitmap_full_region_le(rdx->bits, ind, nbits));
	lg_nbits = count_lg_bits(rdx->bits, ind, nbits);
	bitmap_clear_le(rdx->bits, ind, nbits);

	fixup_parent_refs(sb, bl, -nbits, -lg_nbits);
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
	int tail;
	int i;

	/* we use native long bitmap functions on the block bitmaps */
	BUILD_BUG_ON(offsetof(struct scoutfs_radix_block, bits) &
		     (sizeof(long) - 1));

	rdx->hdr.fsid = super->hdr.fsid;
	rdx->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_RADIX);
	rdx->hdr.blkno = cpu_to_le64(blkno);
	rdx->hdr.seq = seq;

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

static int find_next_change_blkno(struct super_block *sb,
				  struct radix_change *chg,
				  u64 *blkno);

enum {
	GLF_NEXT_SM	= (1 << 0),
	GLF_NEXT_LG	= (1 << 1),
	GLF_DIRTY	= (1 << 2),
};

/*
 * Get the caller their block for walking down the radix.  We can have
 * to populate synthetic blocks, read existing blocks, and cow new dirty
 * copies of either of those for callers who need to modify.  We update
 * references and record the blocks and references in the change for
 * callers to further build atomic changes with.
 */
static int get_radix_block(struct super_block *sb,
			   struct scoutfs_radix_allocator *alloc,
			   struct scoutfs_block_writer *wri,
			   struct radix_change *chg,
			   struct scoutfs_radix_root *root, int glf,
			   struct scoutfs_block *parent,
			   struct scoutfs_radix_ref *ref, int level,
			   struct scoutfs_block **bl_ret)
{
	struct radix_block_private *priv = NULL;
	bool saw_inconsistent = false;
	struct scoutfs_radix_block *rdx;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_block *dirty;
	bool put_block = true;
	u64 blkno;
	u64 synth;
	int ret;

	/* create a synthetic block or read an existing block */
	blkno = le64_to_cpu(ref->blkno);
	if (is_stub(blkno)) {
		synth = chg->next_synth++;
		/* don't create synth mistaken for all-full */
		if (synth == U64_MAX) {
			scoutfs_inc_counter(sb, radix_enospc_synth);
			ret = -ENOSPC;
			goto out;
		}
		bl = scoutfs_block_create(sb, synth);
		if (!IS_ERR_OR_NULL(bl)) {
			init_block(sb, bl->data, synth, ref->seq, level,
				   blkno == U64_MAX);
			scoutfs_inc_counter(sb, radix_create_synth);
		}
	} else {
		bl = scoutfs_block_read(sb, blkno);
		if (!IS_ERR_OR_NULL(bl))
			scoutfs_inc_counter(sb, radix_block_read);

		/*
		 * We can have a stale block in the cache but the tree
		 * shouldn't be changing under us.  We don't have to
		 * reread a root and restart descent.  If we don't get a
		 * consistent block after reading from the device then
		 * we've found corruption.
		 */
		while (!IS_ERR(bl) &&
		       !scoutfs_block_consistent_ref(sb, bl, ref->seq,
						     ref->blkno,
						  SCOUTFS_BLOCK_MAGIC_RADIX)) {
			scoutfs_inc_counter(sb, radix_inconsistent_ref);
			scoutfs_block_writer_forget(sb, wri, bl);
			scoutfs_block_invalidate(sb, bl);
			BUG_ON(bl->priv != NULL);
			scoutfs_block_put(sb, bl);
			bl = NULL;
			if (!saw_inconsistent) {
				saw_inconsistent = true;
				bl = scoutfs_block_read(sb, blkno);
			} else {
				bl = ERR_PTR(-EIO);
				scoutfs_inc_counter(sb, radix_inconsistent_eio);
			}
		}
		saw_inconsistent = false;
	}
	if (IS_ERR(bl)) {
		ret = PTR_ERR(bl);
		goto out;
	}

	if ((glf & GLF_DIRTY) && !scoutfs_block_writer_is_dirty(sb, bl)) {
		/* make a cow copy for the caller that needs a dirty block */
		ret = find_next_change_blkno(sb, chg, &blkno);
		if (ret < 0)
			goto out;

		dirty = scoutfs_block_create(sb, blkno);
		if (IS_ERR(dirty)) {
			ret = PTR_ERR(dirty);
			goto out;
		}

		memcpy(dirty->data, bl->data, SCOUTFS_BLOCK_LG_SIZE);
		scoutfs_block_put(sb, bl);
		bl = dirty;
		scoutfs_inc_counter(sb, radix_block_cow);
	}

	priv = bl->priv;
	if (!priv) {
		priv = kzalloc(sizeof(struct radix_block_private), GFP_NOFS);
		if (!priv) {
			ret = -ENOMEM;
			goto out;
		}

		bl->priv = priv;
		priv->bl = bl;
		INIT_LIST_HEAD(&priv->dirtied_entry);
		priv->parent = parent;
		priv->ref = ref;
		priv->orig_ref = *ref;
		/* put at head so for_each restores refs in reverse */
		list_add(&priv->entry, &chg->blocks);
		/* priv holds bl get, put as change is completed */
		put_block = false;
	}

	if ((glf & GLF_DIRTY) && !scoutfs_block_writer_is_dirty(sb, bl)) {
		scoutfs_block_writer_mark_dirty(sb, wri, bl);
		list_add(&priv->dirtied_entry, &chg->dirtied_blocks);
	}

	trace_scoutfs_radix_get_block(sb, root, glf, level,
				      parent ? parent->blkno : 0,
				      le64_to_cpu(ref->blkno), bl->blkno);

	/* update refs to new synth or dirty blocks */
	if (le64_to_cpu(ref->blkno) != bl->blkno) {
		rdx = bl->data;
		rdx->hdr.blkno = cpu_to_le64(bl->blkno);
		prandom_bytes(&rdx->hdr.seq, sizeof(rdx->hdr.seq));
		ref->blkno = rdx->hdr.blkno;
		ref->seq = rdx->hdr.seq;
	}

	ret = 0;
out:
	if (put_block)
		scoutfs_block_put(sb, bl);
	if (ret < 0)
		bl = NULL;

	*bl_ret = bl;
	return ret;
}

static int get_leaf_walk(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct radix_change *chg,
			 struct scoutfs_radix_root *root,
			 int glf, u64 bit, u64 *leaf_bit_ret,
			 struct scoutfs_block **bl_ret)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_radix_ref *ref;
	struct scoutfs_block *parent = NULL;
	struct scoutfs_block *bl;
	u32 level_inds[RADIX_MAX_HEIGHT];
	int level;
	int ind = 0;
	int ret;
	int i;

	/* can't operate outside radix until we support growing devices */
	if (WARN_ON_ONCE(root->height < height_from_last(bit)) ||
	    WARN_ON_ONCE(root->height > RADIX_MAX_HEIGHT) ||
	    WARN_ON_ONCE((glf & GLF_NEXT_SM) && (glf & GLF_NEXT_LG)))
		return -EINVAL;

	calc_level_inds(level_inds, root->height, bit);
	ref = &root->ref;

	for (level = root->height - 1; level >= 0; level--) {
		ret = get_radix_block(sb, alloc, wri, chg, root, glf, parent,
				      ref, level, &bl);
		if (ret)
			goto out;

		trace_scoutfs_radix_walk(sb, root, glf, level, bl->blkno, ind,
					 bit);

		if (level == 0) {
			/* returned leaf_bit is first in the leaf block */
			level_inds[0] = 0;
			break;
		}

		rdx = bl->data;
		ind = level_inds[level];

		/* search for a ref to a child with a set large region */
		while ((glf & GLF_NEXT_LG) && ind < SCOUTFS_RADIX_REFS &&
		       le64_to_cpu(rdx->refs[ind].lg_total) == 0) {
			ind++;
		}

		/* search for a ref to a child with any bits set */
		while ((glf & GLF_NEXT_SM) && ind < SCOUTFS_RADIX_REFS &&
		       le64_to_cpu(rdx->refs[ind].sm_total) == 0) {
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
			level_inds[level + 1]++;
			for (i = level; i >= 0; i--)
				level_inds[i] = 0;
			level += 2;
			continue;
		}

		/* reset all lower indices if we searched */
		if (ind != level_inds[level]) {
			for (i = level - 1; i >= 0; i--)
				level_inds[i] = 0;
			level_inds[level] = ind;
		}

		parent = bl;
		ref = &rdx->refs[ind];
	}

	*leaf_bit_ret = bit_from_inds(level_inds, root->height);
	ret = 0;
	scoutfs_inc_counter(sb, radix_walk);
out:
	if (ret < 0)
		*bl_ret = NULL;
	else
		*bl_ret = bl;
	return ret;
}

/*
 * Get the caller their leaf block in which they'll set or clear bits.
 * If they're asking for a dirty block then the leaf walk might dirty
 * blocks.  For each newly dirtied block we also make sure we have dirty
 * blocks for the leaves that contain the bits for each newly dirtied
 * block's old blkno and new blkno.
 */
static int get_leaf(struct super_block *sb,
		    struct scoutfs_radix_allocator *alloc,
		    struct scoutfs_block_writer *wri, struct radix_change *chg,
		    struct scoutfs_radix_root *root, int glf, u64 bit,
		    u64 *leaf_bit_ret, struct scoutfs_block **bl_ret)
{
	struct radix_block_private *priv;
	struct scoutfs_block *bl;
	u64 leaf_bit;
	u64 old_blkno;
	int ret;

	ret = get_leaf_walk(sb, alloc, wri, chg, root, glf, bit, leaf_bit_ret,
			    bl_ret);
	if (ret < 0 || !(glf & GLF_DIRTY))
		goto out;

	/* walk to leaves containing bits of newly dirtied block's blknos */
	while ((priv = list_first_entry_or_null(&chg->dirtied_blocks,
						struct radix_block_private,
						dirtied_entry))) {
		/* done when we see tail blocks with their blkno_bl set */
		if (priv->blkno_bl != NULL)
			break;

		old_blkno = le64_to_cpu(priv->orig_ref.blkno);
		if (!is_stub(old_blkno) && !is_synth(old_blkno)) {
			ret = get_leaf_walk(sb, alloc, wri, chg, &alloc->freed,
					    GLF_DIRTY, old_blkno, &leaf_bit,
					    &bl);
			if (ret < 0)
				break;
			priv->old_blkno_ind = old_blkno - leaf_bit;
			priv->old_blkno_bl = bl;
		}

		ret = get_leaf_walk(sb, alloc, wri, chg, &alloc->avail,
				    GLF_DIRTY, priv->bl->blkno, &leaf_bit,
				    &bl);
		if (ret < 0)
			break;

		priv->blkno_ind = priv->bl->blkno - leaf_bit;
		priv->blkno_bl = bl;

		list_move_tail(&priv->dirtied_entry, &chg->dirtied_blocks);
	}
out:
	return ret;
}

/*
 * Find the next region of set bits of the given size starting from the
 * given bit.  This only finds the bits, it doesn't change anything.  We
 * always try to return regions past the starting bit.  We can search to
 * a leaf that has bits that are all past the starting bit and we'll
 * retry.  This will wrap around to the start of the tree and fall back
 * to satisfying large regions with small regions.
 */
static int find_next_set_bits(struct super_block *sb, struct radix_change *chg,
			      struct scoutfs_radix_root *root, bool meta,
			      u64 start, int nbits, u64 *bit_ret,
			      int *nbits_ret, struct scoutfs_block **bl_ret)
{
	struct scoutfs_radix_block *rdx;
	struct scoutfs_block *bl;
	u64 leaf_bit;
	u64 bit;
	int end;
	int ind;
	int glf;
	int ret;

	bit = start;
	glf = nbits > 1 ? GLF_NEXT_LG : GLF_NEXT_SM;
retry:
	ret = get_leaf(sb, NULL, NULL, chg, root, glf, bit, &leaf_bit, &bl);
	if (ret == -ENOENT) {
		if (bit != 0) {
			bit = 0;
			goto retry;
		}

		/* switch to searching for small bits if no large found */
		if (glf == GLF_NEXT_LG) {
			glf = GLF_NEXT_SM;
			bit = start;
			goto retry;
		}
		ret = -ENOSPC;
		goto out;
	}
	rdx = bl->data;

	/* start from search bit if it's in the leaf, otherwise 0 */
	if (leaf_bit < bit && ((bit - leaf_bit) < SCOUTFS_RADIX_BITS))
		ind = bit - leaf_bit;
	else
		ind = 0;

	/* large allocs are always aligned from large regions */
	if (nbits >= SCOUTFS_RADIX_LG_BITS && (glf == GLF_NEXT_LG)) {
		ind = find_next_lg(rdx->bits, ind);
		if (ind == SCOUTFS_RADIX_BITS) {
			bit = wrap_bit(sb, meta, leaf_bit + SCOUTFS_RADIX_BITS);
			goto retry;
		}
		nbits = SCOUTFS_RADIX_LG_BITS;
		ret = 0;
		goto out;
	}

	/* otherwise use as much of the next set region as we can */
	ind = find_next_bit_le(rdx->bits, SCOUTFS_RADIX_BITS, ind);
	if (ind == SCOUTFS_RADIX_BITS) {
		bit = wrap_bit(sb, meta, leaf_bit + SCOUTFS_RADIX_BITS);
		goto retry;
	}

	if (nbits > 1) {
		end = find_next_zero_bit_le(rdx->bits, min_t(int, ind + nbits,
					    SCOUTFS_RADIX_BITS), ind);
		nbits = end - ind;
	}
	ret = 0;

out:
	*bit_ret = leaf_bit + ind;
	*nbits_ret = nbits;
	if (bl_ret)
		*bl_ret = bl;

	return ret;
}

static void prepare_change(struct radix_change *chg,
			   struct scoutfs_radix_root *avail)
{
	memset(chg, 0, sizeof(struct radix_change));
	chg->avail = avail;
	INIT_LIST_HEAD(&chg->blocks);
	INIT_LIST_HEAD(&chg->dirtied_blocks);
	chg->next_synth = RADIX_SYNTH_BLKNO;
	chg->next_find_bit = le64_to_cpu(avail->next_find_bit);
}

/*
 * We successfully got all the dirty block references we need to make
 * the change.  Set their old blkno's freed bits and clear all their new
 * dirty blkno's avail bits.  We drop the blocks from the dirtied_blocks
 * list here as we go so we won't attempt to do this all over again
 * as we complete the change.
 */
static void apply_change_bits(struct super_block *sb, struct radix_change *chg)
{
	struct radix_block_private *priv;
	struct scoutfs_block *bl;

	/* first update the contents of the blocks */
	list_for_each_entry(priv, &chg->blocks, entry) {
		bl = priv->bl;

		/* complete cow allocations for dirtied blocks */
		if (was_dirtied(priv)) {
			/* can't try to write to synth blknos */
			BUG_ON(is_synth(bl->blkno));

			clear_leaf_bits(sb, priv->blkno_bl, priv->blkno_ind, 1);
			if (priv->old_blkno_bl) {
				set_leaf_bits(sb, priv->old_blkno_bl,
					      priv->old_blkno_ind, 1);
			}
			scoutfs_inc_counter(sb, radix_complete_dirty_block);

			list_del_init(&priv->dirtied_entry);
		}
	}
}

/*
 * Drop all references to the blocks that we held as we worked with the
 * radix blocks.
 *
 * If the operation failed then we drop the blocks we dirtied during
 * this change and restore their refs.  Nothing can update a ref to a
 * dirty block so these will always be current.
 *
 * We always drop synthetic blocks.  They could been cowed so they might
 * not be currently referenced.  Blocks are added to the head of the
 * blocks list as they're first used so we're undoing ref changes in
 * reverse order.  This means that the error case will always first
 * unwind synthetic cows then the synthetic source block itself.
 */
static void complete_change(struct super_block *sb,
			    struct scoutfs_block_writer *wri,
			    struct radix_change *chg, int err)
{
	struct radix_block_private *priv;
	struct radix_block_private *tmp;
	struct scoutfs_block *bl;

	/* only complete once for each call to prepare */
	if (!chg->avail)
		return;

	/* finish dirty block frees and allocs on success */
	if (err == 0 && !list_empty(&chg->dirtied_blocks))
		apply_change_bits(sb, chg);

	/* replace refs and remove blocks from the cache */
	list_for_each_entry(priv, &chg->blocks, entry) {
		bl = priv->bl;

		if (is_synth(bl->blkno) || (err < 0 && was_dirtied(priv))) {
			if (le64_to_cpu(priv->ref->blkno) == bl->blkno) {
				*priv->ref = priv->orig_ref;
				scoutfs_inc_counter(sb, radix_undo_ref);
			}
			scoutfs_block_writer_forget(sb, wri, bl);
			scoutfs_block_invalidate(sb, bl);
		}
	}

	/* finally put all blocks now that were done with contents */
	list_for_each_entry_safe(priv, tmp, &chg->blocks, entry) {
		bl = priv->bl;

		bl->priv = NULL;
		scoutfs_block_put(sb, bl);
		list_del(&priv->entry);
		kfree(priv);
	}

	if (err == 0)
		store_next_find_bit(sb, true, chg->avail, chg->next_find_bit);
	chg->avail = NULL;
}

/*
 * Find the next free metadata blkno from the metadata allocator that
 * the change is tracking.  This is used to find the next free blkno for
 * the next cowed block without modifying the allocator.  Because it's
 * not modifying the allocator it can wrap and find the same block
 * twice, we watch for that.
 */
static int find_next_change_blkno(struct super_block *sb,
				  struct radix_change *chg, u64 *blkno)
{
	struct scoutfs_radix_block *rdx;
	u64 bit;
	int nbits;
	int ret;

	if (chg->free_bl == NULL) {
		ret = find_next_set_bits(sb, chg, chg->avail, true,
					 chg->next_find_bit, 1, &bit, &nbits,
					 &chg->free_bl);
		if (ret < 0)
			goto out;
		chg->free_leaf_bit = calc_leaf_bit(bit);
		chg->free_ind = bit - chg->free_leaf_bit;
	}

	bit = chg->free_leaf_bit + chg->free_ind;
	if (chg->first_free == 0) {
		chg->first_free = bit;
	} else if (chg->first_free == bit) {
		ret = -ENOSPC;
		goto out;
	}

	*blkno = bit;

	rdx = chg->free_bl->data;
	chg->free_ind = find_next_bit_le(rdx->bits, SCOUTFS_RADIX_BITS,
					 chg->free_ind + 1);
	if (chg->free_ind >= SCOUTFS_RADIX_BITS) {
		chg->free_ind = SCOUTFS_RADIX_BITS;
		chg->free_bl = NULL;
	}
	chg->next_find_bit = wrap_bit(sb, true,
				      chg->free_leaf_bit + chg->free_ind);

	ret = 0;
out:
	if (ret == -ENOSPC)
		scoutfs_inc_counter(sb, radix_enospc_meta);
	return ret;
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
	struct scoutfs_block *bl;
	DECLARE_RADIX_CHANGE(chg);
	u64 leaf_bit;
	int ind;
	int ret;

	/* we only operate on one leaf */
	if (WARN_ON_ONCE(!valid_free_bit_range(sb, meta, bit, nbits)) ||
	    WARN_ON_ONCE(calc_leaf_bit(bit) != calc_leaf_bit(bit + nbits - 1)))
		return -EINVAL;

	mutex_lock(&alloc->mutex);
	prepare_change(&chg, &alloc->avail);

	ret = get_leaf(sb, alloc, wri, &chg, root, GLF_DIRTY, bit,
		       &leaf_bit, &bl);
	if (ret < 0)
		goto out;

	ind = bit - leaf_bit;
	set_leaf_bits(sb, bl, ind, nbits);
out:
	complete_change(sb, wri, &chg, ret);
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
	struct scoutfs_block *bl;
	DECLARE_RADIX_CHANGE(chg);
	u64 leaf_bit;
	u64 bit;
	int ind;
	int ret;

	scoutfs_inc_counter(sb, radix_alloc);

	mutex_lock(&alloc->mutex);
	prepare_change(&chg, &alloc->avail);

	ret = find_next_change_blkno(sb, &chg, &bit);
	if (ret < 0)
		goto out;

	ret = get_leaf(sb, alloc, wri, &chg, &alloc->avail, GLF_DIRTY, bit,
		       &leaf_bit, &bl);
	if (ret < 0)
		goto out;

	ind = bit - leaf_bit;
	clear_leaf_bits(sb, bl, ind, 1);
	*blkno = bit;
	ret = 0;
out:
	complete_change(sb, wri, &chg, ret);
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
	struct scoutfs_block *bl;
	DECLARE_RADIX_CHANGE(chg);
	u64 leaf_bit;
	u64 bit;
	int nbits;
	int ind;
	int ret;

	scoutfs_inc_counter(sb, radix_alloc_data);

	*blkno_ret = 0;
	*count_ret = 0;

	if (WARN_ON_ONCE(count <= 0 || blkno_ret == NULL || count_ret == NULL))
		return -EINVAL;

	nbits = min(count, SCOUTFS_RADIX_LG_BITS);

	mutex_lock(&alloc->mutex);
	prepare_change(&chg, &alloc->avail);

	ret = find_next_set_bits(sb, &chg, root, false,
				 le64_to_cpu(root->next_find_bit), nbits,
				 &bit, &nbits, NULL);
	if (ret < 0) {
		if (ret == -ENOSPC)
			scoutfs_inc_counter(sb, radix_enospc_data);
		goto out;
	}

	ret = get_leaf(sb, alloc, wri, &chg, root, GLF_DIRTY, bit,
		       &leaf_bit, &bl);
	if (ret < 0)
		goto out;

	ind = bit - leaf_bit;
	clear_leaf_bits(sb, bl, ind, nbits);
	*blkno_ret = bit;
	*count_ret = nbits;
	store_next_find_bit(sb, false, root, bit + nbits);
	ret = 0;
out:
	complete_change(sb, wri, &chg, ret);
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
	scoutfs_inc_counter(sb, radix_free);
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
	scoutfs_inc_counter(sb, radix_free_data);
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
 * avail tree.  In this case dirtying the leaf blocks can consume bits
 * in the source tree.  We notice when dirtying the src block and we
 * retry finding a new leaf to merge.
 *
 * The caller specifies the minimum count to move.  -ENOENT will be
 * returned if the source tree runs out of bits, potentially after
 * having already moved bits.  Up to 63 bits more than the minimum can
 * be moved because bits are manipulated in chunks of 64 bits.
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
	struct scoutfs_block *inp_bl;
	struct scoutfs_block *src_bl;
	struct scoutfs_block *dst_bl;
	DECLARE_RADIX_CHANGE(chg);
	s64 src_lg_delta;
	s64 dst_lg_delta;
	u64 leaf_bit;
	u64 bit;
	int merge_size;
	int merged;
	int ind;
	int ret;

	trace_scoutfs_radix_merge(sb, le64_to_cpu(dst->ref.blkno),
				  le64_to_cpu(dst->ref.sm_total),
				  le64_to_cpu(src->ref.blkno),
				  le64_to_cpu(src->ref.sm_total),
				  le64_to_cpu(inp->ref.blkno),
				  le64_to_cpu(inp->ref.sm_total), count);
	scoutfs_inc_counter(sb, radix_merge);

	mutex_lock(&alloc->mutex);

	/* can't try to free too much when inp is read-only */
	if (inp != src &&
	    WARN_ON_ONCE(count > le64_to_cpu(inp->ref.sm_total))) {
		ret = -EINVAL;
		goto out;
	}

	while (count > 0) {

		prepare_change(&chg, &alloc->avail);
		bit = le64_to_cpu(src->next_find_bit);
wrapped:
		ret = get_leaf(sb, NULL, NULL, &chg, inp, GLF_NEXT_SM, bit,
			       &leaf_bit, &inp_bl);
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
		bit = leaf_bit;
		inp_rdx = inp_bl->data;

		ret = get_leaf(sb, alloc, wri, &chg, src, GLF_DIRTY, bit,
			       &leaf_bit, &src_bl);
		if (ret < 0)
			goto out;
		src_rdx = src_bl->data;

		ret = get_leaf(sb, alloc, wri, &chg, dst, GLF_DIRTY, bit,
			       &leaf_bit, &dst_bl);
		if (ret < 0)
			goto out;
		dst_rdx = dst_bl->data;

		apply_change_bits(sb, &chg);

		/* change allocs could have cleared all of inp if its avail */
		ind = find_next_bit_le(inp_rdx->bits, SCOUTFS_RADIX_BITS, 0);
		if (ind == SCOUTFS_RADIX_BITS) {
			scoutfs_inc_counter(sb, radix_merge_empty);
			complete_change(sb, wri, &chg, -EAGAIN);
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
		merged = bitmap_xor_bitmap_le(dst_rdx->bits, inp_rdx->bits,
					      ind, count, &merge_size);
		dst_lg_delta = count_lg_from_set(dst_rdx->bits, inp_rdx->bits,
						 ind, merge_size);

		src_lg_delta = count_lg_from_set(src_rdx->bits, inp_rdx->bits,
						 ind, merge_size);
		bitmap_xor_bitmap_le(src_rdx->bits, inp_rdx->bits, ind, merged,
				     NULL);

		fixup_parent_refs(sb, src_bl, -merged, -src_lg_delta);
		fixup_parent_refs(sb, dst_bl, merged, dst_lg_delta);

		trace_scoutfs_radix_merged_blocks(sb, inp, inp_bl->blkno, src,
						  src_bl->blkno, dst,
						  dst_bl->blkno, count, bit,
						  ind, merged, src_lg_delta,
						  dst_lg_delta);

		complete_change(sb, wri, &chg, 0);

		store_next_find_bit(sb, meta, src, bit + SCOUTFS_RADIX_BITS);
		count -= min_t(u64, count, merged);
	}

	ret = 0;
out:
	complete_change(sb, wri, &chg, ret);
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
