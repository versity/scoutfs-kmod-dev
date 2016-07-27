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

#include "super.h"
#include "format.h"
#include "block.h"
#include "buddy.h"
#include "scoutfs_trace.h"

/*
 * scoutfs uses buddy bitmaps to allocate block regions.  The buddy
 * allocator is nice because it uses one index for allocating by size
 * and freeing and merging by location.  The index is dense and has a
 * predictable worst case size that we can preallocate.  As described
 * below, it also makes it easy to find unions of free regions between
 * two indexes.
 *
 * The buddy allocator is built from a hierarchy of bitmaps for each
 * power of two order of blocks that we can allocate.  If a high order
 * buddy bit is set then all the lower order bits that it covers are
 * clear.  The bits are stored in blocks that are stored in a fixed
 * depth radix with a single parent indirect block.  The super block
 * references the indirect block.  The block references in the indirect
 * block also include a bitmap of orders that are free in the referenced
 * block.
 *
 * The blknos for the buddy blocks themselves are allocated out of a
 * single bitmap block that is referenced by the super.
 *
 * All the blocks are read and cowed with the usual block layer routines
 * so that we reuse the same code to evict and retry stale cached
 * blocks, cow, etc.  The allocator in the block code gives us the
 * source blkno for a cow operation so we can use the correct allocator
 * (none for bitmap blocks, bitmap for buddy blocks, buddy for btree
 * blocks and extents).
 *
 * The trickiest part of the allocator is due to the cow nature of our
 * consistent updates.  We can't satisfy an allocation with a region
 * that's been freed in this transaction and is still referenced by the
 * old stable transaction.  We solve this by only returning regions that
 * are free in both the stable and currently dirty allocator structures.
 *
 * The single indirect block in the radix limits the number of blocks
 * that can be described by the radix to just under a TB.  The device
 * will be managed by multiple radix trees some day.
 *
 * XXX:
 *  - verify blocks on read?
 *  - more rigorously test valid blkno/order inputs
 *  - detect corruption/errors when trying to free free extents
 *  - mkfs should initialize all the slots
 *  - shrink and grow
 *  - metadata and data regions
 *  - worry about testing for free buddies outside device during free?
 *  - btree should free blocks on merge and some failure
 *  - we could track the first set in order bitmaps, dunno if it'd be worth it
 */

enum {
	REGION_PAIR,	/* two bitmap blocks at known blknos */
	REGION_BM,	/* buddy blocks in the bitmap block off the super */
	REGION_BUDDY,	/* btree blocks and extents in the buddy bitmaps */
};

static int blkno_region(struct scoutfs_super_block *super, u64 blkno)
{
	u64 end;

	end = SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR;
	if (blkno < end)
		return REGION_PAIR;

	end += le32_to_cpu(super->buddy_blocks);
	if (blkno < end)
		return REGION_BM;

	return REGION_BUDDY;
}

/* the first device blkno covered by the buddy allocator */
static u64 first_blkno(struct scoutfs_super_block *super)
{
	return SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR +
	       le32_to_cpu(super->buddy_blocks);
}

/* the slot in the indirect block of a given blkno */
static int indirect_slot(struct scoutfs_super_block *super, u64 blkno)
{
	return (u32)(blkno - first_blkno(super)) / SCOUTFS_BUDDY_ORDER0_BITS;
}

/* device blkno of order bit in slot */
static u64 slot_buddy_blkno(struct scoutfs_super_block *super, int sl,
			    int order, int nr)
{
	return first_blkno(super) + ((u64)sl * SCOUTFS_BUDDY_ORDER0_BITS) +
	       ((u64)nr << order);
}

/* number of blocks managed by the buddy block referenced by the given slot */
static int slot_count(struct scoutfs_super_block *super, int sl)
{
	u64 first = first_blkno(super) + ((u64)sl * SCOUTFS_BUDDY_ORDER0_BITS);

	return min_t(int, le64_to_cpu(super->total_blocks) - first,
		     SCOUTFS_BUDDY_ORDER0_BITS);
}

/* the order 0 bit offset of blkno */
static int buddy_bit(struct scoutfs_super_block *super, u64 blkno)
{
	return (u32)(blkno - first_blkno(super)) % SCOUTFS_BUDDY_ORDER0_BITS;
}

/* true if the blkno could be the start of an allocation of the order */
static bool valid_order(struct scoutfs_super_block *super, u64 blkno, int order)
{
	return (buddy_bit(super, blkno) & ((1 << order) - 1)) == 0;
}

/* the starting bit offset in the block bitmap of an order's bitmap */
static int order_off(int order)
{
	if (order == 0)
		return 0;

	return (2 * SCOUTFS_BUDDY_ORDER0_BITS) -
	       (SCOUTFS_BUDDY_ORDER0_BITS / (1 << (order - 1)));
}

/* the bit offset in the block bitmap of an order's bit */
static int order_nr(int order, int nr)
{
	return order_off(order) + nr;
}

static int test_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	return !!test_bit_le(order_nr(order, nr), bud->bits);
}

static int test_buddy_bit_or_higher(struct scoutfs_buddy_block *bud, int order,
				    int nr)
{
	int i;

	for (i = order; i < SCOUTFS_BUDDY_ORDERS; i++) {
		if (test_buddy_bit(bud, i, nr))
			return true;
		nr >>= 1;
	}

	return false;
}

static void set_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (!test_and_set_bit_le(order_nr(order, nr), bud->bits))
		le32_add_cpu(&bud->order_counts[order], 1);
}

static void clear_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (test_and_clear_bit_le(order_nr(order, nr), bud->bits))
		le32_add_cpu(&bud->order_counts[order], -1);
}

/* returns INT_MAX when there are no bits set */
static int find_next_buddy_bit(struct scoutfs_buddy_block *bud, int order,
			       int nr)
{
	int size = order_off(order + 1);

	nr = find_next_bit_le(bud->bits, size, order_nr(order, nr));
	if (nr >= size)
		return INT_MAX;

	return nr - order_off(order);
}

static void update_free_orders(struct scoutfs_buddy_slot *slot,
			       struct scoutfs_buddy_block *bud)
{
	u8 free = 0;
	int i;

	for (i = 0; i < SCOUTFS_BUDDY_ORDERS; i++)
		free |= (!!bud->order_counts[i]) << i;

	slot->free_orders = free;
}

/*
 * Allocate a buddy block blkno from the super's dirty bitmap block.
 * Stable buddy blocks are freed as they're cowed so we have to make
 * sure that we only return blknos that were free in the previous stable
 * bitmap block.
 */
static int bitmap_alloc(struct super_block *sb, u64 *blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_bitmap_block *st_bm;
	struct scoutfs_bitmap_block *bm;
	struct scoutfs_block *st_bl;
	struct scoutfs_block *bm_bl;
	int size;
	int ret;
	int d;
	int s;

	/* mkfs should have ensured that there's bitmap blocks */
	/* XXX corruption */
	if (sbi->super.buddy_bm_ref.blkno == 0 ||
	    sbi->stable_super.buddy_bm_ref.blkno == 0)
		return -EIO;

	/* dirty the bitmap block */
	bm_bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_bm_ref);
	if (IS_ERR(bm_bl))
		return PTR_ERR(bm_bl);
	bm = bm_bl->data;

	/* read the stable bitmap block */
	st_bl = scoutfs_read_ref(sb, &sbi->stable_super.buddy_bm_ref);
	if (IS_ERR(st_bl)) {
		ret = PTR_ERR(st_bl);
		goto out;
	}
	st_bm = st_bl->data;

	/* find the first bit that is set in both dirty and stable bitmaps */
	size = le32_to_cpu(sbi->super.buddy_blocks);
	s = 0;
	do {
		d = find_next_bit_le(bm->bits, size, s);
		s = find_next_bit_le(st_bm->bits, size, d);
	} while (d != s);
	if (d >= size) {
		ret = -ENOSPC;
		goto out;
	}

	*blkno = SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR + d;
	clear_bit_le(d, &bm->bits);
	ret = 0;
out:
	scoutfs_put_block(st_bl);
	scoutfs_put_block(bm_bl);
	return ret;
}

/* Free a buddy block blkno in the super's bitmap block. */
static int bitmap_free(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_bitmap_block *bm;
	struct scoutfs_block *bl;
	int nr;

	/* mkfs should have ensured that there's bitmap blocks */
	/* XXX corruption */
	if (sbi->super.buddy_bm_ref.blkno == 0)
		return -EIO;

	bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_bm_ref);
	if (IS_ERR(bl))
		return PTR_ERR(bl);
	bm = bl->data;

	nr = blkno - (SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR);
	set_bit_le(nr, bm->bits);
	scoutfs_put_block(bl);

	return 0;
}

/*
 * Give the caller a dirty buddy block.  If the slot hasn't been used
 * yet then we need to allocate and initialize a new block.
 */
static struct scoutfs_block *dirty_buddy_block(struct super_block *sb, int sl,
					       struct scoutfs_buddy_slot *slot)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block *bl;
	u64 blkno;
	int count;
	int order;
	int size;
	int ret;
	int nr;

	/* the fast path is to dirty an existing block */
	if (slot->ref.blkno)
		return scoutfs_block_cow_ref(sb, &slot->ref);

	ret = bitmap_alloc(sb, &blkno);
	if (ret)
		return ERR_PTR(ret);

	bl = scoutfs_new_block(sb, blkno);
	if (IS_ERR(bl)) {
		bitmap_free(sb, blkno);
		return bl;
	}
	bud = bl->data;
	scoutfs_zero_block_tail(bl, sizeof(bud->hdr));

	/* mark the initial run of highest orders free */
	count = slot_count(super, sl);
	order = SCOUTFS_BUDDY_ORDERS - 1;
	size = 1 << order;
	nr = 0;
	while (count > size) {
		set_buddy_bit(bud, order, nr);
		nr++;
		count -= size;
	}

	/* set order bits for each of the bits set in the remaining count */
	do {
		if (count & (1 << order)) {
			set_buddy_bit(bud, order, nr);
			nr = (nr + 1) << 1;
		} else {
			nr <<= 1;
		}
	} while (order--);

	slot->ref.blkno = bud->hdr.blkno;
	slot->ref.seq = bud->hdr.seq;

	update_free_orders(slot, bud);

	return bl;
}

/*
 * Return the order bitmap offset and order of the first allocation
 * that fits the desired order.
 *
 * Returns INT_MAX if there are no free orders.
 */
static int find_first_fit(struct scoutfs_super_block *super, int sl,
			  struct scoutfs_buddy_block *bud,
			  struct scoutfs_buddy_block *st_bud,
			  int order, int *order_ret)
{
	int nrs[SCOUTFS_BUDDY_ORDERS] = {0,};
	u64 blkno = U64_MAX;
	bool made_progress;
	int ret = INT_MAX;
	u64 bno;
	int nr;
	int i;

	do {
		made_progress = false;
		for (i = order; i < SCOUTFS_BUDDY_ORDERS; i++) {
			/* find the next bit in each order */
			nr = find_next_buddy_bit(bud, i, nrs[i]);
			nrs[i] = nr;
			if (nr == INT_MAX) {
				continue;
			}
			made_progress = true;

			/* advance to next bit if it's not free in stable */
			if (!st_bud ||
			    !test_buddy_bit_or_higher(st_bud, i, nr)) {
				nrs[i] = nr + 1;
				continue;
			}

			/* use the first lowest order blkno */
			bno = slot_buddy_blkno(super, sl, i, nr);
			if (bno < blkno) {
				blkno = bno;
				*order_ret = i;
				ret = nr;
			}
		}

	} while (ret == INT_MAX && made_progress);

	return ret;
}

/*
 * Find the first free region that satisfies the given order that is
 * also free in the stable buddy bitmaps.  This can return an allocation
 * that breaks up a larger order.  Higher level callers iterate over
 * smaller orders to provide partial allocations.
 */
static int alloc_slot(struct super_block *sb,  int sl,
		      struct scoutfs_buddy_slot *slot,
		      struct scoutfs_block_ref *stable_ref,
		      u64 *blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_buddy_block *st_bud;
	struct scoutfs_block *st_bl;
	struct scoutfs_block *bl;
	int found;
	int ret;
	int nr;
	int i;

	/* initialize or dirty the slot's buddy block */
	bl = dirty_buddy_block(sb, sl, slot);
	if (IS_ERR(bl))
		return PTR_ERR(bl);
	bud = bl->data;

	/* read stable slots's buddy block if there is one */
	if (stable_ref->blkno) {
		st_bl = scoutfs_read_ref(sb, stable_ref);
		if (IS_ERR(st_bl)) {
			ret = PTR_ERR(st_bl);
			goto out;
		}
		st_bud = st_bl->data;
	} else {
		st_bl = NULL;
		st_bud = NULL;
	}

	nr = find_first_fit(super, sl, bud, st_bud, order, &found);
	if (nr == INT_MAX) {
		ret = -ENOSPC;
		goto out;
	}

	/* we'll succeed from this point on, use nr before mangling it */
	*blkno = slot_buddy_blkno(super, sl, found, nr);

	/* always clear the found order */
	clear_buddy_bit(bud, found, nr);

	/* free right buddies if we're breaking up a larger order */
	for (nr <<= 1, i = found - 1; i >= order; i--, nr <<= 1)
		set_buddy_bit(bud, i, nr | 1);

	update_free_orders(slot, bud);
	ret = 0;
out:
	scoutfs_put_block(st_bl);
	scoutfs_put_block(bl);
	return ret;
}

/*
 * Try and find a free block extent of the given order.  We can fail to
 * find a free order when none of the slots have free orders as the
 * volume fills or gets fragmented.
 *
 * We also have to be careful to only return free extents that were free
 * in the old stable buddy allocator so that we don't allocate and write
 * over referenced data.  This can cause us to skip otherwise available
 * extents but it should be rare.  There can only be a transaction's
 * worth of difference between the dirty allocator and the stable
 * allocator.  This is one of the motivations to cap the size of
 * transactions.
 */
static int alloc_order(struct super_block *sb, u64 *blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_buddy_indirect *st_ind;
	struct scoutfs_buddy_indirect *ind;
	struct scoutfs_block *st_bl = NULL;
	struct scoutfs_block *bl = NULL;
	u8 mask;
	int ret;
	int i;

	/* mkfs should have ensured that there's indirect blocks */
	if (sbi->super.buddy_ind_ref.blkno == 0 ||
	    sbi->stable_super.buddy_ind_ref.blkno == 0) {
		ret = -EIO;
		goto out;
	}

	/* get the dirty indirect block */
	bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_ind_ref);
	if (IS_ERR(bl)) {
		ret = PTR_ERR(bl);
		goto out;
	}
	ind = bl->data;

	/* get the stable indirect block */
	st_bl = scoutfs_read_ref(sb, &sbi->stable_super.buddy_ind_ref);
	if (IS_ERR(st_bl)) {
		ret = PTR_ERR(st_bl);
		goto out;
	}
	st_ind = st_bl->data;

	mask = ~0U << order;

	/*
	 * try to alloc from each slot that has at least the order free
	 * in both the dirty and stable buddy blocks.
	 */
	for (i = 0; i < SCOUTFS_BUDDY_SLOTS; i++) {
		if (!((mask & ind->slots[i].free_orders) &&
		      (mask & st_ind->slots[i].free_orders))) {
			ret = -ENOSPC;
			continue;
		}

		ret = alloc_slot(sb, i, &ind->slots[i], &st_ind->slots[i].ref,
				 blkno, order);
		if (ret != -ENOSPC)
			break;
	}

out:
	scoutfs_put_block(st_bl);
	scoutfs_put_block(bl);

	return ret;
}

/*
 * The buddy allocator keeps trying smaller orders until it finds an
 * allocation.
 *
 * The order of the allocation is returned.
 */
static int buddy_alloc(struct super_block *sb, u64 *blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	if (WARN_ON_ONCE(order < 0 || order >= SCOUTFS_BUDDY_ORDERS))
		return -EINVAL;

	mutex_lock(&sbi->buddy_mutex);

	do {
		ret = alloc_order(sb, blkno, order);
	} while (ret == -ENOSPC && order--);

	mutex_unlock(&sbi->buddy_mutex);

	return ret ?: order;
}

/*
 * Allocate a block from the given region.  The caller has the buddy
 * mutex if we're called for either of the pair or bitmap internal
 * regions.
 */
static int alloc_region(struct super_block *sb, u64 *blkno, int order,
			u64 existing, int region)
{
	int ret;

	switch(region) {
		case REGION_PAIR:
			*blkno = existing ^ 1;
			ret = 0;
			break;
		case REGION_BM:
			ret = bitmap_alloc(sb, blkno);
			break;
		case REGION_BUDDY:
			ret = buddy_alloc(sb, blkno, order);
			break;
	}

	trace_scoutfs_buddy_alloc(*blkno, order, region, ret);
	return ret;
}

int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order)
{
	return alloc_region(sb, blkno, order, 0, REGION_BUDDY);
}

static int bitmap_dirty(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block *bl;

	/* mkfs should have ensured that there's bitmap blocks */
	/* XXX corruption */
	if (sbi->super.buddy_bm_ref.blkno == 0)
		return -EIO;

	/* dirty the bitmap block */
	bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_bm_ref);
	if (IS_ERR(bl))
		return PTR_ERR(bl);

	scoutfs_put_block(bl);
	return 0;
}

static int buddy_dirty(struct super_block *sb, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_buddy_indirect *ind;
	struct scoutfs_block *ind_bl = NULL;
	struct scoutfs_block *bl = NULL;
	int ret;
	int sl;

	mutex_lock(&sbi->buddy_mutex);

	/* mkfs should have ensured that there's indirect blocks */
	if (sbi->super.buddy_ind_ref.blkno == 0) {
		ret = -EIO;
		goto out;
	}

	/* get the dirty indirect block */
	ind_bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_ind_ref);
	if (IS_ERR(ind_bl)) {
		ret = PTR_ERR(ind_bl);
		goto out;
	}
	ind = ind_bl->data;

	sl = indirect_slot(super, blkno);
	bl = dirty_buddy_block(sb, sl, &ind->slots[sl]);
	if (IS_ERR(bl))
		ret = PTR_ERR(bl);
	else
		ret = 0;
out:
	mutex_unlock(&sbi->buddy_mutex);
	scoutfs_put_block(ind_bl);
	scoutfs_put_block(bl);

	return ret;
}


/*
 * Create dirty cow copies of the bitmap, indirect, and buddy blocks
 * so that a free of the given extent in the current transaction is
 * guaranteed to succeed.
 *
 * This is only meant for buddy allocators who are complicated enough
 * to need help avoiding error conditions.
 */
int scoutfs_buddy_dirty(struct super_block *sb, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	switch(blkno_region(super, blkno)) {
		case REGION_BM:
			return bitmap_dirty(sb, blkno);
		case REGION_BUDDY:
			return buddy_dirty(sb, blkno, order);
	}

	return 0;
}

/*
 * The block layer allocates from the same region as an existing blkno
 * when it's allocating for cow.
 */
int scoutfs_buddy_alloc_same(struct super_block *sb, u64 *blkno, int order,
			     u64 existing)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	return alloc_region(sb, blkno, order, existing,
			    blkno_region(super, existing));
}

/*
 * Free the aligned allocation of the given order at the given blkno to
 * the allocator.  We merge it into adjoining free space by looking for
 * free buddies as we increase the order.
 */
static int buddy_free(struct super_block *sb, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_buddy_indirect *ind;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block *ind_bl = NULL;
	struct scoutfs_block *bl = NULL;
	int ret;
	int sl;
	int nr;
	int i;

	if (WARN_ON_ONCE(order < 0 || order >= SCOUTFS_BUDDY_ORDERS) ||
	    WARN_ON_ONCE(!valid_order(super, blkno, order)))
		return -EINVAL;

	mutex_lock(&sbi->buddy_mutex);

	/* mkfs should have ensured that there's indirect blocks */
	if (sbi->super.buddy_ind_ref.blkno == 0) {
		ret = -EIO;
		goto out;
	}

	ind_bl = scoutfs_block_cow_ref(sb, &sbi->super.buddy_ind_ref);
	if (IS_ERR(ind_bl)) {
		ret = PTR_ERR(ind_bl);
		goto out;
	}
	ind = ind_bl->data;

	sl = indirect_slot(super, blkno);
	bl = scoutfs_block_cow_ref(sb, &ind->slots[sl].ref);
	if (IS_ERR(bl)) {
		ret = PTR_ERR(bl);
		goto out;
	}
	bud = bl->data;

	/*
	 * Merge our region with its free buddy and then try to merge
	 * that higher order region with its buddy, and so on, until the
	 * highest order.  The highest order doesn't have buddies.
	 */
	nr = buddy_bit(super, blkno) >> order;
	for (i = order; i < SCOUTFS_BUDDY_ORDERS - 1; i++) {

		if (!test_buddy_bit(bud, i, nr ^ 1))
			break;

		clear_buddy_bit(bud, i, nr ^ 1);
		nr >>= 1;
	}

	set_buddy_bit(bud, i, nr);

	update_free_orders(&ind->slots[sl], bud);
	scoutfs_put_block(bl);
	ret = 0;
out:
	mutex_unlock(&sbi->buddy_mutex);
	scoutfs_put_block(ind_bl);

	return ret;
}

int scoutfs_buddy_free(struct super_block *sb, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	int region;
	int ret;

	region = blkno_region(super, blkno);
	switch(blkno_region(super, blkno)) {
		case REGION_PAIR:
			ret = 0;
			break;
		case REGION_BM:
			ret = bitmap_free(sb, blkno);
			break;
		case REGION_BUDDY:
			ret = buddy_free(sb, blkno, order);
			break;
	}

	trace_scoutfs_buddy_free(blkno, order, region, ret);
	return ret;
}
