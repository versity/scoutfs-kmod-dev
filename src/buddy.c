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
#include <linux/statfs.h>
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "buddy.h"
#include "scoutfs_trace.h"

/*
 * scoutfs uses buddy bitmaps in an augmented radix to index free space.
 *
 * At the heart of the allocator are the buddy bitmaps in the radix
 * leaves.  For a given region of blocks there are bitmaps for each
 * power of two order of blocks that can be allocated.  N bits record
 * whether each order 0 size block region is allocated or freed, then
 * N/2 bits describe order 1 regions that span pairs of order 0 blocks,
 * and so on.  This ends up using two bits in the bitmaps for each
 * device block that's managed.
 *
 * An order bit is set when it is free.  All of its lower order bits
 * will be clear.  To allocate we clear a bit.  A partial allocation
 * clears the higher order bit and each buddy for each lower order until
 * the allocated order.  Freeing sets an order bit.  Then if it's buddy
 * order is also set we clear both and set their higher order bit.  This
 * proceeds to the highest order.
 *
 * Each buddy block records the first set bit in each order bitmap.  As
 * bits are set they update these first set records if they're before
 * the previous value.  As bits are cleared we find the next set if it
 * was the first.
 *
 * These buddy bitmap blocks that each fully describe a region of blocks
 * are assembled into a radix tree.  Each reference to a leaf block in
 * parent blocks have a bitmap of the orders that are free in its leaf
 * block.  The parent blocks then also record the first slot that has
 * each order bit set in its child references.  This indexing holds all
 * the way to the root.  This lets us quickly determine an order that
 * will satisfy an allocation and descend to the leaf that contains the
 * first free region of that order.
 *
 * These buddy blocks themselves are located in preallocated space. Each
 * logical position in the tree occupies two blocks on the device.  In
 * each transaction we use the currently referenced block to cow into
 * its partner.   Since the block positions are calculated the block
 * references only need a bit to specify which of the pair is being
 * referenced.  The number of blocks needed is precisely calculated by
 * taking the number of leaf blocks needed to track the device blocks
 * and dividing by the radix fanout until we have a single root block.
 *
 * Each aligned block allocation order is stored in a path down the
 * radix to a leaf that's a function of the block offset.  This lets us
 * ensure that we can allocate or free a given allocation order by
 * dirtying those blocks.  If we've allocated an order in a transaction
 * it can always be freed (or re-allocated) while the transaction holds
 * the dirty buddy blocks.
 *
 * We use that property to ensure that frees of stable data don't
 * satisfy allocation until the next transaction.  When we free stable
 * data we dirty the path to its position in the radix and record the
 * free in an rbtree.  We can then apply these frees as we commit the
 * transaction.  If the transaction fails we can undo the frees and let
 * the file system carry on.  We'll try to reapply the frees before the
 * next transaction commits.  The allocator never introduces
 * unrecoverable errors.
 *
 * The radix isn't fully populated when it's created.  mkfs only
 * initializes the two paths down the tree that have partially
 * initialized parent slots and leaf bitmaps.  The path down the left
 * spine has the initial file system blocks allocated.  The path down
 * the right spine can have partial parent slots and bits set in the
 * leaf when device sizes aren't multiples of the leaf block bit count
 * and radix fanout.  The kernel then only has to initialize the rest of
 * the buddy blocks blocks which have fully populated parent slots and
 * leaf bitmaps.
 *
 * XXX
 *  - resize is going to be a thing.  figure out that thing.
 */

struct buddy_info {
	struct mutex mutex;

	atomic_t alloc_count;
	struct rb_root pending_frees;

	/* max height given total blocks */
	u8 max_height;
	/* the device blkno of the first block of a given level */
	u64 level_blkno[SCOUTFS_BUDDY_MAX_HEIGHT];
	/* blk divisor to find slot index at each level */
	u64 level_div[SCOUTFS_BUDDY_MAX_HEIGHT];

	struct buddy_stack {
		struct scoutfs_block *bl[SCOUTFS_BUDDY_MAX_HEIGHT];
		u16 sl[SCOUTFS_BUDDY_MAX_HEIGHT];
		int nr;
	} stack;
};

/* the first device blkno covered by the buddy allocator */
static u64 first_blkno(struct scoutfs_super_block *super)
{
	return SCOUTFS_BUDDY_BLKNO + le64_to_cpu(super->buddy_blocks);
}

/* the last device blkno covered by the buddy allocator */
static u64 last_blkno(struct scoutfs_super_block *super)
{
	return le64_to_cpu(super->total_blocks) - 1;
}

/* the last relative blkno covered by the buddy allocator */
static u64 last_blk(struct scoutfs_super_block *super)
{
	return last_blkno(super) - first_blkno(super);
}

/* true when the device blkno is covered by the allocator */
static bool device_blkno(struct scoutfs_super_block *super, u64 blkno)
{
	return blkno >= first_blkno(super) && blkno <= last_blkno(super);
}

/* true when the device blkno is used for buddy blocks */
static bool buddy_blkno(struct scoutfs_super_block *super, u64 blkno)
{
	return blkno < first_blkno(super);
}

/* the order 0 bit offset in a buddy block of a given relative blk */
static int buddy_bit(u64 blk)
{
	return do_div(blk, SCOUTFS_BUDDY_ORDER0_BITS);
}

/* true if the rel blk could be the start of an allocation of the order */
static bool valid_order(u64 blk, int order)
{
	return (buddy_bit(blk) & ((1 << order) - 1)) == 0;
}

/* the block bit offset of the first bit of the given order's bitmap */
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

static void stack_push(struct buddy_stack *sta, struct scoutfs_block *bl,
		       u16 sl)
{
	sta->bl[sta->nr] = bl;
	sta->sl[sta->nr++] = sl;
}

/* sl isn't returned because callers peek the leaf where sl is meaningless */ 
static struct scoutfs_block *stack_peek(struct buddy_stack *sta)
{
	if (sta->nr)
		return sta->bl[sta->nr - 1];

	return NULL;
}

static struct scoutfs_block *stack_pop(struct buddy_stack *sta, u16 *sl)
{
	if (sta->nr) {
		*sl = sta->sl[--sta->nr];
		return sta->bl[sta->nr];
	}

	return NULL;
}

/* update first_set if the caller set an earlier nr for the given order */
static void set_order_nr(struct scoutfs_buddy_block *bud, int order, u16 nr)
{
	u16 first = le16_to_cpu(bud->first_set[order]);

	trace_printk("set level %u order %d nr %u first %u\n",
		     bud->level, order, nr, first);

	if (nr <= first)
		bud->first_set[order] = cpu_to_le16(nr);
}

/* find the next first set if the caller just cleared the current first_set */
static void clear_order_nr(struct scoutfs_buddy_block *bud, int order, u16 nr)
{
	u16 first = le16_to_cpu(bud->first_set[order]);
	int size;
	int i;

	trace_printk("cleared level %u order %d nr %u first %u\n",
		     bud->level, order, nr, first);

	if (nr != first)
		return;

	if (bud->level) {
		for (i = nr + 1; i < SCOUTFS_BUDDY_SLOTS; i++) {
			if (le16_to_cpu(bud->slots[i].free_orders) &
			    (1 << order))
				break;
		}
		if (i == SCOUTFS_BUDDY_SLOTS)
			i = U16_MAX;

	} else {
		size = order_off(order + 1);
		i = find_next_bit_le(bud->bits, size,
				       order_nr(order, first) + 1);
		if (i >= size)
			i = U16_MAX;
		else
			i -= order_off(order);
	}

	bud->first_set[order] = cpu_to_le16(i);

}

#define for_each_changed_bit(nr, bit, old, new, tmp)		\
	for (tmp = old ^ new;					\
	     tmp && (nr = ffs(tmp) - 1, bit = 1 << nr, 1);	\
	     tmp ^= bit)

/*
 * Set a slot's free_orders value and update first_set for each order
 * that it changes.  Returns true of the slot's free_orders was changed.
 */
static bool set_slot_free_orders(struct scoutfs_buddy_block *bud, u16 sl,
				 u16 free_orders)
{
	u16 old = le16_to_cpu(bud->slots[sl].free_orders);
	int order;
	int tmp;
	int bit;

	if (old == free_orders)
		return false;

	for_each_changed_bit(order, bit, old, free_orders, tmp) {
		if (old & bit)
			clear_order_nr(bud, order, sl);
		else
			set_order_nr(bud, order, sl);
	}

	bud->slots[sl].free_orders = cpu_to_le16(free_orders);
	return true;
}

/*
 * The block at the top of the stack has changed its bits or slots and
 * updated its first set.  We propagate those changes up through
 * free_orders in parents slots and their first_set up through the tree
 * to free_orders in the root.  We can stop when a block's first_set
 * values don't change free_orders in their parent's slot.
 */
static void stack_cleanup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct buddy_stack *sta = &binf->stack;
	struct scoutfs_buddy_root *root = &sbi->super.buddy_root;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block *bl;
	u16 free_orders = 0;
	bool parent;
	u16 sl;
	int i;

	parent = false;
	while ((bl = stack_pop(sta, &sl))) {

		bud = scoutfs_block_data(bl);
		if (parent && !set_slot_free_orders(bud, sl, free_orders)) {
			scoutfs_block_put(bl);
			break;
		}

		free_orders = 0;
		for (i = 0; i < ARRAY_SIZE(bud->first_set); i++) {
			if (bud->first_set[i] != cpu_to_le16(U16_MAX))
				free_orders |= 1 << i;
		}

		scoutfs_block_put(bl);
		parent = true;
	}

	/* set root if we got that far */
	if (bl == NULL)
		root->slot.free_orders = cpu_to_le16(free_orders);

	/* put any remaining blocks */
	while ((bl = stack_pop(sta, &sl)))
		scoutfs_block_put(bl);

}

static int test_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	return !!test_bit_le(order_nr(order, nr), bud->bits);
}

static void set_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (!test_and_set_bit_le(order_nr(order, nr), bud->bits))
		set_order_nr(bud, order, nr);
}

static void clear_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (test_and_clear_bit_le(order_nr(order, nr), bud->bits))
		clear_order_nr(bud, order, nr);
}

/*
 * mkfs always writes the paths down the sides of the radix that have
 * partially populated blocks.  We only have to initialize full blocks
 * in the middle of the tree.
 */
static void init_buddy_block(struct buddy_info *binf,
			     struct scoutfs_super_block *super,
			     struct scoutfs_block *bl, int level)
{
	struct scoutfs_buddy_block *bud = scoutfs_block_data(bl);
	u16 count;
	int nr;
	int i;

	scoutfs_block_zero(bl, sizeof(bud->hdr));

	for (i = 0; i < ARRAY_SIZE(bud->first_set); i++)
		bud->first_set[i] = cpu_to_le16(U16_MAX);

	bud->level = level;

	if (level) {
		for (i = 0; i < SCOUTFS_BUDDY_SLOTS; i++)
			set_slot_free_orders(bud, i, SCOUTFS_BUDDY_ORDER0_BITS);
	} else {
		/* ensure that there aren't multiple highest orders */
		BUILD_BUG_ON((SCOUTFS_BUDDY_ORDER0_BITS /
			      (1 << (SCOUTFS_BUDDY_ORDERS - 1))) > 1);

		count = SCOUTFS_BUDDY_ORDER0_BITS;
		nr = 0;
		for (i = SCOUTFS_BUDDY_ORDERS - 1; i >= 0; i--) {
			if (count & (1 << i)) {
				set_buddy_bit(bud, i, nr);
				nr = (nr + 1) << 1;
			} else {
				nr <<= 1;
			}
		}
	}
}

/*
 * Give the caller the block referenced by the given slot.  They've
 * calculated the blkno of the pair of blocks while walking the tree.
 * The slot describes which of the pair its referencing.  The caller is
 * always going to modify the block so we always try and cow it.  We
 * construct a fake ref so we can re-use the block ref cow code.  When
 * we initialize the first use of a block we use the first of the pair.
 */
static struct scoutfs_block *get_buddy_block(struct super_block *sb,
					     struct scoutfs_buddy_slot *slot,
					     u64 blkno, int level)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_info *binf = sbi->buddy_info;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block_ref ref;
	struct scoutfs_block *bl;

	trace_printk("getting block level %d blkno %llu slot seq %llu off %u\n",
		     level, blkno, le64_to_cpu(slot->seq), slot->blkno_off);

	/* init a new block for an unused slot */
	if (slot->seq == 0) {
		bl = scoutfs_block_dirty(sb, blkno);
		if (!IS_ERR(bl))
			init_buddy_block(binf, super, bl, level);
	} else {
		/* construct block ref from tree walk blkno and slot ref */
		ref.blkno = cpu_to_le64(blkno + slot->blkno_off);
		ref.seq = slot->seq;
		bl = scoutfs_block_dirty_ref(sb, &ref);
	}

	if (!IS_ERR(bl)) {
		bud = scoutfs_block_data(bl);

		/* rebuild slot ref to blkno */
		if (slot->seq != bud->hdr.seq) {
			slot->blkno_off = le64_to_cpu(bud->hdr.blkno) - blkno;
			/* alloc_same only xors low bit */
			BUG_ON(slot->blkno_off > 1);
			slot->seq = bud->hdr.seq;
		}
	}

	return bl;
}

/*
 * Walk the buddy block radix to the leaf that contains either the given
 * relative blk or the first free given order.  The radix is of a fixed
 * depth and we initialize new blocks as we descend through
 * uninitialized refs.
 *
 * If order is -1 then we search for the blk.
 *
 * As we descend we calculate the base blk offset of the path we're
 * taking down the tree.  This is used to find the blkno of the next
 * block relative to the blkno of the given level.  It's then used by
 * the caller to calculate the total blk offset by adding the bit they
 * find in the block.
 *
 * The path through the tree is recorded in the stack in the buddy info.
 * The caller is responsible for cleaning up the stack and must do so
 * even if we return an error.
 */
static int buddy_walk(struct super_block *sb, u64 blk, int order, u64 *base)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_info *binf = sbi->buddy_info;
	struct buddy_stack *sta = &binf->stack;
	struct scoutfs_buddy_root *root = &sbi->super.buddy_root;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_buddy_slot *slot;
	struct scoutfs_block *bl;
	u64 blkno;
	int level;
	int ret = 0;
	int sl = 0;

	/* XXX corruption? */
	if (blk > last_blk(super) || root->height == 0 ||
	    root->height > SCOUTFS_BUDDY_MAX_HEIGHT)
		return -EIO;

	slot = &root->slot;
	level = root->height;
	blkno = SCOUTFS_BUDDY_BLKNO;
	*base = 0;

	while (level--) {
		/* XXX do base and level make sense here? */
		bl = get_buddy_block(sb, slot, blkno, level);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			break;
		}

		trace_printk("before blk %llu order %d level %d blkno %llu base %llu sl %d\n",
			     blk, order, level, blkno, *base, sl);

		bud = scoutfs_block_data(bl);

		if (level) {
			if (order >= 0) {
				/* find first slot with order free */
				sl = le16_to_cpu(bud->first_set[order]);
				/* XXX corruption */
				if (sl == U16_MAX) {
					scoutfs_block_put(bl);
					ret = -EIO;
					break;
				}
			} else {
				/* find slot based on blk */
				sl = div64_u64_rem(blk, binf->level_div[level],
						   &blk);
			}

			/* shouldn't be sl * 2, right? */
			*base = (*base * SCOUTFS_BUDDY_SLOTS) + sl;
			/* this is the only place we * 2 */
			blkno = binf->level_blkno[level - 1] + (*base * 2);
			slot = &bud->slots[sl];
		} else {
			*base *= SCOUTFS_BUDDY_ORDER0_BITS;
			/* sl in stack is 0 for final leaf block */
			sl = 0;
		}

		trace_printk("after blk %llu order %d level %d blkno %llu base %llu sl %d\n",
			     blk, order, level, blkno, *base, sl);


		stack_push(sta, bl, sl);
	}

	trace_printk("walking ret %d\n", ret);

	return ret;
}

/*
 * Find the order to search for to allocate a requested order.  We try
 * to use the smallest greater or equal order and then the largest
 * smaller order.
 */
static int find_free_order(struct scoutfs_buddy_root *root, int order)
{
	u16 free = le16_to_cpu(root->slot.free_orders);
	u16 smaller_mask = (1 << order) - 1;
	u16 larger = free & ~smaller_mask;
	u16 smaller = free & smaller_mask;

	if (larger)
		return ffs(larger) - 1;
	if (smaller)
		return fls(smaller) - 1;

	return -ENOSPC;
}

/*
 * Walk to the leaf that contains the found order and allocate a region
 * of the given order, returning the relative blk to the caller.
 */
static int buddy_alloc(struct super_block *sb, u64 *blk, int order, int found)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct buddy_stack *sta = &binf->stack;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block *bl;
	u64 base;
	int ret;
	int nr;
	int i;

	trace_printk("alloc order %d found %d\n", order, found);

	if (WARN_ON_ONCE(found >= 0 && order > found))
		return -EINVAL;

	ret = buddy_walk(sb, *blk, found, &base);
	if (ret)
		goto out;

	bl = stack_peek(sta);
	bud = scoutfs_block_data(bl);

	if (found >= 0) {
		nr = le16_to_cpu(bud->first_set[found]);
		/* XXX corruption */
		if (nr == U16_MAX) {
			ret = -EIO;
			goto out;
		}

		/* give caller the found blk for the order */
		*blk = base + (nr << found);
	} else {
		nr = buddy_bit(*blk) >> found;
	}

	/* always allocate the higher or equal found order */
	clear_buddy_bit(bud, found, nr);

	/* and maybe free our buddies between smaller order and larger found */
	nr = buddy_bit(*blk) >> order;
	for (i = order; i < found; i++) {
		set_buddy_bit(bud, i, nr ^ 1);
		nr >>= 1;
	}

	ret = 0;
out:
	trace_printk("alloc order %d found %d blk %llu ret %d\n",
		     order, found, *blk, ret);
	stack_cleanup(sb);
	return ret;
}

/*
 * Free a given order by setting its order bit.  If the order's buddy
 * isn't set then it isn't free and we can't merge so we set our order
 * and are done.  If the buddy is free then we can clear it and ascend
 * up to try and set the next higher order.  That performs the same
 * buddy merging test.  Eventually we make it to the highest order which
 * doesn't have a buddy so we can always set it.
 *
 * As we're freeing orders in the final buddy bitmap that only partially
 * covers the end of the device we might try to test buddies which are
 * past the end of the device.  The test will still fall within the leaf
 * block bitmap and those bits past the device will never be set so we
 * will fail the merge and correctly set the orders free.
 */
static int buddy_free(struct super_block *sb, u64 blk, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct buddy_stack *sta = &binf->stack;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_block *bl;
	u64 unused;
	int ret;
	int nr;
	int i;

	ret = buddy_walk(sb, blk, -1, &unused);
	if (ret)
		goto out;

	bl = stack_peek(sta);
	bud = scoutfs_block_data(bl);

	nr = buddy_bit(blk) >> order;
	for (i = order; i < SCOUTFS_BUDDY_ORDERS - 2; i++) {

		if (!test_buddy_bit(bud, i, nr ^ 1))
			break;

		clear_buddy_bit(bud, i, nr ^ 1);
		nr >>= 1;
	}

	set_buddy_bit(bud, i, nr);

	ret = 0;
out:
	stack_cleanup(sb);
	return ret;
}

/*
 * Try to allocate an extent with the size number of blocks.  blkno is
 * set to the start of the extent and the order of the block count is
 * returned.
 */
int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_info *binf = sbi->buddy_info;
	int found;
	u64 blk;
	int ret;

	trace_printk("order %d\n", order);

	mutex_lock(&binf->mutex);

	found = find_free_order(&super->buddy_root, order);
	if (found < 0) {
		ret = found;
		goto out;
	}

	if (found < order)
		order = found;

	blk = 0;
	ret = buddy_alloc(sb, &blk, order, found);
	if (ret)
		goto out;

	*blkno = first_blkno(super) + blk;
	le64_add_cpu(&super->free_blocks, -(1ULL << order));
	atomic_add((1ULL << order), &binf->alloc_count);
	ret = order;

out:
	trace_printk("blkno %llu order %d ret %d\n", *blkno, order, ret);
	mutex_unlock(&binf->mutex);
	return ret;
}

/*
 * We use the block _ref() routines to dirty existing blocks to reuse
 * all the block verification and cow machinery.  During cow this is
 * called to allocate a new blkno to cow an existing buddy block.  We
 * use the existing blkno to see if we have to return the other mirrored
 * buddy blkno or do a real allocation for every other kind of block
 * being cowed.
 */
int scoutfs_buddy_alloc_same(struct super_block *sb, u64 *blkno, u64 existing)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	if (buddy_blkno(super, existing)) {
		*blkno = existing ^ 1;
		trace_printk("existing %llu ret blkno %llu\n",
			     existing, *blkno);
		return 0;
	}

	return scoutfs_buddy_alloc(sb, blkno, 0);
}

struct extent_node {
	struct rb_node node;
	u64 start;
	u64 len;
};

static int add_enode_extent(struct rb_root *root, u64 start, u64 len)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct extent_node *left = NULL;
	struct extent_node *right = NULL;
	struct extent_node *enode;

	trace_printk("adding enode [%llu,%llu]\n", start, len);

	while (*node && !(left && right)) {
		parent = *node;
		enode = container_of(*node, struct extent_node, node);

		if (start < enode->start) {
			if (!right && start + len == enode->start)
				right = enode;
			node = &(*node)->rb_left;
		} else {
			if (!left && enode->start + enode->len == start)
				left = enode;
			node = &(*node)->rb_right;
		}
	}

	if (right) {
		right->start = start;
		right->len += len;
		trace_printk("right now [%llu, %llu]\n",
			     right->start, right->len);
	}

	if (left) {
		if (right) {
			left->len += right->len;
			rb_erase(&right->node, root);
			kfree(right);
		} else {
			left->len += len;
		}
		trace_printk("left now [%llu, %llu]\n", left->start, left->len);
	}

	if (left || right)
		return 0;

	enode = kmalloc(sizeof(struct extent_node), GFP_NOFS);
	if (!enode)
		return -ENOMEM;

	enode->start = start;
	enode->len = len;

	trace_printk("inserted new [%llu, %llu]\n", enode->start, enode->len);

	rb_link_node(&enode->node, parent, node);
	rb_insert_color(&enode->node, root);

	return 0;
}

static void destroy_pending_frees(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct extent_node *enode;
	struct rb_node *node;

	for (node = rb_first(&binf->pending_frees); node;) {
		enode = rb_entry(node, struct extent_node, node);
		node = rb_next(node);

		rb_erase(&enode->node, &binf->pending_frees);
		kfree(enode);
	}
}

/* XXX this should be generic */
#define min3_t(t, a, b, c) min3((t)(a), (t)(b), (t)(c))

/*
 * Allocate or free all the orders that make up a given arbitrary block
 * extent.  Today this is used by callers who know that the blocks for
 * the extent have already been pinned so we BUG on error.
 */
static void apply_extent(struct super_block *sb, bool alloc, u64 blk, u64 len)
{
	unsigned int blk_order;
	unsigned int blk_bit;
	unsigned int size;
	int order;
	int ret;

	trace_printk("applying extent blk %llu len %llu\n", blk, len);

	while (len) {
		/* buddy bit might be 0, len always has a bit set */
		blk_bit = buddy_bit(blk);
		blk_order = blk_bit ? ffs(blk_bit) - 1  : 0;
		order = min3_t(int, blk_order, fls64(len) - 1,
			       SCOUTFS_BUDDY_ORDERS - 1);
		size = 1 << order;

		trace_printk("applying blk %llu order %d\n", blk, order);

		if (alloc)
			ret = buddy_alloc(sb, &blk, order, -1);
		else
			ret = buddy_free(sb, blk, order);
		BUG_ON(ret);

		blk += size;
		len -= size;
	}
}

/*
 * The pending rbtree has recorded frees of stable data that we had to
 * wait until transaction commit to record.  Once these are tracked in
 * the allocator we can't use the allocator until the commit succeeds.
 * This is called by transaction commit to get these pending frees into
 * the current commit.  If it fails they pull them back out.
 */
int scoutfs_buddy_apply_pending(struct super_block *sb, bool alloc)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct extent_node *enode;
	struct rb_node *node;

	for (node = rb_first(&binf->pending_frees); node;) {
		enode = rb_entry(node, struct extent_node, node);
		node = rb_next(node);

		apply_extent(sb, alloc, enode->start, enode->len);
	}

	return 0;
}

/*
 * Free a given allocated extent.  The seq tells us which transaction
 * first allocated the extent.  If it was allocated in this transaction
 * then we can return it to the free buddy and that must succeed.
 *
 * If it was allocated in a previous transaction then we dirty the
 * blocks it will take to free it then record it in an rbtree.  The
 * rbtree entries are replayed into the dirty blocks as the transaction
 * commits.
 *
 * Buddy block numbers are preallocated and calculated from the radix
 * tree structure so we can ignore the block layer's calls to free buddy
 * blocks during cow.
 */
int scoutfs_buddy_free(struct super_block *sb, __le64 seq, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_info *binf = sbi->buddy_info;
	u64 unused;
	u64 blk;
	int ret;

	trace_printk("seq %llu blkno %llu order %d rsv %u\n",
		     le64_to_cpu(seq), blkno, order, buddy_blkno(super, blkno));

	/* no specific free tracking for buddy blocks */
	if (buddy_blkno(super, blkno))
		return 0;

	/* XXX corruption? */
	if (!device_blkno(super, blkno))
		return -EINVAL;

	blk = blkno - first_blkno(super);

	if (!valid_order(blk, order))
		return -EINVAL;

	mutex_lock(&binf->mutex);

	if (seq == super->hdr.seq) {
		ret = buddy_free(sb, blk, order);
		/*
		 * If this order was allocated in this transaction then its
		 * blocks should be pinned and we should always be able
		 * to free it.
		 */
		BUG_ON(ret);
	} else {
		ret = buddy_walk(sb, blk, -1, &unused) ?:
		      add_enode_extent(&binf->pending_frees, blk, 1 << order);
		if (ret == 0)
			trace_printk("added blk %llu order %d\n", blk, order);
		stack_cleanup(sb);
	}

	if (ret == 0)
		le64_add_cpu(&super->free_blocks, 1ULL << order);

	mutex_unlock(&binf->mutex);

	return ret;
}

/*
 * This is current only used to return partial extents from larger
 * allocations in this transaction.
 */
void scoutfs_buddy_free_extent(struct super_block *sb, u64 blkno, u64 count)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct scoutfs_super_block *super = &sbi->stable_super;
	u64 blk;

	BUG_ON(!device_blkno(super, blkno));

	blk = blkno - first_blkno(super);

	mutex_lock(&binf->mutex);

	apply_extent(sb, false, blkno - first_blkno(super), count);
	le64_add_cpu(&super->free_blocks, count);

	mutex_unlock(&binf->mutex);
}

/*
 * Return the number of block allocations since the last time the
 * counter was reset.  This count doesn't include dirty buddy blocks.
 */
unsigned int scoutfs_buddy_alloc_count(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;

	return atomic_read(&binf->alloc_count);
}

u64 scoutfs_buddy_bfree(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;
	struct scoutfs_super_block *super = &sbi->super;
	u64 ret;

	mutex_lock(&binf->mutex);
	ret = le64_to_cpu(super->free_blocks);
	mutex_unlock(&binf->mutex);

	return ret;
}

void scoutfs_buddy_committed(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;

	atomic_set(&binf->alloc_count, 0);
	destroy_pending_frees(sb);
}

int scoutfs_buddy_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_info *binf = sbi->buddy_info;
	u64 level_blocks[SCOUTFS_BUDDY_MAX_HEIGHT];
	u64 blocks;
	int i;

	/* first bit offsets in blocks are __le16 */
	BUILD_BUG_ON(SCOUTFS_BUDDY_ORDER0_BITS >= U16_MAX);

	/* bits need to be naturally aligned to long for _le bitops */
	BUILD_BUG_ON(offsetof(struct scoutfs_buddy_block, bits) &
		     (sizeof(long) - 1));

	binf = kzalloc(sizeof(struct buddy_info), GFP_KERNEL);
	if (!binf)
		return -ENOMEM;
	sbi->buddy_info = binf;

	mutex_init(&binf->mutex);
	atomic_set(&binf->alloc_count, 0);
	binf->pending_frees = RB_ROOT;

	/* calculate blocks at each level */
	blocks = DIV_ROUND_UP_ULL(last_blk(super) + 1,
				  SCOUTFS_BUDDY_ORDER0_BITS);
	for (i = 0; i < SCOUTFS_BUDDY_MAX_HEIGHT; i++) {
		level_blocks[i] = (blocks * 2);
		if (blocks == 1) {
			binf->max_height = i + 1;
			break;
		}
		blocks = DIV_ROUND_UP_ULL(blocks, SCOUTFS_BUDDY_SLOTS);
	}

	/* calculate device blkno of first block in each level */
	binf->level_blkno[binf->max_height - 1] = SCOUTFS_BUDDY_BLKNO;
	for (i = (binf->max_height - 2); i >= 0; i--) {
		binf->level_blkno[i] = binf->level_blkno[i + 1] +
				       level_blocks[i + 1];
	}

	/* calculate blk divisor to find slot at a given level */
	binf->level_div[1] = SCOUTFS_BUDDY_ORDER0_BITS;
	for (i = 2; i < binf->max_height; i++) {
		binf->level_div[i] = binf->level_div[i - 1] *
				     SCOUTFS_BUDDY_SLOTS;
	}

	for (i = 0; i < binf->max_height; i++)
		trace_printk("level %d div %llu blkno %llu blocks %llu\n",
			     i, binf->level_div[i], binf->level_blkno[i],
			     level_blocks[i]);

	return 0;
}

void scoutfs_buddy_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct buddy_info *binf = sbi->buddy_info;

	if (binf)
		WARN_ON_ONCE(!RB_EMPTY_ROOT(&binf->pending_frees));
	kfree(binf);
}

