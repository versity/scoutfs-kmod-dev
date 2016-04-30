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
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "buddy.h"
#include "msg.h"

/*
 * scoutfs uses buddy bitmaps to allocate block regions.  It has a nice
 * and simple implementation and reasonably small storage and memory
 * overhead, particularly in the pathological fragmented case, but
 * results in more rigid allocation constraints and fragmentation.
 *
 * The buddy allocator is build from a hierarchy of bitmaps for each
 * power of two order of blocks that we can allocate.  If a high order
 * buddy bit is set then all the lower order bits that it covers are
 * clear.
 *
 * At runtime all the bitmaps for all the orders are stored in a single
 * packed bitmap in memory.  We construct an array of pointers into the
 * big bitmap for each individual order bitmap.  This lets us easily
 * track modifications of all the order bitmaps with a second bitmap
 * which tracks fixed size chunks of the main bitmap.
 *
 * As a transaction is written the modified chunks of the main bitmap
 * are written to the tail of a preallocated ring of buddy blocks.
 * This turns noisy scattered bit modification operations into one large
 * contiguous block IO.
 *
 * We always write to the tail of the ring so we need to ensure that the
 * blocks at the tail don't contain live data.  As we mark each chunk of
 * the bitmap modified during a transaction we also sweep through the
 * bitmap finding another chunk that has never been modified by the
 * current sweep.  Eventually enough chunks are modified by transactions
 * to advance the sweep through the whole bitmap.  At this point we're
 * sure that all the blocks written to the tail during the sweep have to
 * contain the full bitmap.  By sizing the ring to 4x the bitmap size we
 * ensure that we'll finish the sweep in each half, ensuring that the
 * tail is always far enough behind the head to not overwrite live
 * chunks.
 *
 * The entire ring is read the first time the allocator is needed.
 * Today that's on mount for the entire system.  As we layer on
 * functionality we'll have multiple allocators and they'll be passed
 * around the cluster as mounts are given access.  As mounts get access
 * they only need to read the newly written blocks in the ring to bring
 * their stale allocator up to date with recent modifications written to
 * the tail.  The ring indices are full 64bits so that readers can
 * recognize when they need to read the whole ring.
 *
 * The allocator only covers the blocks after the ring blocks to the end
 * of the device.  When we move to multiple allocators each will cover a
 * fixed set of blocks excluding their ring blocks.  Resizing will
 * change the number of allocators needed to cover the device and will
 * modify the bits in a final allocator.  The bitmap modifications for
 * resizing would be written to ring blocks as usual.  Care will be
 * taken to recognize device sizes whose final blocks land in the ring
 * blocks.
 */

struct buddy_alloc {

	/*
	 * addr: pointer to le64 that contains the start of the bitmap
	 * addr_bit: full bit nr of lsb at addr
	 * addr_off: bit offset from addr to first order bit
	 * addr_size: bit count from addr of the order's bits
	 * first_set: first logical order bit offset that might be set
	 */
	struct buddy_order {
		__le64 *addr;
		long addr_bit;
		long addr_off;
		long addr_size;
		long first_set;
	} orders[64];

	int max_order;

	u64 orig_tail;
	long *modified;
	long modified_size;

	long reserved_chunks;

	__le64 *bitmap;
};

/* return the first device blkno covered by the allocator */
static u64 first_blkno(struct scoutfs_super_block *super)
{
	return SCOUTFS_BUDDY_BLKNO + le32_to_cpu(super->buddy_blocks);
}

/* return the number of blocks addressible by the allocator. */
static u64 covered_blocks(struct scoutfs_super_block *super)
{
	return le64_to_cpu(super->total_blocks) - first_blkno(super);
}

/* return the device block number of a ring index */
static u64 ring_blkno(struct scoutfs_super_block *super, u64 index)
{
	return SCOUTFS_BUDDY_BLKNO +
		do_div(index, le32_to_cpu(super->buddy_blocks));
}

/*
 * Find and mark the next chunk in the bitmap that has never been
 * written to the current half of the block ring.
 *
 * If we finish the sweep through the bitmap then we know that the most
 * current half of the ring contain the full bitmap and reading at the
 * head no longer has to start from the previous half.
 */
static bool modify_sweep_bit(struct scoutfs_super_block *super,
			     struct buddy_alloc *bud)
{
	bool did_set;
	long bit;

	bit = le32_to_cpu(super->buddy_sweep_bit);
	if (bit >= bud->modified_size)
		return false;

	bit = find_next_zero_bit(bud->modified, bud->modified_size, bit);
	if (bit < bud->modified_size) {
		set_bit(bit, bud->modified);
		bud->reserved_chunks--;
		bit++;
		did_set = true;
	} else {
		bit = bud->modified_size;
		did_set = false;
	}

	super->buddy_sweep_bit = cpu_to_le32(bit);

	/* advance head once we finish the sweep */
	if (bit == bud->modified_size) {
		u64 head = le64_to_cpu(super->buddy_head);
		u64 tail = le64_to_cpu(super->buddy_tail);
		u32 half = le32_to_cpu(super->buddy_blocks) / 2;

		if ((tail - head) > half)
			le64_add_cpu(&super->buddy_head, half);
	}

	return did_set;
}

/*
 * The caller has modified the given bit in the full buddy bitmap.  We
 * try to mark its chunk modified and advance the sweep through older
 * chunks.
 */
static void modified_bit(struct scoutfs_super_block *super,
			 struct buddy_alloc *bud, int order, long bit)
{
	struct buddy_order *ord = &bud->orders[order];

	bit = (ord->addr_bit + ord->addr_off + bit) / SCOUTFS_BUDDY_CHUNK_BITS;

	if (!test_and_set_bit(bit, bud->modified)) {
		bud->reserved_chunks--;
		modify_sweep_bit(super, bud);
	}
}

static int test_buddy_bit(struct buddy_alloc *bud, int order, long bit)
{
	struct buddy_order *ord = &bud->orders[order];

	return !!test_bit_le(ord->addr_off + bit, ord->addr);
}

static void set_buddy_bit(struct scoutfs_super_block *super,
			  struct buddy_alloc *bud, int order, long bit)
{
	struct buddy_order *ord = &bud->orders[order];

	set_bit_le(ord->addr_off + bit, ord->addr);
	ord->first_set = min(bit, ord->first_set);

	modified_bit(super, bud, order, bit);
}

static void clear_buddy_bit(struct scoutfs_super_block *super,
			    struct buddy_alloc *bud, int order, long bit)
{
	struct buddy_order *ord = &bud->orders[order];

	clear_bit_le(ord->addr_off + bit, ord->addr);
	if (ord->first_set == bit)
		ord->first_set++;

	modified_bit(super, bud, order, bit);
}

/* returns LONG_MAX when there are no bits set */
static long find_first_buddy_bit(struct buddy_alloc *bud, int order)
{
	struct buddy_order *ord = &bud->orders[order];
	long ret;

	ret = find_next_bit_le(ord->addr, ord->addr_size,
			       ord->addr_off + ord->first_set);
	if (ret >= ord->addr_size) {
		ret = LONG_MAX;
		ord->first_set = ord->addr_size - ord->addr_off;
	} else {
		ret -= ord->addr_off;
		ord->first_set = ret;
	}

	return ret;
}

/* test if the index is at the first block in either half of the ring */
static bool start_of_half(struct scoutfs_super_block *super, u64 index)
{
	u32 half = le32_to_cpu(super->buddy_blocks) / 2;

	return do_div(index, half) == 0;
}

/*
 * A buddy operation can modify bits at every order in the worst case.
 * (This is a bit overly conservative because high orders will
 * eventually share a chunk.)  We'll also try to mark old chunks
 * modified for each new chunk we modify.
 *
 * Before we modify the buddy bits we pin dirty blocks to make sure that
 * we have enough chunks to store the modified chunks.
 *
 * As we advance the tail to store new blocks we might wander into the
 * next half of the ring.  When that happens we reset the sweep bit so
 * that we'll start migrating chunks into this new half of the ring.
 *
 * This is called with the buddy mutex held.  It's the only thing that
 * does blocking work under the mutex so we could be more clever and
 * make the allocation fast path locking more efficient.
 */
static int reserve_block_chunks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_alloc *bud = sbi->bud;
	struct scoutfs_block *bl;
	u64 blkno;

	if (bud->reserved_chunks >= (bud->max_order * 2))
		return 0;

	blkno = ring_blkno(super, le64_to_cpu(super->buddy_tail));
	bl = scoutfs_new_block(sb, blkno);
	if (IS_ERR(bl))
		return PTR_ERR(bl);

	scoutfs_put_block(bl);
	bud->reserved_chunks += SCOUTFS_BUDDY_CHUNKS_PER_BLOCK;
	le64_add_cpu(&super->buddy_tail, 1);
	if (start_of_half(super, le64_to_cpu(super->buddy_tail)))
		super->buddy_sweep_bit = 0;

	return 0;
}

/*
 * Return the block number of an allocation of at least the requested
 * order.  If an allocation at the given order isn't free then first try
 * to satisfy the allocation with a part of a larger order, then return
 * a smaller allocation.
 *
 * The order of the allocation is returned.
 */
int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_alloc *bud = sbi->bud;
	int found;
	long bit;
	int ret;
	int i;

	if (WARN_ON_ONCE(order < 0 || order > bud->max_order))
		return -EINVAL;

	mutex_lock(&sbi->buddy_mutex);

	ret = reserve_block_chunks(sb);
	if (ret)
		goto out;

	/* search for larger and smaller orders */
	i = order;
	while (i >= 0) {
		bit = find_first_buddy_bit(bud, i);
		if (bit < LONG_MAX)
			break;

		if (i >= order && i < bud->max_order)
			i++;
		else if (i == bud->max_order)
			i = order - 1;
		else
			i--;
	}
	if (i < 0) {
		ret = -ENOSPC;
		goto out;
	}
	found = i;

	/* we'll succeed from this point on, use bit before mangling it */
	*blkno = first_blkno(super) + ((u64)bit << found);
	ret = min(found, order);

	/* always clear the found order */
	clear_buddy_bit(super, bud, found, bit);

	/* free right buddies if we're breaking up a larger order */
	for (bit <<= 1, i = found - 1; i >= order; i--, bit <<= 1)
		set_buddy_bit(super, bud, i, bit | 1);

out:
	mutex_unlock(&sbi->buddy_mutex);
	if (WARN_ON_ONCE(ret < 0))
		*blkno = 0;
	return ret;
}

/*
 * Free the aligned allocation of the given order at the given blkno to
 * the allocator.  We merge it into adjoining free space by looking for
 * free buddies as we increase the order.
 */
int scoutfs_buddy_free(struct super_block *sb, u64 blkno, int order)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_alloc *bud = sbi->bud;
	long bit;
	int ret;
	int i;

	if (WARN_ON_ONCE(order < 0 || order > bud->max_order) ||
	    WARN_ON_ONCE(((blkno + 1) << order) >= covered_blocks(super)))
		return -EINVAL;

	mutex_lock(&sbi->buddy_mutex);

	ret = reserve_block_chunks(sb);
	if (ret)
		goto out;

	bit = (blkno - first_blkno(super)) >> order;
	for (i = order; i <= bud->max_order; i++) {

		/* set bit free and finish when buddy isn't free */
		if (!test_buddy_bit(bud, i, bit ^ 1)) {
			set_buddy_bit(super, bud, i, bit);
			break;
		}

		/* otherwise clear buddy and try to set higher parent */
		clear_buddy_bit(super, bud, i, bit ^ 1);
		bit >>= 1;
	}

out:
	mutex_unlock(&sbi->buddy_mutex);
	return ret;
}

/*
 * We're writing a transaction.  The buddy allocator records chunks of
 * the main bitmap which have been modified during the transaction.  We
 * copy them to the pinned dirty blocks which will be written as part of
 * the transaction.  The bitmap of modified chunks and the old ring tail
 * are only reset when the transaction is successfully written.
 */
int scoutfs_dirty_buddy_chunks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_alloc *bud = sbi->bud;
	struct scoutfs_buddy_chunk *chunk;
	struct scoutfs_buddy_block *bb;
	struct scoutfs_block *bl;
	long bit;
	long ind;
	u64 tail;
	int i;

	/* short circuit a transaction with no modified chunks */
	if (bud->orig_tail == le64_to_cpu(super->buddy_tail))
		return 0;

	while (bud->reserved_chunks && modify_sweep_bit(super, bud))
		;

	for (tail = bud->orig_tail, bit = 0;
	     tail < le64_to_cpu(super->buddy_tail) && bit < bud->modified_size;
	     tail++) {

		bl = scoutfs_read_block(sb, ring_blkno(super, tail));
		if (WARN_ON_ONCE(IS_ERR(bl)))
			return PTR_ERR(bl);

		bb = bl->data;
		bb->hdr.seq = cpu_to_le64(tail);
		bb->nr_chunks = 0;

		for (i = 0; i < SCOUTFS_BUDDY_CHUNKS_PER_BLOCK; i++) {
			bit = find_next_bit(bud->modified, bud->modified_size,
					    bit);
			if (bit >= bud->modified_size)
				break;

			chunk = &bb->chunks[i];
			chunk->pos = cpu_to_le32(bit);
			ind = bit * SCOUTFS_BUDDY_CHUNK_LE64S;
			memcpy(chunk->bits, &bud->bitmap[ind],
			       SCOUTFS_BUDDY_CHUNK_BYTES);
			bit++;
		}

		bb->nr_chunks = i;
		scoutfs_zero_block_tail(bl, offsetof(struct scoutfs_buddy_block,
						     chunks[bb->nr_chunks]));
		scoutfs_put_block(bl);
	}

	/*
	 * Chunk reservation should have ensured that there's always room
	 * in the tail blocks for the modified chunks.
	 */
	if (WARN_ON_ONCE(bit < bud->modified_size))
		return -EIO;

	return 0;
}

void scoutfs_reset_buddy_chunks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct buddy_alloc *bud = sbi->bud;

	bud->orig_tail = le64_to_cpu(super->buddy_tail);
	memset(bud->modified, 0, DIV_ROUND_UP(bud->modified_size, 8));
}

static int check_buddy_fields(struct super_block *sb,
			      struct scoutfs_super_block *super)
{
	u32 blocks = le32_to_cpu(super->buddy_blocks);
	u32 half = blocks / 2;
	u64 head = le64_to_cpu(super->buddy_head);
	u64 tail = le64_to_cpu(super->buddy_tail);
	u64 buddy_bits;
	u64 chunk_bits;

	/* have to at least have two halves */
	if (blocks < 2) {
		scoutfs_info(sb, "buddy_blocks %lu must be at least 2", blocks);
		return -EIO;
	}

	/*
	 * insist that blocks be a multiple of two so that we don't have
	 * scary fencepost off by ones around the half calculations.
	 */
	if (blocks & 1) {
		scoutfs_info(sb, "buddy_blocks %lu isn't even", blocks);
		return -EIO;
	}

	/* shouldn't fill the device with buddy blocks */
	if (first_blkno(super) >= le64_to_cpu(super->total_blocks)) {
		scoutfs_info(sb, "buddy_blocks %lu must be at least 2", blocks);
		return -EIO;
	}

	/* can only reference a 32bit long's worth of buddy bits */
	buddy_bits = covered_blocks(super) * 2;
	if (buddy_bits >= INT_MAX) {
		scoutfs_info(sb, "device needs %llu > INT_MAX buddy bits",
			     buddy_bits);
		return -EIO;
	}

	/* need enough ring blocks for 4 full buddy copies */
	chunk_bits = blocks * SCOUTFS_BUDDY_CHUNKS_PER_BLOCK *
		     SCOUTFS_BUDDY_CHUNK_BITS;
	if (buddy_bits * 4 > chunk_bits) {
		scoutfs_info(sb, "only room for %llu bits in chunks, need %llu",
				chunk_bits, buddy_bits * 4);
		return -EIO;
	}

	if (head > tail) {
		scoutfs_info(sb, "buddy_head %llu > buddy_tail %llu",
			     head, tail);
		return -EIO;
	}

	/* tail can't wrap around into head */
	if ((tail - head) >= blocks) {
		scoutfs_info(sb, "buddy_tail %llu overlaps buddy_head %llu",
			     tail, head);
		return -EIO;
	}

	/* head always has to start one of the halves */
	if (!start_of_half(super, head)) {
		scoutfs_info(sb, "buddy_head %llu isn't multiple of half %u",
			     head, half);
		return -EIO;
	}

	return 0;
}

/*
 * Reconstruct the entire buddy bitmap by replaying the chunks that are
 * contained in the buddy block ring.
 *
 * The allocator doesn't cover the super blocks and ring blocks and is
 * initialized with all the device blocks marked free so that mkfs
 * doesn't have to write any chunks to initialize free space.
 *
 * We go a little nuts with variables to make it easier to read.
 */
int scoutfs_read_buddy_chunks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_buddy_chunk *chunk;
	struct scoutfs_buddy_block *bb;
	struct scoutfs_block *bl;
	struct buddy_alloc *bud;
	struct buddy_order *ord;
	u64 buddy_bits;
	u64 dev_blocks;
	u64 chunks;
	u64 head;
	u64 tail;
	long bits;
	long bit;
	long ind;
	int ret;
	int i;

	ret = check_buddy_fields(sb, super);
	if (ret)
		return ret;

	dev_blocks = covered_blocks(super);
	buddy_bits = dev_blocks * 2;
	chunks = DIV_ROUND_UP(buddy_bits, SCOUTFS_BUDDY_CHUNK_BITS);

	bud = kzalloc(sizeof(struct buddy_alloc), GFP_KERNEL);
	if (bud) {
		bud->bitmap = vzalloc(round_up(buddy_bits, 64) / 8);
		bud->modified = vzalloc(round_up(chunks, BITS_PER_LONG) / 8);
	}
	if (!bud || !bud->bitmap || !bud->modified) {
		ret = -ENOMEM;
		goto out;
	}
	sbi->bud = bud;

	bud->modified_size = chunks;

	/*
	 * Updating first_set across the orders would be tricky so we
	 * initialize it to 0 and suffer an initial expensive find_first
	 * call.
	 */
	bit = 0;
	bits = dev_blocks;
	for (i = 0; i < ARRAY_SIZE(bud->orders); i++) {
		ord = &bud->orders[i];

		ord->addr = &bud->bitmap[bit / 64];
		ord->addr_bit = bit & ~63ULL;
		ord->addr_off = bit & 63;
		ord->addr_size = ord->addr_off + bits;
		ord->first_set = 0;

		bit += bits;
		bits >>= 1;
		if (!bits)
			break;
	}
	bud->max_order = i;

	/*
	 * Initialize the allocator with the all the blocks covered by
	 * the fewest number of greatest order free allocations.  Ring
	 * replay will overwrite this.
	 */
	bit = 0;
	for (i = bud->max_order; i >= 0; i--) {
		ord = &bud->orders[i];

		if (ord->addr_off + bit == ord->addr_size)
			break;

		set_bit_le(ord->addr_off + bit, ord->addr);
		bit = (bit + 1) << 1;
	}

	head = le64_to_cpu(super->buddy_head);
	tail = le64_to_cpu(super->buddy_tail);
	while (head < tail) {
		bl = scoutfs_read_block(sb, ring_blkno(super, head));
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}

		bb = bl->data;
		if (le64_to_cpu(bb->hdr.seq) != head) {
			/* XXX corruption */
			ret = -EIO;
			scoutfs_put_block(bl);
			goto out;
		}

		for (i = 0; i < bb->nr_chunks; i++) {
			chunk = &bb->chunks[i];

			/* XXX check */
			ind = le32_to_cpu(chunk->pos) *
			      SCOUTFS_BUDDY_CHUNK_LE64S;

			memcpy(&bud->bitmap[ind], chunk->bits,
				SCOUTFS_BUDDY_CHUNK_BYTES);
		}
		scoutfs_put_block(bl);
		head++;
	}
	ret = 0;
out:
	if (ret) {
		if (bud) {
			vfree(bud->bitmap);
			vfree(bud->modified);
		}
	}
	return ret;
}
