/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/random.h>
#include <linux/log2.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "kvec.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"
#include "client.h"
#include "lock.h"
#include "file.h"
#include "extents.h"

/*
 * scoutfs uses extent items to track file data block mappings and free
 * blocks.
 *
 * Block allocation maintains a fixed number of allocation cursors that
 * remember the position of tasks within free regions.  This is very
 * simple and maintains contiguous allocations for simple streaming
 * writes.  It eventually won't be good enough and we'll spend
 * complexity on delalloc but we want to put that off as long as
 * possible.
 *
 * There's no unwritten extents.  As we dirty file data pages we track
 * their inodes.  Before we commit dirty metadata we write out all
 * tracked inodes.  This ensures that data is persistent before the
 * metadata that references it is visible.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - forced unmount with dirty data
 *  - direct IO
 *  - need trans around each bulk alloc
 */

/* more than enough for a few tasks per core on moderate hardware */
#define NR_CURSORS		4096
#define CURSOR_HASH_HEADS	(PAGE_SIZE / sizeof(void *) / 2)
#define CURSOR_HASH_BITS	ilog2(CURSOR_HASH_HEADS)

struct data_info {
	struct rw_semaphore alloc_rwsem;
	struct list_head cursor_lru;
	struct hlist_head cursor_hash[CURSOR_HASH_HEADS];
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

struct task_cursor {
	u64 blkno;
	struct hlist_node hnode;
	struct list_head list_head;
	struct task_struct *task;
	pid_t pid;
};

#if 0
/*
 * Block mapping items and their native decoded form can be pretty big.
 * Let's allocate them to avoid blowing the stack.
 */
struct block_mapping {
	/* native representation */
	unsigned long offline[DIV_ROUND_UP(SCOUTFS_BLOCK_MAPPING_BLOCKS,
					   BITS_PER_LONG)];
	u64 blknos[SCOUTFS_BLOCK_MAPPING_BLOCKS];

	/* encoded persistent item */
	u8 encoded[SCOUTFS_BLOCK_MAPPING_MAX_BYTES];
} __packed;

/*
 * We encode u64 blknos as a vlq zigzag encoded delta from the previous
 * blkno.  zigzag moves the sign bit down into the lsb so that small
 * negative values have very few bits set.  Then vlq outputs the least
 * significant set bits into bytes in groups of 7.
 *
 *   https://en.wikipedia.org/wiki/Variable-length_quantity
 *
 * The end result is that a series of blknos, which are limited by
 * device size and often allocated near each other, are encoded with a
 * handful of bytes.
 */
static unsigned zigzag_encode(u8 *bytes, u64 prev, u64 x)
{
	unsigned pos = 0;

	x -= prev;
	/* careful, relying on shifting extending the sign bit */
	x = (x << 1) ^ ((s64)x >> 63);

	do {
		bytes[pos++] = x & 127;
		x >>= 7;
	} while (x);

	bytes[pos - 1] |= 128;

	return pos;
}

static int zigzag_decode(u64 *res, u64 prev, u8 *bytes, unsigned len)
{
	unsigned shift = 0;
	int ret = -EIO;
	u64 x = 0;
	int i;
	u8 b;

	for (i = 0; i < len; i++) {
		b = bytes[i];
		x |= (u64)(b & 127) << shift;
		if (b & 128) {
			ret = i + 1;
			break;
		}
		shift += 7;

		/* falls through to return -EIO if we run out of bytes */
	}

	x = (x >> 1) ^ (-(x & 1));
	*res = prev + x;

	return ret;
}

/*
 * Block mappings are encoded into a byte stream.
 *
 * The first byte's low bits contains the last mapping index that will
 * be decoded.
 *
 * As we walk through the encoded blocks we add control bits to the
 * current control byte for the encoding of the block: zero, offline,
 * increment from prev, or zigzag encoding.
 *
 * When the control byte is full we start filling the next byte in the
 * output as the control byte for the coming blocks.  When we zigzag
 * encode blocks we add them to the output stream.  The result is an
 * interleaving of control bytes and zigzag blocks, when they're needed.
 *
 * In practice the typical mapping will have a zigzag for the first
 * block and then the rest will be described by the control bits.
 * Regions of sparse, advancing allocations, and offline are all
 * described only by control bits, getting us down to 2 bits per block.
 */
static unsigned encode_mapping(struct block_mapping *map)
{
	unsigned shift;
	unsigned len;
	u64 blkno;
	u64 prev;
	u8 *enc;
	u8 *ctl;
	u8 last;
	int ret;
	int i;

	enc = map->encoded;
	ctl = enc++;
	len = 1;

	/* find the last set block in the mapping */
	last = SCOUTFS_BLOCK_MAPPING_BLOCKS;
	for (i = 0; i < SCOUTFS_BLOCK_MAPPING_BLOCKS; i++) {
		if (map->blknos[i] || test_bit(i, map->offline))
			last = i;
	}

	if (last == SCOUTFS_BLOCK_MAPPING_BLOCKS)
		return 0;

	/* start with 6 bits of last */
	*ctl = last;
	shift = 6;

	prev = 0;
	for (i = 0; i <= last; i++) {
		blkno = map->blknos[i];


		if (shift == 8) {
			ctl = enc++;
			len++;
			*ctl = 0;
			shift = 0;
		}


		if (blkno == prev + 1)
			*ctl |= (SCOUTFS_BLOCK_ENC_INC << shift);
		else if (test_bit(i, map->offline))
			*ctl |= (SCOUTFS_BLOCK_ENC_OFFLINE << shift);
		else if (!blkno)
			*ctl |= (SCOUTFS_BLOCK_ENC_ZERO << shift);
		else {
			*ctl |= (SCOUTFS_BLOCK_ENC_DELTA << shift);

			ret = zigzag_encode(enc, prev, blkno);
			enc += ret;
			len += ret;
		}

		shift += 2;
		if (blkno)
			prev = blkno;
	}


	return len;
}

static int decode_mapping(struct block_mapping *map, int size)
{
	unsigned ctl_bits;
	u64 blkno;
	u64 prev;
	u8 *enc;
	u8 ctl;
	u8 last;
	int ret;
	int i;

	if (size < 1 || size > SCOUTFS_BLOCK_MAPPING_MAX_BYTES)
		return -EIO;

	memset(map->blknos, 0, sizeof(map->blknos));
	memset(map->offline, 0, sizeof(map->offline));

	enc = map->encoded;
	ctl = *(enc++);
	size--;

	/* start with lsb 6 bits of last */
	last = ctl & SCOUTFS_BLOCK_MAPPING_MASK;
	ctl >>= 6;
	ctl_bits = 2;

	prev = 0;
	for (i = 0; i <= last; i++) {

		if (ctl_bits == 0) {
			if (size-- == 0)
				return -EIO;
			ctl = *(enc++);
			ctl_bits = 8;
		}


		switch(ctl & SCOUTFS_BLOCK_ENC_MASK) {
		case SCOUTFS_BLOCK_ENC_INC:
			blkno = prev + 1;
			break;
		case SCOUTFS_BLOCK_ENC_OFFLINE:
			set_bit(i, map->offline);
			blkno = 0;
			break;
		case SCOUTFS_BLOCK_ENC_ZERO:
			blkno = 0;
			break;
		case SCOUTFS_BLOCK_ENC_DELTA:
			ret = zigzag_decode(&blkno, prev, enc, size);
			/* XXX corruption, ran out of encoded bytes */
			if (ret <= 0)
				return -EIO;
			enc += ret;
			size -= ret;
			break;
		}

		ctl >>= 2;
		ctl_bits -= 2;

		map->blknos[i] = blkno;
		if (blkno)
			prev = blkno;
	}

	/* XXX corruption: didn't use up all the bytes */
	if (size != 0)
		return -EIO;

	return 0;
}

static void init_mapping_key(struct scoutfs_key *key, u64 ino, u64 iblock)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skm_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_BLOCK_MAPPING_TYPE,
		.skm_base = cpu_to_le64(iblock >> SCOUTFS_BLOCK_MAPPING_SHIFT),
	};
}

static void init_free_key(struct scoutfs_key *key, u64 node_id, u64 full_bit,
			  u8 type)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_NODE_ZONE,
		.skf_node_id = cpu_to_le64(node_id),
		.sk_type = type,
		.skf_base = cpu_to_le64(full_bit >> SCOUTFS_FREE_BITS_SHIFT),
	};
}

/*
 * Mark the given segno as allocated.  We set its bit in a free segno
 * item, possibly after creating it.
 */
static int set_segno_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key key;
	struct kvec val;
	int bit = 0;
	int ret;

	init_free_key(&key, sbi->node_id, segno, SCOUTFS_FREE_BITS_SEGNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, &val, lock);
	if (ret && ret != -ENOENT)
		goto out;

	bit = segno & SCOUTFS_FREE_BITS_MASK;

	if (ret == -ENOENT) {
		memset(&frb, 0, sizeof(frb));
		set_bit_le(bit, &frb);
		ret = scoutfs_item_create(sb, &key, &val, lock);
		goto out;
	}

	if (test_and_set_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	ret = scoutfs_item_update(sb, &key, &val, lock);
out:
	trace_scoutfs_data_set_segno_free(sb, segno, le64_to_cpu(key.skf_base),
					  bit, ret);
	return ret;
}

/*
 * Create a new free blkno item with all but the given blkno marked
 * free.  We use the caller's key so they can delete it later if they
 * need to.
 */
static int create_blkno_free(struct super_block *sb, u64 blkno,
			     struct scoutfs_key *key)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct kvec val;
	int bit;

	init_free_key(key, sbi->node_id, blkno, SCOUTFS_FREE_BITS_BLKNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));

	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	memset(&frb, 0xff, sizeof(frb));
	clear_bit_le(bit, frb.bits);

	return scoutfs_item_create(sb, key, &val, lock);
}

/*
 * Mark the first block in the segno as allocated.  This isn't a general
 * purpose bit clear.  It knows that it's only called from allocation
 * that found the bit so it won't create the segno item.
 *
 * And because it's allocating a block in the segno, it also has to
 * create a free block item that marks the rest of the blknos in segno
 * as free.
 *
 * It deletes the free segno item if it clears the last bit.
 */
static int clear_segno_free(struct super_block *sb, u64 segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key b_key;
	struct scoutfs_key key;
	struct kvec val;
	u64 blkno;
	int bit;
	int ret;

	init_free_key(&key, sbi->node_id, segno, SCOUTFS_FREE_BITS_SEGNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, &val, lock);
	if (ret) {
		/* XXX corruption, caller saw item.. should still exist */
		if (ret == -ENOENT)
			ret = -EIO;
		goto out;
	}

	/* XXX corruption, bit couldn't have been set */
	bit = segno & SCOUTFS_FREE_BITS_MASK;
	if (!test_and_clear_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	/* create the new blkno item, we can safely delete it */
	blkno = segno << SCOUTFS_SEGMENT_BLOCK_SHIFT;
	ret = create_blkno_free(sb, blkno, &b_key);
	if (ret)
		goto out;

	if (bitmap_empty((long *)frb.bits, SCOUTFS_FREE_BITS_BITS))
		ret = scoutfs_item_delete(sb, &key, lock);
	else
		ret = scoutfs_item_update(sb, &key, &val, lock);
	if (ret)
		scoutfs_item_delete_dirty(sb, &b_key);
out:
	return ret;
}

/*
 * Mark the given blkno free.  Set its bit in its free blkno item,
 * possibly after creating it.  If all the bits are set we try to mark
 * its segno free and delete the blkno item.
 */
static int set_blkno_free(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key key;
	struct kvec val;
	u64 segno;
	int bit;
	int ret;

	/* get the specified item */
	init_free_key(&key, sbi->node_id, blkno, SCOUTFS_FREE_BITS_BLKNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, &val, lock);
	if (ret && ret != -ENOENT)
		goto out;

	bit = blkno & SCOUTFS_FREE_BITS_MASK;

	if (ret == -ENOENT) {
		memset(&frb, 0, sizeof(frb));
		set_bit_le(bit, &frb);
		ret = scoutfs_item_create(sb, &key, &val, lock);
		goto out;
	}

	if (test_and_set_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	if (!bitmap_full((long *)frb.bits, SCOUTFS_FREE_BITS_BITS)) {
		ret = scoutfs_item_update(sb, &key, &val, lock);
		goto out;
	}

	/* dirty so we can safely delete if set segno fails */
	ret = scoutfs_item_dirty(sb, &key, lock);
	if (ret)
		goto out;

	segno = blkno >> SCOUTFS_SEGMENT_BLOCK_SHIFT;
	ret = set_segno_free(sb, segno);
	if (ret)
		goto out;

	scoutfs_item_delete_dirty(sb, &key);
	ret = 0;
out:
	return ret;
}

/*
 * Mark the given blkno as allocated.  This is working on behalf of a
 * caller who just saw the item, it must exist.  We delete the free
 * blkno item if all its bits are empty.
 */
static int clear_blkno_free(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key key;
	struct kvec val;
	int bit;
	int ret;

	/* get the specified item */
	init_free_key(&key, sbi->node_id, blkno, SCOUTFS_FREE_BITS_BLKNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));
	ret = scoutfs_item_lookup_exact(sb, &key, &val, lock);
	if (ret) {
		/* XXX corruption, bits should have existed */
		if (ret == -ENOENT)
			ret = -EIO;
		goto out;
	}

	/* XXX corruption, bit couldn't have been set */
	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	if (!test_and_clear_bit_le(bit, frb.bits)) {
		ret = -EIO;
		goto out;
	}

	if (bitmap_empty((long *)frb.bits, SCOUTFS_FREE_BITS_BITS))
		ret = scoutfs_item_delete(sb, &key, lock);
	else
		ret = scoutfs_item_update(sb, &key, &val, lock);
out:
	return ret;
}

/*
 * In each iteration iblock is the logical block and i is the index into
 * blknos array and the bit in the offline bitmap.  The iteration won't
 * advance past the last logical block.
 */
#define for_each_block(i, iblock, last)					\
	for (i = iblock & SCOUTFS_BLOCK_MAPPING_MASK;			\
	     i < SCOUTFS_BLOCK_MAPPING_BLOCKS && iblock <= (last);	\
	     i++, iblock++)
#endif

static void init_file_extent_key(struct scoutfs_key *key, u64 ino, u64 last)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skfe_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_FILE_EXTENT_TYPE,
		.skfe_last = cpu_to_le64(last),
	};
}

static void init_free_extent_key(struct scoutfs_key *key, u8 type, u64 node_id,
				 u64 major, u64 minor)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_NODE_ZONE,
		.sknf_node_id = cpu_to_le64(node_id),
		.sk_type = type,
		.sknf_major = cpu_to_le64(major),
		.sknf_minor = cpu_to_le64(minor),
	};
}

static int init_extent_from_item(struct scoutfs_extent *ext,
				 struct scoutfs_key *key,
				 struct scoutfs_file_extent *fex)
{
	u64 owner;
	u64 start;
	u64 map;
	u64 len;
	u8 flags;

	if (key->sk_type != SCOUTFS_FILE_EXTENT_TYPE &&
	    key->sk_type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	    key->sk_type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		return -EIO; /* XXX corruption, unknown key type */

	if (key->sk_type == SCOUTFS_FILE_EXTENT_TYPE) {
		owner = le64_to_cpu(key->skfe_ino);
		len = le64_to_cpu(fex->len);
		start = le64_to_cpu(key->skfe_last) - len + 1;
		map = le64_to_cpu(fex->blkno);
		flags = fex->flags;

	} else {
		owner = le64_to_cpu(key->sknf_node_id);
		start = le64_to_cpu(key->sknf_major);
		len = le64_to_cpu(key->sknf_minor);
		if (key->sk_type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
			swap(start, len);
		start -= len - 1;
		map = 0;
		flags = 0;
	}

	return scoutfs_extent_init(ext, key->sk_type, owner, start, len, map,
				   flags);
}

/*
 * Read and write file extent and free extent items.
 *
 * File extents and free extents are indexed by the last position in the
 * extent so that we can find intersections with _next.
 *
 * We also index free extents by their length.  We implement that by
 * keeping their _BLOCKS_ item in sync with the primary _BLKNO_ item
 * that callers operate on.
 */
static int data_extent_io(struct super_block *sb, int op,
			  struct scoutfs_extent *ext, void *data)
{
	struct scoutfs_lock *lock = data;
	struct scoutfs_file_extent fex;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct kvec val;
	bool mirror = false;
	u8 mirror_type;
	u8 mirror_op = 0;
	int expected;
	int ret;
	int err;

	if (WARN_ON_ONCE(ext->type != SCOUTFS_FILE_EXTENT_TYPE &&
			 ext->type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
			 ext->type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE))
		return -EINVAL;

	if (ext->type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	    (op == SEI_INSERT || op == SEI_DELETE)) {
		mirror = true;
		mirror_type = SCOUTFS_FREE_EXTENT_BLOCKS_TYPE;
		mirror_op = op == SEI_INSERT ? SEI_DELETE : SEI_INSERT;
	}

	if (ext->type == SCOUTFS_FILE_EXTENT_TYPE) {
		init_file_extent_key(&key, ext->owner,
				     ext->start + ext->len - 1);
		init_file_extent_key(&last, ext->owner, U64_MAX);
		fex.blkno = cpu_to_le64(ext->map);
		fex.len = cpu_to_le64(ext->len);
		fex.flags = ext->flags;
		kvec_init(&val, &fex, sizeof(fex));
	} else {
		init_free_extent_key(&key, ext->type, ext->owner,
				     ext->start + ext->len - 1, ext->len);
		if (ext->type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
			swap(key.sknf_major, key.sknf_minor);
		init_free_extent_key(&last, ext->type, ext->owner,
				     U64_MAX, U64_MAX);
		kvec_init(&val, NULL, 0);
	}

	if (op == SEI_NEXT) {
		expected = val.iov_len;
		ret = scoutfs_item_next(sb, &key, &last, &val, lock);
		if (ret >= 0 && ret != expected)
			ret = -EIO;
		if (ret == expected)
			ret = init_extent_from_item(ext, &key, &fex);

	} else if (op == SEI_INSERT) {
		ret = scoutfs_item_create(sb, &key, &val, lock);

	} else if (op == SEI_DELETE) {
		ret = scoutfs_item_delete(sb, &key, lock);

	} else {
		ret = WARN_ON_ONCE(-EINVAL);
	}

	if (ret == 0 && mirror) {
		swap(ext->type, mirror_type);
		ret = data_extent_io(sb, op, ext, data);
		swap(ext->type, mirror_type);
		if (ret) {
			err = data_extent_io(sb, mirror_op, ext, data);
			BUG_ON(err);
		}
	}

	return ret;
}

/*
 * Find and remove or mark offline the next extent that intersects with
 * the caller's range.  The caller is responsible for transactions and
 * locks.
 *
 * Returns:
 *  - -errno on errors
 *  - 0 if there are no more extents to stop iteration
 *  - +iblock of next logical block to truncate the next block from
 *
 * Since our extents are block granular we can never have > S64_MAX
 * iblock values.  Returns -ENOENT if no extent was found and -errno on
 * errors.
 */
static s64 truncate_one_extent(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_extent next;
	struct scoutfs_extent rem;
	struct scoutfs_extent fr;
	struct scoutfs_extent ofl;
	bool rem_fr = false;
	bool add_rem = false;
	s64 ret;
	int err;

	scoutfs_extent_init(&next, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &next, lock);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	trace_scoutfs_data_truncate_next(sb, &next);

	scoutfs_extent_init(&rem, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, last - iblock + 1, 0, 0);
	if (!scoutfs_extent_intersection(&rem, &next)) {
		ret = 0;
		goto out;
	}

	trace_scoutfs_data_truncate_remove(sb, &rem);

	/* nothing to do if the extent's already offline */
	if (offline && (rem.flags & SEF_OFFLINE)) {
		ret = 1;
		goto out;
	}

	/* free an allocated mapping */
	if (rem.map) {
		scoutfs_extent_init(&fr, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id, rem.map, rem.len, 0, 0);
		ret = scoutfs_extent_add(sb, data_extent_io, &fr,
					 sbi->node_id_lock);
		if (ret)
			goto out;
		rem_fr = true;
	}

	/* remove the mapping */
	ret = scoutfs_extent_remove(sb, data_extent_io, &rem, lock);
	if (ret)
		goto out;
	add_rem = true;

	/* add an offline extent */
	if (offline) {
		scoutfs_extent_init(&ofl, SCOUTFS_FILE_EXTENT_TYPE, rem.owner,
				    rem.start, rem.len, 0, SEF_OFFLINE);
		trace_scoutfs_data_truncate_offline(sb, &ofl);
		ret = scoutfs_extent_add(sb, data_extent_io, &ofl, lock);
		if (ret)
			goto out;
	}

	scoutfs_inode_add_onoff(inode, rem.map ? -rem.len : 0,
				(rem.flags & SEF_OFFLINE ? -rem.len : 0) +
				(offline ? ofl.len : 0));
	ret = 1;
out:
	if (ret < 0) {
		err = 0;
		if (add_rem)
			err |= scoutfs_extent_add(sb, data_extent_io, &rem,
						  lock);
		if (rem_fr)
			err |= scoutfs_extent_remove(sb, data_extent_io, &fr,
						     sbi->node_id_lock);
		BUG_ON(err); /* inconsistency, could save/restore */

	} else if (ret > 0) {
		ret = rem.start + rem.len;
	}

	return ret;
}

/*
 * Free blocks inside the logical block range from 'iblock' to 'last',
 * inclusive.
 *
 * If 'offline' is given then blocks are freed an offline mapping is
 * left behind.  Only blocks that have been allocated can be marked
 * offline.
 *
 * This is the low level extent item manipulation code.  We hold and
 * release the transaction so the caller doesn't have to deal with
 * partial progress.
 *
 * If the inode is provided then we update its tracking of the online
 * and offline blocks.  If it's not provided then the inode is being
 * destroyed and we don't have to keep it updated.
 */
int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	s64 ret = 0;

	WARN_ON_ONCE(inode && !mutex_is_locked(&inode->i_mutex));

	/* clamp last to the last possible block? */
	if (last > SCOUTFS_BLOCK_MAX)
		last = SCOUTFS_BLOCK_MAX;

	trace_scoutfs_data_truncate_items(sb, iblock, last, offline);

	if (WARN_ON_ONCE(last < iblock))
		return -EINVAL;

	while (iblock <= last) {
		ret = scoutfs_hold_trans(sb, SIC_TRUNC_EXTENT());
		if (ret)
			break;

		down_write(&datinf->alloc_rwsem);
		ret = truncate_one_extent(sb, inode, ino, iblock, last,
					  offline, lock);
		up_write(&datinf->alloc_rwsem);
		scoutfs_release_trans(sb);

		if (ret <= 0)
			break;

		iblock = ret;
		ret = 0;
	}

	return ret;
}

static inline struct hlist_head *cursor_head(struct data_info *datinf,
					     struct task_struct *task,
					     pid_t pid)
{
	unsigned h = hash_ptr(task, CURSOR_HASH_BITS) ^
		     hash_long(pid, CURSOR_HASH_BITS);

	return &datinf->cursor_hash[h];
}

static struct task_cursor *search_head(struct hlist_head *head,
				       struct task_struct *task, pid_t pid)
{
	struct task_cursor *curs;

	hlist_for_each_entry(curs, head, hnode) {
		if (curs->task == task && curs->pid == pid)
			return curs;
	}

	return NULL;
}

static void destroy_cursors(struct data_info *datinf)
{
	struct task_cursor *curs;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < CURSOR_HASH_HEADS; i++) {
		hlist_for_each_entry_safe(curs, tmp, &datinf->cursor_hash[i],
					  hnode) {
			hlist_del_init(&curs->hnode);
			kfree(curs);
		}
	}
}

/*
 * These cheesy cursors are only meant to encourage nice IO patterns for
 * concurrent tasks either streaming large file writes or creating lots
 * of small files.  It will do very poorly in many other situations.  To
 * do better we'd need to go further down the road to delalloc and take
 * more surrounding context into account.
 */
static struct task_cursor *get_cursor(struct data_info *datinf)
{
	struct task_struct *task = current;
	pid_t pid = current->pid;
	struct hlist_head *head;
	struct task_cursor *curs;

	head = cursor_head(datinf, task, pid);
	curs = search_head(head, task, pid);
	if (!curs) {
		curs = list_last_entry(&datinf->cursor_lru,
				       struct task_cursor, list_head);
		trace_scoutfs_data_get_cursor(curs, task, pid);
		hlist_del_init(&curs->hnode);
		curs->task = task;
		curs->pid = pid;
		hlist_add_head(&curs->hnode, head);
		curs->blkno = 0;
	}

	list_move(&curs->list_head, &datinf->cursor_lru);

	return curs;
}

static int bulk_alloc(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_extent ext;
	u64 *segnos = NULL;
	int ret = 0;
	int i;

	segnos = scoutfs_client_bulk_alloc(sb);
	if (IS_ERR(segnos)) {
		ret = PTR_ERR(segnos);
		goto out;
	}

	for (i = 0; segnos[i]; i++) {
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id,
				    segnos[i] << SCOUTFS_SEGMENT_BLOCK_SHIFT,
				    SCOUTFS_SEGMENT_BLOCKS, 0, 0);
		trace_scoutfs_data_bulk_alloc(sb, &ext);
		ret = scoutfs_extent_add(sb, data_extent_io, &ext,
					 sbi->node_id_lock);
		if (ret)
			break;
	}

out:
	if (!IS_ERR_OR_NULL(segnos))
		kfree(segnos);

	/* XXX don't orphan segnos on error, crash recovery with server */

	return ret;
}

#if 0
/*
 * Find the free bit item that contains the blkno and return the next blkno
 * set starting with this blkno.
 *
 * Returns -ENOENT if there's no free blknos at or after the given blkno.
 */
static int find_free_blkno(struct super_block *sb, u64 blkno, u64 *blkno_ret)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key key;
	struct kvec val;
	int ret;
	int bit;

	init_free_key(&key, sbi->node_id, blkno, SCOUTFS_FREE_BITS_BLKNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));

	ret = scoutfs_item_lookup_exact(sb, &key, &val, lock);
	if (ret < 0)
		goto out;

	bit = blkno & SCOUTFS_FREE_BITS_MASK;
	bit = find_next_bit_le(frb.bits, SCOUTFS_FREE_BITS_BITS, bit);
	if (bit >= SCOUTFS_FREE_BITS_BITS) {
		ret = -ENOENT;
		goto out;
	}

	*blkno_ret = (le64_to_cpu(key.skf_base) << SCOUTFS_FREE_BITS_SHIFT) +
		     bit;
	ret = 0;
out:
	return ret;
}

/*
 * Find a free segno to satisfy allocation by finding the first bit set
 * in the first free segno item.
 */
static int find_free_segno(struct super_block *sb, u64 *segno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock = sbi->node_id_lock;
	struct scoutfs_free_bits frb;
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	struct kvec val;
	int bit;
	int ret;

	init_free_key(&key, sbi->node_id, 0, SCOUTFS_FREE_BITS_SEGNO_TYPE);
	init_free_key(&last_key, sbi->node_id, U64_MAX,
		      SCOUTFS_FREE_BITS_SEGNO_TYPE);
	kvec_init(&val, &frb, sizeof(struct scoutfs_free_bits));

	ret = scoutfs_item_next(sb, &key, &last_key, &val, lock);
	if (ret < 0)
		goto out;

	bit = find_next_bit_le(frb.bits, SCOUTFS_FREE_BITS_BITS, 0);
	/* XXX corruption, shouldn't see empty items */
	if (bit >= SCOUTFS_FREE_BITS_BITS) {
		ret = -EIO;
		goto out;
	}

	*segno = (le64_to_cpu(key.skf_base) << SCOUTFS_FREE_BITS_SHIFT) + bit;
	ret = 0;
out:
	return ret;
}
#endif

/*
 * Allocate a single block for the logical block offset in the file.
 * The caller tells us if the block was offline or not.  We modify the
 * extent items and the caller will search for the resulting extent.
 *
 * We try to encourage contiguous allocation by having per-task cursors
 * that track large extents.  Each new allocating task will get a new
 * extent.
 */
/* XXX initially tied to segment size, should be a lot larger */
#define LARGE_EXTENT_BLOCKS SCOUTFS_SEGMENT_BLOCKS
static int find_alloc_block(struct super_block *sb, struct inode *inode,
			    u64 iblock, bool was_offline,
			    struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_extent ext;
	struct scoutfs_extent ofl;
	struct scoutfs_extent fr;
	struct task_cursor *curs;
	bool add_ofl = false;
	bool add_fr = false;
	int err;
	int ret;

	down_write(&datinf->alloc_rwsem);

	curs = get_cursor(datinf);

	trace_scoutfs_data_find_alloc_block_curs(sb, curs, curs->blkno);

	/* see if our cursor is still free */
	if (curs->blkno) {
		/* look for the extent that overlaps our iblock */
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id, curs->blkno, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext,
					  sbi->node_id_lock);
		if (ret && ret != -ENOENT)
			goto out;

		if (ret == 0)
			trace_scoutfs_data_alloc_block_cursor(sb, &ext);

		/* find a new large extent if our cursor isn't free */
		if (ret < 0 || ext.start > curs->blkno)
			curs->blkno = 0;
	}

	/* try to find a new large extent, possibly asking for more */
	while (curs->blkno == 0) {
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLOCKS_TYPE,
				    sbi->node_id, 0, 2 * LARGE_EXTENT_BLOCKS,
				    0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext,
					  sbi->node_id_lock);
		if (ret && ret != -ENOENT)
			goto out;

		/* XXX should try to look for smaller free extents :/ */

		/*
		 * set our cursor to the aligned start of a large extent
		 * We'll then remove it and the next aligned free large
		 * extent will start much later.  This stops us from
		 * constantly setting cursors to the start of a large
		 * free extent that keeps have its start allocated.
		 */
		if (ret == 0) {
			trace_scoutfs_data_alloc_block_free(sb, &ext);
			curs->blkno = ALIGN(ext.start, LARGE_EXTENT_BLOCKS);
			break;
		}

		/* try to get allocation from the server if we're out */
		ret = bulk_alloc(sb);
		if (ret < 0)
			goto out;
	}


	/* remove the free block we're using */
	scoutfs_extent_init(&fr, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
			    sbi->node_id, curs->blkno, 1, 0, 0);
	ret = scoutfs_extent_remove(sb, data_extent_io, &fr, sbi->node_id_lock);
	if (ret)
		goto out;
	add_fr = true;

	/* remove an offline file extent */
	if (was_offline) {
		scoutfs_extent_init(&ofl, SCOUTFS_FILE_EXTENT_TYPE, ino,
				    iblock, 1, 0, SEF_OFFLINE);
		ret = scoutfs_extent_remove(sb, data_extent_io, &ofl, lock);
		if (ret)
			goto out;
		add_ofl = true;
	}

	/* add (and hopefully merge!) the new allocation */
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, 1, curs->blkno, 0);
	trace_scoutfs_data_alloc_block(sb, &ext);
	ret = scoutfs_extent_add(sb, data_extent_io, &ext, lock);
	if (ret)
		goto out;

	scoutfs_inode_add_onoff(inode, 1, was_offline ? -1ULL : 0);

	/* set cursor to next block, clearing if we finish a large extent */
	BUILD_BUG_ON(!is_power_of_2(LARGE_EXTENT_BLOCKS));
	curs->blkno++;
	if ((curs->blkno & (LARGE_EXTENT_BLOCKS - 1)) == 0)
		curs->blkno = 0;

	ret = 0;
out:
	if (ret) {
		err = 0;
		if (add_ofl)
			err |= scoutfs_extent_add(sb, data_extent_io, &ofl,
						  lock);
		if (add_fr)
			err |= scoutfs_extent_add(sb, data_extent_io, &fr,
						  sbi->node_id_lock);
		BUG_ON(err); /* inconsistency */
	}

	up_write(&datinf->alloc_rwsem);

	trace_scoutfs_data_find_alloc_block_ret(sb, ret);
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_extent ext;
	struct scoutfs_lock *lock;
	u64 offset;
	int ret;

	WARN_ON_ONCE(create && !mutex_is_locked(&inode->i_mutex));

	lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!lock))
		return -EINVAL;

restart:
	/* look for the extent that overlaps our iblock */
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
			    scoutfs_ino(inode), iblock, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
	if (ret && ret != -ENOENT)
		goto out;

	if (ret == 0)
		trace_scoutfs_data_get_block_next(sb, &ext);

	/* didn't find an extent or it's past our iblock */
	if (ret == -ENOENT || ext.start > iblock)
		memset(&ext, 0, sizeof(ext));

	if (ext.len)
		trace_scoutfs_data_get_block_intersection(sb, &ext);

	/* fail read and write if it's offline and we're not staging */
	if ((ext.flags & SEF_OFFLINE) && !si->staging) {
		ret = -EINVAL;
		goto out;
	}

	/* try to allocate if we're writing */
	if (create && !ext.map) {
		/*
		 * XXX can blow the transaction here.. need to back off
		 * and try again if we've already done a bulk alloc in
		 * our transaction.
		 */
		ret = find_alloc_block(sb, inode, iblock,
				       ext.flags & SEF_OFFLINE, lock);
		if (ret)
			goto out;
		set_buffer_new(bh);
		/* restart the search now that it's been allocated */
		goto restart;
	}

	/* map the bh and set the size to as much of the extent as we can */
	if (ext.map) {
		offset = iblock - ext.start;
		map_bh(bh, inode->i_sb, ext.map + offset);
		bh->b_size = min_t(u64, bh->b_size,
				   (ext.len - offset) << SCOUTFS_BLOCK_SHIFT);
	}
	ret = 0;
out:
	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				ret, bh->b_blocknr, bh->b_size);
	return ret;
}

/*
 * This is almost never used.  We can't block on a cluster lock while
 * holding the page lock because lock invalidation gets the page lock
 * while blocking locks.  If we can't use an existing lock then we drop
 * the page lock and try again.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int flags;
	int ret;

	flags = SCOUTFS_LKF_REFRESH_INODE | SCOUTFS_LKF_NONBLOCK;
	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, flags, inode, &inode_lock);
	if (ret < 0) {
		unlock_page(page);
		if (ret == -EAGAIN) {
			flags &= ~SCOUTFS_LKF_NONBLOCK;
			ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, flags, inode,
					   &inode_lock);
			if (ret == 0) {
				scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
				ret = AOP_TRUNCATED_PAGE;
			}
		}
		return ret;
	}

	ret = mpage_readpage(page, scoutfs_get_block);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
	return ret;
}

static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret)
		return ret;

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
	return ret;
}

static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, scoutfs_get_block, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, scoutfs_get_block);
}

/* fsdata allocated in write_begin and freed in write_end */
struct write_begin_data {
	struct list_head ind_locks;
	struct scoutfs_lock *lock;
};

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd;
	u64 ind_seq;
	int ret;

	trace_scoutfs_write_begin(sb, scoutfs_ino(inode), (__u64)pos, len);

	wbd = kmalloc(sizeof(struct write_begin_data), GFP_NOFS);
	if (!wbd)
		return -ENOMEM;

	INIT_LIST_HEAD(&wbd->ind_locks);
	*fsdata = wbd;

	wbd->lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!wbd->lock)) {
		ret = -EINVAL;
		goto out;
	}

	do {
		ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
		      scoutfs_inode_index_prepare(sb, &wbd->ind_locks, inode,
						  true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, &wbd->ind_locks,
							ind_seq,
							SIC_WRITE_BEGIN());
	} while (ret > 0);
	if (ret < 0)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode, wbd->lock);
	if (ret == 0)
		ret = block_write_begin(mapping, pos, len, flags, pagep,
					scoutfs_get_block);
	if (ret)
		scoutfs_release_trans(sb);
out:
	if (ret) {
		scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
		kfree(wbd);
	}
        return ret;
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd = fsdata;
	int ret;

	trace_scoutfs_write_end(sb, scoutfs_ino(inode), page->index, (u64)pos,
				len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		if (!si->staging) {
			scoutfs_inode_set_data_seq(inode);
			scoutfs_inode_inc_data_version(inode);
		}

		scoutfs_update_inode_item(inode, wbd->lock, &wbd->ind_locks);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
	kfree(wbd);
	return ret;
}

struct pending_fiemap {
	u64 logical;
	u64 phys;
	u64 size;
	u32 flags;
};

#if 0
/*
 * The caller is iterating over mapped blocks.  We merge the current
 * pending fiemap entry with the next block if we can.  If we can't
 * merge then we fill the current entry and start on the next.  We also
 * fill the pending mapping if the caller specifically tells us that
 * this will be the last call.
 *
 * returns 0 to continue, 1 to stop, and -errno to stop with error.
 */
static int merge_or_fill(struct fiemap_extent_info *fieinfo,
			 struct pending_fiemap *pend, u64 logical, u64 phys,
			 bool offline, bool last)
{
	u32 flags = offline ? FIEMAP_EXTENT_UNKNOWN : 0;
	int ret;

	/* merge if we can, returning if we don't have to fill last */
	if (pend->logical + pend->size == logical &&
	    ((pend->phys == 0 && phys == 0) ||
	     (pend->phys + pend->size == phys)) &&
	    pend->flags == flags) {
		pend->size += SCOUTFS_BLOCK_SIZE;
		if (!last)
			return 0;
	}

	if (pend->size) {
		if (last)
			pend->flags |= FIEMAP_EXTENT_LAST;

		/* returns 1 to end, including if we passed in _LAST */
		ret = fiemap_fill_next_extent(fieinfo, pend->logical,
					      pend->phys, pend->size,
					      pend->flags);
		if (ret != 0)
			return ret;
	}

	pend->logical = logical;
	pend->phys = phys;
	pend->size = SCOUTFS_BLOCK_SIZE;
	pend->flags = flags;

	return 0;
}
#endif

/*
 * Return all the file's extents whose blocks overlap with the caller's
 * byte region.  We set _LAST on the last extent and _UNKNOWN on offline
 * extents.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_extent ext;
	loff_t i_size;
	u64 blk_off;
	u64 logical = 0;
	u64 phys = 0;
	u64 size = 0;
	u32 flags = 0;
	int ret;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	/* XXX overkill? */
	mutex_lock(&inode->i_mutex);

	/* stop at i_size, we don't allocate outside i_size */
	i_size = i_size_read(inode);
	if (i_size == 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, 0, inode, &inode_lock);
	if (ret)
		goto out;

	blk_off = start >> SCOUTFS_BLOCK_SHIFT;

	for (;;) {
		scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
				    scoutfs_ino(inode), blk_off, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext, inode_lock);
		/* fiemap will return last and stop when we see enoent */
		if (ret < 0 && ret != -ENOENT)
			break;

		if (ret == 0)
			trace_scoutfs_data_fiemap_extent(sb, &ext);

		if (size) {
			if (ret == -ENOENT)
				flags |= FIEMAP_EXTENT_LAST;
			ret = fiemap_fill_next_extent(fieinfo, logical, phys,
						      size, flags);
			if (ret || (logical + size >= (start + len))) {
				if (ret == 1)
					ret = 0;
				break;
			}
		}

		logical = ext.start << SCOUTFS_BLOCK_SHIFT;
		phys = ext.map << SCOUTFS_BLOCK_SHIFT;
		size = ext.len << SCOUTFS_BLOCK_SHIFT;
		flags = (ext.flags & SEF_OFFLINE) ? FIEMAP_EXTENT_UNKNOWN : 0;

		blk_off = ext.start + ext.len;
	}

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
out:
	mutex_unlock(&inode->i_mutex);

	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.readpages		= scoutfs_readpages,
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= scoutfs_file_aio_read,
	.aio_write	= scoutfs_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= scoutfs_file_llseek,
};


int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct hlist_head *head;
	struct data_info *datinf;
	struct task_cursor *curs;
	int i;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	init_rwsem(&datinf->alloc_rwsem);
	INIT_LIST_HEAD(&datinf->cursor_lru);

	for (i = 0; i < CURSOR_HASH_HEADS; i++)
		INIT_HLIST_HEAD(&datinf->cursor_hash[i]);

	/* just allocate all of these up front */
	for (i = 0; i < NR_CURSORS; i++) {
		curs = kzalloc(sizeof(struct task_cursor), GFP_KERNEL);
		if (!curs) {
			destroy_cursors(datinf);
			kfree(datinf);
			return -ENOMEM;
		}

		curs->pid = i;

		head = cursor_head(datinf, curs->task, curs->pid);
		hlist_add_head(&curs->hnode, head);

		list_add(&curs->list_head, &datinf->cursor_lru);
	}

	sbi->data_info = datinf;

	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		destroy_cursors(datinf);
		kfree(datinf);
	}
}

#if 0
/*
 * Basic correctness tests of u64 and mapping encoding.
 */
int __init scoutfs_data_test(void)
{
	u8 encoded[SCOUTFS_ZIGZAG_MAX_BYTES];
	struct block_mapping *input;
	struct block_mapping *output;
	u64 blkno;
	u8 bits;
	u64 prev;
	u64 in;
	u64 out;
	int ret;
	int len;
	int b;
	int i;

	prev = 0;
	for (i = 0; i < 10000; i++) {
		get_random_bytes_arch(&bits, sizeof(bits));
		get_random_bytes_arch(&in, sizeof(in));
		in &= (1ULL << (bits % 64)) - 1;

		len = zigzag_encode(encoded, prev, in);

		ret = zigzag_decode(&out, prev, encoded, len);

		if (ret <= 0 || ret > SCOUTFS_ZIGZAG_MAX_BYTES || in != out) {
			printk("i %d prev %llu in %llu out %llu len %d ret %d\n",
				i, prev, in, out, len, ret);

			ret = -EINVAL;
		}
		if (ret < 0)
			return ret;

		prev = out;
	}

	input = kmalloc(sizeof(struct block_mapping), GFP_KERNEL);
	output = kmalloc(sizeof(struct block_mapping), GFP_KERNEL);
	if (!input || !output) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < 1000; i++) {
		prev = 0;
		for (b = 0; b < SCOUTFS_BLOCK_MAPPING_BLOCKS; b++) {

			if (b % (64 / 2) == 0)
				get_random_bytes_arch(&in, sizeof(in));

			clear_bit(b, input->offline);

			switch(in & SCOUTFS_BLOCK_ENC_MASK) {
			case SCOUTFS_BLOCK_ENC_INC:
				blkno = prev + 1;
				break;
			case SCOUTFS_BLOCK_ENC_OFFLINE:
				set_bit(b, input->offline);
				blkno = 0;
				break;
			case SCOUTFS_BLOCK_ENC_ZERO:
				blkno = 0;
				break;
			case SCOUTFS_BLOCK_ENC_DELTA:
				get_random_bytes_arch(&bits, sizeof(bits));
				get_random_bytes_arch(&blkno, sizeof(blkno));
				blkno &= (1ULL << (bits % 64)) - 1;
				break;
			}

			input->blknos[b] = blkno;

			in >>= 2;
			if (blkno)
				prev = blkno;
		}

		len = encode_mapping(input);
		if (len >= 1 && len < SCOUTFS_BLOCK_MAPPING_MAX_BYTES)
			memcpy(output->encoded, input->encoded, len);
		ret = decode_mapping(output, len);
		if (ret) {
			printk("map len %d decoding failed %d\n", len, ret);
			ret = -EINVAL;
			goto out;
		}

		for (b = 0; b < SCOUTFS_BLOCK_MAPPING_BLOCKS; b++) {
			if (input->blknos[b] != output->blknos[b] ||
			    !!test_bit(b, input->offline) !=
			    !!test_bit(b, output->offline))
				break;
		}

		if (b < SCOUTFS_BLOCK_MAPPING_BLOCKS) {
			printk("map ind %u: in %llu %u, out %llu %u\n",
			       b, input->blknos[b], 
			       !!test_bit(b, input->offline),
			       output->blknos[b],
			       !!test_bit(b, output->offline));
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;
out:
	kfree(input);
	kfree(output);

	return ret;
}
#endif
