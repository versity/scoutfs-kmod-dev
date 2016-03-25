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
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/crc32c.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "bloom.h"

/*
 * Each log segment starts with a bloom filters that spans multiple
 * blocks.  It's used to test for the presence of key in the log segment
 * without having to read and search the much larger array of items and
 * their keys.
 */

/* XXX garbage hack until we have siphash */
static u32 bloom_hash(struct scoutfs_key *key, __le32 salt)
{
	return crc32c(le32_to_cpu(salt), key, sizeof(struct scoutfs_key));
}

/*
 * Find the bits in the bloom filter for the given key.  The caller calculates
 * these once and uses them to test all the blocks.
 */
void scoutfs_calc_bloom_bits(struct scoutfs_bloom_bits *bits,
			     struct scoutfs_key *key, __le32 *salts)
{
	unsigned h_bits = 0;
	unsigned int b;
	unsigned s = 0;
	u64 h = 0;
	int i;

	BUILD_BUG_ON(SCOUTFS_BLOOM_BIT_WIDTH > 32);

	for (i = 0; i < SCOUTFS_BLOOM_BITS; i++) {
		if (h_bits < SCOUTFS_BLOOM_BIT_WIDTH) {
			h = (h << 32) | bloom_hash(key, salts[s++]);
			h_bits += 32;
		}

		b = h & SCOUTFS_BLOOM_BIT_MASK;
		h >>= SCOUTFS_BLOOM_BIT_WIDTH;
		h_bits -= SCOUTFS_BLOOM_BIT_WIDTH;

		bits->block[i] = (b / SCOUTFS_BLOOM_BITS_PER_BLOCK) %
				SCOUTFS_BLOOM_BLOCKS;
		bits->bit_off[i] = b % SCOUTFS_BLOOM_BITS_PER_BLOCK;
	}
}

/*
 * Set the caller's bit numbers in the bloom filter contained in bloom
 * blocks starting at the given block number.  The caller has
 * initialized the blocks and is responsible for locking and dirtying
 * and writeout.
 */
int scoutfs_set_bloom_bits(struct super_block *sb, u64 blkno,
			   struct scoutfs_bloom_bits *bits)
{
	struct scoutfs_bloom_block *blm;
	struct buffer_head *bh;
	int ret = 0;
	int i;

	for (i = 0; i < SCOUTFS_BLOOM_BITS; i++) {
		bh = scoutfs_read_block(sb, blkno + bits->block[i]);
		if (!bh) {
			ret = -EIO;
			break;
		}

		blm = (void *)bh->b_data;
		set_bit_le(bits->bit_off[i], blm->bits);

		brelse(bh);
	}

	return ret;
}

/*
 * Returns zero if the bits' key can't be found in the block, true if it
 * might, and -errno if IO fails.
 */
int scoutfs_test_bloom_bits(struct super_block *sb, u64 blkno,
			    struct scoutfs_bloom_bits *bits)
{
	struct scoutfs_bloom_block *blm;
	struct buffer_head *bh;
	int ret;
	int i;

	for (i = 0; i < SCOUTFS_BLOOM_BITS; i++) {
		bh = scoutfs_read_block(sb, blkno + bits->block[i]);
		if (!bh) {
			ret = -EIO;
			break;
		}

		blm = (void *)bh->b_data;
		ret = !!test_bit_le(bits->bit_off[i], blm->bits);
		brelse(bh);
		if (!ret)
			break;
	}

	return ret;
}
