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

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/random.h>

#include "format.h"
#include "key.h"
#include "block.h"
#include "skip.h"

/*
 * The items in a log segment block are sorted by their keys in a skip
 * list.  The skip list was chosen because it is so easy to implement
 * and could, maybe some day, offer solid concurrent updates and reads.
 * It also adds surprisingly little per-item overhead because half of
 * the items only have one link.
 *
 * The list is rooted in the item block which follows the last bloom
 * block in the segment.  The links in the skip list elements are byte
 * offsets of the start of items relative to the start of the log
 * segment.
 *
 * We chose a limit on the height of 16 links.  That gives around 64k
 * items without going too crazy.  That's around the higher end of the
 * number of items we expect in log segments.
 *
 * This isn't quite a generic implementation.  It knows that the items
 * are rooted in the item block at a given offset in the log segment.
 * It knows that the pointers are items and where the skip links are in
 * its struct.  It knows to compare the items by their key.
 *
 * The caller is completely responsible for serialization.
 *
 * The buffer_head reads here won't be as expensive as they might seem.
 * The caller holds the blocks pinned so the worst case are block device
 * page radix rcu lookups.  Repeated reads of the recent blocks will hit
 * the per-cpu lru bh reference caches.
 */

struct skip_path {
	struct buffer_head *root_bh;

	/*
	 * Pointers to the buffer heads which contain the blocks which are
	 * referenced by the next pointers in the path.
	 */
	struct buffer_head *bh[SCOUTFS_SKIP_HEIGHT];

	/*
	 * Store the location of the index that references the item that
	 * we found.  Insertion will modify the referenced index to add
	 * an entry before the item and deletion will modify the referenced
	 * index to remove the item.
	 */
	__le32 *next[SCOUTFS_SKIP_HEIGHT];
};

#define DECLARE_SKIP_PATH(name) \
	struct skip_path name = {NULL, }

/*
 * Not all byte offsets are possible locations of items.  Items have to
 * be after the bloom blocks and item block header, can't be in
 * the block headers for the rest of the blocks, and can't be a partial
 * struct at the end of a block.
 *
 * This is just a rough check. It doesn't catch items offsets that overlap
 * with other items or values.
 */
static int invalid_item_off(u32 off)
{
	return off < ((SCOUTFS_BLOCK_SIZE * SCOUTFS_BLOOM_BLOCKS) +
		      sizeof(struct scoutfs_item_block)) ||
		(off & SCOUTFS_BLOCK_MASK) <
			sizeof(struct scoutfs_block_header) ||
		(off & SCOUTFS_BLOCK_MASK) >
			(SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_item));
}

/*
 * Set the caller's item to the item in the segment at the given byte
 * offset and set their bh to the block that contains it.
 */
static int skip_read_item(struct super_block *sb, u64 blkno, __le32 off,
			  struct buffer_head **bh, struct scoutfs_item **item)
{
	if (WARN_ON_ONCE(invalid_item_off(le32_to_cpu(off))))
		return -EINVAL;

	*bh = scoutfs_read_block_off(sb, blkno, le32_to_cpu(off));
	if (!(*bh)) {
		*bh = NULL;
		*item = NULL;
		return -EIO;
	}

	*item = (void *)(*bh)->b_data + (le32_to_cpu(off) & SCOUTFS_BLOCK_MASK);
	return 0;
}

/*
 * Find the next item in the skiplist with a key greater than or equal
 * to the given key.  Set the path pointers to the hops before this item
 * so that we can modify those pointers to insert an item before it in
 * the list or delete it.
 *
 * The caller is responsible for initializing the path and cleaning it up.
 */
static int skip_search(struct super_block *sb, u64 blkno,
		       struct skip_path *path, struct scoutfs_key *key,
		       int *cmp)
{
	struct scoutfs_item_block *iblk;
	struct scoutfs_item *item;
	struct buffer_head *bh;
	__le32 *next;
	int ret = 0;
	int i;

	/* fake lesser comparison for insertion into an empty list */
	*cmp = -1;

	bh = scoutfs_read_block(sb, blkno + SCOUTFS_BLOOM_BLOCKS);
	if (!bh)
		return -EIO;

	/* XXX verify */
	iblk = (void *)bh->b_data;
	next = iblk->skip_root.next;
	path->root_bh = bh;

	for (i = SCOUTFS_SKIP_HEIGHT - 1; i >= 0; i--) {
		while (next[i]) {
			ret = skip_read_item(sb, blkno, next[i], &bh, &item);
			if (ret)
				goto out;

			*cmp = scoutfs_key_cmp(key, &item->key);
			if (*cmp <= 0) {
				brelse(bh);
				break;
			}

			next = item->skip_next;
			if (path->bh[i])
				brelse(path->bh[i]);
			path->bh[i] = bh;
		}

		path->next[i] = &next[i];
	}
out:
	return ret;
}

static void skip_release_path(struct skip_path *path)
{
	int i;

	if (path->root_bh)
		brelse(path->root_bh);

	for (i = 0; i < SCOUTFS_SKIP_HEIGHT; i++) {
		if (path->bh[i]) {
			brelse(path->bh[i]);
			path->bh[i] = NULL;
		}
	}
}

/*
 * We want heights with a distribution of 1 / (2^h).  Half the items
 * have a height of 1, a quarter have 2, an eighth have 3, etc.
 *
 * Finding the first low set bit in a random number achieves this
 * nicely.  ffs() even counts the bits from 1 so it matches our height.
 *
 * But ffs() returns 0 if no bits are set.  We prevent a 0 height and
 * limit the max height returned by oring in our max height.
 */
u8 scoutfs_skip_random_height(void)
{
	return ffs(get_random_int() | (1 << (SCOUTFS_SKIP_HEIGHT - 1)));
}

/*
 * Insert a new item in the item block's skip list.  The caller provides
 * an initialized item, particularly it's skip height and key, and
 * the byte offset in the log segment of the item struct.
 */
int scoutfs_skip_insert(struct super_block *sb, u64 blkno,
			struct scoutfs_item *item, u32 off)
{
	DECLARE_SKIP_PATH(path);
	int cmp;
	int ret;
	int i;

	if (WARN_ON_ONCE(invalid_item_off(off)) ||
	    WARN_ON_ONCE(item->skip_height > SCOUTFS_SKIP_HEIGHT))
		return -EINVAL;

	ret = skip_search(sb, blkno, &path, &item->key, &cmp);
	if (ret == 0) {
		if (cmp == 0) {
			ret = -EEXIST;
		} else {
			for (i = 0; i < item->skip_height; i++) {
				item->skip_next[i] = *path.next[i];
				*path.next[i] = cpu_to_le32(off);
			}
		}
	}

	skip_release_path(&path);
	return ret;
}

static int skip_lookup(struct super_block *sb, u64 blkno,
		       struct scoutfs_key *key, struct buffer_head **bh,
		       struct scoutfs_item **item, bool exact)
{
	DECLARE_SKIP_PATH(path);
	int cmp;
	int ret;

	ret = skip_search(sb, blkno, &path, key, &cmp);
	if (ret == 0) {
		if ((exact && cmp) || *path.next[0] == 0) {
			ret = -ENOENT;
		} else {
			ret = skip_read_item(sb, blkno, *path.next[0],
					     bh, item);
		}
	}

	skip_release_path(&path);
	return ret;
}

/*
 * Find the item at the given key in the skip list.
 */
int scoutfs_skip_lookup(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key, struct buffer_head **bh,
			struct scoutfs_item **item)
{
	return skip_lookup(sb, blkno, key, bh, item, true);
}

/*
 * Find the next item after the given key in the skip list.
 */
int scoutfs_skip_search(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key, struct buffer_head **bh,
			struct scoutfs_item **item)
{
	return skip_lookup(sb, blkno, key, bh, item, false);
}

int scoutfs_skip_delete(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key)
{
	struct scoutfs_item *item;
	DECLARE_SKIP_PATH(path);
	struct buffer_head *bh;
	int cmp;
	int ret;
	int i;

	ret = skip_search(sb, blkno, &path, key, &cmp);
	if (ret == 0) {
		if (*path.next[0] && cmp) {
			ret = -ENOENT;
		} else {
			ret = skip_read_item(sb, blkno, *path.next[0],
					     &bh, &item);
			if (!ret) {
				for (i = 0; i < item->skip_height; i++)
					*path.next[i] = item->skip_next[i];
				brelse(bh);
			}
		}
	}

	skip_release_path(&path);
	return ret;
}

/*
 * The caller has found a valid item with search or lookup.  We can use
 * the lowest level links to advance through the rest of the items.  The
 * caller has made sure that this is safe.
 */
int scoutfs_skip_next(struct super_block *sb, u64 blkno,
		      struct buffer_head **bh, struct scoutfs_item **item)
{
	__le32 next;

	if (!(*bh))
		return -ENOENT;

	next = (*item)->skip_next[0];
	brelse(*bh);

	if (!next) {
		*bh = NULL;
		*item = NULL;
		return -ENOENT;
	}

	return skip_read_item(sb, blkno, next, bh, item);
}
