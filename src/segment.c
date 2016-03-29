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
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#include "super.h"
#include "key.h"
#include "segment.h"
#include "manifest.h"
#include "block.h"
#include "chunk.h"
#include "ring.h"
#include "bloom.h"
#include "skip.h"

/*
 * scoutfs log segments are large multi-block structures that contain
 * key/value items.  This file implements manipulations of the items.
 *
 * Each log segment starts with a bloom filter to supports quickly
 * testing for key values without having to search the whole block for a
 * key.
 *
 * After the bloom filter come the packed structures that describe the
 * items that are present in the block.  They're sorted in a skip list
 * to support reasonably efficient insertion, sorted iteration, and
 * deletion.
 *
 * Finally the item values are stored at the end of the block.  This
 * supports finding that an item's key isn't present by only reading the
 * item structs, not the values.
 *
 * All told, should we chose to, we can have three large portions of the
 * blocks resident for searching.  It's likely that we'll keep the bloom
 * filters hot but that the items and especially the values may age out
 * of the cache.
 */

void scoutfs_put_ref(struct scoutfs_item_ref *ref)
{
	if (ref->item_bh)
		brelse(ref->item_bh);
	if (ref->val_bh)
		brelse(ref->val_bh);

	memset(ref, 0, sizeof(struct scoutfs_item_ref));
}

/* private to here */
struct scoutfs_item_iter {
	struct list_head list;
	struct buffer_head *bh;
	struct scoutfs_item *item;
	u64 blkno;
	bool restart_after;
};

void scoutfs_put_iter_list(struct list_head *list)
{
	struct scoutfs_item_iter *iter;
	struct scoutfs_item_iter *pos;

	list_for_each_entry_safe(iter, pos, list, list) {
		list_del_init(&iter->list);
		brelse(iter->bh);
		kfree(iter);
	}
}

/*
 * The caller has a pointer to an item and a reference to its block.  We
 * read the value block and populate the reference.
 *
 * The item references get their own buffer head references so that the
 * caller doesn't have to play funny games.  They always have to drop
 * their release bh.  If this succeeds then they also need to put the
 * ref.
 */
static int populate_ref(struct super_block *sb, u64 blkno,
			struct buffer_head *item_bh, struct scoutfs_item *item,
			struct scoutfs_item_ref *ref)
{
	struct buffer_head *bh;

	bh = scoutfs_read_block_off(sb, blkno, le32_to_cpu(item->offset));
	if (!bh)
		return -EIO;

	ref->key = &item->key;
	ref->val_len = le16_to_cpu(item->len);
	ref->val = bh->b_data + (le32_to_cpu(item->offset) &
				 SCOUTFS_BLOCK_MASK);
	get_bh(item_bh);
	ref->item_bh = item_bh;
	ref->val_bh = bh;

	return 0;
}

/*
 * Segments are immutable once they're written.  As they're being
 * dirtied we need to lock concurrent access.  XXX the dirty blkno test
 * is probably racey.  We could use reader/writer locks here.  And we
 * could probably make the skip lists support concurrent access.
 */
static bool try_lock_dirty_mutex(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (blkno == sbi->dirty_blkno) {
		mutex_lock(&sbi->dirty_mutex);
		if (blkno == sbi->dirty_blkno)
			return true;
		mutex_unlock(&sbi->dirty_mutex);
	}

	return false;
}

/*
 * Return a reference to the item at the given key.  We walk the manifest
 * to find blocks that might contain the key from most recent to oldest.
 * To find the key in each log segment we test it's bloom filter and
 * then search through the item keys.  The first matching item we find
 * is returned.
 *
 * XXX lock the dirty log segment?
 *
 * -ENOENT is returned if the item isn't present.  The caller needs to put
 * the ref if we return success.
 */
int scoutfs_read_item(struct super_block *sb, struct scoutfs_key *key,
		      struct scoutfs_item_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_ring_manifest_entry ment;
	struct scoutfs_item *item = NULL;
	struct scoutfs_bloom_bits bits;
	struct buffer_head *bh;
	bool locked;
	int ret;

	/* XXX hold manifest */

	scoutfs_calc_bloom_bits(&bits, key, sbi->super.bloom_salts);

	item = NULL;
	ret = -ENOENT;
	memset(&ment, 0, sizeof(struct scoutfs_ring_manifest_entry));
	while (scoutfs_foreach_range_segment(sb, key, key, &ment)) {

		/* XXX read-ahead all bloom blocks */

		ret = scoutfs_test_bloom_bits(sb, le64_to_cpu(ment.blkno),
					      key, &bits);
		if (ret < 0)
			break;
		if (!ret) {
			ret = -ENOENT;
			continue;
		}

		/* XXX read-ahead all item header blocks */

		locked = try_lock_dirty_mutex(sb, le64_to_cpu(ment.blkno));
		ret = scoutfs_skip_lookup(sb, le64_to_cpu(ment.blkno), key,
					  &bh, &item);
		if (locked)
			mutex_unlock(&sbi->dirty_mutex);
		if (ret) {
			if (ret == -ENOENT)
				continue;
			break;
		}
		break;
	}

	/* XXX release manifest */

	/* XXX read-ahead all value blocks? */

	if (!ret) {
		ret = populate_ref(sb, le64_to_cpu(ment.blkno), bh, item, ref);
		brelse(bh);
	}

	return ret;
}

/* return the byte length of the item header including its skip elements */
static int item_bytes(int height)
{
	return offsetof(struct scoutfs_item, skip_next[height]);
}

/*
 * The dirty_item_off points to the byte offset after the last item.
 * Advance it past block tails and initial block headers until there's
 * room for an item with the given skip list elements height.  Then set
 * the dirty_item_off past the item offset item we return.
 */
static int add_item_off(struct scoutfs_sb_info *sbi, int height)
{
	int len = item_bytes(height);
	int off = sbi->dirty_item_off;
	int block_off;
	int tail_free;

	/* items can't start in a block header */
	block_off = off & SCOUTFS_BLOCK_MASK;
	if (block_off < sizeof(struct scoutfs_block_header))
		off += sizeof(struct scoutfs_block_header) - block_off;

	/* items can't cross a block boundary */
	tail_free = SCOUTFS_BLOCK_SIZE - (off & SCOUTFS_BLOCK_MASK);
	if (tail_free < len)
		off += tail_free + sizeof(struct scoutfs_block_header);

	sbi->dirty_item_off = off + len;
	return off;
}

/*
 * The dirty_val_off points to the first byte of the last value that
 * was allocated.  Subtract the offset to make room for a new item
 * of the given length.  If that crosses a block boundary or wanders
 * into the block header then pull it back into the tail of the previous
 * block.
 */
static int sub_val_off(struct scoutfs_sb_info *sbi, int len)
{
	int off = sbi->dirty_val_off - len;
	int block_off;
	int tail_free;

	/* values can't start in a block header */
	block_off = off & SCOUTFS_BLOCK_MASK;
	if (block_off < sizeof(struct scoutfs_block_header))
		off -= (block_off + 1);

	/* values can't cross a block boundary */
	tail_free = SCOUTFS_BLOCK_SIZE - (off & SCOUTFS_BLOCK_MASK);
	if (tail_free < len)
		off -= len - tail_free;

	sbi->dirty_val_off = off;
	return off;
}

/*
 * Initialize the buffers for the next dirty segment.  We have to initialize
 * the bloom filter bits and the item block header.
 *
 * XXX we need to really pin the blocks somehow
 */
static int start_dirty_segment(struct super_block *sb, u64 blkno)
{
	struct scoutfs_bloom_block *blm;
	struct scoutfs_item_block *iblk;
	struct buffer_head *bh;
	int ret = 0;
	int i;

	for (i = 0; i < SCOUTFS_BLOCKS_PER_CHUNK; i++) {
		bh = scoutfs_new_block(sb, blkno + i);
		if (!bh) {
			ret = -EIO;
			break;
		}

		if (i < SCOUTFS_BLOOM_BLOCKS) {
			blm = (void *)bh->b_data;
			memset(blm->bits, 0, SCOUTFS_BLOCK_SIZE -
			       offsetof(struct scoutfs_bloom_block, bits));
		}

		if (i == SCOUTFS_BLOOM_BLOCKS) {
			iblk = (void *)bh->b_data;
			memset(&iblk->first, ~0, sizeof(struct scoutfs_key));
			memset(&iblk->last, 0, sizeof(struct scoutfs_key));
			memset(&iblk->skip_root, 0, sizeof(iblk->skip_root) +
			       sizeof(struct scoutfs_item));
		}

		/* bh is pinned by sbi->dirty_blkno */
	}

	while (ret && i--) {
		/* unwind pinned blocks on failure */
		bh = sb_getblk(sb, blkno + i);
		if (bh) {
			brelse(bh);
			brelse(bh);
		}
	}

	return ret;
}

/*
 * As we fill a dirty segment we don't know which keys it's going to
 * contain.  We add a manifest entry in memory that has it contain all
 * items so that reading will know to search the dirty segment.
 *
 * Once it's finalized we know the specific range of items it contains
 * and we update the manifest entry in memory for that range and write
 * that to the ring.
 */
static int update_dirty_segment_manifest(struct super_block *sb, u64 blkno,
					 bool all_items)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_ring_manifest_entry ment;
	struct scoutfs_item_block *iblk;
	struct buffer_head *bh;
	int ret;

	ment.blkno = cpu_to_le64(blkno);
	ment.seq = sbi->super.hdr.seq;
	ment.level = 0;

	if (all_items) {
		memset(&ment.first, 0, sizeof(struct scoutfs_key));
		memset(&ment.last, ~0, sizeof(struct scoutfs_key));
	} else {
		bh = scoutfs_read_block(sb, blkno + SCOUTFS_BLOOM_BLOCKS);
		if (!bh) {
			ret = -EIO;
			goto out;
		}

		iblk = (void *)bh->b_data;
		ment.first = iblk->first;
		ment.last = iblk->last;
		brelse(bh);
	}

	if (all_items)
		ret = scoutfs_insert_manifest(sb, &ment);
	else
		ret = scoutfs_new_manifest(sb, &ment);
out:
	return ret;
}

/*
 * Zero the portion of this block that intersects with the free space in
 * the middle of the segment.  @start and @end are chunk-relative byte
 * offsets of the inclusive start and exclusive end of the free region.
 */
static void zero_unused_block(struct super_block *sb, struct buffer_head *bh,
			      u32 start, u32 end)
{
	u32 off = bh->b_blocknr << SCOUTFS_BLOCK_SHIFT;

	/* see if the segment range falls outside our block */
	if (start >= off + SCOUTFS_BLOCK_SIZE || end <= off)
		return;

	/* convert the chunk offsets to our block offsets */
	start = max(start, off) - off;
	end = min(off + SCOUTFS_BLOCK_SIZE, end) - off;

	/* don't zero block headers */
	start = max_t(u32, start, sizeof(struct scoutfs_block_header));
	end = max_t(u32, start, sizeof(struct scoutfs_block_header));

	if (start < end)
		memset(bh->b_data + start, 0, end - start);
}

/*
 * Finish off a dirty segment if we have one.  Calculate the checksums of
 * all the blocks, mark them dirty, and drop their pinned reference.
 *
 * XXX should do something with empty dirty segments.
 */
static int finish_dirty_segment(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	struct buffer_head *bh;
	u64 blkno = sbi->dirty_blkno;
	int ret = 0;
	u64 i;

	WARN_ON_ONCE(!blkno);

	for (i = 0; i < SCOUTFS_BLOCKS_PER_CHUNK; i++) {
		bh = scoutfs_read_block(sb, blkno + i);
		/* should have been pinned */
		if (WARN_ON_ONCE(!bh)) {
			ret = -EIO;
			break;
		}

		zero_unused_block(sb, bh, sbi->dirty_item_off,
				  sbi->dirty_val_off);

		scoutfs_calc_hdr_crc(bh);
		mark_buffer_dirty(bh);
		brelse(bh);
		/* extra release to unpin */
		brelse(bh);
	}

	/* update manifest with range of items and add to ring */
	ret = update_dirty_segment_manifest(sb, blkno, false);

	/*
	 * Try to kick off a background write of the finished segment.  Callers
	 * can wait for the buffers in writeback if they need to.
	 */
	if (!ret) {
		filemap_fdatawrite_range(mapping, blkno << SCOUTFS_CHUNK_SHIFT,
				((blkno + 1) << SCOUTFS_CHUNK_SHIFT) - 1);
		sbi->dirty_blkno = 0;
	}

	return ret;
}

/*
 * We've been dirtying log segment blocks and ring blocks as items were
 * modified.  sync makes sure that they're all persistent and updates
 * the super.
 *
 * XXX need to synchronize with transactions
 * XXX is state clean after errors?
 */
int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret = 0;

	mutex_unlock(&sbi->dirty_mutex);
	if (sbi->dirty_blkno) {
		ret = finish_dirty_segment(sb) ?:
		      scoutfs_finish_dirty_ring(sb) ?:
		      filemap_write_and_wait(mapping) ?:
		      scoutfs_write_dirty_super(sb) ?:
		      scoutfs_advance_dirty_super(sb);
	}
	mutex_unlock(&sbi->dirty_mutex);
	return ret;
}


/*
 * Return a reference to a newly allocated and initialized item in a
 * block in the currently dirty log segment.
 *
 * Item creation is purposely kept very simple. Item and value offset
 * allocation proceed from either end of the log segment.  Once they
 * intersect the log segment is full and written out.  Deleted dirty
 * items don't reclaim their space.  The free space will be reclaimed by
 * the level 0 -> level 1 merge that happens anyway.  Not reclaiming
 * free space makes item location more rigid and lets us relax the
 * locking requirements of item references.  An item reference doesn't
 * have to worry about unrelated item modification moving their item
 * around to, say, defragment free space.
 */
int scoutfs_create_item(struct super_block *sb, struct scoutfs_key *key,
		        unsigned bytes, struct scoutfs_item_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_bloom_bits bits;
	struct scoutfs_item *item;
	struct scoutfs_item_block *iblk;
	struct buffer_head *bh;
	int item_off;
	int val_off;
	int height;
	u64 blkno;
	int ret = 0;

	/* XXX how big should items really get? */
	if (WARN_ON_ONCE(bytes == 0 || bytes > 4096))
		return -EINVAL;

	height = scoutfs_skip_random_height();

	mutex_lock(&sbi->dirty_mutex);

next_chunk:
	if (!sbi->dirty_blkno) {
		ret = scoutfs_alloc_chunk(sb, &blkno);
		if (ret)
			goto out;

		/* XXX free blkno on error? */
		ret = start_dirty_segment(sb, blkno);
		if (ret)
			goto out;

		/* add initial in-memory manifest entry with all items */
		ret = update_dirty_segment_manifest(sb, blkno, true);
		if (ret)
			goto out;

		sbi->dirty_blkno = blkno;
		sbi->dirty_item_off =
			(SCOUTFS_BLOCK_SIZE * SCOUTFS_BLOOM_BLOCKS) +
				sizeof(struct scoutfs_item_block);
		sbi->dirty_val_off = SCOUTFS_CHUNK_SIZE;
	}

	item_off = add_item_off(sbi, height);
	val_off = sub_val_off(sbi, bytes);

	trace_printk("item_off %u val_off %u\n", item_off, val_off);

	if (item_off + item_bytes(height) > val_off) {
		ret = finish_dirty_segment(sb);
		if (ret)
			goto out;
		goto next_chunk;
	}

	/* XXX fix up this error handling in general */

	bh = scoutfs_read_block_off(sb, sbi->dirty_blkno, item_off);
	if (!bh) {
		ret = -EIO;
		goto out;
	}

	item = (void *)bh->b_data + (item_off & SCOUTFS_BLOCK_MASK);
	item->key = *key;
	item->offset = cpu_to_le32(val_off);
	item->len = cpu_to_le16(bytes);
	item->skip_height = height;

	ret = scoutfs_skip_insert(sb, sbi->dirty_blkno, item, item_off);
	if (ret)
		goto out;

	ret = populate_ref(sb, sbi->dirty_blkno, bh, item, ref);
	brelse(bh);
	if (ret)
		goto out;

	bh = scoutfs_read_block(sb, sbi->dirty_blkno + SCOUTFS_BLOOM_BLOCKS);
	if (!bh) {
		ret = -EIO;
		goto out;
	}

	/*
	 * Update first and last keys as we go.  It's ok if future deletions
	 * make this range larger than the actual keys.  That'll almost
	 * never happen and it'll get fixed up in merging.
	 */
	iblk = (void *)bh->b_data;
	if (scoutfs_key_cmp(key, &iblk->first) < 0)
		iblk->first = *key;
	if (scoutfs_key_cmp(key, &iblk->last) > 0)
		iblk->last = *key;
	brelse(bh);

	/* XXX delete skip on failure? */

	/* set the bloom bits last because we can't unset them */
	scoutfs_calc_bloom_bits(&bits, key, sbi->super.bloom_salts);
	ret = scoutfs_set_bloom_bits(sb, sbi->dirty_blkno, &bits);
out:
	WARN_ON_ONCE(ret); /* XXX error paths are not robust */
	mutex_unlock(&sbi->dirty_mutex);
	return ret;
}

/*
 * Ensure that there is a dirty item with the given key in the current
 * dirty segment.
 *
 * The caller locks access to the item and prevents sync and made sure
 * that there's enough free space in the segment for their dirty inodes.
 *
 * This is better than getting -EEXIST from create_item because that
 * will leave the allocated item and val dangling in the block when it
 * returns the error.
 */
int scoutfs_dirty_item(struct super_block *sb, struct scoutfs_key *key,
		       unsigned bytes, struct scoutfs_item_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_item *item;
	struct buffer_head *bh;
	bool create = false;
	int ret;

	mutex_lock(&sbi->dirty_mutex);

	if (sbi->dirty_blkno) {
		ret = scoutfs_skip_lookup(sb, sbi->dirty_blkno, key, &bh,
					  &item);
		if (ret == -ENOENT)
			create = true;
		else if (!ret) {
			ret = populate_ref(sb, sbi->dirty_blkno, bh, item,
					   ref);
			brelse(bh);
		}
	} else {
		create = true;
	}
	mutex_unlock(&sbi->dirty_mutex);

	if (create)
		ret = scoutfs_create_item(sb, key, bytes, ref);

	return ret;
}

/*
 * This is a really cheesy temporary delete method.  It only works on items
 * that are stored in dirty blocks.  The caller is responsible for dropping
 * the ref.  XXX be less bad.
 */
int scoutfs_delete_item(struct super_block *sb, struct scoutfs_item_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 blkno;
	int ret;

	mutex_lock(&sbi->dirty_mutex);

	blkno = round_down(ref->item_bh->b_blocknr, SCOUTFS_BLOCKS_PER_CHUNK);
	if (WARN_ON_ONCE(blkno != sbi->dirty_blkno)) {
		ret = -EINVAL;
	} else {
		ret = scoutfs_skip_delete(sb, blkno, ref->key);
		WARN_ON_ONCE(ret);
	}

	mutex_unlock(&sbi->dirty_mutex);

	return ret;
}

/*
 * Return a reference to the next item in the inclusive search range.
 * The caller should have access to the search key range.
 *
 * We walk the manifest to find all the log segments that could contain
 * the start of the range.  We hold cursors on the blocks in the
 * segments.  Each next item iteration comes from finding the least of
 * the next item at all these cursors.
 *
 * If we exhaust a segment at a given level we may need to search the
 * next segment in that level to find the next item.  The manifest may
 * have changed under us while we walked our old set of segments.  So we
 * restart the entire search to get another consistent collection of
 * segments to search.
 *
 * We put the segment references and iteration cursors in a list in the
 * caller so that they can find many next items by advancing the cursors
 * without having to walk the manifest and perform initial binary
 * searches in each segment.
 *
 * The caller is responsible for putting the item ref if we return
 * success.  -ENOENT is returned if there are no more items in the
 * search range.
 *
 * XXX this is wonky.  We don't want to search the manifest for the
 * range, just the initial value.  Then we record the last key in
 * segments we finish and only restart if least is > that or there are
 * no least.  We have to advance the first key when restarting the
 * search.
 */
int scoutfs_next_item(struct super_block *sb, struct scoutfs_key *first,
		      struct scoutfs_key *last, struct list_head *iter_list,
		      struct scoutfs_item_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_ring_manifest_entry ment;
	struct scoutfs_item_iter *least;
	struct scoutfs_item_iter *iter;
	struct scoutfs_item_iter *pos;
	bool locked;
	int ret;

restart:
	if (list_empty(iter_list)) {

		/*
		 * Find all the segments that intersect the search range
		 * and find the next item in the block from the start
		 * of the range.
		 */
		memset(&ment, 0, sizeof(struct scoutfs_ring_manifest_entry));
		while (scoutfs_foreach_range_segment(sb, first, last, &ment)) {
			iter = kzalloc(sizeof(struct scoutfs_item_iter),
				      GFP_NOFS);
			if (!iter) {
				ret = -ENOMEM;
				goto out;
			}

			/*
			 * We will restart the walk of the manifest blocks if
			 * we iterate over all the items in this block without
			 * exhausting the search range.
			 */
			if (ment.level > 0 &&
			    scoutfs_key_cmp(&ment.last, last) < 0)
				iter->restart_after = true;

			iter->blkno = le64_to_cpu(ment.blkno);
			list_add_tail(&iter->list, iter_list);
		}
		if (list_empty(iter_list)) {
			ret = -ENOENT;
			goto out;
		}
	}

	least = NULL;
	ret = 0;
	list_for_each_entry_safe(iter, pos, iter_list, list) {

		locked = try_lock_dirty_mutex(sb, iter->blkno);

		/* search towards the first key if we haven't yet */
		if (!iter->item) {
			ret = scoutfs_skip_search(sb, iter->blkno, first,
						  &iter->bh, &iter->item);
		}

		/* then iterate until we find or pass the first key */
		while (!ret && scoutfs_key_cmp(&iter->item->key, first) < 0) {
			ret = scoutfs_skip_next(sb, iter->blkno,
						&iter->bh, &iter->item);
		}

		if (locked)
			mutex_unlock(&sbi->dirty_mutex);

		/* we're done with this block if we past the last key */
		while (!ret && scoutfs_key_cmp(&iter->item->key, last) > 0) {
			brelse(iter->bh);
			iter->bh = NULL;
			iter->item = NULL;
			ret = -ENOENT;
		}

		if (ret == -ENOENT) {
			if (iter->restart_after) {
				/* need next block at this level */
				scoutfs_put_iter_list(iter_list);
				goto restart;
			} else {
				/* this level is done */
				list_del_init(&iter->list);
				brelse(iter->bh);
				kfree(iter);
				continue;
			}
		}
		if (ret)
			goto out;

		/* remember the most recent smallest key from the first */
		if (!least ||
		    scoutfs_key_cmp(&iter->item->key, &least->item->key) < 0)
			least = iter;
	}

	if (least)
		ret = populate_ref(sb, least->blkno, least->bh, least->item,
				   ref);
	else
		ret = -ENOENT;
out:
	if (ret)
		scoutfs_put_iter_list(iter_list);
	return ret;

}
