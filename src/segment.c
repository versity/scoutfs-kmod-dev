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
#include "item.h"
#include "segment.h"
#include "manifest.h"
#include "block.h"
#include "chunk.h"
#include "ring.h"

static struct scoutfs_item_header *next_ihdr(struct scoutfs_item_header *ihdr)
{
	return (void *)(ihdr + 1) + le16_to_cpu(ihdr->len);
}

/*
 * Use the manifest to search log segments for the most recent version
 * of the item with the given key.  Return a reference to the item after
 * it's been added to the item cache.
 */
struct scoutfs_item *scoutfs_read_segment_item(struct super_block *sb,
					       struct scoutfs_key *key)
{
	struct scoutfs_ring_manifest_entry ment;
	struct scoutfs_item_header *ihdr;
	struct scoutfs_item_block *iblk;
	struct scoutfs_item *item;
	struct buffer_head *bh;
	int cmp;
	int err;
	int i;

	/* XXX hold manifest */

	memset(&ment, 0, sizeof(struct scoutfs_ring_manifest_entry));

	item = NULL;
	err = -ENOENT;
	while (scoutfs_next_manifest_segment(sb, key, &ment)) {

		bh = scoutfs_read_block(sb, le64_to_cpu(ment.blkno));
		if (!bh) {
			err = -EIO;
			break;
		}

		iblk = (void *)bh->b_data;
		/* XXX seq corruption */

		ihdr = (void *)(iblk + 1);

		/* XXX test bloom filter blocks */
		/* XXX binary search of key array */
		/* XXX could populate more from granted range */

		for (i = 0; i < le32_to_cpu(iblk->nr_items);
		     i++, ihdr = next_ihdr(ihdr)) {
			cmp = scoutfs_key_cmp(key, &ihdr->key);
			if (cmp > 0)
				continue;
			if (cmp < 0)
				break;

			item = scoutfs_clean_item(sb, key,
						  le16_to_cpu(ihdr->len));
			if (IS_ERR(item)) {
				err = PTR_ERR(item);
			} else {
				memcpy(item->val, (void *)(ihdr + 1),
				       item->val_len);
				err = 0;
			}
			break;
		}

		brelse(bh);
		if (item) /* also breaks for IS_ERR */
			break;
	}

	/* XXX release manifest */

	if (err)
		item = ERR_PTR(err);

	return item;
}

static int finish_item_block(struct super_block *sb, struct buffer_head *bh,
			      void *until)
{
	struct scoutfs_item_block *iblk = (void *)bh->b_data;
	struct scoutfs_ring_manifest_entry ment;

	memset(until, 0, (void *)bh->b_data + SCOUTFS_BLOCK_SIZE - until);
	scoutfs_calc_hdr_crc(bh);
	unlock_buffer(bh);
	brelse(bh);

	ment.blkno = cpu_to_le64(bh->b_blocknr);
	ment.seq = iblk->hdr.seq;
	ment.level = 0;
	ment.first = iblk->first;
	ment.last = iblk->last;

	return scoutfs_new_manifest(sb, &ment);
}

/*
 * Write all the currently dirty items in newly allocated log segments.
 * New ring entries are added as the alloc bitmap is modified and as the
 * manifest is updated.  If we write out all the item and ring blocks then
 * we write a new super that references those new blocks.
 */
int scoutfs_write_dirty_items(struct super_block *sb)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	struct scoutfs_item_header *ihdr;
	struct scoutfs_item_block *iblk;
	struct scoutfs_item *item;
	struct buffer_head *bh;
	int val_space;
	u64 blkno;
	int ret;

	/* XXX wait until transactions are complete */

	item = NULL;
	iblk = NULL;
	while ((item = scoutfs_item_next_dirty(sb, item))) {

		if (iblk && (item->val_len > val_space)) {
			iblk = NULL;
			ret = finish_item_block(sb, bh, ihdr);
			if (ret)
				break;
		}

		if (!iblk) {
			/* get the next item block */
			ret = scoutfs_alloc_chunk(sb, &blkno);
			if (ret)
				break;

			bh = scoutfs_dirty_block(sb, blkno);
			if (!bh) {
				ret = -ENOMEM;
				break;
			}

			iblk = (void *)bh->b_data;
			iblk->first = item->key;
			iblk->nr_items = 0;
			ihdr = (void *)(iblk + 1);
			/* XXX assuming that val_space is big enough */
		}

		iblk->last = item->key;
		ihdr->key = item->key;
		ihdr->len = cpu_to_le16(item->val_len);
		memcpy((void *)(ihdr + 1), item->val, item->val_len);
		le32_add_cpu(&iblk->nr_items, 1);

		/* XXX assuming that the next ihdr fits */
		ihdr = (void *)(ihdr + 1) + le16_to_cpu(ihdr->len);
		val_space = (char *)iblk + SCOUTFS_BLOCK_SIZE -
			    (char *)(ihdr + 1);
	}

	scoutfs_item_put(item); /* only if the loop aborted */

	/* finish writing if we did work and haven't failed */
	if (iblk && !ret) {
		ret = finish_item_block(sb, bh, ihdr) ?:
		      scoutfs_finish_dirty_ring(sb) ?:
		      filemap_write_and_wait(mapping) ?:
		      scoutfs_write_dirty_super(sb);
		if (!ret) {
			scoutfs_advance_dirty_super(sb);
			scoutfs_item_all_clean(sb);
		}
	}

	/* XXX better tear down down in the error case */

	return ret;
}
