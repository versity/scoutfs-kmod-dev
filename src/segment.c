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
