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
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>

#include "format.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "item.h"
#include "super.h"
#include "lsm.h"

#define PAGE_CACHE_PAGE_BITS (PAGE_CACHE_SIZE * 8)

/* XXX garbage hack until we have siphash */
static u64 bloom_hash(struct scoutfs_key *key, __le64 *hash_key)
{
	__le32 *salts = (void *)hash_key;

	return ((u64)crc32c(le32_to_cpu(salts[0]), key, sizeof(*key)) << 32) |
		     crc32c(le32_to_cpu(salts[1]), key, sizeof(*key));
}

/*
 * Set the caller's bloom indices for their item key.
 */
static void get_bloom_indices(struct super_block *sb,
			      struct scoutfs_key *key, u32 *ind)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	__le64 *hash_key = sbi->bloom_hash_keys;
	u64 hash;
	int h;
	int i;

	for (i = 0; ; ) {
		hash = bloom_hash(key, hash_key);
		hash_key += 2;

		for (h = 0; h < 64 / SCOUTFS_BLOOM_INDEX_BITS; h++) {
			ind[i++] = hash & SCOUTFS_BLOOM_INDEX_MASK;
			if (i == SCOUTFS_BLOOM_INDEX_NR)
				return;

			hash >>= SCOUTFS_BLOOM_INDEX_BITS;
		}
	}
}

struct pages {
	/* fixed for the group of pages */
	struct address_space *mapping;
	struct page **pages;
	pgoff_t pgoff;

	/* number of pages stored in the pages array */
	int nr;
	/* byte offset of the free space at end of current page */
	int off;
	/* bytes remaining in the ovarall large block */
	int remaining;
};

/*
 * The caller has our fixed-size bloom filter in the locked pages
 * starting at the given byte offset in the first page.  Our job is to
 * hash the key and set its bits in the bloom filter.
 */
static void set_bloom_bits(struct super_block *sb, struct page **pages,
			   unsigned int offset, struct scoutfs_key *key)
{
	u32 inds[SCOUTFS_BLOOM_INDEX_NR];
	struct page *page;
	int offset_bits = offset * 8;
	int full_bit;
	int page_bit;
	void *addr;
	int i;

	get_bloom_indices(sb, key, inds);

	for (i = 0; i < SCOUTFS_BLOOM_INDEX_NR; i++) {
		full_bit = offset_bits + inds[i];
		page = pages[full_bit / PAGE_CACHE_PAGE_BITS];
		page_bit = full_bit % PAGE_CACHE_PAGE_BITS;

		addr = kmap_atomic(page);
		set_bit_le(page_bit, addr);
		kunmap_atomic(addr);
	}
}

/*
 * XXX the zeroing here is unreliable.  We'll want to zero the bloom but
 * not all the pages that are about to be overwritten.  Bleh.
 *
 * Returns the number of bytes copied if there was room.  Returns 0 if
 * there wasn't.  Returns -errno on a hard failure.
 */
static int copy_to_pages(struct pages *pgs, void *ptr, size_t count)
{
	struct page *page;
	int ret = count;
	void *addr;
	int bytes;

	if (count > pgs->remaining)
		return 0;

	while (count) {
		if (pgs->off == PAGE_CACHE_SIZE) {
			page = find_or_create_page(pgs->mapping,
						   pgs->pgoff + pgs->nr,
						   GFP_NOFS | __GFP_ZERO);
			trace_printk("page %p\n", page);
			if (!page) {
				ret = -ENOMEM;
				break;
			}

			pgs->pages[pgs->nr++] = page;
			pgs->off = 0;
		} else {
			page = pgs->pages[pgs->nr - 1];
		}

		bytes = min(PAGE_CACHE_SIZE - pgs->off, count);

		trace_printk("page %p off %d ptr %p count %zu bytes %d remaining %d\n",
			     page, pgs->off, ptr, count, bytes, pgs->remaining);

		if (ptr) {
			addr = kmap_atomic(page);
			memcpy(addr + pgs->off, ptr, bytes);
			kunmap_atomic(addr);
			ptr += bytes;
		}
		count -= bytes;
		pgs->off += bytes;
		pgs->remaining -= bytes;
	}

	return ret;
}

static void drop_pages(struct pages *pgs, bool dirty)
{
	struct page *page;
	int i;

	if (!pgs->pages)
		return;

	for (i = 0; i < pgs->nr; i++) {
		page = pgs->pages[i];

		SetPageUptodate(page);
		if (dirty)
			set_page_dirty(page);
		unlock_page(page);
		page_cache_release(page);
	}
}

/*
 * Write dirty items from the given item into dirty page cache pages in
 * the block device at the given large block number.
 *
 * All the page cache pages are locked and pinned while they're being
 * dirtied.  The intent is to have a single large IO leave once they're
 * all ready.  This is an easy way to do that while maintaining
 * consistency with the block device page cache.  But it might not work :).
 *
 * We do one sweep over the items.  The item's aren't indexed.  We might
 * want to change that.
 *
 * Even though we're doing one sweep over the items we're holding the
 * bloom filter and header pinned until the items are done.  If we didn't
 * mind the risk of the blocks going out of order we wouldn't need the
 * allocated array of page pointers.
 */
static struct scoutfs_item *dirty_block_pages(struct super_block *sb,
					    struct scoutfs_item *item, u64 blkno)
{
	struct scoutfs_item_header ihdr;
	struct scoutfs_lsm_block lblk;
	struct pages pgs;
	void *addr;
	int ret;

	/* assuming header starts page, and pgoff shift calculation */
	BUILD_BUG_ON(SCOUTFS_BLOCK_SHIFT < PAGE_CACHE_SHIFT);

	if (WARN_ON_ONCE(!item))
		return item;

	/* XXX not super thrilled with this allocation */
	pgs.pages = kmalloc_array(SCOUTFS_BLOCK_SIZE / PAGE_CACHE_SIZE,
				  sizeof(struct page *), GFP_NOFS);
	if (!pgs.pages) {
		ret = -ENOMEM;
		goto out;
	}

	pgs.mapping = sb->s_bdev->bd_inode->i_mapping;
	pgs.pgoff = blkno >> (SCOUTFS_BLOCK_SHIFT - PAGE_CACHE_SHIFT);
	pgs.nr = 0;
	pgs.off = PAGE_CACHE_SIZE,
	pgs.remaining = SCOUTFS_BLOCK_SIZE;

	/* reserve space at the start of the block for header and bloom */
	ret = copy_to_pages(&pgs, NULL, sizeof(lblk));
	if (ret > 0)
		ret = copy_to_pages(&pgs, NULL, SCOUTFS_BLOOM_FILTER_BYTES);
	if (ret <= 0)
		goto out;

	lblk.first = item->key;
	lblk.nr_items = 0;
	do {
		trace_printk("item %p key "CKF"\n", item, CKA(&item->key));

		ihdr.key = item->key;
		ihdr.len = cpu_to_le16(item->val_len);
		ret = copy_to_pages(&pgs, &ihdr, sizeof(ihdr));
		if (ret > 0)
		      ret = copy_to_pages(&pgs, item->val, item->val_len);
		if (ret <= 0)
			goto out;

		lblk.last = item->key;
		le32_add_cpu(&lblk.nr_items, 1);

		/* set each item's bloom bits */
		set_bloom_bits(sb, pgs.pages, sizeof(lblk), &item->key);

		item = scoutfs_item_next_dirty(sb, item);
	} while (item);

	/* copy the filled in header to the start of the block */
	addr = kmap_atomic(pgs.pages[0]);
	memcpy(addr, &lblk, sizeof(lblk));
	kunmap_atomic(addr);

out:
	/* dirty if no error (null ok!), unlock, and release */
	drop_pages(&pgs, !IS_ERR(item));
	kfree(pgs.pages);
	if (ret < 0) {
		scoutfs_item_put(item);
		item = ERR_PTR(ret);
	}
	return item;
}

/*
 * Sync dirty data by writing all the dirty items into a series of level
 * 0 blocks.
 *
 * This is an initial first pass, the full method will need to:
 *  - wait for pending writers
 *  - block future writers
 *  - update our manifest regardless of server communication
 *  - communicate blocks and key ranges to server
 *  - ensure that racing sync/dirty don't livelock
 */
int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_item *item;
	u64 blknos[16]; /* XXX */
	u64 blkno;
	int ret = 0;
	int i;

	item = scoutfs_item_next_dirty(sb, NULL);
	if (!item)
		return 0;

	for (i = 0; i < ARRAY_SIZE(blknos); i++) {
		blkno = atomic64_inc_return(&sbi->next_blkno);

		item = dirty_block_pages(sb, item, blkno);
		if (IS_ERR(item)) {
			ret = PTR_ERR(item);
			goto out;
		}

		/* start each block's IO */
		ret = filemap_flush(mapping);
		if (ret)
			goto out;

		if (!item)
			break;
	}
	/* dirty items should have been limited */
	WARN_ON_ONCE(i >= ARRAY_SIZE(blknos));

	/* then wait for all block IO to finish */
	if (wait) {
		ret = filemap_write_and_wait(mapping);
		if (ret)
			goto out;
	}

	/* mark everything clean */
	scoutfs_item_all_clean(sb);
	ret = 0;
out:
	trace_printk("ret %d\n", ret);
	WARN_ON_ONCE(ret);
	return ret;
}
