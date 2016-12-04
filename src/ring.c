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

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "bio.h"
#include "manifest.h"
#include "ring.h"

/*
 * OK, log:
 *  - big preallocated ring of variable length entries
 *  - entries are rounded to 4k blocks
 *  - entire thing is read and indexed in rbtree
 *  - static allocated page is kept around to record and write entries
 *  - indexes have cursor that points to next node to migrate
 *  - any time an entry is written an entry is migrated
 *  - allocate room for 4x (maybe including worst case rounding)
 *  - mount does binary search looking for newest entry
 *  - newest entry describes block where we started migrating
 *  - replay then walks from oldest to newest replaying
 *  - entries are marked with migration so we know where to set cursor after
 *
 * XXX
 *  - verify blocks
 *  - could compress
 */

/* read in a meg at a time */
#define NR_PAGES DIV_ROUND_UP(1024 * 1024, PAGE_SIZE)
#define NR_BLOCKS (NR_PAGES * SCOUTFS_BLOCKS_PER_PAGE)

#if 0
#define BLOCKS_PER_PAGE (PAGE_SIZE / SCOUTFS_BLOCK_SIZE)
static void read_page_end_io(struct bio *bio, int err)
{
	struct bio_vec *bvec;
	struct page *page;
	unsigned long i;

	for_each_bio_segment(bio, bvec, i) {
		page = bvec->bv_page;

		if (err)
			SetPageError(page);
		else
			SetPageUptodate(page);
		unlock_page(page);
	}

	bio_put(bio);
}

/*
 * Read the given number of 4k blocks into the pages provided by the
 * caller.  We translate the block count into a page count and fill
 * bios a page at a time.
 */
static int read_blocks(struct super_block *sb, struct page **pages,
		       u64 blkno, unsigned int nr_blocks)
{
	unsigned int nr_pages = DIV_ROUND_UP(nr_blocks, PAGES_PER_BLOCK);
	unsigned int bytes;
	struct bio *bio;
	int ret = 0;

	for (i = 0; i < nr_pages; i++) {
		page = pages[i];

		if (!bio) {
			bio = bio_alloc(GFP_NOFS, nr_pages - i);
			if (!bio)
				bio = bio_alloc(GFP_NOFS, 1);
			if (!bio) {
				ret = -ENOMEM;
				break;
			}

			bio->bi_sector = blkno << (SCOUTFS_BLOCK_SHIFT - 9);
			bio->bi_bdev = sb->s_bdev;
			bio->bi_end_io = read_pages_end_io;
		}

		lock_page(page);
		ClearPageError(page);
		ClearPageUptodate(page);

		bytes = min(nr_blocks << SCOUTFS_BLOCK_SHIFT, PAGE_SIZE);

		if (bio_add_page(bio, page, bytes, 0) != bytes) {
			/* submit the full bio and retry this page */
			submit_bio(READ, bio);
			bio = NULL;
			unlock_page(page);
			i--;
			continue;
		}

		blkno += BLOCKS_PER_PAGE;
		nr_blocks -= BLOCKS_PER_PAGE;
	}

	if (bio)
		submit_bio(READ, bio);

	for (i = 0; i < nr_pages; i++) {
		page = pages[i];

		wait_on_page_locked(page);
		if (!ret && (!PageUptodate(page) || PageError(page)))
			ret = -EIO;
	}

	return ret;
}
#endif


static int read_one_entry(struct super_block *sb,
	                  struct scoutfs_ring_entry_header *eh)
{
	struct scoutfs_ring_add_manifest *am;
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);
	int ret;

	switch(eh->type) {
	case SCOUTFS_RING_ADD_MANIFEST:
		am = container_of(eh, struct scoutfs_ring_add_manifest, eh);

		scoutfs_kvec_init(first, am + 1,
				  le16_to_cpu(am->first_key_len));
		scoutfs_kvec_init(last,
				  first[0].iov_base + first[0].iov_len,
				  le16_to_cpu(am->last_key_len));

		ret = scoutfs_manifest_add(sb, first, last,
					   le64_to_cpu(am->segno),
					   le64_to_cpu(am->seq), am->level);
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static int read_entries(struct super_block *sb,
			struct scoutfs_ring_block *ring)
{
	struct scoutfs_ring_entry_header *eh;
	int ret = 0;
	int i;

	eh = ring->entries;

	for (i = 0; i < le32_to_cpu(ring->nr_entries); i++) {
		ret = read_one_entry(sb, eh);
		if (ret)
			break;

		eh = (void *)eh + le16_to_cpu(eh->len);
	}

	return ret;
}

#if 0
/* return pointer to the blk 4k block offset amongst the pages */
static void *page_block_address(struct page **pages, unsigned int blk)
{
	unsigned int i = blk / BLOCKS_PER_PAGE;
	unsigned int off = (blk % BLOCKS_PER_PAGE) << SCOUTFS_BLOCK_SHIFT;

	return page_address(pages[i]) + off;
}
#endif

int scoutfs_ring_read(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_ring_block *ring;
	struct page **pages;
	struct page *page;
	u64 index;
	u64 blkno;
	u64 tail;
	u64 seq;
	int ret;
	int nr;
	int i;

	/* nr_blocks/pages calc doesn't handle multiple pages per block */
	BUILD_BUG_ON(PAGE_SIZE < SCOUTFS_BLOCK_SIZE);

	pages = kcalloc(NR_PAGES, sizeof(struct page *), GFP_NOFS);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < NR_PAGES; i++) {
		page = alloc_page(GFP_NOFS);
		if (!page) {
			ret = -ENOMEM;
			goto out;
		}

		pages[i] = page;
	}

	index = le64_to_cpu(super->ring_head_index);
	tail = le64_to_cpu(super->ring_tail_index);
	seq = le64_to_cpu(super->ring_head_seq);

	for(;;) {
		blkno = le64_to_cpu(super->ring_blkno) + index;

		if (index <= tail)
			nr = tail - index + 1;
		else
			nr = le64_to_cpu(super->ring_blocks) - index;
		nr = min_t(int, nr, NR_BLOCKS);

		ret = scoutfs_bio_read(sb, pages, blkno, nr);
		if (ret)
			goto out;

		/* XXX verify block header */

		for (i = 0; i < nr; i++) {
			ring = scoutfs_page_block_address(pages, i);
			ret = read_entries(sb, ring);
			if (ret)
				goto out;
		}

		if (index == tail)
			break;

		index += nr;
		if (index == le64_to_cpu(super->ring_blocks))
			index = 0;
	}

out:
	for (i = 0; i < NR_PAGES && pages && pages[i]; i++)
		__free_page(pages[i]);
	kfree(pages);

	return ret;
}
