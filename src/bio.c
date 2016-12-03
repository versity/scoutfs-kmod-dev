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
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "bio.h"

struct bio_end_io_args {
	struct super_block *sb;
	atomic_t bytes_in_flight;
	int err;
	scoutfs_bio_end_io_t end_io;
	void *data;
};

static void dec_end_io(struct bio_end_io_args *args, size_t bytes, int err)
{
	if (err && !args->err)
		args->err = err;

	if (atomic_sub_return(bytes, &args->bytes_in_flight) == 0) {
		args->end_io(args->sb, args->data, args->err);
		kfree(args);
	}
}

static void bio_end_io(struct bio *bio, int err)
{
	struct bio_end_io_args *args = bio->bi_private;

	dec_end_io(args, bio->bi_size, err);
	bio_put(bio);
}

/*
 * Read or write the given number of 4k blocks from the front of the
 * pages provided by the caller.  We translate the block count into a
 * page count and fill bios a page at a time.
 *
 * The caller is responsible for ensuring that the pages aren't freed
 * while bios are in flight.
 *
 * The end_io function is always called once with the error result of
 * the IO.  It can be called before _submit returns.
 */
void scoutfs_bio_submit(struct super_block *sb, int rw, struct page **pages,
		        u64 blkno, unsigned int nr_blocks,
			scoutfs_bio_end_io_t end_io, void *data)
{
	unsigned int nr_pages = DIV_ROUND_UP(nr_blocks,
					     SCOUTFS_BLOCKS_PER_PAGE);
	struct bio_end_io_args *args;
	struct blk_plug plug;
	unsigned int bytes;
	struct page *page;
	struct bio *bio = NULL;
	int ret = 0;
	int i;

	args = kmalloc(sizeof(struct bio_end_io_args), GFP_NOFS);
	if (!args) {
		end_io(sb, data, -ENOMEM);
		return;
	}

	args->sb = sb;
	atomic_set(&args->bytes_in_flight, 1);
	args->err = 0;
	args->end_io = end_io;
	args->data = data;

	blk_start_plug(&plug);

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
			bio->bi_end_io = bio_end_io;
			bio->bi_private = args;
		}

		bytes = min_t(int, nr_blocks << SCOUTFS_BLOCK_SHIFT, PAGE_SIZE);

		if (bio_add_page(bio, page, bytes, 0) != bytes) {
			/* submit the full bio and retry this page */
			atomic_add(bio->bi_size, &args->bytes_in_flight);
			submit_bio(rw, bio);
			bio = NULL;
			i--;
			continue;
		}

		blkno += SCOUTFS_BLOCKS_PER_PAGE;
		nr_blocks -= SCOUTFS_BLOCKS_PER_PAGE;
	}

	if (bio) {
		atomic_add(bio->bi_size, &args->bytes_in_flight);
		submit_bio(rw, bio);
	}

	blk_finish_plug(&plug);
	dec_end_io(args, 1, ret);
}

struct end_io_completion {
	struct completion comp;
	int err;
};

static void end_io_complete(struct super_block *sb, void *data, int err)
{
	struct end_io_completion *comp = data;

	comp->err = err;
	complete(&comp->comp);
}

/*
 * A synchronous read of the given blocks.
 *
 * XXX we could make this interruptible.
 */
int scoutfs_bio_read(struct super_block *sb, struct page **pages,
		     u64 blkno, unsigned int nr_blocks)
{
	struct end_io_completion comp = {
		.comp = COMPLETION_INITIALIZER(comp.comp),
	};

	scoutfs_bio_submit(sb, READ, pages, blkno, nr_blocks,
			   end_io_complete, &comp);
	wait_for_completion(&comp.comp);
	return comp.err;
}

/* return pointer to the blk 4k block offset amongst the pages */
void *scoutfs_page_block_address(struct page **pages, unsigned int blk)
{
	unsigned int i = blk / SCOUTFS_BLOCKS_PER_PAGE;
	unsigned int off = (blk % SCOUTFS_BLOCKS_PER_PAGE) <<
				SCOUTFS_BLOCK_SHIFT;

	return page_address(pages[i]) + off;
}
