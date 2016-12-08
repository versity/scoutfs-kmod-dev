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
#include <linux/pagemap.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "bio.h"
#include "manifest.h"
#include "alloc.h"
#include "ring.h"
#include "crc.h"


/*
 * Right now we're only writing a segment a time.  The entries needed to
 * write a segment will always be smaller than a segment itself.
 *
 * XXX This'll get more clever as we can write multiple segments and build
 * up dirty entries while processing compaction results.
 */
struct ring_info {
	struct page *pages[SCOUTFS_SEGMENT_PAGES];
	struct scoutfs_ring_block *ring;
	struct scoutfs_ring_entry_header *next_eh;
	unsigned int nr_blocks;
	unsigned int space;
};

#define DECLARE_RING_INFO(sb, name) \
	struct ring_info *name = SCOUTFS_SB(sb)->ring_info

/*
 * XXX
 *  - verify blocks
 *  - could compress
 *  - have all entry sources dirty at cursors before dirtying
 *  - advancing cursor updates head as cursor wraps
 */

/*
 * The space calculation when starting a block included a final empty
 * entry header.  That is zeroed here.
 */
static void finish_block(struct scoutfs_ring_block *ring, unsigned int tail)
{
	memset((char *)ring + SCOUTFS_BLOCK_SIZE - tail, 0, tail);
	scoutfs_crc_block(&ring->hdr);
}

void scoutfs_ring_append(struct super_block *sb,
			 struct scoutfs_ring_entry_header *eh)
{
	DECLARE_RING_INFO(sb, rinf);
	struct scoutfs_ring_block *ring = rinf->ring;
	unsigned int len = le16_to_cpu(eh->len);

	if (rinf->space < len) {
		if (ring)
			finish_block(ring, rinf->space);
		ring = scoutfs_page_block_address(rinf->pages, rinf->nr_blocks);
		rinf->ring = ring;

		memset(ring, 0, sizeof(struct scoutfs_ring_block));

		rinf->nr_blocks++;
		rinf->next_eh = ring->entries;
		rinf->space = SCOUTFS_BLOCK_SIZE -
			      offsetof(struct scoutfs_ring_block, entries) -
			      sizeof(struct scoutfs_ring_entry_header);
	}

	memcpy(rinf->next_eh, eh, len);
	rinf->next_eh = (void *)((char *)eh + len);
	rinf->space -= len;
}

/*
 * Kick off the writes to update the ring.  Update the dirty super to
 * reference the written ring.
 */
int scoutfs_ring_submit_write(struct super_block *sb,
			      struct scoutfs_bio_completion *comp)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_RING_INFO(sb, rinf);
	u64 head_blocks;
	u64 blocks;
	u64 blkno;
	u64 ind;

	if (!rinf->nr_blocks)
		return 0;

	if (rinf->space)
		finish_block(rinf->ring, rinf->space);

	ind = le64_to_cpu(super->ring_tail_index) + 1;
	blocks = rinf->nr_blocks;
	blkno = le64_to_cpu(super->ring_blkno) + ind;

	/*
	 * If the log wrapped then we have to write two fragments to the
	 * tail and head of the ring.  We submit the head fragment
	 * first.
	 *
	 * The head fragment starts at some block offset in the
	 * preallocated pages.  This hacky page math only works when our
	 * 4k blocks size == page_size.  To fix it we'd add a offset
	 * block to the bio submit loop which could add an initial
	 * partial page vec to the bios.
	 */
	BUILD_BUG_ON(SCOUTFS_BLOCK_SIZE != PAGE_SIZE);

	if (ind + blocks > le64_to_cpu(super->ring_blocks)) {
		head_blocks = (ind + blocks) - le64_to_cpu(super->ring_blocks);
		blocks -= head_blocks;
		scoutfs_bio_submit_comp(sb, WRITE, rinf->pages + blocks,
					le64_to_cpu(super->ring_blkno),
					head_blocks, comp);
	}

	scoutfs_bio_submit_comp(sb, WRITE, rinf->pages, blkno, blocks, comp);

	ind += blocks;
	if (ind == le64_to_cpu(super->ring_blocks))
		ind = 0;
	super->ring_tail_index = cpu_to_le64(ind);

	return 0;
}

static int read_one_entry(struct super_block *sb,
	                  struct scoutfs_ring_entry_header *eh)
{
	struct scoutfs_ring_alloc_region *reg;
	struct scoutfs_ring_add_manifest *am;
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);
	int ret;

	trace_printk("type %u len %u\n", eh->type, le16_to_cpu(eh->len));

	switch(eh->type) {
	case SCOUTFS_RING_ADD_MANIFEST:
		am = container_of(eh, struct scoutfs_ring_add_manifest, eh);

		trace_printk("lens %u %u\n",
				  le16_to_cpu(am->first_key_len),
				  le16_to_cpu(am->last_key_len));

		scoutfs_kvec_init(first, am + 1,
				  le16_to_cpu(am->first_key_len));
		scoutfs_kvec_init(last,
				  first[0].iov_base + first[0].iov_len,
				  le16_to_cpu(am->last_key_len));

		ret = scoutfs_manifest_add(sb, first, last,
					   le64_to_cpu(am->segno),
					   le64_to_cpu(am->seq), am->level,
					   false);
		break;

	case SCOUTFS_RING_ADD_ALLOC:
		reg = container_of(eh, struct scoutfs_ring_alloc_region, eh);
		ret = scoutfs_alloc_add(sb, reg);
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

	for (eh = ring->entries; eh->len;
	     eh = (void *)eh + le16_to_cpu(eh->len)) {

		ret = read_one_entry(sb, eh);
		if (ret)
			break;
	}

	return ret;
}


/* read in a meg at a time */
#define NR_PAGES DIV_ROUND_UP(1024 * 1024, PAGE_SIZE)
#define NR_BLOCKS (NR_PAGES * SCOUTFS_BLOCKS_PER_PAGE)

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

		trace_printk("index %llu tail %llu nr %u\n", index, tail, nr);

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

int scoutfs_ring_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct ring_info *rinf;
	struct page *page;
	int i;

	rinf = kzalloc(sizeof(struct ring_info), GFP_KERNEL);
	if (!rinf)
		return -ENOMEM;
	sbi->ring_info = rinf;

	for (i = 0; i < ARRAY_SIZE(rinf->pages); i++) {
		page = alloc_page(GFP_KERNEL);
		if (!page) {
			while (--i >= 0)
				__free_page(rinf->pages[i]);
			return -ENOMEM;
		}

		rinf->pages[i] = page;
	}

	return 0;
}

void scoutfs_ring_destroy(struct super_block *sb)
{
	DECLARE_RING_INFO(sb, rinf);
	int i;

	if (rinf) {
		for (i = 0; i < ARRAY_SIZE(rinf->pages); i++)
			__free_page(rinf->pages[i]);

		kfree(rinf);
	}
}

