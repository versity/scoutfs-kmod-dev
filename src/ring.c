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
#include <linux/crc32c.h>

#include "super.h"
#include "format.h"
#include "bio.h"
#include "ring.h"

/*
 * scoutfs stores the persistent indexes for the server in a simple log
 * entries in a preallocated ring of blocks.
 *
 * The index is read from the log and loaded in to an rbtree in memory.
 * Callers then lock around operations that work on the rbtrees.  Dirty
 * and deleted nodes are tracked and are eventually copied to pages that
 * are written to the tail of the log.
 *
 * This has the great benefit of updating an index with very few (often
 * one) contiguous block writes with low write amplification.
 *
 * This has the significant cost of requiring reading the indexes in to
 * memory before doing any work and then having to hold them resident.
 * This is fine for now but we'll have to address these latency and
 * capacity limitations before too long.
 *
 * Callers are entirely responsible for locking.
 */

/*
 * XXX
 *  - deletion entries could be smaller if we understood keys
 *  - shouldn't be too hard to compress
 */

/*
 * @block records the logical ring index of the block that contained the
 * node.  As we commit a ring update we can look at the clean list to
 * find the first block that we have to read out of the ring.  This
 * helps minimize the active region of the ring.
 *
 * @in_ring is used to mark nodes that were present in the ring and
 * which need deletion entries written to the ring before they can be
 * freed.
 */
struct ring_node {
	struct rb_node rb_node;
	struct list_head head;
	u64 block;

	u16 data_len;

	u8 dirty:1,
	   deleted:1,
	   in_ring:1;

	/* data is packed but callers perform native long bitops */
	u8 data[0] __aligned(__alignof__(long));
};

static struct ring_node *data_rnode(void *data)
{
	return data ? container_of(data, struct ring_node, data) : NULL;
}

static void *rnode_data(struct ring_node *rnode)
{
	return rnode ? rnode->data : NULL;
}

static unsigned total_entry_bytes(unsigned data_len)
{
	return offsetof(struct scoutfs_ring_entry, data[data_len]);
}

/*
 * Each time we mark a node dirty we also dirty the oldest clean entry.
 * This ensures that we never overwrite stable data.
 *
 * Picture a ring of blocks where the first half of the ring is full of
 * existing entries.  Imagine that we continuously update a set of
 * entries that make up a single block.  Each new update block
 * invalidates the previous update block but it advances through the
 * ring while the old entries are sitting idle in the first half.
 * Eventually the new update blocks wrap around and clobber the old
 * blocks.
 *
 * Now instead imagine that each time we dirty an entry in this set of
 * constantly changing entries that we also go and dirty the earliest
 * existing entry in the ring.  Now each update is a block of the
 * useless updating entries and a block of old entries that have been
 * migrated.  Each time we write two blocks to the ring we migrate one
 * block from the start of the ring.  Now by the time we fill the second
 * half of the ring we've reclaimed half of the first half of the ring.
 *
 * So we size the ring to fit 4x the largest possible index.  Now we're
 * sure that we'll be able to fully migrate the index from the first
 * half of the ring into the second half before it wraps around and
 * starts overwriting the first.
 */
static void mark_node_dirty(struct scoutfs_ring_info *ring,
			    struct ring_node *rnode, bool migrate)
{
	struct ring_node *pos;
	long total;

	if (!rnode || rnode->dirty)
		return;

	list_move_tail(&rnode->head, &ring->dirty_list);
	rnode->dirty = 1;
	ring->dirty_bytes += total_entry_bytes(rnode->data_len);

	if (migrate) {
		total = total_entry_bytes(rnode->data_len);

		list_for_each_entry_safe(rnode, pos, &ring->clean_list, head) {
			mark_node_dirty(ring, rnode, false);
			total -= total_entry_bytes(rnode->data_len);
			if (total < 0)
				break;
		}
	}
}

static void mark_node_clean(struct scoutfs_ring_info *ring,
			    struct ring_node *rnode)
{
	if (!rnode || !rnode->dirty)
		return;

	list_move_tail(&rnode->head, &ring->clean_list);
	rnode->dirty = 0;
	ring->dirty_bytes -= total_entry_bytes(rnode->data_len);
}

static void free_node(struct scoutfs_ring_info *ring,
		      struct ring_node *rnode)
{
	if (rnode) {
		mark_node_clean(ring, rnode);

		if (!list_empty(&rnode->head))
			list_del_init(&rnode->head);
		if (!RB_EMPTY_NODE(&rnode->rb_node))
			rb_erase(&rnode->rb_node, &ring->rb_root);

		kfree(rnode);
	}
}

/*
 * Walk the tree and return the last node traversed.  cmp gives the
 * caller the comparison between their key and the returned node.  The
 * caller can provide either their key or another nodes data to compare
 * with during descent.  If we're asked to insert we replace any node we
 * find in the key's place.
 */
static struct ring_node *ring_rb_walk(struct scoutfs_ring_info *ring,
				      void *key, void *data,
				      struct ring_node *ins,
				      int *cmp)
{
	struct rb_node **node = &ring->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct ring_node *found = NULL;
	struct ring_node *rnode = NULL;

	/* only provide one or the other */
	BUG_ON(!!key == !!data);

	while (*node) {
		parent = *node;
		rnode = container_of(*node, struct ring_node, rb_node);

		if (key)
			*cmp = ring->compare_key(key, &rnode->data);
		else
			*cmp = ring->compare_data(data, &rnode->data);

		if (*cmp < 0) {
			node = &(*node)->rb_left;
		} else if (*cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			found = rnode;
			break;
		}
	}

	if (ins) {
		if (found) {
			rb_replace_node(&found->rb_node, &ins->rb_node,
					&ring->rb_root);
			RB_CLEAR_NODE(&found->rb_node);
			free_node(ring, found);
		} else {
			rb_link_node(&ins->rb_node, parent, node);
			rb_insert_color(&ins->rb_node, &ring->rb_root);
		}
		found = ins;
		*cmp = 0;
	}

	return rnode;
}

static struct ring_node *ring_rb_entry(struct rb_node *node)
{
	return node ? rb_entry(node, struct ring_node, rb_node) : NULL;
}

/* return the next node, skipping deleted */
static struct ring_node *ring_rb_next(struct ring_node *rnode)
{
	do {
		if (rnode)
			rnode = ring_rb_entry(rb_next(&rnode->rb_node));
	} while (rnode && rnode->deleted);

	return rnode;
}

/* return the prev node, skipping deleted */
static struct ring_node *ring_rb_prev(struct ring_node *rnode)
{
	do {
		if (rnode)
			rnode = ring_rb_entry(rb_prev(&rnode->rb_node));
	} while (rnode && rnode->deleted);

	return rnode;
}

/* return the first node, skipping deleted */
static struct ring_node *ring_rb_first(struct scoutfs_ring_info *ring)
{
	struct ring_node *rnode;

	rnode = ring_rb_entry(rb_first(&ring->rb_root));
	if (rnode && rnode->deleted)
		rnode = ring_rb_next(rnode);
	return rnode;
}

static struct ring_node *alloc_node(unsigned data_len)
{
	struct ring_node *rnode;

	rnode = kzalloc(offsetof(struct ring_node, data[data_len]), GFP_NOFS);
	if (rnode) {
		RB_CLEAR_NODE(&rnode->rb_node);
		INIT_LIST_HEAD(&rnode->head);
		rnode->data_len = data_len;
	}

	return rnode;
}

/*
 * Insert a new node.  This will replace any existing node which could
 * be in any state.
 */
void *scoutfs_ring_insert(struct scoutfs_ring_info *ring, void *key,
			  unsigned data_len)
{
	struct ring_node *rnode;
	int cmp;

	rnode = alloc_node(data_len);
	if (!rnode)
		return NULL;

	ring_rb_walk(ring, key, NULL, rnode, &cmp);
	/* just put it on a list, dirtying moves it to dirty */
	list_add_tail(&rnode->head, &ring->dirty_list);
	mark_node_dirty(ring, rnode, true);

	trace_printk("inserted rnode %p in %u deleted %u dirty %u\n",
			rnode, rnode->in_ring, rnode->deleted,
			rnode->dirty);

	return rnode->data;
}

void *scoutfs_ring_first(struct scoutfs_ring_info *ring)
{
	return rnode_data(ring_rb_first(ring));
}

void *scoutfs_ring_lookup(struct scoutfs_ring_info *ring, void *key)
{
	struct ring_node *rnode;
	int cmp;

	rnode = ring_rb_walk(ring, key, NULL, NULL, &cmp);
	if (rnode && (cmp || rnode->deleted))
		rnode = NULL;

	return rnode_data(rnode);
}

void *scoutfs_ring_lookup_next(struct scoutfs_ring_info *ring, void *key)
{
	struct ring_node *rnode;
	int cmp;

	rnode = ring_rb_walk(ring, key, NULL, NULL, &cmp);
	if (rnode && (cmp > 0 || rnode->deleted))
		rnode = ring_rb_next(rnode);

	return rnode_data(rnode);
}

void *scoutfs_ring_lookup_prev(struct scoutfs_ring_info *ring, void *key)
{
	struct ring_node *rnode;
	int cmp;

	rnode = ring_rb_walk(ring, key, NULL, NULL, &cmp);
	if (rnode && (cmp < 0 || rnode->deleted))
		rnode = ring_rb_prev(rnode);

	return rnode_data(rnode);
}

void *scoutfs_ring_next(struct scoutfs_ring_info *ring, void *data)
{
	return rnode_data(ring_rb_next(data_rnode(data)));
}

void *scoutfs_ring_prev(struct scoutfs_ring_info *ring, void *data)
{
	return rnode_data(ring_rb_prev(data_rnode(data)));
}

/*
 * Calculate the most blocks we could have to use to store a given number
 * of bytes of entries.  At worst each block has a header and leaves one
 * less than the max manifest entry unused.
 */
static unsigned most_blocks(unsigned long bytes)
{
	unsigned long space;

	space = SCOUTFS_BLOCK_SIZE -
		sizeof(struct scoutfs_ring_block) -
		(sizeof(struct scoutfs_manifest_entry) +
		 (2 * SCOUTFS_MAX_KEY_SIZE) - 1);

	return DIV_ROUND_UP(bytes, space);
}

static u64 wrap_ring_block(struct scoutfs_ring_descriptor *rdesc, u64 block)
{
	if (block >= le64_to_cpu(rdesc->total_blocks))
		block -= le64_to_cpu(rdesc->total_blocks);

	/* XXX callers should have verified on load */
	BUG_ON(block >= le64_to_cpu(rdesc->total_blocks));

	return block;
}

static u64 calc_first_dirty_block(struct scoutfs_ring_descriptor *rdesc)
{
	return wrap_ring_block(rdesc, le64_to_cpu(rdesc->first_block) +
			       le64_to_cpu(rdesc->nr_blocks));
}

static __le32 rblk_crc(struct scoutfs_ring_block *rblk)
{
	unsigned long skip = (char *)(&rblk->crc + 1) - (char *)rblk;

	return cpu_to_le32(crc32c(~0, (char *)rblk + skip,
				  SCOUTFS_BLOCK_SIZE - skip));
}

/*
 * This is called after the caller has copied all the dirty nodes into
 * blocks in pages for writing.  We might be able to dirty a few more
 * clean nodes to fill up the end of the last dirty block to keep the
 * ring blocks densely populated.
 */
static void fill_last_dirty_block(struct scoutfs_ring_info *ring,
				  unsigned space)
{
	struct ring_node *rnode;
	struct ring_node *pos;
	unsigned tot;

	list_for_each_entry_safe(rnode, pos, &ring->clean_list, head) {

		tot = total_entry_bytes(rnode->data_len);
		if (tot > space)
			break;

		mark_node_dirty(ring, rnode, false);
		space -= tot;
	}
}

void scoutfs_ring_dirty(struct scoutfs_ring_info *ring, void *data)
{
	struct ring_node *rnode;

	rnode = data_rnode(data);
	if (rnode)
		mark_node_dirty(ring, rnode, true);
}

/*
 * Delete the given node.  This can free the node so the caller cannot
 * use the data after calling this.
 *
 * If the node previously existed in the ring then we have to save it and
 * write a deletion entry before freeing it.
 */
void scoutfs_ring_delete(struct scoutfs_ring_info *ring, void *data)
{
	struct ring_node *rnode = data_rnode(data);

	trace_printk("deleting rnode %p in %u deleted %u dirty %u\n",
		      rnode, rnode->in_ring, rnode->deleted, rnode->dirty);

	BUG_ON(rnode->deleted);

	if (rnode->in_ring) {
		rnode->deleted = 1;
		mark_node_dirty(ring, rnode, true);
	} else {
		free_node(ring, rnode);
	}
}

static struct scoutfs_ring_block *block_in_pages(struct page **pages,
						 unsigned i)
{
	return page_address(pages[i / SCOUTFS_BLOCKS_PER_PAGE]) +
		((i % SCOUTFS_BLOCKS_PER_PAGE) << SCOUTFS_BLOCK_SHIFT);
}

static int load_ring_block(struct scoutfs_ring_info *ring,
			   struct scoutfs_ring_block *rblk)
{
	struct scoutfs_ring_entry *rent;
	struct ring_node *rnode;
	unsigned data_len;
	unsigned i;
	int ret = 0;
	int cmp;

	trace_printk("block %llu\n", le64_to_cpu(rblk->block));

	rent = rblk->entries;
	for (i = 0; i < le32_to_cpu(rblk->nr_entries); i++) {

		/* XXX verify fields? */
		data_len = le16_to_cpu(rent->data_len);

		trace_printk("rent %u data_len %u\n", i, data_len);

		if (rent->flags & SCOUTFS_RING_ENTRY_FLAG_DELETION) {
			rnode = ring_rb_walk(ring, NULL, rent->data, NULL,
					     &cmp);
			if (rnode && cmp == 0)
				free_node(ring, rnode);
		} else {
			rnode = alloc_node(data_len);
			if (!rnode) {
				ret = -ENOMEM;
				break;
			}

			rnode->block = le64_to_cpu(rblk->block);
			rnode->in_ring = 1;
			memcpy(rnode->data, rent->data, data_len);

			ring_rb_walk(ring, NULL, rnode->data, rnode, &cmp);
			list_add_tail(&rnode->head, &ring->clean_list);
		}

		rent = (void *)&rent->data[data_len];
	}

	return ret;
}

/*
 * Read the ring entries into rb nodes with nice large synchronous reads.
 */
#define LOAD_BYTES	(4 * 1024 * 1024)
#define LOAD_BLOCKS	DIV_ROUND_UP(LOAD_BYTES, SCOUTFS_BLOCK_SIZE)
#define LOAD_PAGES	DIV_ROUND_UP(LOAD_BYTES, PAGE_SIZE)
int scoutfs_ring_load(struct super_block *sb, struct scoutfs_ring_info *ring)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_ring_descriptor *rdesc = ring->rdesc;
	struct scoutfs_ring_block *rblk;
	struct page **pages;
	unsigned read_nr;
	unsigned i;
	__le32 crc;
	u64 block;
	u64 total;
	u64 seq;
	u64 nr;
	int ret;

	pages = kcalloc(LOAD_PAGES, sizeof(struct page *), GFP_NOFS);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < LOAD_PAGES; i++) {
		pages[i] = alloc_page(GFP_NOFS);
		if (!pages[i]) {
			ret = -ENOMEM;
			goto out;
		}
	}

	block = le64_to_cpu(rdesc->first_block);
	seq = le64_to_cpu(rdesc->first_seq);
	total = le64_to_cpu(rdesc->total_blocks);
	nr = le64_to_cpu(rdesc->nr_blocks);

	while (nr) {
		read_nr = min3(nr, (u64)LOAD_BLOCKS, total - block);

		ret = scoutfs_bio_read(sb, pages, le64_to_cpu(rdesc->blkno) +
				       block, read_nr);
		if (ret)
			goto out;

		for (i = 0; i < read_nr; i++) {
			rblk = block_in_pages(pages, i);
			crc = rblk_crc(rblk);

			if (rblk->fsid != super->hdr.fsid ||
			    le64_to_cpu(rblk->block) != (block + i) ||
			    le64_to_cpu(rblk->seq) != (seq + i) ||
			    rblk->crc != crc) {
				ret = -EIO;
				goto out;
			}

			ret = load_ring_block(ring, rblk);
			if (ret)
				goto out;
		}

		block = wrap_ring_block(rdesc, block + read_nr);
		seq += read_nr;
		nr -= read_nr;
	}
	ret = 0;

out:
	for (i = 0; pages && i < LOAD_PAGES && pages[i]; i++)
		__free_page(pages[i]);
	kfree(pages);

	if (ret)
		scoutfs_ring_destroy(ring);

	return ret;
}

static struct ring_node *first_dirty_node(struct scoutfs_ring_info *ring)
{
	return list_first_entry_or_null(&ring->dirty_list, struct ring_node,
					head);
}

static struct ring_node *next_dirty_node(struct scoutfs_ring_info *ring,
					 struct ring_node *rnode)
{
	if (rnode->head.next == &ring->dirty_list)
		return NULL;

	return list_next_entry(rnode, head);
}

static void ring_free_pages(struct scoutfs_ring_info *ring)
{
	unsigned i;

	if (!ring->pages)
		return;

	for (i = 0; i < ring->nr_pages; i++) {
		if (ring->pages[i])
			__free_page(ring->pages[i]);
	}

	kfree(ring->pages);

	ring->pages = NULL;
	ring->nr_pages = 0;
}

int scoutfs_ring_has_dirty(struct scoutfs_ring_info *ring)
{
	return !!ring->dirty_bytes;
}

int scoutfs_ring_submit_write(struct super_block *sb,
			      struct scoutfs_ring_info *ring,
			      struct scoutfs_bio_completion *comp)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_ring_descriptor *rdesc = ring->rdesc;
	struct scoutfs_ring_block *rblk;
	struct scoutfs_ring_entry *rent;
	struct ring_node *rnode;
	struct ring_node *next;
	struct page **pages;
	unsigned nr_blocks;
	unsigned nr_pages;
	unsigned i;
	u64 blkno;
	u64 block;
	u64 first;
	u64 last;
	u64 seq;
	u64 nr;
	u8 *end;
	int ret;

	if (ring->dirty_bytes == 0)
		return 0;

	nr_blocks = most_blocks(ring->dirty_bytes);
	nr_pages = DIV_ROUND_UP(nr_blocks, SCOUTFS_BLOCKS_PER_PAGE);

	ring_free_pages(ring);

	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_NOFS);
	if (!pages)
		return -ENOMEM;

	ring->pages = pages;
	ring->nr_pages = nr_pages;

	for (i = 0; i < nr_pages; i++) {
		pages[i] = alloc_page(GFP_NOFS | __GFP_ZERO);
		if (!pages[i]) {
			ret = -ENOMEM;
			goto out;
		}
	}

	block = ring->first_dirty_block;
	seq = ring->first_dirty_seq;
	rnode = first_dirty_node(ring);

	for (i = 0; rnode && i < nr_blocks; i++) {

		rblk = block_in_pages(pages, i);
		end = (u8 *)rblk + SCOUTFS_BLOCK_SIZE;

		rblk->fsid = super->hdr.fsid;
		rblk->seq = cpu_to_le64(seq);
		rblk->block = cpu_to_le64(block);

		rent = rblk->entries;

		while (rnode && &rent->data[rnode->data_len] <= end) {

			trace_printk("writing ent %u rnode %p in %u deleted %u dirty %u\n",
					le32_to_cpu(rblk->nr_entries),
					rnode, rnode->in_ring, rnode->deleted,
					rnode->dirty);

			rent->data_len = cpu_to_le16(rnode->data_len);
			if (rnode->deleted)
				rent->flags = SCOUTFS_RING_ENTRY_FLAG_DELETION;
			memcpy(rent->data, rnode->data, rnode->data_len);

			le32_add_cpu(&rblk->nr_entries, 1);

			rnode->block = block;

			rent = (void *)&rent->data[le16_to_cpu(rent->data_len)];

			next = next_dirty_node(ring, rnode);
			if (!next) {
				fill_last_dirty_block(ring, (char *)end -
							    (char *)rent);
				next = next_dirty_node(ring, rnode);
			}
			rnode = next;
		}

		rblk->crc = rblk_crc(rblk);

		block = wrap_ring_block(rdesc, block + 1);
		seq++;
	}

	/* update the number of blocks we actually filled */
	nr_blocks = i;

	/* point the descriptor at the new active region of the ring */
	rnode = list_first_entry_or_null(&ring->clean_list, struct ring_node,
					 head);
	if (rnode)
		first = rnode->block;
	else
		first = ring->first_dirty_block;

	last = wrap_ring_block(rdesc, ring->first_dirty_block + nr_blocks);

	if (first < last)
		nr = last - first;
	else
		nr = last + le64_to_cpu(rdesc->total_blocks) - first;

	rdesc->first_block = cpu_to_le64(first);
	rdesc->first_seq = cpu_to_le64(ring->first_dirty_seq);
	rdesc->nr_blocks = cpu_to_le64(nr);

	/* the contig dirty blocks in pages might wrap around ring */
	blkno = le64_to_cpu(rdesc->blkno) + ring->first_dirty_block;
	nr = min_t(u64, nr_blocks,
		   le64_to_cpu(rdesc->total_blocks) - ring->first_dirty_block);

	scoutfs_bio_submit_comp(sb, WRITE, pages, blkno, nr, comp);

	if (nr != nr_blocks) {
		pages += nr / SCOUTFS_BLOCKS_PER_PAGE;
		blkno = le64_to_cpu(rdesc->blkno);
		nr = nr_blocks - nr;

		scoutfs_bio_submit_comp(sb, WRITE, pages, blkno, nr, comp);
	}

	ret = 0;

out:
	if (ret)
		ring_free_pages(ring);

	return ret;
}

void scoutfs_ring_write_complete(struct scoutfs_ring_info *ring)
{
	struct ring_node *rnode;
	struct ring_node *pos;

	list_for_each_entry_safe(rnode, pos, &ring->dirty_list, head) {
		if (rnode->deleted) {
			free_node(ring, rnode);
		} else {
			mark_node_clean(ring, rnode);
			rnode->in_ring = 1;
		}
	}

	ring_free_pages(ring);

	ring->dirty_bytes = 0;
	ring->first_dirty_block = calc_first_dirty_block(ring->rdesc);
	ring->first_dirty_seq = le64_to_cpu(ring->rdesc->first_seq) +
				le64_to_cpu(ring->rdesc->nr_blocks);
}

void scoutfs_ring_init(struct scoutfs_ring_info *ring,
		       struct scoutfs_ring_descriptor *rdesc,
		       scoutfs_ring_cmp_t compare_key,
		       scoutfs_ring_cmp_t compare_data)
{
	ring->rdesc = rdesc;
	ring->compare_key = compare_key;
	ring->compare_data = compare_data;
	ring->rb_root = RB_ROOT;
	INIT_LIST_HEAD(&ring->clean_list);
	INIT_LIST_HEAD(&ring->dirty_list);
	ring->dirty_bytes = 0;
	ring->first_dirty_block = calc_first_dirty_block(rdesc);
	ring->first_dirty_seq = le64_to_cpu(rdesc->first_seq) +
				le64_to_cpu(rdesc->nr_blocks);
	ring->pages = NULL;
	ring->nr_pages = 0;
}

void scoutfs_ring_destroy(struct scoutfs_ring_info *ring)
{
	struct ring_node *rnode;
	struct ring_node *pos;

	/* XXX we don't really have a coherent forced dirty unmount story */
	WARN_ON_ONCE(!list_empty(&ring->dirty_list));

	list_splice_init(&ring->dirty_list, &ring->clean_list);

	list_for_each_entry_safe(rnode, pos, &ring->clean_list, head) {
		list_del_init(&rnode->head);
		kfree(rnode);
	}

	ring_free_pages(ring);
	scoutfs_ring_init(ring, ring->rdesc, ring->compare_key,
			  ring->compare_data);
}
