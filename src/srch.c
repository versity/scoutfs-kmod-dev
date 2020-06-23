/*
 * Copyright (C) 2020 Versity Software, Inc.  All rights reserved.
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
#include <linux/random.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>

#include "super.h"
#include "format.h"
#include "counters.h"
#include "block.h"
#include "radix.h"
#include "srch.h"
#include "btree.h"
#include "spbm.h"
#include "client.h"
#include "scoutfs_trace.h"

/*
 * This srch subsystem gives us a way to find inodes that have a given
 * tagged xattr set.  It's designed for an xattr population that is
 * orders of magnitudes larger than the file population, is updated much
 * more frequently than it is searched, and can have slightly relaxed
 * consistency requirements so that searches don't have to serialize
 * with updates through locking.
 *
 * A srch entry is logged every time a .srch. xattr is created or
 * deleted.  Commits append entries to a growing srch log file along
 * with the item btree and allocator block structures they're modifying.
 *
 * The server regularly rotates these growing log files so that they
 * don't exceed a given size.  Once there are enough log files they're
 * all read and their sorted entries are written to a larger sorted
 * file.  Once there are enough sorted files they're all read and their
 * combined sorted entries are written to a larger file, and so on.
 *
 * Searches combine all the entries read from unsorted log files and
 * binary searches of larger sorted files to come up with the candidate
 * inodes that probably contain the given named .srch. xattr.
 *
 * Searches read rotated log files and sorted files which have been
 * committed.  There is nothing protecting their blocks from being
 * re-allocated and re-written.  Search can restart by checking the
 * btree for the current set of files.  Compaction reads log files which
 * are protected from other compactions by the persistent busy items
 * created by the server.  Compaction won't see it's blocks reused out
 * from under it, but it can encounter stale cached blocks that need to
 * be invalidated.
 */

struct srch_info {
	struct super_block *sb;
	atomic_t shutdown;
	struct workqueue_struct *workq;
	struct delayed_work compact_dwork;
};

#define DECLARE_SRCH_INFO(sb, name) \
	struct srch_info *name = SCOUTFS_SB(sb)->srch_info

#define SRE_FMT "%016llx.%llu.%llu"
#define SRE_ARG(sre)						\
	le64_to_cpu((sre)->hash), le64_to_cpu((sre)->ino),	\
	le64_to_cpu((sre)->id)

/*
 * Compactions dirty radix allocator blocks, file radix parent blocks,
 * and especially srch file blocks.  The files can get enormous and we
 * can't have compactions OOM the box but they're meant to be large
 * streaming operations, so we only stop and write out dirty blocks in
 * large chunks.
 */
#define SRCH_COMPACT_DIRTY_LIMIT_BYTES (32 * 1024 * 1024)

static int sre_cmp(const struct scoutfs_srch_entry *a,
		   const struct scoutfs_srch_entry *b)
{
	return scoutfs_cmp_u64s(le64_to_cpu(a->hash), le64_to_cpu(b->hash)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->ino), le64_to_cpu(b->ino)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->id), le64_to_cpu(b->id));
}

/*
 * srch items are first grouped by type and we have log files, sorted
 * files, and busy compactions.
 */
static void init_srch_key(struct scoutfs_key *key, int type,
			  u64 major, u64 minor)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_SRCH_ZONE,
		.sk_type = type,
		._sk_second = cpu_to_le64(major),
		._sk_third = cpu_to_le64(minor),
	};
}

/*
 * The caller has ensured that there is space for a full word at the
 * buf.  Only the set low order bytes will be used.  The clear high
 * order bytes will be overwritten in the future and ignored in the
 * final encoding in the block.
 */
static int encode_u64(__le64 *buf, u64 val)
{
	int bytes;

	val = (val << 1) ^ ((s64)val >> 63); /* shift sign extend */
	bytes = (fls64(val) + 7) >> 3;

	put_unaligned_le64(val, buf);
	return bytes;
}

/* shifting by width is undefined :/ */
#define BYTE_MASK(b) ((1ULL << (b << 3)) - 1)
static u64 byte_masks[] = {
	0, BYTE_MASK(1), BYTE_MASK(2), BYTE_MASK(3),
	BYTE_MASK(4), BYTE_MASK(5), BYTE_MASK(6), BYTE_MASK(7), U64_MAX,
};

static u64 decode_u64(void *buf, int bytes)
{
	u64 val = get_unaligned_le64(buf) & byte_masks[bytes];

	return (val >> 1) ^ (-(val & 1));
}

/*
 * Encode an entry at the offset in the block.  Leave room for the
 * lengths short, encode the diff of the encoded entry from the
 * previous, then update the length short with the length of each
 * encoded diff.  The caller ensures that there's room for a full size
 * entry at position in the block.
 */
static int encode_entry(void *buf, struct scoutfs_srch_entry *sre,
			struct scoutfs_srch_entry *prev)
{
	u64 diffs[] = {
		le64_to_cpu(sre->hash) - le64_to_cpu(prev->hash),
		le64_to_cpu(sre->ino) - le64_to_cpu(prev->ino),
		le64_to_cpu(sre->id) - le64_to_cpu(prev->id),
	};
	u16 lengths = 0;
	int bytes;
	int tot = 2;
	int i;

	for (i = 0; i < ARRAY_SIZE(diffs); i++) {
		bytes = encode_u64(buf + tot, diffs[i]);
		lengths |= bytes << (i << 2);
		tot += bytes;
	}

	put_unaligned_le16(lengths, buf);

	return tot;
}

/*
 * Decode an entry from the offset of the block.  Load the length short
 * and decode the bytes of diffs and apply them to the previous entry.
 * The caller ensures that we won't read off the end of block if we were
 * to try and decode a full size set of diffs.
 */
static int decode_entry(void *buf, struct scoutfs_srch_entry *sre,
			struct scoutfs_srch_entry *prev)
{
	u64 diffs[3];
	u16 lengths;
	int bytes;
	int tot;
	int i;

	lengths = get_unaligned_le16(buf);
	tot = 2;

	for (i = 0; i < ARRAY_SIZE(diffs); i++) {
		bytes = min_t(int, 8, lengths & 15);
		diffs[i] = decode_u64(buf + tot, bytes);
		tot += bytes;
		lengths >>= 4;
	}

	sre->hash = cpu_to_le64(le64_to_cpu(prev->hash) + diffs[0]);
	sre->ino = cpu_to_le64(le64_to_cpu(prev->ino) + diffs[1]);
	sre->id = cpu_to_le64(le64_to_cpu(prev->id) + diffs[2]);

	return tot;
}

/* return refs ind to traverse through parent at level to blk */
static int calc_ref_ind(u64 blk, int level)
{
	int ind;
	int i;

	BUG_ON(level < 1);

	for (i = 1; i <= level; i++)
		blk = div_u64_rem(blk, SCOUTFS_SRCH_PARENT_REFS, &ind);

	return ind;
}

static u8 height_for_blk(u64 blk)
{
	u64 total = SCOUTFS_SRCH_PARENT_REFS;
	int hei = 2;

	if (blk == 0)
		return 1;

	while (blk >= total) {
		hei++;
		total *= SCOUTFS_SRCH_PARENT_REFS;
	}

	return hei;
}

static void init_file_block(struct super_block *sb, struct scoutfs_block *bl,
			    int level)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_block_header *hdr;

	/* don't leak uninit kernel mem.. block should do this for us? */
	memset(bl->data, 0, SCOUTFS_BLOCK_LG_SIZE);

	hdr = bl->data;
	hdr->fsid = super->hdr.fsid;
	hdr->blkno = cpu_to_le64(bl->blkno);
	prandom_bytes(&hdr->seq, sizeof(hdr->seq));

	if (level)
		hdr->magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SRCH_PARENT);
	else
		hdr->magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SRCH_BLOCK);
}

/*
 * This is operating on behalf of writers writing into private files and
 * readers who could see stale blocks.  We can find stale cached blocks
 * and should retry the read ourselves after invalidating, but if we hit
 * stale blocks on disk then we have to return to the caller who can
 * decide to return errors or retry.
 */
static int read_srch_block(struct super_block *sb,
			   struct scoutfs_block_writer *wri, int level,
			   struct scoutfs_srch_ref *ref,
			   struct scoutfs_block **bl_ret)
{
	struct scoutfs_block *bl;
	int retries = 0;
	int ret = 0;
	int mag;

	mag = level ? SCOUTFS_BLOCK_MAGIC_SRCH_PARENT :
		      SCOUTFS_BLOCK_MAGIC_SRCH_BLOCK;
retry:
	bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	if (!IS_ERR_OR_NULL(bl) &&
	    !scoutfs_block_consistent_ref(sb, bl, ref->seq, ref->blkno, mag)) {

		scoutfs_inc_counter(sb, srch_inconsistent_ref);
		scoutfs_block_writer_forget(sb, wri, bl);
		scoutfs_block_invalidate(sb, bl);
		scoutfs_block_put(sb, bl);
		bl = NULL;

		if (retries++ == 0)
			goto retry;

		bl = ERR_PTR(-ESTALE);
		scoutfs_inc_counter(sb, srch_read_stale);
	}
	if (IS_ERR(bl)) {
		ret = PTR_ERR(bl);
		bl = NULL;
	}

	*bl_ret = bl;
	return ret;
}

/*
 * Walk radix blocks to find the logical file block and return the
 * reference to the caller.  Flags determine if we cow new dirty blocks,
 * allocate new blocks, or return errors for missing blocks (files are
 * never sparse, this won't happen).
 */
enum {
	GFB_INSERT = (1 << 0),
	GFB_DIRTY = (1 << 1),
};
static int get_file_block(struct super_block *sb,
			  struct scoutfs_radix_allocator *alloc,
			  struct scoutfs_block_writer *wri,
			  struct scoutfs_srch_file *sfl,
			  int gfb, u64 blk, struct scoutfs_block **bl_ret)
{
	struct scoutfs_block *parent = NULL;
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_parent *srp;
	struct scoutfs_block *new_bl;
	struct scoutfs_srch_ref *ref;
	u64 blkno = 0;
	int level;
	int ind;
	int err;
	int ret;
	u8 hei;

	/* see if we need to grow to insert a new largest blk */
	hei = height_for_blk(blk);
	while (sfl->height < hei) {
		if (!(gfb & GFB_INSERT)) {
			ret = -ENOENT;
			goto out;
		}

		ret = scoutfs_radix_alloc(sb, alloc, wri, &blkno);
		if (ret < 0)
			goto out;

		bl = scoutfs_block_create(sb, blkno);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}
		blkno = 0;

		scoutfs_block_writer_mark_dirty(sb, wri, bl);

		init_file_block(sb, bl, sfl->height);
		if (sfl->height) {
			srp = bl->data;
			srp->refs[0].blkno = sfl->ref.blkno;
			srp->refs[0].seq = sfl->ref.seq;
		}

		hdr = bl->data;
		sfl->ref.blkno = hdr->blkno;
		sfl->ref.seq = hdr->seq;
		sfl->height++;
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	/* walk file and parent block references to the leaf blocks */
	level = sfl->height;
	ref = &sfl->ref;
	while (level--) {
		/* searchin an unused part of the tree */
		if (!ref->blkno && !(gfb & GFB_INSERT)) {
			ret = -ENOENT;
			goto out;
		}

		/* read an existing block */
		if (ref->blkno) {
			ret = read_srch_block(sb, wri, level, ref, &bl);
			if (ret < 0)
				goto out;
		}

		/* allocate a new block if we need it */
		if (!ref->blkno || ((gfb & GFB_DIRTY) &&
				    !scoutfs_block_writer_is_dirty(sb, bl))) {
			ret = scoutfs_radix_alloc(sb, alloc, wri, &blkno);
			if (ret < 0)
				goto out;

			new_bl = scoutfs_block_create(sb, blkno);
			if (IS_ERR(new_bl)) {
				ret = PTR_ERR(new_bl);
				goto out;
			}

			if (bl) {
				/* cow old block if we have one */
				ret = scoutfs_radix_free(sb, alloc, wri,
							 bl->blkno);
				if (ret)
					goto out;

				memcpy(new_bl->data, bl->data,
				       SCOUTFS_BLOCK_LG_SIZE);
				scoutfs_block_put(sb, bl);
				bl = new_bl;
				hdr = bl->data;
				hdr->blkno = cpu_to_le64(bl->blkno);
				prandom_bytes(&hdr->seq, sizeof(hdr->seq));
			} else {
				/* init new allocated block */
				bl = new_bl;
				init_file_block(sb, bl, level);
			}

			blkno = 0;
			scoutfs_block_writer_mark_dirty(sb, wri, bl);

			/* update file or parent block ref */
			hdr = bl->data;
			ref->blkno = hdr->blkno;
			ref->seq = hdr->seq;
		}

		if (level == 0) {
			ret = 0;
			break;
		}

		srp = bl->data;
		ind = calc_ref_ind(blk, level);
		ref = &srp->refs[ind];

		scoutfs_block_put(sb, parent);
		parent = bl;
		bl = NULL;
	}
	ret = 0;

out:
	scoutfs_block_put(sb, parent);

	/* return allocated blkno on error */
	if (blkno > 0) {
		err = scoutfs_radix_free(sb, alloc, wri, blkno);
		BUG_ON(err); /* radix should have been dirty */
	}

	if (ret < 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	/* record that we successfully grew the file */
	if (ret == 0 && (gfb & GFB_INSERT) && blk >= le64_to_cpu(sfl->blocks))
		sfl->blocks = cpu_to_le64(blk + 1);

	*bl_ret = bl;
	return ret;
}

int scoutfs_srch_add(struct super_block *sb,
		     struct scoutfs_radix_allocator *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_srch_file *sfl,
		     struct scoutfs_block **bl_ret,
		     u64 hash, u64 ino, u64 id)
{
	struct scoutfs_srch_block *srb;
	struct scoutfs_block *bl = NULL;
	u64 blk;
	int ret;
	struct scoutfs_srch_entry sre = {
		.hash = cpu_to_le64(hash),
		.ino = cpu_to_le64(ino),
		.id = cpu_to_le64(id),
	};

	/* start with a new block or the last existing block */
	if (le64_to_cpu(sfl->blocks) > 1)
		blk = le64_to_cpu(sfl->blocks) - 1;
	else
		blk = 0;

	bl = *bl_ret;
get_last_block:
	if (bl == NULL) {
		ret = get_file_block(sb, alloc, wri, sfl,
				     GFB_INSERT | GFB_DIRTY, blk, &bl);
		if (ret < 0) {
			/* writing into a private file, shouldn't happen */
			WARN_ON_ONCE(ret == -ESTALE);
			goto out;
		}
	}
	srb = bl->data;

	/* stop encoding once we might overflow the block */
	if (le32_to_cpu(srb->entry_bytes) > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
		blk++;
		goto get_last_block;
	}

	ret = encode_entry(srb->entries + le32_to_cpu(srb->entry_bytes),
			   &sre, &srb->tail);
	if (ret > 0) {
		if (srb->entry_bytes == 0) {
			if (blk == 0) {
				sfl->first = sre;
				sfl->last = sre;
			}
			srb->first = sre;
			srb->last = sre;
		} else {
			if (sre_cmp(&sre, &sfl->first) < 0)
				sfl->first = sre;
			else if (sre_cmp(&sre, &sfl->last) > 0)
				sfl->last = sre;
			if (sre_cmp(&sre, &srb->first) < 0)
				srb->first = sre;
			else if (sre_cmp(&sre, &srb->last) > 0)
				srb->last = sre;
		}
		srb->tail = sre;
		le32_add_cpu(&srb->entry_nr, 1);
		le32_add_cpu(&srb->entry_bytes, ret);
		le64_add_cpu(&sfl->entries, 1);
		ret = 0;
		scoutfs_inc_counter(sb, srch_add_entry);
	}

out:
	if (ret < 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}
	*bl_ret = bl;

	return ret;
}

/*
 * Track an inode and id of an xattr hash that we found while searching.
 * We'll return inos from the nodes in order to userspace when we're
 * done searching.  The first time we see the entry we track it, the
 * second time must be a deletion so we remove it
 *
 * We track the size of the pool of tracked inodes here.  Once its full
 * we're still able to replace greater inodes with earlier ones.  We do
 * that work here because we can minimize the number of traversals and
 * comparisons that the caller would otherwise have to make.
 */
static int track_found(struct scoutfs_srch_rb_root *sroot, u64 ino, u64 id,
		       unsigned long limit)
{
	struct rb_node **node = &sroot->root.rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_srch_rb_node *snode;
	int cmp = 1; /* set last for first insertion */

	while (*node) {
		parent = *node;
		snode = container_of(*node, struct scoutfs_srch_rb_node, node);

		cmp = scoutfs_cmp(ino, snode->ino) ?:
		      scoutfs_cmp(id, snode->id);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			/* update last if removed as a dupe */
			if (sroot->last == &snode->node)
				sroot->last = rb_prev(sroot->last);
			rb_erase(&snode->node, &sroot->root);
			kfree(snode);
			sroot->nr--;
			return 0;
		}
	}

	/* can't track greater while we're at the limit */
	if (sroot->nr >= limit && cmp > 0 && parent == sroot->last)
		return -ENOSPC;

	snode = kzalloc(sizeof(*snode), GFP_NOFS);
	if (!snode)
		return -ENOMEM;

	rb_link_node(&snode->node, parent, node);
	rb_insert_color(&snode->node, &sroot->root);

	/* track a newly inserted last item */
	if (cmp > 0 && parent == sroot->last)
		sroot->last = &snode->node;

	snode->ino = ino;
	snode->id = id;
	sroot->nr++;

	/* remove and update last if we inserted earlier at limit */
	if (sroot->nr > limit && sroot->last != &snode->node) {
		snode = container_of(sroot->last, struct scoutfs_srch_rb_node,
				     node);
		sroot->last = rb_prev(sroot->last);
		rb_erase(&snode->node, &sroot->root);
		kfree(snode);
		sroot->nr--;
	}

	return 0;
}

/*
 * Sweep all the unsorted entries of a log file looking for hash matches
 * and tracking their xattr inos and ids.  If the tracking sroot fills
 * we update end but keep searching because we might find earlier
 * entries.
 */
static int search_log_file(struct super_block *sb,
			   struct scoutfs_srch_file *sfl,
			   struct scoutfs_srch_rb_root *sroot,
			   struct scoutfs_srch_entry *start,
			   struct scoutfs_srch_entry *end,
			   unsigned long limit)
{
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_entry sre;
	struct scoutfs_srch_entry prev;
	struct scoutfs_srch_block *srb;
	int ret = 0;
	u64 blk;
	int pos;
	int i;

	for (blk = 0; blk < le64_to_cpu(sfl->blocks); blk++) {
		scoutfs_block_put(sb, bl);
		ret = get_file_block(sb, NULL, NULL, sfl, 0, blk, &bl);
		if (ret < 0)
			break;
		srb = bl->data;

		memset(&prev, 0, sizeof(prev));
		pos = 0;
		scoutfs_inc_counter(sb, srch_search_log_block);

		for (i = 0; i < le32_to_cpu(srb->entry_nr); i++) {
			if (pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
				/* can only be inconsistency :/ */
				ret = EIO;
				break;
			}

			ret = decode_entry(srb->entries + pos, &sre, &prev);
			if (ret <= 0) {
				/* can only be inconsistency :/ */
				ret = EIO;
				break;
			}
			pos += ret;
			prev = sre;

			if (sre_cmp(start, &sre) > 0 ||
			    sre_cmp(&sre, end) > 0)
				continue;

			ret = track_found(sroot, le64_to_cpu(sre.ino),
					  le64_to_cpu(sre.id), limit);
			if (ret < 0) {
				/* have to keep searching */
				if (ret == -ENOSPC) {
					if (sre_cmp(&sre, end) < 0)
						*end = sre;
					ret = 0;
				} else {
					break;
				}
			}
		}
	}

	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * Search a sorted file for entries for inodes that could contain the
 * xattr hash that we're looking for.  The caller has checked that the
 * start entry is contained in the file.  We find the first block that
 * could contain it and stream entries from there until we fill the
 * rbtree or arrive at the end entry.
 */
static int search_sorted_file(struct super_block *sb,
			      struct scoutfs_srch_file *sfl,
			      struct scoutfs_srch_rb_root *sroot,
			      struct scoutfs_srch_entry *start,
			      struct scoutfs_srch_entry *end,
			      unsigned long limit)
{
	DECLARE_SRCH_INFO(sb, srinf);
	struct scoutfs_srch_block *srb = NULL;
	struct scoutfs_srch_entry sre;
	struct scoutfs_srch_entry prev;
	struct scoutfs_block *bl = NULL;
	int ret = 0;
	int pos = 0;
	u64 left;
	u64 right;
	u64 blk;

	/* binary search for the block that contains the start */
	blk = 0;
	left = 0;
	right = le64_to_cpu(sfl->blocks) - 1;
	while (left != right) {
		blk = (left + right) >> 1;

		scoutfs_block_put(sb, bl);
		ret = get_file_block(sb, NULL, NULL, sfl, 0, blk, &bl);
		if (ret < 0)
			goto out;
		srb = bl->data;

		if (sre_cmp(start, &srb->first) < 0)
			right = --blk;
		else if (sre_cmp(start, &srb->last) > 0)
			left = ++blk;
		else
			break;
	}

	/* blk is the result of the search */
	scoutfs_block_put(sb, bl);
	bl = NULL;

	/* stream entries until end or we're past the full tracking rb_root */
	for (;;) {
		if (bl == NULL) {
			/* only check on each new input block */
			if (atomic_read(&srinf->shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			ret = get_file_block(sb, NULL, NULL, sfl, 0, blk, &bl);
			if (ret < 0)
				goto out;
			srb = bl->data;

			memset(&prev, 0, sizeof(prev));
			pos = 0;
			scoutfs_inc_counter(sb, srch_search_sorted_block);
		}

		if (pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
			/* can only be inconsistency :/ */
			ret = EIO;
			break;
		}

		ret = decode_entry(srb->entries + pos, &sre, &prev);
		if (ret <= 0) {
			/* can only be inconsistency :/ */
			ret = EIO;
			break;
		}
		pos += ret;
		prev = sre;


		if (sre_cmp(start, &sre) > 0)
			continue;
		if (sre_cmp(&sre, end) > 0)
			break;

		ret = track_found(sroot, le64_to_cpu(sre.ino),
				  le64_to_cpu(sre.id), limit);
		if (ret < 0) {
			if (ret == -ENOSPC) {
				ret = 0;
				/* done when we're past full rb_root */
				if (sre_cmp(&sre, end) < 0)
					*end = sre;
				break;
			}
			goto out;
		}

		if (pos >= le32_to_cpu(srb->entry_bytes)) {
			scoutfs_block_put(sb, bl);
			bl = NULL;
			if (++blk == le64_to_cpu(sfl->blocks))
				break;
		}
	}
	ret = 0;
out:
	scoutfs_block_put(sb, bl);
	return ret;
}

static int search_file(struct super_block *sb, int type,
		       struct scoutfs_srch_file *sfl,
		       struct scoutfs_srch_rb_root *sroot,
		       struct scoutfs_srch_entry *start,
		       struct scoutfs_srch_entry *end, unsigned long limit)
{

	/* ignore files that don't have our hash */
	if (sre_cmp(start, &sfl->last) > 0 ||
	    sre_cmp(end, &sfl->first) < 0)
		return 0;

	if (type == SCOUTFS_SRCH_LOG_TYPE) {
		scoutfs_inc_counter(sb, srch_search_log);
		return search_log_file(sb, sfl, sroot, start, end, limit);
	} else {
		scoutfs_inc_counter(sb, srch_search_sorted);
		return search_sorted_file(sb, sfl, sroot, start, end, limit);
	}
}

static void srch_init_rb_root(struct scoutfs_srch_rb_root *sroot)
{
	sroot->root = RB_ROOT;
	sroot->last = NULL;
	sroot->nr = 0;
}

void scoutfs_srch_destroy_rb_root(struct scoutfs_srch_rb_root *sroot)
{
	struct scoutfs_srch_rb_node *snode;
	struct scoutfs_srch_rb_node *pos;

	rbtree_postorder_for_each_entry_safe(snode, pos, &sroot->root, node)
		kfree(snode);

	srch_init_rb_root(sroot);
}

/*
 * There are no constraints on the distribution of entries in log or
 * sorted srch files.  We limit the number of entries we track to avoid
 * consuming absurd amounts of memory for very large searches.  The
 * larger the limit the more memory each search will take.  The smaller
 * this is the more searches will be necessary to find all the entries.
 */
#define SRCH_LIMIT  1000000

/*
 * Search all the srch files for entries recording that inodes might
 * have a given xattr.
 *
 * Advancing from an inode number that was returned is the only way the
 * caller can make forward progress between searches.  We might not find
 * any inodes if we have the bad luck of pruning all the entries we
 * tracked with deletions.  We'll restart the search ourselves in this
 * case to see if we can find an inode to return to the caller.
 */
int scoutfs_srch_search_xattrs(struct super_block *sb,
			       struct scoutfs_srch_rb_root *sroot,
			       u64 hash, u64 ino, u64 last_ino, bool *done)
{
	struct scoutfs_net_roots prev_roots;
	struct scoutfs_net_roots roots;
	struct scoutfs_srch_entry start;
	struct scoutfs_srch_entry end;
	struct scoutfs_srch_entry final;
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_srch_file sfl;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	unsigned long limit = SRCH_LIMIT;
	int ret;

	scoutfs_inc_counter(sb, srch_search_xattrs);

	*done = false;
	srch_init_rb_root(sroot);
	memset(&prev_roots, 0, sizeof(prev_roots));

	start.hash = cpu_to_le64(hash);
	start.ino = cpu_to_le64(ino);
	start.id = 0;
	final.hash = cpu_to_le64(hash);
	final.ino = cpu_to_le64(last_ino);
	final.id = cpu_to_le64(U64_MAX);

retry:
	scoutfs_srch_destroy_rb_root(sroot);

	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;
	memset(&roots.fs_root, 0, sizeof(roots.fs_root));

	end = final;

	/* search intersecting sorted files, then logs */
	init_srch_key(&key, SCOUTFS_SRCH_BLOCKS_TYPE, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &roots.srch_root, &key, &iref);
		if (ret == 0) {
			if (iref.key->sk_type != key.sk_type) {
				ret = -ENOENT;
			} else if (iref.val_len == sizeof(sfl)) {
				key = *iref.key;
				scoutfs_key_inc(&key);
				memcpy(&sfl, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0) {
			if (ret == -ENOENT) {
				if (key.sk_type == SCOUTFS_SRCH_BLOCKS_TYPE) {
					init_srch_key(&key,
						SCOUTFS_SRCH_LOG_TYPE, 0, 0);
					continue;
				} else {
					break;
				}
			}
			goto out;
		}

		ret = search_file(sb, key.sk_type, &sfl, sroot,
				  &start, &end, limit);
		if (ret < 0)
			goto out;
	}

	/* search all the log files being written by mounts */
	scoutfs_key_init_log_trees(&key, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &roots.logs_root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0) {
			if (iref.val_len == sizeof(ltv)) {
				key = *iref.key;
				scoutfs_key_inc(&key);
				memcpy(&ltv, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		ret = search_file(sb, SCOUTFS_SRCH_LOG_TYPE, &ltv.srch_file,
				  sroot, &start, &end, limit);
		if (ret < 0)
			goto out;
	}

	/* keep searching if we didn't find any entries in the limit */
	if (sroot->nr == 0 && sre_cmp(&end, &final) < 0) {
		start = end;
		scoutfs_inc_counter(sb, srch_search_retry_empty);
		goto retry;
	}

	/* let the caller know our search was exhaustive */
	*done = sre_cmp(&end, &final) == 0;
	ret = 0;
out:
	if (ret == -ESTALE) {
		if (memcmp(&prev_roots, &roots, sizeof(roots)) == 0) {
			scoutfs_inc_counter(sb, srch_search_stale_eio);
			ret = -EIO;
		} else {
			scoutfs_inc_counter(sb, srch_search_stale_retry);
			prev_roots = roots;
			goto retry;
		}
	}

	return ret;
}

/*
 * Running in the server, rotate the client's log file as they commit if
 * it's large enough.
 */
int scoutfs_srch_rotate_log(struct super_block *sb,
			    struct scoutfs_radix_allocator *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_btree_root *root,
			    struct scoutfs_srch_file *sfl)
{
	struct scoutfs_key key;
	int ret;

	if (le64_to_cpu(sfl->blocks) < SCOUTFS_SRCH_LOG_BLOCK_LIMIT)
		return 0;

	init_srch_key(&key, SCOUTFS_SRCH_LOG_TYPE,
		      le64_to_cpu(sfl->ref.blkno), 0);
	ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
				   sfl, sizeof(*sfl));
	if (ret == 0) {
		memset(sfl, 0, sizeof(*sfl));
		scoutfs_inc_counter(sb, srch_rotate_log);
	}
	return ret;
}

/*
 * Running in the server, find candidates for a compaction operation.
 * We see if any tier has enough files waiting for a compaction.  We
 * first search log files and then each greater size tier.  We skip any
 * files which are currently referenced by existing compaction busy
 * items.
 */
int scoutfs_srch_get_compact(struct super_block *sb,
			     struct scoutfs_radix_allocator *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_btree_root *root,
			     u64 rid,
			     struct scoutfs_srch_compact_input *scin)
{
	struct scoutfs_srch_compact_input busy_scin = {{0,}};
	struct scoutfs_srch_file sfl;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_spbm busy;
	struct scoutfs_key key;
	int cur_order = -1;
	int order;
	int type;
	int ret;
	int i;

	/* build up a bitmap of file files already being compacted */
	scoutfs_spbm_init(&busy);
	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, 0, 0);

	for (;;) {
		/* _BUSY_ is last type, _next won't see other types */
		ret = scoutfs_btree_next(sb, root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0) {
			if (iref.val_len == sizeof(busy_scin)) {
				key = *iref.key;
				scoutfs_key_inc(&key);
				memcpy(&busy_scin, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		for (i = 0; i < busy_scin.nr; i++) {
			ret = scoutfs_spbm_set(&busy,
				le64_to_cpu(busy_scin.sfl[i].ref.blkno));
			if (ret < 0)
				goto out;
		}
	}

	/* first look for unsorted log files */
	type = SCOUTFS_SRCH_LOG_TYPE;
	init_srch_key(&key, type, 0, 0);

	scin->nr = 0;
	for (;;scoutfs_key_inc(&key)) {
		ret = scoutfs_btree_next(sb, root, &key, &iref);
		if (ret == -ENOENT) {
			ret = 0;
			scin->nr = 0;
			goto out;
		}

		if (ret == 0) {
			if (iref.val_len == sizeof(struct scoutfs_srch_file)) {
				key = *iref.key;
				memcpy(&sfl, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		/* skip any files already being compacted */
		if (scoutfs_spbm_test(&busy, le64_to_cpu(sfl.ref.blkno)))
			continue;

		/* see if we ran out of log files or files entirely */
		if (key.sk_type != type) {
			scin->nr = 0;
			if (key.sk_type == SCOUTFS_SRCH_BLOCKS_TYPE) {
				type = SCOUTFS_SRCH_BLOCKS_TYPE;
			} else {
				ret = 0;
				goto out;
			}
		}

		/* reset if we iterated into the next size category */
		if (type == SCOUTFS_SRCH_BLOCKS_TYPE) {
			order = fls64(le64_to_cpu(sfl.blocks)) /
				SCOUTFS_SRCH_COMPACT_ORDER;
			if (order != cur_order) {
				cur_order = order;
				scin->nr = 0;
			}
		}

		scin->sfl[scin->nr++] = sfl;
		if (scin->nr == SCOUTFS_SRCH_COMPACT_NR)
			break;

		scoutfs_key_inc(&key);
	}

	if (type == SCOUTFS_SRCH_LOG_TYPE)
		scin->flags = SCOUTFS_SRCH_COMPACT_FLAG_LOG;

	/* record that our client has a compaction in process */
	scin->id = scin->sfl[0].ref.blkno;
	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(scin->id));
	ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
				   scin, sizeof(*scin));
out:
	scoutfs_spbm_destroy(&busy);
	if (ret < 0)
		scin->nr = 0;
	if (scin->nr < SCOUTFS_SRCH_COMPACT_NR)
		memset(&scin->sfl[scin->nr], 0,
		       (SCOUTFS_SRCH_COMPACT_NR - scin->nr) *
		       sizeof(scin->sfl[0]));
	return ret;
}

/*
 * get_ previously created a busy item to reserve the files for a compaction.
 * The caller has finished the input struct and we can update the persistent
 * copy.
 */
int scoutfs_srch_update_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact_input *scin)
{
	struct scoutfs_key key;

	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(scin->id));
	return scoutfs_btree_update(sb, alloc, wri, root, &key,
				    scin, sizeof(*scin));
}

static int mod_srch_items(struct super_block *sb,
			  struct scoutfs_radix_allocator *alloc,
			  struct scoutfs_block_writer *wri,
			  struct scoutfs_btree_root *root, u8 scom_flags,
			  bool ins, struct scoutfs_srch_file *sfls, int nr)
{
	struct scoutfs_srch_file *sfl;
	struct scoutfs_key key;
	int ret = 0;
	int type;
	int i;

	if (nr <= 0)
		return 0;

	if (scom_flags & SCOUTFS_SRCH_COMPACT_FLAG_LOG)
		type = SCOUTFS_SRCH_LOG_TYPE;
	else
		type = SCOUTFS_SRCH_BLOCKS_TYPE;

	for (i = 0; i < nr; i++) {
		sfl = &sfls[i];

		/* don't bother inserting empty files */
		if (ins && sfl->entries == 0)
			continue;

		if (type == SCOUTFS_SRCH_LOG_TYPE)
			init_srch_key(&key, type,
				      le64_to_cpu(sfl->ref.blkno), 0);
		else
			init_srch_key(&key, type,
				      le64_to_cpu(sfl->blocks),
				      le64_to_cpu(sfl->ref.blkno));

		if (ins)
			ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
						   sfl, sizeof(*sfl));
		else
			ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
		if (ret < 0)
			break;
	}

	return ret;
}

/*
 * Running in the server: commit the result of a compaction.  Given the
 * response id, find the input files in the compact's busy item.  Remove
 * the input files, add the new sorted file, and remove the busy item.
 * We give the caller the allocator trees to merge if we return success.
 */
int scoutfs_srch_commit_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact_result *scres,
				struct scoutfs_radix_root *av,
				struct scoutfs_radix_root *fr)
{
	struct scoutfs_srch_compact_input scin;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	/* find the record of our compaction */
	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid,
		      le64_to_cpu(scres->id));
	ret = scoutfs_btree_lookup(sb, root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len == sizeof(scin))
			memcpy(&scin, iref.val, iref.val_len);
		else
			ret = -EIO;
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0) /* XXX leaks allocators */
		goto out;

	if (!(scres->flags & SCOUTFS_SRCH_COMPACT_FLAG_ERROR)) {
		/* delete old items and insert new file items */
		ret = mod_srch_items(sb, alloc, wri, root, scin.flags, false,
				     scin.sfl, scin.nr) ?:
		      mod_srch_items(sb, alloc, wri, root, 0, true,
				     &scres->sfl, 1);
		if (ret < 0)
			goto out;

		*av = scres->meta_avail;
		*fr = scres->meta_freed;
	} else {
		/* reclaim input allocators on error */
		*av = scin.meta_avail;
		*fr = scin.meta_freed;
	}

	/* delete the record of our compaction */
	ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
out:
	WARN_ON_ONCE(ret < 0); /* XXX inconsistency */
	return ret;
}

/*
 * Remove a busy item for the given client and give the caller its
 * allocators.  Returns -ENOENT when there are no more items.
 */
int scoutfs_srch_cancel_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_radix_root *av,
				struct scoutfs_radix_root *fr)
{
	struct scoutfs_srch_compact_input scin;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	struct scoutfs_key last;
	int ret;

	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, 0);
	init_srch_key(&last, SCOUTFS_SRCH_BUSY_TYPE, rid, U64_MAX);

	ret = scoutfs_btree_next(sb, root, &key, &iref);
	if (ret == 0) {
		if (scoutfs_key_compare(iref.key, &last) > 0) {
			ret = -ENOENT;
		} else if (iref.val_len != sizeof(scin)) {
			ret = -EIO;
		} else {
			key = *iref.key;
			memcpy(&scin, iref.val, iref.val_len);
		}
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0)
		goto out;

	*av = scin.meta_avail;
	*fr = scin.meta_freed;

	ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
out:
	return ret;
}

struct tourn_node {
	struct scoutfs_srch_entry sre;
	int ind;
};

static void tourn_update(struct tourn_node *tnodes, struct tourn_node *tn)
{
	struct tourn_node *sib;
	struct tourn_node *par;
	size_t ind;

	/* root is at [1] */
	while (tn != &tnodes[1]) {
		ind = tn - tnodes;
		sib = &tnodes[ind ^ 1];
		par = &tnodes[ind >> 1];
		*par = sre_cmp(&tn->sre, &sib->sre) < 0 ? *tn : *sib;
		tn = par;
	}
}

typedef int (*kway_next_func_t)(struct super_block *sb,
				struct scoutfs_srch_entry *sre_ret, void *arg);

static int kway_merge(struct super_block *sb,
		      struct scoutfs_radix_allocator *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_srch_file *sfl,
		      kway_next_func_t kway_next, void **args, int nr)
{
	DECLARE_SRCH_INFO(sb, srinf);
	struct scoutfs_srch_block *srb = NULL;
	struct scoutfs_block *bl = NULL;
	struct tourn_node *tnodes;
	struct tourn_node *leaves;
	struct tourn_node *root;
	struct tourn_node *tn;
	int nr_parents;
	int nr_nodes;
	int ret = 0;
	u64 blk;
	int ind;
	int i;

	if (WARN_ON_ONCE(nr <= 1))
		return -EINVAL;

	nr_parents = roundup_pow_of_two(nr) - 1;
	/* root at [1] for easy sib/parent index calc, final pad for odd sib */
	nr_nodes = 1 + nr_parents + nr + 1;
	tnodes = __vmalloc(nr_nodes * sizeof(struct tourn_node),
			   GFP_NOFS, PAGE_KERNEL);
	if (!tnodes)
		return -ENOMEM;

	memset(tnodes, 0xff, nr_nodes * sizeof(struct tourn_node));
	root = &tnodes[1];
	leaves = &root[nr_parents];

	/* initialize tournament leaves */
	for (i = 0; i < nr; i++) {
		tn = &leaves[i];
		tn->ind = i;
		ret = kway_next(sb, &tn->sre, args[i]);
		if (ret < 0)
			goto out;
	}

	/* prepare parents.. not optimal, but not a big deal either */
	for (i = 0; i < nr; i += 2)
		tourn_update(tnodes, &leaves[i]);

	blk = 0;
	while (nr > 0) {
		if (bl == NULL) {
			if (atomic_read(&srinf->shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			/* check dirty limit before each block creation */
			if (scoutfs_block_writer_dirty_bytes(sb, wri) >=
			    SRCH_COMPACT_DIRTY_LIMIT_BYTES) {
				scoutfs_inc_counter(sb, srch_compact_flush);
				ret = scoutfs_block_writer_write(sb, wri);
				if (ret < 0)
					goto out;
			}

			ret = get_file_block(sb, alloc, wri, sfl,
					     GFB_INSERT | GFB_DIRTY, blk, &bl);
			if (ret < 0)
				goto out;
			srb = bl->data;
			scoutfs_inc_counter(sb, srch_compact_dirty_block);
		}

		if (sre_cmp(&root->sre, &sfl->last) != 0) {
			ret = encode_entry(srb->entries +
					   le32_to_cpu(srb->entry_bytes),
					   &root->sre, &srb->tail);
			if (WARN_ON_ONCE(ret <= 0)) {
				/* shouldn't happen */
				ret = -EIO;
				goto out;
			}

			if (srb->entry_bytes == 0) {
				if (blk == 0)
					sfl->first = root->sre;
				srb->first = root->sre;
			}
			le32_add_cpu(&srb->entry_nr, 1);
			le32_add_cpu(&srb->entry_bytes, ret);
			srb->last = root->sre;
			srb->tail = root->sre;
			sfl->last = root->sre;
			le64_add_cpu(&sfl->entries, 1);
			ret = 0;

			if (le32_to_cpu(srb->entry_bytes) >
			    SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
				scoutfs_block_put(sb, bl);
				bl = NULL;
				blk++;
			}

			scoutfs_inc_counter(sb, srch_compact_entry);

		} else {
			scoutfs_inc_counter(sb, srch_compact_removed_entry);
		}

		/* get the next */
		ind = root->ind;
		tn = &leaves[ind];
		ret = kway_next(sb, &tn->sre, args[ind]);
		if (ret == -ENOENT) {
			/* this index is done */
			memset(&tn->sre, 0xff, sizeof(tn->sre));
			nr--;
			ret = 0;
		} else if (ret < 0) {
			goto out;
		}

		/* update the tourney and carry on */
		tourn_update(tnodes, tn);
#if 0
		/* would be worth it if we have uneven key distribution */
			if (ind < nr - 1) {
				/* order doesn't matter, fill hole */
				swap(args[ind], args[nr - 1]);
				swap(tn->sre, leaves[nr - 1].sre);
			}
		/* drop a level of the tree when we shrink to a power of 2 */
		if (nr > 0 && is_power_of_two(nr)) {
			memcpy(leaves - nr, leaves, nr * sizeof(*tn));
			leaves -= nr;
			for (i = 0; i < nr; i += 2)
				tourn_update(least, leaves[i]);
		}
#endif
	}

	/* could stream a final index.. arguably a small portion of work */

out:
	scoutfs_block_put(sb, bl);
	vfree(tnodes);
	return ret;
}

#define SRES_PER_PAGE (PAGE_SIZE / sizeof(struct scoutfs_srch_entry))

static struct scoutfs_srch_entry *page_priv_sre(struct page *page)
{
	return (struct scoutfs_srch_entry *)page_address(page) + page->private;
}

static int kway_next_page(struct super_block *sb,
			  struct scoutfs_srch_entry *sre_ret, void *arg)
{
	struct page *page = arg;
	struct scoutfs_srch_entry *sre = page_priv_sre(page);

	if (page->private >= SRES_PER_PAGE || sre->ino == 0)
		return -ENOENT;

	*sre_ret = *sre;
	page->private++;
	return 0;
}

static int cmp_page_sre(const void *A, const void *B)
{
	const struct scoutfs_srch_entry *a = A;
	const struct scoutfs_srch_entry *b = B;

	return sre_cmp(a, b);
}

static void swap_page_sre(void *A, void *B, int size)
{
	struct scoutfs_srch_entry *a = A;
	struct scoutfs_srch_entry *b = B;

	swap(*a, *b);
}

/*
 * Compact a set of log files by sorting all their entries and writing
 * them to a sorted output file.  We decode all the file's entries into
 * pages, sort the contents of each page, and then stream a k-way merge
 * of the entries in the pages into an output file.  While not sorted,
 * the input log files entries are encoded so we can allocate quite a
 * bit more memory in pages than the files took in blocks on disk (~2x
 * typically, ~10x worst case).
 */
static int compact_logs(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_srch_file *sfl_out,
			struct scoutfs_srch_file *sfls, int nr_sfls)
{
	DECLARE_SRCH_INFO(sb, srinf);
	struct scoutfs_srch_file *sfl_end = sfls + nr_sfls;
	struct scoutfs_srch_file *sfl = &sfls[0];
	struct scoutfs_srch_block *srb = NULL;
	struct scoutfs_srch_entry *sre;
	struct scoutfs_srch_entry prev;
	struct scoutfs_block *bl = NULL;
	struct page *page = NULL;
	struct page *tmp;
	void **args = NULL;
	int nr_pages = 0;
	LIST_HEAD(pages);
	u64 blk = 0;
	int pos = 0;
	int ret;
	int i;

	if (WARN_ON_ONCE(nr_sfls <= 1))
		return -EINVAL;

	memset(&prev, 0, sizeof(prev));

	/* decode all the log file's block's entries into pages */
	while (sfl < sfl_end) {
		if (bl == NULL) {
			/* only check on each new input block */
			if (atomic_read(&srinf->shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			ret = get_file_block(sb, NULL, NULL, sfl, 0, blk, &bl);
			if (ret < 0)
				goto out;
			srb = bl->data;
		}

		if (page == NULL) {
			page = alloc_page(GFP_NOFS);
			if (!page) {
				ret = -ENOMEM;
				goto out;
			}
			page->private = 0;
			list_add_tail(&page->list, &pages);
			nr_pages++;
			scoutfs_inc_counter(sb, srch_compact_log_page);
		}

		sre = page_priv_sre(page);

		if (pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
			/* can only be inconsistency :/ */
			ret = EIO;
			break;
		}

		ret = decode_entry(srb->entries + pos, sre, &prev);
		if (ret <= 0) {
			/* can only be inconsistency :/ */
			ret = EIO;
			goto out;
		}
		prev = *sre;

		pos += ret;
		if (pos >= le32_to_cpu(srb->entry_bytes)) {
			scoutfs_block_put(sb, bl);
			bl = NULL;
			memset(&prev, 0, sizeof(prev));
			pos = 0;
			if (++blk == le64_to_cpu(sfl->blocks)) {
				blk = 0;
				sfl++;
			}
		}

		if (++page->private == SRES_PER_PAGE)
			page = NULL;
	}

	/* add a terminal entry to the last partial page */
	if (page) {
		sre = page_priv_sre(page);
		sre->ino = 0;
	}

	/* allocate args array for k-way merge */
	args = vmalloc(nr_pages * sizeof(struct page *));
	if (!args) {
		ret = -ENOMEM;
		goto out;
	}

	/* sort page entries and reset private for _next */
	i = 0;
	list_for_each_entry(page, &pages, list) {
		args[i++] = page;

		if (atomic_read(&srinf->shutdown)) {
			ret = -ESHUTDOWN;
			goto out;
		}

		sort(page_address(page), page->private,
		     sizeof(struct scoutfs_srch_entry), cmp_page_sre,
		     swap_page_sre);
		page->private = 0;

	}

	ret = kway_merge(sb, alloc, wri, sfl_out, kway_next_page, args,
			 nr_pages);
out:
	scoutfs_block_put(sb, bl);
	vfree(args);
	list_for_each_entry_safe(page, tmp, &pages, list) {
		list_del(&page->list);
		__free_page(page);
	}

	return ret;
}

struct kway_file_reader {
	struct scoutfs_srch_file *sfl;
	struct scoutfs_block *bl;
	struct scoutfs_srch_entry prev;
	u64 blk;
	u32 pos;
};

static int kway_next_file_reader(struct super_block *sb,
				 struct scoutfs_srch_entry *sre_ret, void *arg)
{
	struct kway_file_reader *rdr = arg;
	struct scoutfs_srch_block *srb;
	int ret;

	if (rdr->sfl == NULL)
		return -ENOENT;

	if (rdr->bl == NULL) {
		ret = get_file_block(sb, NULL, NULL, rdr->sfl, 0, rdr->blk,
				     &rdr->bl);
		if (ret < 0)
			goto out;
		memset(&rdr->prev, 0, sizeof(rdr->prev));
		rdr->pos = 0;
	}
	srb = rdr->bl->data;

	if (rdr->pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
		/* XXX inconsistency */
		return -EIO;
	}

	ret = decode_entry(srb->entries + rdr->pos, sre_ret, &rdr->prev);
	if (ret <= 0) {
		/* XXX inconsistency */
		return -EIO;
	}

	rdr->prev = *sre_ret;
	rdr->pos += ret;

	if (rdr->pos >= le32_to_cpu(srb->entry_bytes)) {
		scoutfs_block_put(sb, rdr->bl);
		rdr->bl = NULL;
		if (++rdr->blk == le64_to_cpu(rdr->sfl->blocks))
			rdr->sfl = NULL;
	}

	ret = 0;
out:
	return ret;
}

/*
 * Compact a set of sorted files by performing a k-way merge of the files
 * into an output sorted file.  The k-way merge works with an iterator
 * which reads blocks and decodes entries.
 */
static int compact_sorted(struct super_block *sb,
			  struct scoutfs_radix_allocator *alloc,
			  struct scoutfs_block_writer *wri,
			  struct scoutfs_srch_file *sfl_out,
			  struct scoutfs_srch_file *sfls, int nr)
{
	struct kway_file_reader *rdrs = NULL;
	void **args = NULL;
	int ret;
	int i;

	if (WARN_ON_ONCE(nr <= 1))
		return -EINVAL;

	/* allocate args array for k-way merge */
	rdrs = kmalloc_array(nr, sizeof(rdrs[0]), __GFP_ZERO | GFP_NOFS);
	args = kmalloc_array(nr, sizeof(args[0]), GFP_NOFS);
	if (!rdrs || !args) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nr; i++) {
		rdrs[i].sfl = &sfls[i];
		args[i] = &rdrs[i];
	}

	ret = kway_merge(sb, alloc, wri, sfl_out, kway_next_file_reader,
			 args, nr);
out:
	for (i = 0; rdrs && i < nr; i++)
		scoutfs_block_put(sb, rdrs[i].bl);
	kfree(rdrs);
	kfree(args);

	return ret;
}

/*
 * Perform a depth-first walk of the file's parent blocks, freeing all
 * the blocks that were allocated to the file.  This is working with a
 * read-only file in the block cache that can also be currently read by
 * searchers.  If we return an error then the server is going to clean
 * up our entire operation, partial state doesn't matter.
 */
static int free_file(struct super_block *sb,
		     struct scoutfs_radix_allocator *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_srch_file *sfl)
{
	struct scoutfs_block **bls = NULL;
	struct scoutfs_srch_parent *srp;
	struct scoutfs_srch_ref *ref;
	unsigned int *inds = NULL;
	u64 blkno;
	u8 height;
	int level;
	int ret;
	int i;

	if (sfl->ref.blkno == 0)
		return 0;

	height = height_for_blk(le64_to_cpu(sfl->blocks) - 1);
	if (height == 1)
		goto free_root;

	bls = kmalloc_array(height, sizeof(bls[0]), __GFP_ZERO | GFP_NOFS);
	inds = kmalloc_array(height, sizeof(inds[0]), __GFP_ZERO | GFP_NOFS);
	if (!bls || !inds) {
		ret = -ENOMEM;
		goto out;
	}

	ref = &sfl->ref;
	level = height - 1;
	while (level < height) {
		if (bls[level] == NULL) {
			ret = read_srch_block(sb, wri, level, ref, &bls[level]);
			if (ret < 0)
				goto out;
		}
		srp = bls[level]->data;

		/* find a parent to descend to, remembering where we were */
		ref = NULL;
		for (i = inds[level]; level >= 2 &&
		     i < SCOUTFS_SRCH_PARENT_REFS; i++) {
			if (srp->refs[i].blkno) {
				inds[level] = i + 1;
				ref = &srp->refs[i];
				level--;
				break;
			}
		}
		if (ref)
			continue;

		/* free all our referenced blocks */
		for (i = 0; i < SCOUTFS_SRCH_PARENT_REFS; i++) {
			blkno = le64_to_cpu(srp->refs[i].blkno);
			if (blkno == 0)
				continue;

			ret = scoutfs_radix_free(sb, alloc, wri, blkno);
			if (ret < 0)
				goto out;
			scoutfs_inc_counter(sb, srch_compact_free_block);
		}

		scoutfs_block_put(sb, bls[level]);
		bls[level] = NULL;
		level++;
	}

free_root:
	ret = scoutfs_radix_free(sb, alloc, wri, le64_to_cpu(sfl->ref.blkno));
	if (ret < 0)
		goto out;

out:
	for (i = 0; bls && i < height; i++)
		scoutfs_block_put(sb, bls[i]);
	kfree(bls);
	kfree(inds);
	return ret;
}

/* wait 10s between compact attempts on error, immediate after success */
#define SRCH_COMPACT_DELAY_MS (10 * MSEC_PER_SEC)

/*
 * Get a compaction operation from the server, sort the entries from the
 * input files as they're read, and stream the remaining sorted entries
 * into a newly written output file.  The server is protecting the input
 * files from other compactions, they will be stable.  The server gives
 * us a populated allocator that should be enough to write a new file
 * and delete the old file blocks.  We'll regularly write out dirty
 * blocks as we hit a dirty limit threshold so there will be some cow
 * overhead of repeatedly dirtying, say, parent allocator and file radix
 * blocks.  We don't reclaim freed blocks in the allocator after each
 * write so the initial allocator pool has to account for that cow
 * overhead.
 *
 * All of our modifications are written into free blocks from the
 * filesystem's perspective.  If anything goes wrong we return an error
 * and the server will ignore all our work and reclaim the initial
 * allocator they gave us.
 */
static void scoutfs_srch_compact_worker(struct work_struct *work)
{
	struct srch_info *srinf = container_of(work, struct srch_info,
					       compact_dwork.work);
	struct super_block *sb = srinf->sb;
	struct scoutfs_radix_allocator alloc;
	struct scoutfs_srch_compact_result scres;
	struct scoutfs_srch_compact_input scin;
	struct scoutfs_block_writer wri;
	unsigned long delay;
	int ret;
	int i;

	scoutfs_block_writer_init(sb, &wri);
	memset(&scres, 0, sizeof(scres));

	ret = scoutfs_client_srch_get_compact(sb, &scin);
	if (ret < 0 || scin.nr == 0)
		goto out;

	scoutfs_radix_init_alloc(&alloc, &scin.meta_avail, &scin.meta_freed);

	if (scin.flags & SCOUTFS_SRCH_COMPACT_FLAG_LOG)
		ret = compact_logs(sb, &alloc, &wri, &scres.sfl,
				   scin.sfl, scin.nr);
	else
		ret = compact_sorted(sb, &alloc, &wri, &scres.sfl,
				     scin.sfl, scin.nr);
	if (ret < 0)
		goto commit;

	for (i = 0; i < scin.nr; i++) {
		ret = free_file(sb, &alloc, &wri, &scin.sfl[i]);
		if (ret < 0)
			goto commit;
	}

	ret = scoutfs_block_writer_write(sb, &wri);
commit:
	scres.meta_avail = alloc.avail;
	scres.meta_freed = alloc.freed;
	scres.id = scin.id;
	scres.flags = ret < 0 ? SCOUTFS_SRCH_COMPACT_FLAG_ERROR : 0;

	ret = scoutfs_client_srch_commit_compact(sb, &scres);
out:
	/* our allocators and files should be stable */
	WARN_ON_ONCE(ret == -ESTALE);

	scoutfs_block_writer_forget_all(sb, &wri);
	if (!atomic_read(&srinf->shutdown)) {
		delay = ret == 0 ? 0 : msecs_to_jiffies(SRCH_COMPACT_DELAY_MS);
		queue_delayed_work(srinf->workq, &srinf->compact_dwork, delay);
	}
}

void scoutfs_srch_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_SRCH_INFO(sb, srinf);

	if (!srinf)
		return;

	if (srinf->workq) {
		/* pending grace work queues normal work */
		atomic_set(&srinf->shutdown, 1);
		cancel_delayed_work_sync(&srinf->compact_dwork);
		flush_workqueue(srinf->workq);
		destroy_workqueue(srinf->workq);
	}

	kfree(srinf);
	sbi->srch_info = NULL;
}

int scoutfs_srch_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct srch_info *srinf;
	int ret;

	srinf = kzalloc(sizeof(struct srch_info), GFP_KERNEL);
	if (!srinf)
		return -ENOMEM;

	srinf->sb = sb;
	atomic_set(&srinf->shutdown, 0);
	INIT_DELAYED_WORK(&srinf->compact_dwork, scoutfs_srch_compact_worker);
	sbi->srch_info = srinf;

	srinf->workq = alloc_workqueue("scoutfs_srch_compact",
				       WQ_NON_REENTRANT | WQ_UNBOUND |
				       WQ_HIGHPRI, 0);
	if (!srinf->workq) {
		ret = -ENOMEM;
		goto out;
	}

	queue_delayed_work(srinf->workq, &srinf->compact_dwork,
			   msecs_to_jiffies(SRCH_COMPACT_DELAY_MS));

	ret = 0;
out:
	if (ret)
		scoutfs_srch_destroy(sb);

	return ret;
}
