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
#include "alloc.h"
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

static void sre_inc(struct scoutfs_srch_entry *sre)
{
	le64_add_cpu(&sre->id, 1);
	if (sre->id != 0)
		return;
	le64_add_cpu(&sre->ino, 1);
	if (sre->ino != 0)
		return;
	le64_add_cpu(&sre->hash, 1);
}

static void sre_dec(struct scoutfs_srch_entry *sre)
{
	le64_add_cpu(&sre->id, -1);
	if (sre->id != cpu_to_le64(U64_MAX))
		return;
	le64_add_cpu(&sre->ino, -1);
	if (sre->ino != cpu_to_le64(U64_MAX))
		return;
	le64_add_cpu(&sre->hash, -1);
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
 * Give the caller a read-only reference to the block along the path to
 * the logical block at the given level.  This shouldn't be called on an
 * empty root.
 */
static int read_path_block(struct super_block *sb,
			   struct scoutfs_block_writer *wri,
			   struct scoutfs_srch_file *sfl,
			   u64 blk, int at_level,
			   struct scoutfs_block **bl_ret)
{
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_parent *srp;
	struct scoutfs_srch_ref ref;
	int level;
	int ind;
	int ret;

	if (WARN_ON_ONCE(at_level < 0 || at_level >= sfl->height))
		return -EINVAL;

	level = sfl->height;
	ref = sfl->ref;
	while (level--) {
		if (ref.blkno == 0) {
			ret = -ENOENT;
			break;
		}

		ret = read_srch_block(sb, wri, level, &ref, &bl);
		if (ret < 0)
			break;

		if (level == at_level) {
			ret = 0;
			break;
		}

		srp = bl->data;
		ind = calc_ref_ind(blk, level);
		ref = srp->refs[ind];
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	if (ret < 0)
		scoutfs_block_put(sb, bl);
	else
		*bl_ret = bl;
	return ret;
}

/*
 * Walk radix blocks to find the logical file block and return the
 * reference to the caller.  Flags determine if we cow new dirty blocks,
 * allocate new blocks, or return errors for missing blocks (files are
 * never sparse, this won't happen).
 */
enum gfb_flags {
	GFB_INSERT = (1 << 0),
	GFB_DIRTY = (1 << 1),
};
static int get_file_block(struct super_block *sb,
			  struct scoutfs_alloc *alloc,
			  struct scoutfs_block_writer *wri,
			  struct scoutfs_srch_file *sfl,
			  int flags, u64 blk, struct scoutfs_block **bl_ret)
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
		if (!(flags & GFB_INSERT)) {
			ret = -ENOENT;
			goto out;
		}

		ret = scoutfs_alloc_meta(sb, alloc, wri, &blkno);
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
		/* searching an unused part of the tree */
		if (!ref->blkno && !(flags & GFB_INSERT)) {
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
		if (!ref->blkno || ((flags & GFB_DIRTY) &&
				    !scoutfs_block_writer_is_dirty(sb, bl))) {
			ret = scoutfs_alloc_meta(sb, alloc, wri, &blkno);
			if (ret < 0)
				goto out;

			new_bl = scoutfs_block_create(sb, blkno);
			if (IS_ERR(new_bl)) {
				ret = PTR_ERR(new_bl);
				goto out;
			}

			if (bl) {
				/* cow old block if we have one */
				ret = scoutfs_free_meta(sb, alloc, wri,
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
		err = scoutfs_free_meta(sb, alloc, wri, blkno);
		BUG_ON(err); /* radix should have been dirty */
	}

	if (ret < 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	/* record that we successfully grew the file */
	if (ret == 0 && (flags & GFB_INSERT) && blk >= le64_to_cpu(sfl->blocks))
		sfl->blocks = cpu_to_le64(blk + 1);

	*bl_ret = bl;
	return ret;
}

int scoutfs_srch_add(struct super_block *sb,
		     struct scoutfs_alloc *alloc,
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
	s64 left;
	s64 right;
	u64 first;
	u64 blk;

	if (sfl->blocks == 0)
		return 0;

	/* binary search for first block in the range */
	first = U64_MAX;
	left = 0;
	right = le64_to_cpu(sfl->blocks) - 1;
	while (left <= right) {
		blk = (left + right) >> 1;

		ret = get_file_block(sb, NULL, NULL, sfl, 0, blk, &bl);
		if (ret < 0)
			goto out;
		srb = bl->data;

		if (sre_cmp(end, &srb->first) < 0) {
			right = blk - 1;
		} else if (sre_cmp(start, &srb->last) > 0) {
			left = blk + 1;
		} else {
			first = min(blk, first);
			right = blk - 1;
		}

		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	/* no blocks in range */
	if (first == U64_MAX) {
		ret = 0;
		goto out;
	}
	blk = first;

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
	struct scoutfs_log_trees lt;
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
			scoutfs_btree_put_iref(&iref);
		}
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
			if (iref.val_len == sizeof(lt)) {
				key = *iref.key;
				scoutfs_key_inc(&key);
				memcpy(&lt, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		ret = search_file(sb, SCOUTFS_SRCH_LOG_TYPE, &lt.srch_file,
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
			    struct scoutfs_alloc *alloc,
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
 * Running in the server, get a compaction operation to send to the
 * client.  We first see if there are any pending operations to continue
 * working on.  If not, we see if any tier has enough files waiting for
 * a compaction.  We first search log files and then each greater size
 * tier.  We skip input files which are currently being read by busy
 * compaction items.
 */
int scoutfs_srch_get_compact(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_btree_root *root,
			     u64 rid, struct scoutfs_srch_compact *sc)
{
	struct scoutfs_srch_file sfl;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_spbm busy;
	struct scoutfs_key key;
	int cur_order = -1;
	int order;
	int type;
	int ret;
	int err;
	int i;

	/*
	 * Search for pending or busy items.  If we find a pending item
	 * we move it to busy and return it.  We build up a bitmap of
	 * input files which are in busy items.
	 */
	scoutfs_spbm_init(&busy);
	for (init_srch_key(&key, SCOUTFS_SRCH_PENDING_TYPE, 0, 0);  ;
	     scoutfs_key_inc(&key)) {

		/* _PENDING_ and _BUSY_ are last, _next won't see other types */
		ret = scoutfs_btree_next(sb, root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0) {
			if (iref.val_len == sizeof(*sc)) {
				key = *iref.key;
				memcpy(sc, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		/* record all the busy input files */
		if (key.sk_type == SCOUTFS_SRCH_BUSY_TYPE) {
			for (i = 0; i < sc->nr; i++) {
				ret = scoutfs_spbm_set(&busy,
					le64_to_cpu(sc->in[i].sfl.ref.blkno));
				if (ret < 0)
					goto out;
			}
			continue;
		}

		/* or move the first pending to busy and return it */
		init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid,
			      le64_to_cpu(sc->id));
		ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
					   sc, sizeof(*sc));
		if (ret < 0)
			goto out;

		init_srch_key(&key, SCOUTFS_SRCH_PENDING_TYPE,
			      le64_to_cpu(sc->id), 0);
		ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
		if (ret < 0) {
			init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid,
				      le64_to_cpu(sc->id));
			err = scoutfs_btree_delete(sb, alloc, wri, root, &key);
			BUG_ON(err); /* XXX both pending and busy :/ */
			goto out;
		}

		/* found one */
		ret = 0;
		goto out;
	}

	/* no pending, look for sufficient files to start a new compaction */
	memset(sc, 0, sizeof(struct scoutfs_srch_compact));

	/* first look for unsorted log files */
	type = SCOUTFS_SRCH_LOG_TYPE;
	init_srch_key(&key, type, 0, 0);

	for (;;scoutfs_key_inc(&key)) {
		ret = scoutfs_btree_next(sb, root, &key, &iref);
		if (ret == -ENOENT) {
			ret = 0;
			sc->nr = 0;
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
			sc->nr = 0;
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
				sc->nr = 0;
			}
		}

		sc->in[sc->nr++].sfl = sfl;
		if (sc->nr == SCOUTFS_SRCH_COMPACT_NR)
			break;

		scoutfs_key_inc(&key);
	}

	if (type == SCOUTFS_SRCH_LOG_TYPE)
		sc->flags = SCOUTFS_SRCH_COMPACT_FLAG_LOG;
	else
		sc->flags = SCOUTFS_SRCH_COMPACT_FLAG_SORTED;

	/* record that our client has a compaction in process */
	sc->id = sc->in[0].sfl.ref.blkno;

	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(sc->id));
	ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
				   sc, sizeof(*sc));
out:
	scoutfs_spbm_destroy(&busy);
	if (ret < 0)
		sc->nr = 0;
	if (sc->nr < SCOUTFS_SRCH_COMPACT_NR)
		memset(&sc->in[sc->nr], 0,
		       (SCOUTFS_SRCH_COMPACT_NR - sc->nr) * sizeof(sc->in[0]));
	return ret;
}

/*
 * get_ previously created a busy item to reserve the files for a compaction.
 * The caller has finished the input struct and we can update the persistent
 * copy.
 */
int scoutfs_srch_update_compact(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact *sc)
{
	struct scoutfs_key key;

	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(sc->id));
	return scoutfs_btree_update(sb, alloc, wri, root, &key,
				    sc, sizeof(struct scoutfs_srch_compact));
}

static void init_file_key(struct scoutfs_key *key, int type,
			  struct scoutfs_srch_file *sfl)
{
	if (type == SCOUTFS_SRCH_LOG_TYPE)
		init_srch_key(key, type, le64_to_cpu(sfl->ref.blkno), 0);
	else
		init_srch_key(key, type, le64_to_cpu(sfl->blocks),
			      le64_to_cpu(sfl->ref.blkno));
}

/*
 * A compaction has completed so we remove the input file reference
 * items and add the output file, if it has contents.  If this returns
 * an error then the file items were not changed.
 */
static int commit_files(struct super_block *sb, struct scoutfs_alloc *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_srch_compact *sc)
{
	struct scoutfs_srch_file *sfl;
	struct scoutfs_key key;
	int type;
	int ret;
	int err;
	int i;

	if (sc->flags & SCOUTFS_SRCH_COMPACT_FLAG_LOG)
		type = SCOUTFS_SRCH_LOG_TYPE;
	else
		type = SCOUTFS_SRCH_BLOCKS_TYPE;

	if (sc->out.blocks != 0) {
		sfl = &sc->out;
		init_file_key(&key, SCOUTFS_SRCH_BLOCKS_TYPE, sfl);
		ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
					   sfl, sizeof(*sfl));
		if (ret < 0)
			goto out;
	}

	for (i = 0; i < sc->nr; i++) {
		sfl = &sc->in[i].sfl;
		init_file_key(&key, type, sfl);

		ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
		if (ret < 0) {
			while (--i >= 0) {
				sfl = &sc->in[i].sfl;
				init_file_key(&key, type, sfl);

				err = scoutfs_btree_insert(sb, alloc, wri,
							   root, &key,
							   sfl, sizeof(*sfl));
				BUG_ON(err); /* lost srch file */
			}

			if (sc->out.blocks != 0) {
				sfl = &sc->out;
				init_file_key(&key, SCOUTFS_SRCH_BLOCKS_TYPE,
					      sfl);
				err = scoutfs_btree_delete(sb, alloc, wri,
							   root, &key);
				BUG_ON(err); /* duplicate srch files data */
			}
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

/*
 * Running in the server: commit the result of a compaction.  Given the
 * response id, find the compaction's busy item.  The busy item is
 * returned to a pending item or is advanced depending on the result.
 * If the compaction completed then we replace the input files with the
 * output files and transition the compaction to delete the input files.
 * Once the input files are deleted we can remove the compaction item.
 */
int scoutfs_srch_commit_compact(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact *res,
				struct scoutfs_alloc_list_head *av,
				struct scoutfs_alloc_list_head *fr)
{
	struct scoutfs_srch_compact *pending = NULL;
	struct scoutfs_srch_compact *busy;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;
	int err;
	int i;

	/* only free allocators when we finish deleting */
	memset(av, 0, sizeof(struct scoutfs_alloc_list_head));
	memset(fr, 0, sizeof(struct scoutfs_alloc_list_head));

	busy = kzalloc(sizeof(struct scoutfs_srch_compact), GFP_NOFS);
	if (busy == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* find the record of our compaction */
	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(res->id));
	ret = scoutfs_btree_lookup(sb, root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_srch_compact))
			memcpy(busy, iref.val, iref.val_len);
		else
			ret = -EIO;
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0) /* XXX leaks allocators */
		goto out;

	/* restore busy to pending if the operation failed */
	if (res->flags & SCOUTFS_SRCH_COMPACT_FLAG_ERROR) {
		pending = busy;
		ret = 0;
		goto update;
	}

	/* store result as pending if it isn't done */
	if (!(res->flags & SCOUTFS_SRCH_COMPACT_FLAG_DONE)) {
		pending = res;
		ret = 0;
		goto update;
	}

	/* update file references if we finished compaction (!deleting) */
	if (!(res->flags & SCOUTFS_SRCH_COMPACT_FLAG_DELETE)) {
		ret = commit_files(sb, alloc, wri, root, res);
		if (ret < 0) {
			/* XXX we can't commit, shutdown? */
			goto out;
		}

		/* transition flags for deleting input files */
		for (i = 0; i < res->nr; i++) {
			res->in[i].blk = 0;
			res->in[i].pos = 0;
		}
		res->flags &= ~(SCOUTFS_SRCH_COMPACT_FLAG_DONE |
			        SCOUTFS_SRCH_COMPACT_FLAG_LOG |
			        SCOUTFS_SRCH_COMPACT_FLAG_SORTED);
		res->flags |= SCOUTFS_SRCH_COMPACT_FLAG_DELETE;
		pending = res;
		ret = 0;
		goto update;
	}

	/* ok, finished deleting, reclaim allocs and delete busy */
	*av = res->meta_avail;
	*fr = res->meta_freed;
	pending = NULL;
	ret = 0;
update:
	if (pending) {
		init_srch_key(&key, SCOUTFS_SRCH_PENDING_TYPE,
			      le64_to_cpu(pending->id), 0);
		ret = scoutfs_btree_insert(sb, alloc, wri, root, &key,
					   pending, sizeof(*pending));
		if (ret < 0)
			goto out;
	}

	init_srch_key(&key, SCOUTFS_SRCH_BUSY_TYPE, rid, le64_to_cpu(res->id));
	ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
	if (ret < 0 && pending) {
		init_srch_key(&key, SCOUTFS_SRCH_PENDING_TYPE,
			      le64_to_cpu(pending->id), 0);
		err = scoutfs_btree_delete(sb, alloc, wri, root, &key);
		BUG_ON(err); /* both busy and pending present */
	}
out:
	WARN_ON_ONCE(ret < 0); /* XXX inconsistency */
	kfree(busy);
	return ret;
}

/*
 * Remove a busy item for the given client and give the caller its
 * allocators.  Returns -ENOENT when there are no more items.
 */
int scoutfs_srch_cancel_compact(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_alloc_list_head *av,
				struct scoutfs_alloc_list_head *fr)
{
	struct scoutfs_srch_compact *sc;
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
		} else if (iref.val_len != sizeof(*sc)) {
			ret = -EIO;
		} else {
			key = *iref.key;
			sc = iref.val;
			*av = sc->meta_avail;
			*fr = sc->meta_freed;
		}
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0)
		goto out;

	ret = scoutfs_btree_delete(sb, alloc, wri, root, &key);
out:
	return ret;
}

/*
 * We should commit our progress when we have sufficient dirty blocks or
 * don't have enough metadata alloc space for our caller's operations.
 */
static bool should_commit(struct super_block *sb, struct scoutfs_alloc *alloc,
			  struct scoutfs_block_writer *wri, u32 nr)
{
	return (scoutfs_block_writer_dirty_bytes(sb, wri) >=
		SRCH_COMPACT_DIRTY_LIMIT_BYTES) ||
		scoutfs_alloc_meta_low(sb, alloc, nr);
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
		      struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_srch_file *sfl,
		      kway_next_func_t kway_next, void **args, int nr)
{
	DECLARE_SRCH_INFO(sb, srinf);
	struct scoutfs_srch_block *srb = NULL;
	struct scoutfs_srch_entry last_tail;
	struct scoutfs_block *bl = NULL;
	struct tourn_node *tnodes;
	struct tourn_node *leaves;
	struct tourn_node *root;
	struct tourn_node *tn;
	int last_bytes = 0;
	int nr_parents;
	int nr_nodes;
	int empty = 0;
	int ret = 0;
	int diff;
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
		if (ret == 0) {
			tourn_update(tnodes, &leaves[i]);
		} else if (ret == -ENOENT) {
			memset(&tn->sre, 0xff, sizeof(tn->sre));
			empty++;
		} else {
			goto out;
		}
	}

	/* always append new blocks */
	blk = le64_to_cpu(sfl->blocks);
	while (empty < nr) {
		if (bl == NULL) {
			if (atomic_read(&srinf->shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			/* could grow and dirty to a leaf */
			if (should_commit(sb, alloc, wri, sfl->height + 1)) {
				ret = 0;
				goto out;
			}

			ret = get_file_block(sb, alloc, wri, sfl,
					     GFB_INSERT | GFB_DIRTY, blk, &bl);
			if (ret < 0)
				goto out;
			srb = bl->data;
			scoutfs_inc_counter(sb, srch_compact_dirty_block);
		}

		if (sre_cmp(&root->sre, &srb->last) != 0) {
			last_bytes = le32_to_cpu(srb->entry_bytes);
			last_tail = srb->last;
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
			/*
			 * Duplicate entries indicate deletion so we
			 * undo the previously encoded entry and ignore
			 * this entry.  This only happens within each
			 * block.  Deletions can span block boundaries
			 * and will be filtered out by search and
			 * hopefully removed in future compactions.
			 */
			diff = le32_to_cpu(srb->entry_bytes) - last_bytes;
			if (diff) {
				memset(srb->entries + last_bytes, 0, diff);
				if (srb->entry_bytes == 0) {
					/* last_tail will be 0 */
					if (blk == 0)
						sfl->first = last_tail;
					srb->first = last_tail;
				}
				le32_add_cpu(&srb->entry_nr, -1);
				srb->entry_bytes = cpu_to_le32(last_bytes);
				srb->last = last_tail;
				srb->tail = last_tail;
				sfl->last = last_tail;
				le64_add_cpu(&sfl->entries, -1);
			}

			scoutfs_inc_counter(sb, srch_compact_removed_entry);
		}

		/* get the next */
		ind = root->ind;
		tn = &leaves[ind];
		ret = kway_next(sb, &tn->sre, args[ind]);
		if (ret == -ENOENT) {
			/* this index is done */
			memset(&tn->sre, 0xff, sizeof(tn->sre));
			empty++;
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
 *
 * Because we read and sort all the input files we must perform the full
 * compaction in one operation.  The server must have given us a
 * sufficiently large avail/freed lists, otherwise we'll return ENOSPC.
 */
static int compact_logs(struct super_block *sb,
			struct scoutfs_alloc *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_srch_compact *sc)
{
	DECLARE_SRCH_INFO(sb, srinf);
	struct scoutfs_srch_block *srb = NULL;
	struct scoutfs_srch_entry *sre;
	struct scoutfs_srch_entry prev;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_file *sfl;
	struct page *page = NULL;
	struct page *tmp;
	void **args = NULL;
	int nr_pages = 0;
	LIST_HEAD(pages);
	int sfl_ind;
	u64 blk = 0;
	int pos = 0;
	int ret;
	int i;

	if (sc->nr <= 1) {
		ret = -EINVAL;
		goto out;
	}

	memset(&prev, 0, sizeof(prev));

	/* decode all the log file's block's entries into pages */
	for (sfl_ind = 0, sfl = &sc->in[0].sfl; sfl_ind < sc->nr; ) {

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
				sfl_ind++;
				sfl = &sc->in[sfl_ind].sfl;
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

	ret = kway_merge(sb, alloc, wri, &sc->out, kway_next_page, args,
			 nr_pages);
	if (ret < 0)
		goto out;

	/* make sure we finished all the pages */
	list_for_each_entry(page, &pages, list) {
		sre = page_priv_sre(page);
		if (page->private < SRES_PER_PAGE && sre->ino != 0) {
			ret = -ENOSPC;
			goto out;
		}
	}

	sc->flags |= SCOUTFS_SRCH_COMPACT_FLAG_DONE;
	ret = 0;
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
	u32 skip;
	u32 pos;
};

static int kway_next_file_reader(struct super_block *sb,
				 struct scoutfs_srch_entry *sre_ret, void *arg)
{
	struct kway_file_reader *rdr = arg;
	struct scoutfs_srch_block *srb;
	int ret;

	if (rdr->blk == le64_to_cpu(rdr->sfl->blocks))
		return -ENOENT;

	if (rdr->bl == NULL) {
		ret = get_file_block(sb, NULL, NULL, rdr->sfl, 0, rdr->blk,
				     &rdr->bl);
		if (ret < 0)
			goto out;

		memset(&rdr->prev, 0, sizeof(rdr->prev));
	}
	srb = rdr->bl->data;

	if (rdr->pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES ||
	    rdr->skip > SCOUTFS_SRCH_BLOCK_SAFE_BYTES ||
	    rdr->skip >= le32_to_cpu(srb->entry_bytes)) {
		/* XXX inconsistency */
		return -EIO;
	}

	/* decode entry, possibly skipping start of the block */
	do {
		ret = decode_entry(srb->entries + rdr->pos, sre_ret,
				   &rdr->prev);
		if (ret <= 0) {
			/* XXX inconsistency */
			return -EIO;
		}

		rdr->prev = *sre_ret;
		rdr->pos += ret;
	} while (rdr->pos <= rdr->skip);
	rdr->skip = 0;

	if (rdr->pos >= le32_to_cpu(srb->entry_bytes)) {
		rdr->pos = 0;
		scoutfs_block_put(sb, rdr->bl);
		rdr->bl = NULL;
		rdr->blk++;
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
			  struct scoutfs_alloc *alloc,
			  struct scoutfs_block_writer *wri,
			  struct scoutfs_srch_compact *sc)
{
	struct kway_file_reader *rdrs = NULL;
	void **args = NULL;
	int ret;
	int nr;
	int i;

	if (WARN_ON_ONCE(sc->nr <= 1))
		return -EINVAL;

	nr = sc->nr;

	/* allocate args array for k-way merge */
	rdrs = kmalloc_array(nr, sizeof(rdrs[0]), __GFP_ZERO | GFP_NOFS);
	args = kmalloc_array(nr, sizeof(args[0]), GFP_NOFS);
	if (!rdrs || !args) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nr; i++) {
		if (le64_to_cpu(sc->in[i].blk) >
		    le64_to_cpu(sc->in[i].sfl.blocks)) {
			ret = -EINVAL;
			goto out;
		}

		rdrs[i].sfl = &sc->in[i].sfl;
		rdrs[i].blk = le64_to_cpu(sc->in[i].blk);
		rdrs[i].skip = le64_to_cpu(sc->in[i].pos);
		args[i] = &rdrs[i];
	}

	ret = kway_merge(sb, alloc, wri, &sc->out, kway_next_file_reader,
			 args, nr);

	sc->flags |= SCOUTFS_SRCH_COMPACT_FLAG_DONE;
	for (i = 0; i < nr; i++) {
		sc->in[i].blk = cpu_to_le64(rdrs[i].blk);
		sc->in[i].pos = cpu_to_le64(rdrs[i].pos);

		if (rdrs[i].blk < le64_to_cpu(sc->in[i].sfl.blocks))
			sc->flags &= ~SCOUTFS_SRCH_COMPACT_FLAG_DONE;
	}
out:
	for (i = 0; rdrs && i < nr; i++)
		scoutfs_block_put(sb, rdrs[i].bl);
	kfree(rdrs);
	kfree(args);

	return ret;
}

/*
 * Delete a file that has been compacted and is no longer referenced by
 * items in the srch_root.  The server protects the input file from
 * other compactions while we're working, but other readers could be
 * still trying to read it while searching.
 *
 * We don't modify the blocks to avoid the cost of allocating and
 * freeing dirty parent metadata blocks, and we want to avoid triggering
 * stale reads in racing readers.   We free blocks from leaf parents
 * upwards and from left to right.  Once we've freed a block we never
 * visit it again.  We store our walk position in each file's compact
 * input so that it can be stored in pending items as progress is made
 * over multiple operations.
 */
static int delete_file(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_srch_compact_input *in)
{
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_parent *srp;
	u64 blkno;
	u64 blk;
	u64 inc;
	int level;
	int ret;
	int i;

	blk = le64_to_cpu(in->blk);
	level = max(le64_to_cpu(in->pos), 1ULL);

	if (level > in->sfl.height) {
		ret = 0;
		goto out;
	}

	for (; level < in->sfl.height; level++) {

		for (inc = 1, i = 2; i <= level; i++)
			inc *= SCOUTFS_SRCH_PARENT_REFS;

		while (blk < le64_to_cpu(in->sfl.blocks)) {

			ret = read_path_block(sb, wri, &in->sfl, blk, level,
					      &bl);
			if (ret < 0)
				goto out;
			srp = bl->data;

			for (i = calc_ref_ind(blk, level);
			     i < SCOUTFS_SRCH_PARENT_REFS &&
				blk < le64_to_cpu(in->sfl.blocks);
			     i++, blk += inc) {

				blkno = le64_to_cpu(srp->refs[i].blkno);
				if (!blkno)
					continue;

				/* free below, then final root block */
				if (should_commit(sb, alloc, wri, 2)) {
					ret = 0;
					goto out;
				}

				ret = scoutfs_free_meta(sb, alloc, wri, blkno);
				if (ret < 0)
					goto out;
			}

			scoutfs_block_put(sb, bl);
			bl = NULL;
		}
		blk = 0;
	}

	if (level == in->sfl.height) {
		ret = scoutfs_free_meta(sb, alloc, wri,
					le64_to_cpu(in->sfl.ref.blkno));
		if (ret < 0)
			goto out;
		level++;
	}

	ret = 0;
out:
	in->blk = cpu_to_le64(blk);
	in->pos = cpu_to_le64(level);

	scoutfs_block_put(sb, bl);
	return ret;
}

static int delete_files(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_srch_compact *sc)
{
	int ret;
	int i;

	for (i = 0; i < sc->nr; i++) {
		ret = delete_file(sb, alloc, wri, &sc->in[i]);
		if (ret < 0 ||
		    (le64_to_cpu(sc->in[i].pos) <= sc->in[i].sfl.height))
			break;
	}
	if (i == sc->nr)
		sc->flags |= SCOUTFS_SRCH_COMPACT_FLAG_DONE;

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
	struct scoutfs_srch_compact *sc = NULL;
	struct super_block *sb = srinf->sb;
	struct scoutfs_block_writer wri;
	struct scoutfs_alloc alloc;
	unsigned long delay;
	int ret;

	sc = kmalloc(sizeof(struct scoutfs_srch_compact), GFP_NOFS);
	if (sc == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_block_writer_init(sb, &wri);

	ret = scoutfs_client_srch_get_compact(sb, sc);
	if (ret < 0 || sc->nr == 0)
		goto out;

	scoutfs_alloc_init(&alloc, &sc->meta_avail, &sc->meta_freed);

	if (sc->flags & SCOUTFS_SRCH_COMPACT_FLAG_LOG) {
		ret = compact_logs(sb, &alloc, &wri, sc);

	} else if (sc->flags & SCOUTFS_SRCH_COMPACT_FLAG_SORTED) {
		ret = compact_sorted(sb, &alloc, &wri, sc);

	} else if (sc->flags & SCOUTFS_SRCH_COMPACT_FLAG_DELETE) {
		ret = delete_files(sb, &alloc, &wri, sc);

	} else {
		ret = -EINVAL;
	}
	if (ret < 0)
		goto commit;

	ret = scoutfs_block_writer_write(sb, &wri);
commit:
	/* the server won't use our partial compact if _ERROR is set */
	sc->meta_avail = alloc.avail;
	sc->meta_freed = alloc.freed;
	sc->flags |= ret < 0 ? SCOUTFS_SRCH_COMPACT_FLAG_ERROR : 0;

	ret = scoutfs_client_srch_commit_compact(sb, sc);
out:
	/* our allocators and files should be stable */
	WARN_ON_ONCE(ret == -ESTALE);

	scoutfs_block_writer_forget_all(sb, &wri);
	if (!atomic_read(&srinf->shutdown)) {
		delay = ret == 0 ? 0 : msecs_to_jiffies(SRCH_COMPACT_DELAY_MS);
		queue_delayed_work(srinf->workq, &srinf->compact_dwork, delay);
	}

	kfree(sc);
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
