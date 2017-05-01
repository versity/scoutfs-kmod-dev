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
#include <linux/mpage.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/random.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"
#include "net.h"

/*
 * scoutfs uses extent records to reference file data.
 *
 * The extent items map logical file regions to device blocks at at 4K
 * block granularity.  File data isn't overwritten so that overwriting
 * doesn't generate extent item locking and modification.
 *
 * Nodes have their own free extent items stored at their node id to
 * avoid lock contention during allocation and freeing.  These pools are
 * filled and drained with RPCs to the server who allocates blocks in
 * segment-sized regions.
 *
 * Block allocation maintains a fixed number of allocation cursors that
 * remember the position of tasks within free regions.  This is very
 * simple and maintains decent extents for simple streaming writes.  It
 * eventually won't be good enough and we'll spend complexity on
 * delalloc but we want to put that off as long as possible.
 *
 * There's no unwritten extents.  As we dirty file data pages, possibly
 * allocating extents for the first time, we track their inodes.  Before
 * we commit dirty metadata we write out all tracked inodes.  This
 * ensures that data is persistent before the metadata that references
 * it is usable.
 *
 * Weirdly, the extents are indexed by the *final* logical block and
 * blkno of the extent.  This lets us search for neighbouring previous
 * extents with a _next() call and avoids having to implement item
 * reading that iterates backwards through the manifest and segments.
 *
 * There are two items that track free extents, one indexed by the block
 * location of the free extent and one indexed by the size of the free
 * region.  This means that one allocation can update a great number of
 * items throughout the tree as file and both kinds of free extents
 * split and merge.  The code goes to great lengths to stage these
 * updates so that it can always unwind and return errors without
 * leaving the items inconsistent.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - forced unmount with dirty data
 *  - direct IO
 */

struct data_info {
	struct rw_semaphore alloc_rwsem;
	u64 next_large_blkno;
	struct rhashtable cursors;
	struct list_head cursor_lru;
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

/* more than enough for a few tasks per core on moderate hardware */
#define NR_CURSORS 4096

/*
 * This is the size of extents that are tracked by a cursor and so end
 * up being the largest file item extent length given concurrent
 * streaming writes.
 *
 * XXX We probably want this to be a bit larger to further reduce the
 * amount of item churn involved in truncating tremendous files.
 */
#define LARGE_EXTENT_BLOCKS SCOUTFS_SEGMENT_BLOCKS

struct cursor_id {
	struct task_struct *task;
	pid_t pid;
} __packed; /* rhashtable_lookup() always memcmp()s, avoid padding */

struct task_cursor {
	u64 blkno;
	u64 blocks;
	struct rhash_head hash_head;
	struct list_head list_head;
	struct cursor_id id;
};

/*
 * Both file extent and free extent keys are converted into this native
 * form for manipulation.  The free extents set blk_off to blkno.
 */
struct native_extent {
	u64 blk_off;
	u64 blkno;
	u64 blocks;
};

/* These are stored in a (type==0) terminated array on caller's stacks */
struct extent_change {
	struct native_extent ext;
	u64 arg;
	unsigned ins:1,
		 type;
};

/* insert file extent + remove both blkno and blocks extents + 0 term */
#define MAX_CHANGES (3 + 3 + 3 + 1)

/* XXX avoiding dynamic on-stack array initializers :/ */
union extent_key_union {
	struct scoutfs_file_extent_key file;
	struct scoutfs_free_extent_blkno_key blkno;
	struct scoutfs_free_extent_blocks_key blocks;
} __packed;
#define MAX_KEY_BYTES sizeof(union extent_key_union)

static void init_file_extent_key(struct scoutfs_key_buf *key, void *key_bytes,
			         struct native_extent *ext, u64 arg)
{
	struct scoutfs_file_extent_key *fkey = key_bytes;

	fkey->type = SCOUTFS_FILE_EXTENT_KEY;
	fkey->ino = cpu_to_be64(arg);
	fkey->last_blk_off = cpu_to_be64(ext->blk_off + ext->blocks - 1);
	fkey->last_blkno = cpu_to_be64(ext->blkno + ext->blocks - 1);
	fkey->blocks = cpu_to_be64(ext->blocks);

	scoutfs_key_init(key, fkey, sizeof(struct scoutfs_file_extent_key));
}

#define INIT_FREE_EXTENT_KEY(which_type, key, key_bytes, ext, arg, type)  \
do {									  \
	struct which_type *fkey = key_bytes;				  \
									  \
	fkey->type = type;						  \
	fkey->node_id = cpu_to_be64(arg);				  \
	fkey->last_blkno = cpu_to_be64(ext->blkno + ext->blocks - 1);	  \
	fkey->blocks = cpu_to_be64(ext->blocks);			  \
									  \
	scoutfs_key_init(key, fkey, sizeof(struct which_type));		  \
} while (0)

static void init_extent_key(struct scoutfs_key_buf *key, void *key_bytes,
			    struct native_extent *ext, u64 arg, u8 type)
{
	if (type == SCOUTFS_FILE_EXTENT_KEY)
		init_file_extent_key(key, key_bytes, ext, arg);
	else if(type == SCOUTFS_FREE_EXTENT_BLKNO_KEY)
		INIT_FREE_EXTENT_KEY(scoutfs_free_extent_blkno_key,
				     key, key_bytes, ext, arg, type);
	else
		INIT_FREE_EXTENT_KEY(scoutfs_free_extent_blocks_key,
				     key, key_bytes, ext, arg, type);
}

/* XXX could have some sanity checks */
static void load_file_extent(struct native_extent *ext,
			     struct scoutfs_key_buf *key)
{
	struct scoutfs_file_extent_key *fkey = key->data;

	ext->blocks = be64_to_cpu(fkey->blocks);
	ext->blk_off = be64_to_cpu(fkey->last_blk_off) - ext->blocks + 1;
	ext->blkno = be64_to_cpu(fkey->last_blkno) - ext->blocks + 1;
}

#define LOAD_FREE_EXTENT(which_type, ext, key)		\
do {							\
	struct which_type *fkey = key->data;		\
							\
	ext->blkno = be64_to_cpu(fkey->last_blkno) -	\
		     be64_to_cpu(fkey->blocks) + 1;	\
	ext->blk_off = ext->blkno;			\
	ext->blocks = be64_to_cpu(fkey->blocks);	\
} while (0)

static void load_extent(struct native_extent *ext, struct scoutfs_key_buf *key)
{
	struct scoutfs_free_extent_blocks_key *fkey = key->data;

	BUILD_BUG_ON(offsetof(struct scoutfs_file_extent_key, type) !=
		     offsetof(struct scoutfs_free_extent_blkno_key, type) ||
		     offsetof(struct scoutfs_file_extent_key, type) !=
		     offsetof(struct scoutfs_free_extent_blocks_key, type));

	if (fkey->type == SCOUTFS_FILE_EXTENT_KEY)
		load_file_extent(ext, key);
	else if (fkey->type == SCOUTFS_FREE_EXTENT_BLKNO_KEY)
		LOAD_FREE_EXTENT(scoutfs_free_extent_blkno_key, ext, key);
	else
		LOAD_FREE_EXTENT(scoutfs_free_extent_blocks_key, ext, key);
}

/*
 * Merge two extents if they're adjacent.  First we arrange them to
 * only test their adjoining endpoints, then are careful to not reference
 * fields after we've modified them.
 */
static int merge_extents(struct native_extent *mod,
			 struct native_extent *ext)
{
	struct native_extent *left;
	struct native_extent *right;

	if (mod->blk_off < ext->blk_off) {
		left = mod;
		right = ext;
	} else {
		left = ext;
		right = mod;
	}

	if (left->blk_off + left->blocks == right->blk_off &&
	    left->blkno + left->blocks == right->blkno) {
		mod->blk_off = left->blk_off;
		mod->blkno = left->blkno;
		mod->blocks = left->blocks + right->blocks;
		return 1;
	}

	return 0;
}

/*
 * The caller has ensured that the inner extent is entirely within
 * the outer extent.  Fill out the left and right regions of outter
 * that don't overlap with inner.
 */
static void trim_extents(struct native_extent *left,
			 struct native_extent *right,
			 struct native_extent *outer,
			 struct native_extent *inner)
{
	left->blk_off = outer->blk_off;
	left->blkno = outer->blkno;
	left->blocks = inner->blk_off - outer->blk_off;

	right->blk_off = inner->blk_off + inner->blocks;
	right->blkno = inner->blkno + inner->blocks;
	right->blocks = (outer->blk_off + outer->blocks) - right->blk_off;
}

/* return true if inner is fully contained by outer */
static bool extents_within(struct native_extent *outer,
			   struct native_extent *inner)
{
	u64 outer_end = outer->blk_off + outer->blocks - 1;
	u64 inner_end = inner->blk_off + inner->blocks - 1;

	return outer->blk_off <= inner_end && outer_end >= inner_end;
}

/*
 * Add a new entry to the array of changes.  The _BLOCKS extent items
 * exactly match the _BLKNO items but with different field order for
 * searching by size.  We keep them in sync by always adding a _BLOCKS
 * change for every _BLKNO change.
 */
static struct extent_change *append_change(struct extent_change *chg,
					   bool ins, struct native_extent *ext,
					   u64 arg, u8 type)
{
	trace_printk("appending ins %d blk_off %llu blkno %llu blocks %llu arg %llu type %u\n",
			ins, ext->blk_off, ext->blkno, ext->blocks,
			arg, type);

	chg->ext = *ext;
	chg->arg = arg;
	chg->ins = ins;
	chg->type = type;

	if (type == SCOUTFS_FREE_EXTENT_BLKNO_KEY) {
		chg++;
		*chg = *(chg - 1);
		chg->type = SCOUTFS_FREE_EXTENT_BLOCKS_KEY;
	}

	return chg + 1;
}

/*
 * Find an adjacent extent in the direction of the delta.  If we can
 * merge with it then we modify the incoming cur extent.  nei is set to
 * the neighbour we found.  > 0 is returned if we merged, 0 if not, and
 * < 0 on error.
 */
static int try_merge(struct super_block *sb, struct native_extent *cur,
		     s64 delta, struct native_extent *nei, u64 arg, u8 type)
{
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent ext;
	int ret;

	/* short circuit prev search for common first block alloc */
	if (cur->blk_off == 0 && delta < 0)
		return 0;

	trace_printk("nei %lld from blk_off %llu blkno %llu blocks %llu\n",
		     delta, cur->blk_off, cur->blkno, cur->blocks);

	memset(&ext, ~0, sizeof(ext));
	init_extent_key(&last, last_bytes, &ext, arg, type);

	ext.blk_off = cur->blk_off + delta;
	ext.blkno = cur->blkno + delta;
	ext.blocks = 1;
	init_extent_key(&key, key_bytes, &ext, arg, type);

	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	load_extent(nei, &key);
	trace_printk("found nei blk_off %llu blkno %llu blocks %llu\n",
		     nei->blk_off, nei->blkno, nei->blocks);

	ret = merge_extents(cur, nei);
out:
	return ret;
}

/*
 * Build the changes needed to insert the given extent.  The semantics
 * of the extents and callers means that we should not find existing extents
 * that overlap the insertion.
 */
static int record_insert_changes(struct super_block *sb,
				 struct extent_change *chg,
				 struct native_extent *caller_ins,
				 u64 arg, u8 type)
{
	struct native_extent ins = *caller_ins;
	struct native_extent ext;
	int ret;

	trace_printk("inserting arg %llu type %u blk_off %llu blkno %llu blocks %llu\n",
		     arg, type, ins.blk_off, ins.blkno, ins.blocks);

	/* find the end */
	while (chg->type)
		chg++;

	/* find previous that might be adjacent */
	ret = try_merge(sb, &ins, -1, &ext, arg, type);
	if (ret < 0)
		goto out;
	else if (ret > 0)
		chg = append_change(chg, false, &ext, arg, type);

	/* find next that might be adjacent */
	ret = try_merge(sb, &ins, 1, &ext, arg, type);
	if (ret < 0)
		goto out;
	else if (ret > 0)
		chg = append_change(chg, false, &ext, arg, type);

	/* and insert the new extent, possibly including merged neighbours */
	chg = append_change(chg, true, &ins, arg, type);
	ret = 0;
out:
	return ret;
}

/*
 * Record the changes needed to remove a portion of an existing extent.
 */
static int record_remove_changes(struct super_block *sb,
				 struct extent_change *chg,
				 struct native_extent *rem, u64 arg,
				 u8 type)
{
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent left;
	struct native_extent right;
	struct native_extent outer;
	int ret;

	trace_printk("removing arg %llu type %u blk_off %llu blkno %llu blocks %llu\n",
		     arg, type, rem->blk_off, rem->blkno, rem->blocks);

	/* find the end */
	while (chg->type)
		chg++;

	memset(&outer, ~0, sizeof(outer));
	init_extent_key(&last, last_bytes, &outer, arg, type);

	/* find outer existing extent that contains removal extent */
	init_extent_key(&key, key_bytes, rem, arg, type);
	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	if (ret)
		goto out;

	load_extent(&outer, &key);

	trace_printk("found outer blk_off %llu blkno %llu blocks %llu\n",
		     outer.blk_off, outer.blkno, outer.blocks);

	if (!extents_within(&outer, rem)) {
		ret = -EIO;
		goto out;
	}

	trim_extents(&left, &right, &outer, rem);

	chg = append_change(chg, false, &outer, arg, type);

	if (left.blocks) {
		trace_printk("left trim blk_off %llu blkno %llu blocks %llu\n",
			     left.blk_off, left.blkno, left.blocks);
		chg = append_change(chg, true, &left, arg, type);
	}

	if (right.blocks) {
		trace_printk("right trim blk_off %llu blkno %llu blocks %llu\n",
			     right.blk_off, right.blkno, right.blocks);
		chg = append_change(chg, true, &right, arg, type);
	}

	ret = 0;
out:
	if (ret)
		trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Any given allocation or free of a file data extent can involve both
 * insertion and deletion of both file extent and free extent items.  To
 * make these atomic we record all the insertions and deletions that are
 * performed.  We first dirty the deletions, then insert, then delete.
 * This lets us always safely unwind on failure.
 */
static int apply_changes(struct super_block *sb, struct extent_change *changes)
{
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf key;
	struct extent_change *chg;
	int ret;
	int err;

	for (chg = changes; chg->type; chg++) {
		if (chg->ins)
			continue;

		init_extent_key(&key, key_bytes, &chg->ext, chg->arg,
				chg->type);
		ret = scoutfs_item_dirty(sb, &key);
		if (ret)
			goto out;
	}

	for (chg = changes; chg->type; chg++) {
		if (!chg->ins)
			continue;

		init_extent_key(&key, key_bytes, &chg->ext, chg->arg,
				chg->type);
		ret = scoutfs_item_create(sb, &key, NULL);
		if (ret) {
			while ((--chg) >= changes) {
				if (!chg->ins)
					continue;
				init_extent_key(&key, key_bytes, &chg->ext,
						chg->arg, chg->type);
				err = scoutfs_item_delete(sb, &key);
				BUG_ON(err);
			}
			goto out;
		}
	}

	for (chg = changes; chg->type; chg++) {
		if (chg->ins)
			continue;

		init_extent_key(&key, key_bytes, &chg->ext, chg->arg,
				chg->type);
		ret = scoutfs_item_delete(sb, &key);
		BUG_ON(ret);
	}

out:
	return ret;
}

int scoutfs_data_truncate_items(struct super_block *sb, u64 ino, u64 iblock,
				u64 len, bool offline)
{
	BUG();  /* NYI */
}

/*
 * These cheesy cursors are only meant to encourage nice IO patterns for
 * concurrent tasks either streaming large file writes or creating lots
 * of small files.  It will do very poorly in many other situations.  To
 * do better we'd need to go further down the road to delalloc and take
 * more surrounding context into account.
 */
static struct task_cursor *get_cursor(struct data_info *datinf)
{
	struct task_cursor *curs;
	struct cursor_id id = {
		.task = current,
		.pid = current->pid,
	};

	curs = rhashtable_lookup(&datinf->cursors, &id);
	if (!curs) {
		curs = list_last_entry(&datinf->cursor_lru,
				       struct task_cursor, list_head);
		trace_printk("resetting curs %p was task %p pid %u\n",
				curs, curs->id.task, curs->id.pid);
		rhashtable_remove(&datinf->cursors, &curs->hash_head, GFP_NOFS);
		curs->id = id;
		rhashtable_insert(&datinf->cursors, &curs->hash_head, GFP_NOFS);
		curs->blkno = 0;
		curs->blocks = 0;
	}

	list_move(&curs->list_head, &datinf->cursor_lru);

	return curs;
}

static int bulk_alloc(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct extent_change changes[MAX_CHANGES];
	struct native_extent ext;
	u64 *segnos = NULL;
	int ret;
	int i;

	segnos = scoutfs_net_bulk_alloc(sb);
	if (IS_ERR(segnos)) {
		ret = PTR_ERR(segnos);
		goto out;
	}

	for (i = 0; segnos[i]; i++) {
		memset(changes, 0, sizeof(changes));

		/* merge or set this one */
		if (i > 0 && (segnos[i] == segnos[i - 1] + 1)) {
			ext.blocks += SCOUTFS_SEGMENT_BLOCKS;
			trace_printk("merged segno [%u] %llu blocks %llu\n",
					i, segnos[i], ext.blocks);
		} else {
			ext.blkno = segnos[i] << SCOUTFS_SEGMENT_BLOCK_SHIFT;
			ext.blocks = SCOUTFS_SEGMENT_BLOCKS;
			trace_printk("set extent segno [%u] %llu blkno %llu\n",
					i, segnos[i], ext.blkno);
		}

		/* don't write if we merge with the next one */
		if ((segnos[i] + 1) == segnos[i + 1])
			continue;

		trace_printk("inserting extent [%u] blkno %llu blocks %llu\n",
			     i, ext.blkno, ext.blocks);

		ext.blk_off = ext.blkno;
		ret = record_insert_changes(sb, changes, &ext, sbi->node_id,
					    SCOUTFS_FREE_EXTENT_BLKNO_KEY) ?:
		      apply_changes(sb, changes);
		/* XXX error here leaks segnos */
		if (ret)
			break;
	}

out:
	if (!IS_ERR_OR_NULL(segnos))
		kfree(segnos);

	return ret;
}

/*
 * Allocate a single block for the logical block offset in the file.
 *
 * We try to merge single block allocations into large extents by using
 * per-task cursors.  Each cursor tracks a block region that should be
 * searched for free extents.  If we don't have a cursor, or we find
 * free space outside of our cursor, then we look for the next large
 * free extent.
 */
static int allocate_block(struct inode *inode, sector_t iblock, u64 *blkno)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	struct extent_change changes[MAX_CHANGES] = {{{0,}}};
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent last_ext;
	struct native_extent found;
	struct native_extent ext;
	struct task_cursor *curs;
	bool alloced = false;
	u8 type;
	int ret;

	memset(&last_ext, ~0, sizeof(last_ext));

	down_write(&datinf->alloc_rwsem);

	curs = get_cursor(datinf);

	/* start from the cursor or look for the next large extent */
reset_cursor:
	if (curs->blocks) {
		ext.blkno = curs->blkno;
		ext.blocks = 0;
		type = SCOUTFS_FREE_EXTENT_BLKNO_KEY;
	} else {
		ext.blkno = datinf->next_large_blkno;
		ext.blocks = LARGE_EXTENT_BLOCKS;
		type = SCOUTFS_FREE_EXTENT_BLOCKS_KEY;
	}

retry:
	trace_printk("searching %llu,%llu curs %p task %p pid %u %llu,%llu\n",
		     ext.blkno, ext.blocks, curs, curs->id.task, curs->id.pid,
		     curs->blkno, curs->blocks);

	ext.blk_off = ext.blkno;
	init_extent_key(&key, key_bytes, &ext, sbi->node_id, type);
	init_extent_key(&last, last_bytes, &last_ext, sbi->node_id, type);

	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	if (ret < 0) {
		if (ret == -ENOENT) {
			/* if the cursor's empty fall back to next large */
	 		if (ext.blkno && ext.blocks == 0) {
				curs->blkno = 0;
				curs->blocks = 0;
				goto reset_cursor;
			}

			/* wrap the search for large extents */
			if (ext.blkno > LARGE_EXTENT_BLOCKS && ext.blocks) {
				datinf->next_large_blkno = LARGE_EXTENT_BLOCKS;
				ext.blkno = datinf->next_large_blkno;
				goto retry;
			}

			/* ask the server for more extents */
			if (ext.blocks && !alloced) {
				ret = bulk_alloc(sb);
				if (ret < 0)
					goto out;
				alloced = true;
				goto retry;
			}

			/* finally look for any free block at all */
			if (ext.blocks) {
				ext.blkno = 0;
				ext.blocks = 0;
				type = SCOUTFS_FREE_EXTENT_BLKNO_KEY;
				goto retry;
			}

			/* after all that return -ENOSPC */
			ret = -ENOSPC;
		}
		goto out;
	}

	load_extent(&found, &key);
	trace_printk("found %llu,%llu\n", found.blkno, found.blocks);

	/* look for a new large extent if found is outside cursor */
	if (curs->blocks &&
	    (found.blkno + found.blocks <= curs->blkno ||
	     found.blkno >= curs->blkno + curs->blocks)) {
		curs->blkno = 0;
		curs->blocks = 0;
		goto reset_cursor;
	}

	/*
	 * Set the cursor if:
	 *  - we didn't already have one
	 *  - it's large enough for a large extent with alignment padding
	 *  - the sufficiently large free region is past next large
	 */
	if (!curs->blocks &&
	    found.blocks >= (2 * LARGE_EXTENT_BLOCKS) &&
	    (found.blkno + found.blocks - (2 * LARGE_EXTENT_BLOCKS) >=
		datinf->next_large_blkno)) {

		curs->blkno = ALIGN(max(found.blkno, datinf->next_large_blkno),
				    LARGE_EXTENT_BLOCKS);
		curs->blocks = LARGE_EXTENT_BLOCKS;
		found.blkno = curs->blkno;
		found.blocks = curs->blocks;

		datinf->next_large_blkno = curs->blkno + LARGE_EXTENT_BLOCKS;
	}

	trace_printk("using %llu,%llu curs %llu,%llu\n",
		     found.blkno, found.blocks, curs->blkno, curs->blocks);

	*blkno = found.blkno;
	ext.blk_off = iblock;
	ext.blkno = found.blkno;
	ext.blocks = 1;
	ret = record_insert_changes(sb, changes, &ext, scoutfs_ino(inode),
				    SCOUTFS_FILE_EXTENT_KEY);
	if (ret < 0)
		goto out;

	ext.blk_off = ext.blkno;
	ret = record_remove_changes(sb, changes, &ext, sbi->node_id,
			    SCOUTFS_FREE_EXTENT_BLKNO_KEY) ?:
	      apply_changes(sb, changes);

	/* advance cursor if we're using it */
	if (ret == 0 && curs->blocks) {
		if (--curs->blocks == 0)
			curs->blkno = 0;
		else
			curs->blkno++;
	}

out:
	up_write(&datinf->alloc_rwsem);
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;
	DECLARE_DATA_INFO(sb, datinf);
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent ext;
	u64 blocks;
	u64 blkno;
	u64 off;
	int ret;

	bh->b_blocknr = 0;
	bh->b_size = 0;
	blocks = 0;

	ext.blk_off = iblock;
	ext.blocks = 1;
	ext.blkno = 0;
	init_extent_key(&key, key_bytes, &ext, scoutfs_ino(inode),
			SCOUTFS_FILE_EXTENT_KEY);

	ext.blk_off = ~0ULL;
	ext.blkno = ~0ULL;
	ext.blocks = ~0ULL;
	init_extent_key(&last, last_bytes, &ext, scoutfs_ino(inode),
			SCOUTFS_FILE_EXTENT_KEY);

	/*
	 * XXX think about how far this next can go, given locking and
	 * item consistency.
	 */
	down_read(&datinf->alloc_rwsem);
	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	up_read(&datinf->alloc_rwsem);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		else
			goto out;
	} else {
		load_extent(&ext, &key);
		trace_printk("found blk_off %llu blkno %llu blocks %llu\n",
			     ext.blk_off, ext.blkno, ext.blocks);
		if (iblock >= ext.blk_off &&
		    iblock < (ext.blk_off + ext.blocks)) {
			off = iblock - ext.blk_off;
			blkno = ext.blkno + off;
			blocks = ext.blocks - off;
		}
	}

	if (blocks == 0 && create) {
		ret = allocate_block(inode, iblock, &blkno);
		if (ret)
			goto out;

		blocks = 1;
	}

	if (blocks) {
		map_bh(bh, inode->i_sb, blkno);
		bh->b_size = min_t(u64, SIZE_MAX,
				   blocks << SCOUTFS_BLOCK_SHIFT);
	}

out:
	trace_printk("ino %llu iblock %llu create %d ret %d bnr %llu size %zu\n",
		     scoutfs_ino(inode), (u64)iblock, create, ret,
		     (u64)bh->b_blocknr, bh->b_size);

	return ret;
}

static int scoutfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, scoutfs_get_block);
}

static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);
}

static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, scoutfs_get_block, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, scoutfs_get_block);
}

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	int ret;

	trace_printk("ino %llu pos %llu len %u\n",
		     scoutfs_ino(inode), (u64)pos, len);

	ret = scoutfs_hold_trans(sb);
	if (ret)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode);
	if (ret == 0)
		ret = block_write_begin(mapping, pos, len, flags, pagep,
					scoutfs_get_block);
	if (ret)
		scoutfs_release_trans(sb);
out:
        return ret;
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	int ret;

	trace_printk("ino %llu pgind %lu pos %llu len %u copied %d\n",
		     scoutfs_ino(inode), page->index, (u64)pos, len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		scoutfs_inode_inc_data_version(inode);
		/* XXX kind of a big hammer, inode life cycle needs work */
		scoutfs_update_inode_item(inode);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.readpages		= scoutfs_readpages,
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
};

static int derpy_global_mutex_is_held(void)
{
	return 1;
}

static struct rhashtable_params cursor_hash_params = {
	.key_len = member_sizeof(struct task_cursor, id),
	.key_offset = offsetof(struct task_cursor, id),
	.head_offset = offsetof(struct task_cursor, hash_head),
	.hashfn = arch_fast_hash,
	.grow_decision = rht_grow_above_75,
	.shrink_decision = rht_shrink_below_30,

	.mutex_is_held = derpy_global_mutex_is_held,
};

static void destroy_cursors(struct data_info *datinf)
{
	struct task_cursor *curs;
	struct task_cursor *pos;

	list_for_each_entry_safe(curs, pos, &datinf->cursor_lru, list_head) {
		list_del_init(&curs->list_head);
		kfree(curs);
	}
	rhashtable_destroy(&datinf->cursors);
}

int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf;
	struct task_cursor *curs;
	int ret;
	int i;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	init_rwsem(&datinf->alloc_rwsem);
	INIT_LIST_HEAD(&datinf->cursor_lru);
	/* always search for large aligned extents */
	datinf->next_large_blkno = LARGE_EXTENT_BLOCKS;

	ret = rhashtable_init(&datinf->cursors, &cursor_hash_params);
	if (ret) {
		kfree(datinf);
		return -ENOMEM;
	}

	/* just allocate all of these up front */
	for (i = 0; i < NR_CURSORS; i++) {
		curs = kzalloc(sizeof(struct task_cursor), GFP_KERNEL);
		if (!curs) {
			destroy_cursors(datinf);
			kfree(datinf);
			return -ENOMEM;
		}

		curs->id.pid = i;
		rhashtable_insert(&datinf->cursors, &curs->hash_head,
				  GFP_KERNEL);
		list_add(&curs->list_head, &datinf->cursor_lru);
	}

	sbi->data_info = datinf;

	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		destroy_cursors(datinf);
		kfree(datinf);
	}
}
