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

#define EXTF "[off %llu bno %llu bks %llu fl %x]"
#define EXTA(ne) (ne)->blk_off, (ne)->blkno, (ne)->blocks, (ne)->flags

/*
 * scoutfs uses extent items to reference file data.
 *
 * The extent items map logical file regions to device blocks at 4K
 * block granularity.  File data isn't overwritten so that overwriting
 * doesn't generate extent item locking and modification.
 *
 * Nodes have their own free extent items stored at their node id to
 * avoid lock contention during allocation and freeing.  These pools are
 * filled and drained with messages to the server who allocates
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
 * it is visible.
 *
 * Weirdly, the extents are indexed by the *final* logical block and
 * blkno of the extent.  This lets us search for neighbouring previous
 * extents with a _next() call and avoids having to implement item
 * reading that iterates backwards through the manifest and segments.
 *
 * There are two items that track free extents, one indexed by the block
 * location of the free extent and one indexed by the size of the free
 * extent.  This means that one allocation can update a great number of
 * items throughout the tree as items are created and deleted as extents
 * are split and merged.  This can introduce inconsistent failure
 * states.  We'll some day address that with preallocation and pinning.
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
	u8 flags;
};

/* avoiding dynamic on-stack array initializers :/ */
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
	fkey->flags = ext->flags;

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
	ext->flags = fkey->flags;
}

#define LOAD_FREE_EXTENT(which_type, ext, key)		\
do {							\
	struct which_type *fkey = key->data;		\
							\
	ext->blkno = be64_to_cpu(fkey->last_blkno) -	\
		     be64_to_cpu(fkey->blocks) + 1;	\
	ext->blk_off = ext->blkno;			\
	ext->blocks = be64_to_cpu(fkey->blocks);	\
	ext->flags = 0;					\
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
	    left->blkno + left->blocks == right->blkno &&
	    left->flags == right->flags) {
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
	left->flags = outer->flags;

	right->blk_off = inner->blk_off + inner->blocks;
	right->blkno = inner->blkno + inner->blocks;
	right->blocks = (outer->blk_off + outer->blocks) - right->blk_off;
	right->flags = outer->flags;
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
 * Find an adjacent extent in the direction of the delta.  If we can
 * merge with it then we modify the incoming cur extent.  nei is set to
 * the neighbour we found.  If we didn't merge then nei's blocks is set
 * to 0.
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

	memset(nei, 0, sizeof(struct native_extent));

	/* short circuit prev search for common first block alloc */
	if (cur->blk_off == 0 && delta < 0)
		return 0;

	memset(&ext, ~0, sizeof(ext));
	init_extent_key(&last, last_bytes, &ext, arg, type);

	ext.blk_off = cur->blk_off + delta;
	ext.blkno = cur->blkno + delta;
	ext.blocks = 1;
	ext.flags = 0;
	init_extent_key(&key, key_bytes, &ext, arg, type);

	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	load_extent(&ext, &key);
	trace_printk("merge nei "EXTF"\n", EXTA(&ext));

	if (merge_extents(cur, &ext))
		*nei = ext;
	ret = 0;
out:
	return ret;
}

/*
 * We have two item types for indexing free extents by either the
 * location of the extent or the size of the extent.  When we create
 * logical extents we might be finding neighbouring extents that could
 * be merged.  We can only search for neighbours in the location items.
 * Once we find them we mirror the item modifications for both the
 * location and size items.
 *
 * If this returns an error then nothing will have changed.
 */
static int modify_items(struct super_block *sb, struct native_extent *ext,
			u64 arg, u8 type, bool create)
{
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf key;
	int ret;
	int err;

	trace_printk("mod cre %u "EXTF"\n", create, EXTA(ext));

	BUG_ON(type != SCOUTFS_FILE_EXTENT_KEY &&
	       type != SCOUTFS_FREE_EXTENT_BLKNO_KEY);

	init_extent_key(&key, key_bytes, ext, arg, type);
	ret = create ? scoutfs_item_create(sb, &key, NULL) :
		       scoutfs_item_delete(sb, &key);

	if (ret == 0 && type == SCOUTFS_FREE_EXTENT_BLKNO_KEY) {
		init_extent_key(&key, key_bytes, ext, arg,
				SCOUTFS_FREE_EXTENT_BLOCKS_KEY);
		ret = create ? scoutfs_item_create(sb, &key, NULL) :
			       scoutfs_item_delete(sb, &key);
		if (ret) {
			init_extent_key(&key, key_bytes, ext, arg, type);
			err = create ? scoutfs_item_delete(sb, &key) :
				       scoutfs_item_create(sb, &key, NULL);
			BUG_ON(err);
		}
	}

	return ret;
}

/*
 * Insert a new extent.  We see if it can be merged with adjacent
 * existing extents.  If this returns an error then the existing extents
 * will not have changed.
 */
static int insert_extent(struct super_block *sb,
				 struct native_extent *caller_ins,
				 u64 arg, u8 type)
{
	struct native_extent left;
	struct native_extent right;
	struct native_extent ins = *caller_ins;
	bool del_ins = false;
	bool ins_left = false;
	int err;
	int ret;

	trace_printk("inserting "EXTF"\n", EXTA(caller_ins));

	/* find previous that might be adjacent */
	ret = try_merge(sb, &ins, -1, &left, arg, type);
	      try_merge(sb, &ins, 1, &right, arg, type);
	if (ret < 0)
		goto out;

	trace_printk("merge left "EXTF"\n", EXTA(&left));
	trace_printk("merge right "EXTF"\n", EXTA(&right));

	ret = modify_items(sb, &ins, arg, type, true);
	if (ret)
		goto out;
	del_ins = true;

	if (left.blocks) {
		ret = modify_items(sb, &left, arg, type, false);
		if (ret)
			goto undo;
		ins_left = true;
	}

	if (right.blocks)
		ret = modify_items(sb, &right, arg, type, false);

undo:
	if (ret) {
		if (ins_left) {
			err = modify_items(sb, &left, arg, type, true);
			BUG_ON(err);
		}
		if (del_ins) {
			err = modify_items(sb, &ins, arg, type, false);
			BUG_ON(err);
		}
	}

out:
	return ret;
}

/*
 * Remove a portion of an existing extent.  The removal might leave
 * behind non-overlapping edges of the existing extent.  If this returns
 * an error then the existing extent will not have changed.
 */
static int remove_extent(struct super_block *sb,
			 struct native_extent *rem, u64 arg, u8 type)
{
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent left = {0,};
	struct native_extent right = {0,};
	struct native_extent outer;
	bool rem_left = false;
	bool rem_right = false;
	int err = 0;
	int ret;

	trace_printk("removing "EXTF"\n", EXTA(rem));

	memset(&outer, ~0, sizeof(outer));
	init_extent_key(&last, last_bytes, &outer, arg, type);

	/* find outer existing extent that contains removal extent */
	init_extent_key(&key, key_bytes, rem, arg, type);
	ret = scoutfs_item_next_same(sb, &key, &last, NULL);
	if (ret)
		goto out;

	load_extent(&outer, &key);

	trace_printk("outer "EXTF"\n", EXTA(&outer));

	if (!extents_within(&outer, rem) || outer.flags != rem->flags) {
		ret = -EIO;
		goto out;
	}

	trim_extents(&left, &right, &outer, rem);

	trace_printk("trim left "EXTF"\n", EXTA(&left));
	trace_printk("trim right "EXTF"\n", EXTA(&right));

	if (left.blocks) {
		ret = modify_items(sb, &left, arg, type, true);
		if (ret)
			goto out;
		rem_left = true;
	}

	if (right.blocks) {
		ret = modify_items(sb, &right, arg, type, true);
		if (ret)
			goto out;
		rem_right = true;
	}

	ret = modify_items(sb, &outer, arg, type, false);

out:
	if (ret) {
		if (rem_right) {
			err = modify_items(sb, &right, arg, type, false);
			BUG_ON(err);
		}
		if (rem_left) {
			err = modify_items(sb, &left, arg, type, false);
			BUG_ON(err);
		}
	}

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * Free extents whose blocks fall inside the specified logical block
 * range.
 *
 * If 'offline' is given then blocks are freed but the extent items are
 * left behind and their _OFFLINE flag is set.
 *
 * This is the low level extent item manipulation code.  Callers manage
 * higher order locking and transactional consistency.
 */
int scoutfs_data_truncate_items(struct super_block *sb, u64 ino, u64 iblock,
				u64 len, bool offline)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent found;
	struct native_extent rng;
	struct native_extent ext;
	struct native_extent ofl;
	struct native_extent fr;
	bool rem_fr = false;
	bool ins_ext = false;
	int ret = 0;
	int err;

	trace_printk("iblock %llu len %llu offline %u\n",
		     iblock, len, offline);

	memset(&ext, ~0, sizeof(ext));
	init_extent_key(&last, last_bytes, &ext, ino, SCOUTFS_FILE_EXTENT_KEY);

	rng.blk_off = iblock;
	rng.blocks = len;
	rng.blkno = 0;
	rng.flags = 0;

	while (rng.blocks) {
		/* find the next extent that could include our first block */
		init_extent_key(&key, key_bytes, &rng, ino,
				SCOUTFS_FILE_EXTENT_KEY);

		ret = scoutfs_item_next_same(sb, &key, &last, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		load_extent(&found, &key);
		trace_printk("found "EXTF"\n", EXTA(&found));

		/* XXX corruption: offline and allocation are exclusive */
		if (!!found.blkno ==
		    !!(found.flags & SCOUTFS_FILE_EXTENT_OFFLINE)) {
			ret = -EIO;
			break;
		}

		/* we're done if the found extent is past us */
		if (found.blk_off >= rng.blk_off + rng.blocks) {
			ret = 0;
			break;
		}

		/* find the intersection */
		ext.blk_off = max(rng.blk_off, found.blk_off);
		ext.blocks = min(rng.blk_off + rng.blocks,
				 found.blk_off + found.blocks) - ext.blk_off;
		ext.blkno = found.blkno + (ext.blk_off - found.blk_off);
		ext.flags = found.flags;

		/* next search will be past the extent we truncate */
		rng.blk_off = ext.blk_off + ext.blocks;
		if (rng.blk_off < iblock + len)
			rng.blocks = (iblock + len) - rng.blk_off;
		else
			rng.blocks = 0;

		/* done if already offline */
		if (offline && (ext.flags & SCOUTFS_FILE_EXTENT_OFFLINE))
			continue;

		/* free the old extent if it was allocated */
		if (ext.blkno) {
			fr = ext;
			fr.blk_off = fr.blkno;
			ret = insert_extent(sb, &fr, sbi->node_id,
					    SCOUTFS_FREE_EXTENT_BLKNO_KEY);
			if (ret)
				break;
			rem_fr = true;
		}

		/* always remove the overlapping file extent */
		ret = remove_extent(sb, &ext, ino, SCOUTFS_FILE_EXTENT_KEY);
		if (ret)
			break;
		ins_ext = true;

		/* maybe add new file extents with the offline flag set */
		if (offline) {
			ofl = ext;
			ofl.blkno = 0;
			ofl.flags = SCOUTFS_FILE_EXTENT_OFFLINE;
			ret = insert_extent(sb, &ofl, sbi->node_id,
					    SCOUTFS_FILE_EXTENT_KEY);
			if (ret)
				break;
		}

		rem_fr = false;
		ins_ext = false;
	}

	if (ret) {
		if (ins_ext) {
			err = insert_extent(sb, &ext, ino,
					    SCOUTFS_FILE_EXTENT_KEY);
			BUG_ON(err);
		}
		if (rem_fr) {
			err = remove_extent(sb, &fr, sbi->node_id,
					    SCOUTFS_FREE_EXTENT_BLKNO_KEY);
			BUG_ON(err);
		}
	}

	return ret;
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

		trace_printk("inserting [%u] "EXTF"\n", i, EXTA(&ext));

		ext.blk_off = ext.blkno;
		ext.flags = 0;
		ret = insert_extent(sb, &ext, sbi->node_id,
				    SCOUTFS_FREE_EXTENT_BLKNO_KEY);
		if (ret)
			break;
	}

out:
	if (!IS_ERR_OR_NULL(segnos))
		kfree(segnos);

	/* XXX don't orphan segnos on error, crash recovery with server */

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
static int allocate_block(struct inode *inode, sector_t iblock, u64 *blkno,
			  bool was_offline)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent last_ext;
	struct native_extent found;
	struct native_extent ext;
	struct native_extent ofl;
	struct native_extent fr;
	struct task_cursor *curs;
	bool alloced = false;
	const u64 ino = scoutfs_ino(inode);
	bool rem_ext = false;
	bool ins_ofl = false;
	u8 type;
	int err;
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
	ext.flags = 0;

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
	trace_printk("found nei "EXTF"\n", EXTA(&found));

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

	/* remove old offline block if we're staging */
	if (was_offline) {
		ofl.blk_off = iblock;
		ofl.blkno = 0;
		ofl.blocks = 1;
		ofl.flags = SCOUTFS_FILE_EXTENT_OFFLINE;
		ret = remove_extent(sb, &ofl, ino, SCOUTFS_FILE_EXTENT_KEY);
		if (ret < 0)
			goto out;
		ins_ofl = true;
	}

	/* insert new file extent */
	*blkno = found.blkno;
	ext.blk_off = iblock;
	ext.blkno = found.blkno;
	ext.blocks = 1;
	ext.flags = 0;
	ret = insert_extent(sb, &ext, ino, SCOUTFS_FILE_EXTENT_KEY);
	if (ret < 0)
		goto out;
	rem_ext = true;

	/* and remove free extents */
	fr = ext;
	fr.blk_off = ext.blkno;
	ret = remove_extent(sb, &fr, sbi->node_id,
			    SCOUTFS_FREE_EXTENT_BLKNO_KEY);
	if (ret)
		goto out;

	/* advance cursor if we're using it */
	if (curs->blocks) {
		if (--curs->blocks == 0)
			curs->blkno = 0;
		else
			curs->blkno++;
	}

	ret = 0;
out:
	if (ret) {
		if (rem_ext) {
			err = remove_extent(sb, &ext, ino,
					    SCOUTFS_FILE_EXTENT_KEY);
			BUG_ON(err);
		}
		if (ins_ofl) {
			err = insert_extent(sb, &ofl, ino,
					    SCOUTFS_FILE_EXTENT_KEY);
			BUG_ON(err);
		}
	}

	up_write(&datinf->alloc_rwsem);
	trace_printk("ret %d\n", ret);
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	DECLARE_DATA_INFO(sb, datinf);
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent ext;
	bool was_offline = false;
	u64 blkno;
	u64 off;
	int ret;

	bh->b_blocknr = 0;
	bh->b_size = 0;

	ext.blk_off = iblock;
	ext.blocks = 1;
	ext.blkno = 0;
	ext.flags = 0;
	init_extent_key(&key, key_bytes, &ext, scoutfs_ino(inode),
			SCOUTFS_FILE_EXTENT_KEY);

	memset(&ext, ~0, sizeof(ext));
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
			memset(&ext, 0, sizeof(ext));
		else
			goto out;
	} else {
		load_extent(&ext, &key);
		trace_printk("found nei "EXTF"\n", EXTA(&ext));
	}

	if ((ext.flags & SCOUTFS_FILE_EXTENT_OFFLINE) && !si->staging) {
		ret = -EINVAL;
		goto out;
	}

	/* use the extent if it intersects */
	if (iblock >= ext.blk_off && iblock < (ext.blk_off + ext.blocks)) {

		if (ext.flags & SCOUTFS_FILE_EXTENT_OFFLINE) {
			/* non-stage can't write to offline */
			if (!si->staging) {
				ret = -EINVAL;
				goto out;
			}
			was_offline = true;
		} else {
			/* found online extent */
			off = iblock - ext.blk_off;
			map_bh(bh, inode->i_sb, ext.blkno + off);
			bh->b_size = min_t(u64, SIZE_MAX,
				    (ext.blocks - off) << SCOUTFS_BLOCK_SHIFT);
		}
	}

	if (!buffer_mapped(bh) && create) {
		ret = allocate_block(inode, iblock, &blkno, was_offline);
		if (ret)
			goto out;

		map_bh(bh, inode->i_sb, blkno);
		bh->b_size = SCOUTFS_BLOCK_SHIFT;
		set_buffer_new(bh);
	}

	ret = 0;
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

/*
 * Return the extents that intersect with the given byte range.  It doesn't
 * trim the returned extents to the byte range.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct super_block *sb = inode->i_sb;
	const u8 type = SCOUTFS_FILE_EXTENT_KEY;
	const u64 ino = scoutfs_ino(inode);
	u8 last_bytes[MAX_KEY_BYTES];
	u8 key_bytes[MAX_KEY_BYTES];
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	struct native_extent ext;
	u64 logical;
	u64 blk_off;
	u64 final;
	u64 phys;
	u64 size;
	u32 flags;
	int ret = 0;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		goto out;

	memset(&ext, ~0, sizeof(ext));
	init_extent_key(&last, last_bytes, &ext, ino, type);

	blk_off = start >> SCOUTFS_BLOCK_SHIFT;
	final = (start + len - 1) >> SCOUTFS_BLOCK_SHIFT;
	size = 0;
	flags = 0;

	/* XXX overkill? */
	mutex_lock(&inode->i_mutex);

	for (;;) {
		ext.blk_off = blk_off;
		ext.blkno = 0;
		ext.blocks = 1;
		ext.flags = 0;
		init_extent_key(&key, key_bytes, &ext, ino, type);

		ret = scoutfs_item_next_same(sb, &key, &last, NULL);
		if (ret < 0) {
			if (ret != -ENOENT)
				break;
			flags |= FIEMAP_EXTENT_LAST;
			ret = 0;
		}

		load_extent(&ext, &key);

		if (ext.blk_off > final)
			flags |= FIEMAP_EXTENT_LAST;

		if (size) {
			ret = fiemap_fill_next_extent(fieinfo, logical, phys,
						      size, flags);
			if (ret != 0) {
				if (ret == 1)
					ret = 0;
				break;
			}
		}

		if (flags & FIEMAP_EXTENT_LAST)
			break;

		logical = ext.blk_off << SCOUTFS_BLOCK_SHIFT;
		phys = ext.blkno << SCOUTFS_BLOCK_SHIFT;
		size = ext.blocks << SCOUTFS_BLOCK_SHIFT;
		flags = ext.flags & SCOUTFS_FILE_EXTENT_OFFLINE ?
			FIEMAP_EXTENT_UNKNOWN : 0;

		blk_off = ext.blk_off + ext.blocks;
	}

	mutex_unlock(&inode->i_mutex);
out:
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
