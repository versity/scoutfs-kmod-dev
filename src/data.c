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
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/falloc.h>
#include <linux/writeback.h>
#include <linux/workqueue.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "kvec.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"
#include "client.h"
#include "lock.h"
#include "file.h"
#include "extents.h"
#include "msg.h"
#include "count.h"

/*
 * scoutfs uses extent items to track file data block mappings and free
 * blocks.
 *
 * Typically we'll allocate a single block in get_block if a mapping
 * isn't found.
 *
 * We special case extending contiguous files.  In that case we'll preallocate
 * an unwritten extent at the end of the file.  The size of the preallocation
 * is based on the file size and is capped.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - forced unmount with dirty data
 *  - direct IO
 *  - need trans around each bulk alloc
 */

/*
 * The largest extent that we'll store in a single item.  This will
 * determine the granularity of interleaved concurrent allocations on a
 * node.  Sequential max length allocations could still see contiguous
 * physical extent allocations.  It limits the amount of IO needed to
 * invalidate a lock.  And it determines the granularity of parallel
 * writes to a file between nodes.
 */
#define MAX_EXTENT_BLOCKS (8ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SHIFT)
/*
 * We ask for a fixed size from the server today.
 */
#define SERVER_ALLOC_BLOCKS (MAX_EXTENT_BLOCKS * 8)
/*
 * Send free extents back to the server if we have plenty locally.
 */
#define NODE_FREE_HIGH_WATER_BLOCKS (SERVER_ALLOC_BLOCKS * 16)

struct data_info {
	struct super_block *sb;
	struct rw_semaphore alloc_rwsem;
	atomic64_t node_free_blocks;
	struct workqueue_struct *workq;
	struct work_struct return_work;
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

static void init_file_extent_key(struct scoutfs_key *key, u64 ino, u64 last)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skfe_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_FILE_EXTENT_TYPE,
		.skfe_last = cpu_to_le64(last),
	};
}

static void init_free_extent_key(struct scoutfs_key *key, u8 type, u64 node_id,
				 u64 major, u64 minor)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_NODE_ZONE,
		.sknf_node_id = cpu_to_le64(node_id),
		.sk_type = type,
		.sknf_major = cpu_to_le64(major),
		.sknf_minor = cpu_to_le64(minor),
	};
}

static int init_extent_from_item(struct scoutfs_extent *ext,
				 struct scoutfs_key *key,
				 struct scoutfs_file_extent *fex)
{
	u64 owner;
	u64 start;
	u64 map;
	u64 len;
	u8 flags;

	if (key->sk_type != SCOUTFS_FILE_EXTENT_TYPE &&
	    key->sk_type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	    key->sk_type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		return -EIO; /* XXX corruption, unknown key type */

	if (key->sk_type == SCOUTFS_FILE_EXTENT_TYPE) {
		owner = le64_to_cpu(key->skfe_ino);
		len = le64_to_cpu(fex->len);
		start = le64_to_cpu(key->skfe_last) - len + 1;
		map = le64_to_cpu(fex->blkno);
		flags = fex->flags;

	} else {
		owner = le64_to_cpu(key->sknf_node_id);
		start = le64_to_cpu(key->sknf_major);
		len = le64_to_cpu(key->sknf_minor);
		if (key->sk_type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
			swap(start, len);
		start -= len - 1;
		map = 0;
		flags = 0;
	}

	return scoutfs_extent_init(ext, key->sk_type, owner, start, len, map,
				   flags);
}

/*
 * Read and write file extent and free extent items.
 *
 * File extents and free extents are indexed by the last position in the
 * extent so that we can find intersections with _next.
 *
 * We also index free extents by their length.  We implement that by
 * keeping their _BLOCKS_ item in sync with the primary _BLKNO_ item
 * that callers operate on.
 *
 * The count of free blocks stored in node items is kept consistent by
 * updating the count every time we create or delete items.  Updated
 * extents are deleted and then recreated so the count can bounce around
 * a bit, but it's OK for it to be imprecise at the margins.
 */
static int data_extent_io(struct super_block *sb, int op,
			  struct scoutfs_extent *ext, void *data)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct scoutfs_lock *lock = data;
	struct scoutfs_file_extent fex;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct kvec val;
	bool mirror = false;
	u8 mirror_type;
	u8 mirror_op = 0;
	int expected;
	int ret;
	int err;

	if (WARN_ON_ONCE(ext->type != SCOUTFS_FILE_EXTENT_TYPE &&
			 ext->type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
			 ext->type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE))
		return -EINVAL;

	if (ext->type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	    (op == SEI_INSERT || op == SEI_DELETE)) {
		mirror = true;
		mirror_type = SCOUTFS_FREE_EXTENT_BLOCKS_TYPE;
		mirror_op = op == SEI_INSERT ? SEI_DELETE : SEI_INSERT;
	}

	if (ext->type == SCOUTFS_FILE_EXTENT_TYPE) {
		init_file_extent_key(&key, ext->owner,
				     ext->start + ext->len - 1);
		init_file_extent_key(&first, ext->owner, 0);
		init_file_extent_key(&last, ext->owner, U64_MAX);
		fex.blkno = cpu_to_le64(ext->map);
		fex.len = cpu_to_le64(ext->len);
		fex.flags = ext->flags;
		kvec_init(&val, &fex, sizeof(fex));
	} else {
		init_free_extent_key(&key, ext->type, ext->owner,
				     ext->start + ext->len - 1, ext->len);
		if (ext->type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
			swap(key.sknf_major, key.sknf_minor);
		init_free_extent_key(&first, ext->type, ext->owner,
				     0, 0);
		init_free_extent_key(&last, ext->type, ext->owner,
				     U64_MAX, U64_MAX);
		kvec_init(&val, NULL, 0);
	}

	if (op == SEI_NEXT || op == SEI_PREV) {
		expected = val.iov_len;

		if (op == SEI_NEXT)
			ret = scoutfs_item_next(sb, &key, &last, &val, lock);
		else
			ret = scoutfs_item_prev(sb, &key, &first, &val, lock);
		if (ret >= 0 && ret != expected)
			ret = -EIO;
		if (ret == expected)
			ret = init_extent_from_item(ext, &key, &fex);

	} else if (op == SEI_INSERT) {
		ret = scoutfs_item_create(sb, &key, &val, lock);

	} else if (op == SEI_DELETE) {
		ret = scoutfs_item_delete(sb, &key, lock);

	} else {
		ret = WARN_ON_ONCE(-EINVAL);
	}

	if (ret == 0 && mirror) {
		swap(ext->type, mirror_type);
		ret = data_extent_io(sb, op, ext, data);
		swap(ext->type, mirror_type);
		if (ret) {
			err = data_extent_io(sb, mirror_op, ext, data);
			BUG_ON(err);
		}
	}

	if (ret == 0 && ext->type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE) {
		if (op == SEI_INSERT)
			atomic64_add(ext->len, &datinf->node_free_blocks);
		else if (op == SEI_DELETE)
			atomic64_sub(ext->len, &datinf->node_free_blocks);
	}

	return ret;
}

/*
 * Find and remove or mark offline the next extent that intersects with
 * the caller's range.  The caller is responsible for transactions and
 * locks.
 *
 * Returns:
 *  - -errno on errors
 *  - 0 if there are no more extents to stop iteration
 *  - +iblock of next logical block to truncate the next block from
 *
 * Since our extents are block granular we can never have > S64_MAX
 * iblock values.  Returns -ENOENT if no extent was found and -errno on
 * errors.
 */
static s64 truncate_one_extent(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	struct scoutfs_extent next;
	struct scoutfs_extent rem;
	struct scoutfs_extent fr;
	struct scoutfs_extent ofl;
	bool rem_fr = false;
	bool add_rem = false;
	s64 offline_delta = 0;
	s64 online_delta = 0;
	s64 ret;

	scoutfs_extent_init(&next, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &next, lock);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	trace_scoutfs_data_truncate_next(sb, &next);

	scoutfs_extent_init(&rem, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, last - iblock + 1, 0, 0);
	if (!scoutfs_extent_intersection(&rem, &next)) {
		ret = 0;
		goto out;
	}

	trace_scoutfs_data_truncate_remove(sb, &rem);

	/* nothing to do if the extent's already offline and unallocated */
	if ((offline && (rem.flags & SEF_OFFLINE)) && !rem.map) {
		ret = 1;
		goto out;
	}

	/* free an allocated mapping */
	if (rem.map) {
		scoutfs_extent_init(&fr, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id, rem.map, rem.len, 0, 0);
		ret = scoutfs_extent_add(sb, data_extent_io, &fr,
					 sbi->node_id_lock);
		if (ret)
			goto out;
		rem_fr = true;
	}

	/* remove the extent */
	ret = scoutfs_extent_remove(sb, data_extent_io, &rem, lock);
	if (ret)
		goto out;
	add_rem = true;

	/* add an offline extent */
	if (offline) {
		scoutfs_extent_init(&ofl, SCOUTFS_FILE_EXTENT_TYPE, rem.owner,
				    rem.start, rem.len, 0, SEF_OFFLINE);
		trace_scoutfs_data_truncate_offline(sb, &ofl);
		ret = scoutfs_extent_add(sb, data_extent_io, &ofl, lock);
		if (ret)
			goto out;
	}

	if (rem.map && !(rem.flags & SEF_UNWRITTEN))
		online_delta += -rem.len;
	if (!offline && (rem.flags & SEF_OFFLINE))
		offline_delta += -rem.len;
	if (offline && !(rem.flags & SEF_OFFLINE))
		offline_delta += ofl.len;

	scoutfs_inode_add_onoff(inode, online_delta, offline_delta);

	/* start returning free extents to the server after a small delay */
	if (rem.map && (atomic64_read(&datinf->node_free_blocks) >
			NODE_FREE_HIGH_WATER_BLOCKS))
		queue_work(datinf->workq, &datinf->return_work);

	ret = 1;
out:
	scoutfs_extent_cleanup(ret < 0 && add_rem, scoutfs_extent_add, sb,
			       data_extent_io, &rem, lock,
			       SC_DATA_EXTENT_TRUNC_CLEANUP,
			       corrupt_data_extent_trunc_cleanup, &rem);
	scoutfs_extent_cleanup(ret < 0 && rem_fr, scoutfs_extent_remove, sb,
			       data_extent_io, &fr, sbi->node_id_lock,
			       SC_DATA_EXTENT_TRUNC_CLEANUP,
			       corrupt_data_extent_trunc_cleanup, &rem);

	if (ret > 0)
		ret = rem.start + rem.len;

	return ret;
}

/*
 * Free blocks inside the logical block range from 'iblock' to 'last',
 * inclusive.
 *
 * If 'offline' is given then blocks are freed an offline mapping is
 * left behind.  Only blocks that have been allocated can be marked
 * offline.
 *
 * If the inode is provided then we update its tracking of the online
 * and offline blocks.  If it's not provided then the inode is being
 * destroyed and isn't reachable, we don't need to update it.
 *
 * The caller is in charge of locking the inode and extents, but we may
 * have to modify far more items than fit in a transaction so we're in
 * charge of batching updates into transactions.  If the inode is
 * provided then we're responsible for updating its item as we go.
 */
int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_item_count cnt = SIC_TRUNC_EXTENT(inode);
	DECLARE_DATA_INFO(sb, datinf);
	LIST_HEAD(ind_locks);
	s64 ret = 0;

	WARN_ON_ONCE(inode && !mutex_is_locked(&inode->i_mutex));

	/* clamp last to the last possible block? */
	if (last > SCOUTFS_BLOCK_MAX)
		last = SCOUTFS_BLOCK_MAX;

	trace_scoutfs_data_truncate_items(sb, iblock, last, offline);

	if (WARN_ON_ONCE(last < iblock))
		return -EINVAL;

	while (iblock <= last) {
		if (inode)
			ret = scoutfs_inode_index_lock_hold(inode, &ind_locks,
							    true, cnt);
		else
			ret = scoutfs_hold_trans(sb, cnt);
		if (ret)
			break;

		if (inode)
			ret = scoutfs_dirty_inode_item(inode, lock);
		else
			ret = 0;

		down_write(&datinf->alloc_rwsem);
		if (ret == 0)
			ret = truncate_one_extent(sb, inode, ino, iblock, last,
						  offline, lock);
		up_write(&datinf->alloc_rwsem);

		if (inode)
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		scoutfs_release_trans(sb);
		if (inode)
			scoutfs_inode_index_unlock(sb, &ind_locks);

		if (ret <= 0)
			break;

		iblock = ret;
		ret = 0;
	}

	return ret;
}

static int get_server_extent(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_extent ext;
	u64 start;
	u64 len;
	int ret;

	ret = scoutfs_client_alloc_extent(sb, SERVER_ALLOC_BLOCKS,
					  &start, &len);
	if (ret)
		goto out;

	scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
			    sbi->node_id, start, len, 0, 0);
	trace_scoutfs_data_get_server_extent(sb, &ext);
	ret = scoutfs_extent_add(sb, data_extent_io, &ext, sbi->node_id_lock);
	/* XXX don't free extent on error, crash recovery with server */

out:
	return ret;
}

/*
 * Find a free extent to satisfy an allocation of at most @len blocks.
 *
 * Returns 0 and fills the caller's extent with a _BLKNO_TYPE extent if
 * we found a match.  It's len may be less than desired.  No stored
 * extents have been modified.
 *
 * Returns -errno on error and -ENOSPC if no free extents were found.
 *
 * The caller's extent is always clobbered.
 */
static int find_free_extent(struct super_block *sb, u64 len,
			    struct scoutfs_extent *ext)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	len = min(len, MAX_EXTENT_BLOCKS);

	for (;;) {
		/* first try to find the first sufficient extent */
		scoutfs_extent_init(ext, SCOUTFS_FREE_EXTENT_BLOCKS_TYPE,
				    sbi->node_id, 0, len, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, ext,
					  sbi->node_id_lock);

		/* if none big enough, look for last largest smaller */
		if (ret == -ENOENT && len > 1)
			ret = scoutfs_extent_prev(sb, data_extent_io, ext,
						  sbi->node_id_lock);

		/* ask the server for more if we think it'll help */
		if (ret == -ENOENT || ext->len < len) {
			ret = get_server_extent(sb);
			if (ret == 0)
				continue;
		}

		/* use the extent we found or return errors */
		break;
	}

	if (ret == 0)
		scoutfs_extent_init(ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id, ext->start,
				    min(ext->len, len), 0, 0);

	trace_scoutfs_data_find_free_extent(sb, ext);
	return ret;
}

/*
 * The caller is writing to a logical block that doesn't have an
 * allocated extent.
 *
 * We always allocate an extent starting at the logical block.  The
 * caller has considered overlapping and following extents and has given
 * us a maximum length that we could safely allocate.  Preallocation
 * heuristics decide to use this length or only a single block.
 *
 * If the caller passes in an existing extent then we remove the
 * allocated region from the existing extent.  We then add a single
 * block extent for the caller to write into.  Then if we allocated
 * multiple blocks we add an unwritten extent for the rest of the blocks
 * in the extent.
 *
 * Preallocation is used if we're strictly contiguously extending
 * writes.  That is, if the logical block offset equals the number of
 * online blocks.  We try to preallocate the number of blocks existing
 * so that small files don't waste inordinate amounts of space and large
 * files will eventually see large extents.  This only works for
 * contiguous single stream writes or stages of files from the first
 * block.  It doesn't work for concurrent stages, releasing behind
 * staging, sparse files, multi-node writes, etc.  fallocate() is always
 * a better tool to use.
 *
 * On success we update the caller's extent to the single block
 * allocated extent for the logical block for use in block mapping.
 */
static int alloc_block(struct super_block *sb, struct inode *inode,
		       struct scoutfs_extent *ext, u64 iblock, u64 len,
		       struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_extent unwr;
	struct scoutfs_extent old;
	struct scoutfs_extent blk;
	struct scoutfs_extent fr;
	bool add_old = false;
	bool add_fr = false;
	bool rem_blk = false;
	u64 offline;
	u64 online;
	int ret;

	down_write(&datinf->alloc_rwsem);

	scoutfs_inode_get_onoff(inode, &online, &offline);

	/* strictly contiguous extending writes will try to preallocate */ 
	if (iblock > 1 && iblock == online)
		len = min3(len, iblock, MAX_EXTENT_BLOCKS);
	else
		len = 1;

	trace_scoutfs_data_alloc_block(sb, inode, ext, iblock, len,
				       online, offline);

	ret = find_free_extent(sb, len, &fr);
	if (ret < 0)
		goto out;

	trace_scoutfs_data_alloc_block_next(sb, &fr);

	/* initialize the new mapped block extent, referenced by cleanup */
	scoutfs_extent_init(&blk, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, 1, fr.start, 0);

	/* remove the free extent that we're allocating */
	ret = scoutfs_extent_remove(sb, data_extent_io, &fr, sbi->node_id_lock);
	if (ret)
		goto out;
	add_fr = true;

	/* remove an existing offline or unwritten block extent */
	if (ext->flags) {
		scoutfs_extent_init(&old, SCOUTFS_FILE_EXTENT_TYPE, ino,
				    iblock, len, 0, ext->flags);
		ret = scoutfs_extent_remove(sb, data_extent_io, &old, lock);
		if (ret)
			goto out;
		add_old = true;
	}

	/* add the block that the caller is writing */
	ret = scoutfs_extent_add(sb, data_extent_io, &blk, lock);
	if (ret)
		goto out;
	rem_blk = true;

	/* and maybe add the remaining unwritten extent */
	if (len > 1) {
		scoutfs_extent_init(&unwr, SCOUTFS_FILE_EXTENT_TYPE, ino,
				    iblock + 1, len - 1, fr.start + 1,
				    ext->flags | SEF_UNWRITTEN);
		ret = scoutfs_extent_add(sb, data_extent_io, &unwr, lock);
		if (ret)
			goto out;
	}

	scoutfs_inode_add_onoff(inode, 1,
				(ext->flags & SEF_OFFLINE) ? -1ULL : 0);
	ret = 0;
out:
	scoutfs_extent_cleanup(ret < 0 && rem_blk, scoutfs_extent_remove, sb,
			       data_extent_io, &blk, lock,
			       SC_DATA_EXTENT_ALLOC_CLEANUP,
			       corrupt_data_extent_alloc_cleanup, &blk);
	scoutfs_extent_cleanup(ret < 0 && add_old, scoutfs_extent_add, sb,
			       data_extent_io, &old, lock,
			       SC_DATA_EXTENT_ALLOC_CLEANUP,
			       corrupt_data_extent_alloc_cleanup, &blk);
	scoutfs_extent_cleanup(ret < 0 && add_fr, scoutfs_extent_add, sb,
			       data_extent_io, &fr, sbi->node_id_lock,
			       SC_DATA_EXTENT_ALLOC_CLEANUP,
			       corrupt_data_extent_alloc_cleanup, &blk);

	up_write(&datinf->alloc_rwsem);

	trace_scoutfs_data_alloc_block_ret(sb, ext, ret);
	if (ret == 0)
		*ext = blk;
	return ret;
}

/*
 * A caller is writing into unwritten allocated space.  This can also be
 * called for staging writes so we clear both the unwritten and offline
 * flags.  We record the extent as online as allocating writes would.
 *
 * We don't have to wait for dirty block IO to complete before clearing
 * the unwritten flag in metadata because we have strict synchronization
 * between data and metadata.  All dirty data in the current transaction
 * is written before the metadata in the transaction that references it
 * is committed.
 */
static int convert_unwritten(struct super_block *sb, struct inode *inode,
			     struct scoutfs_extent *ext, u64 start, u64 len,
			     struct scoutfs_lock *lock)
{
	struct scoutfs_extent conv;
	int err;
	int ret;

	if (WARN_ON_ONCE(!ext->map) ||
	    WARN_ON_ONCE(!(ext->flags & SEF_UNWRITTEN)))
		return -EINVAL;

	scoutfs_extent_init(&conv, ext->type, ext->owner, start, len,
			    ext->map + (start - ext->start), ext->flags);
	ret = scoutfs_extent_remove(sb, data_extent_io, &conv, lock);
	if (ret)
		goto out;

	conv.flags &= ~(SEF_UNWRITTEN | SEF_OFFLINE);
	ret = scoutfs_extent_add(sb, data_extent_io, &conv, lock);
	if (ret) {
		conv.flags = ext->flags;
		err = scoutfs_extent_add(sb, data_extent_io, &conv, lock);
		BUG_ON(err);
		goto out;
	}

	scoutfs_inode_add_onoff(inode, len,
				(ext->flags & SEF_OFFLINE) ? -len : 0);
	*ext = conv;
	ret = 0;
out:
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_extent ext;
	u64 next_iblock = 0;
	u64 offset;
	u64 len;
	int ret;

	WARN_ON_ONCE(create && !mutex_is_locked(&inode->i_mutex));

	/* make sure caller holds a cluster lock */
	lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!lock) ||
	    WARN_ON_ONCE(!create && si->staging)) {
		ret = -EINVAL;
		goto out;
	}

	/* look for the extent that overlaps our iblock */
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
			    scoutfs_ino(inode), iblock, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
	if (ret && ret != -ENOENT)
		goto out;

	if (ret == 0) {
		trace_scoutfs_data_get_block_next(sb, &ext);
		/* remember start of next to limit preallocation */
		if (ext.start > iblock)
			next_iblock = ext.start;
	}

	/* didn't find an extent or it's past our iblock */
	if (ret == -ENOENT || ext.start > iblock)
		memset(&ext, 0, sizeof(ext));

	if (ext.len)
		trace_scoutfs_data_get_block_intersection(sb, &ext);

	/* non-staging callers should have waited on offline blocks */
	if (WARN_ON_ONCE((ext.flags & SEF_OFFLINE) && !si->staging)) {
		ret = -EIO;
		goto out;
	}

	/* convert unwritten to written */
	if (create && (ext.flags & SEF_UNWRITTEN)) {
		ret = convert_unwritten(sb, inode, &ext, iblock, 1, lock);
		if (ret == 0)
			set_buffer_new(bh);
		goto out;
	}

	/* allocate an extent from our logical block */
	if (create && !ext.map) {
		/* limit possible alloc to this extent, next, or logical max */
		if (ext.len > 0)
			len = ext.len - (iblock - ext.start);
		else if (next_iblock > iblock)
			len = ext.start - iblock;
		else
			len = SCOUTFS_BLOCK_MAX - iblock;

		ret = alloc_block(sb, inode, &ext, iblock, len, lock);
		if (ret == 0)
			set_buffer_new(bh);
	} else {
		ret = 0;
	}

out:
	/* map usable extent, else leave bh unmapped for sparse reads */
	if (ret == 0 && ext.map && !(ext.flags & SEF_UNWRITTEN)) {
		offset = iblock - ext.start;
		map_bh(bh, inode->i_sb, ext.map + offset);
		bh->b_size = min_t(u64, bh->b_size,
				   (ext.len - offset) << SCOUTFS_BLOCK_SHIFT);
	}

	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				ret, bh->b_blocknr, bh->b_size);
	return ret;
}

/*
 * This is almost never used.  We can't block on a cluster lock while
 * holding the page lock because lock invalidation gets the page lock
 * while blocking locks.  If a non blocking lock attempt fails we unlock
 * the page and block acquiring the lock.  We unlocked the page so it
 * could have been truncated away, or whatever, so we return
 * AOP_TRUNCATED_PAGE to have the caller try again.
 *
 * A similar process happens if we try to read from an offline extent
 * that a caller hasn't already waited for.  Instead of blocking
 * acquiring the lock we block waiting for the offline extent.  The page
 * lock protects the page from release while we're checking and
 * reading the extent.
 *
 * We can return errors from locking and checking offline extents.  The
 * page is unlocked if we return an error.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	DECLARE_DATA_WAIT(dw);
	int flags;
	int ret;

	flags = SCOUTFS_LKF_REFRESH_INODE | SCOUTFS_LKF_NONBLOCK;
	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags, inode,
				 &inode_lock);
	if (ret < 0) {
		unlock_page(page);
		if (ret == -EAGAIN) {
			flags &= ~SCOUTFS_LKF_NONBLOCK;
			ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags,
						 inode, &inode_lock);
			if (ret == 0) {
				scoutfs_unlock(sb, inode_lock,
					       SCOUTFS_LOCK_READ);
				ret = AOP_TRUNCATED_PAGE;
			}
		}
		return ret;
	}

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, inode_lock)) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_CACHE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, &dw,
					      inode_lock);
		if (ret != 0) {
			unlock_page(page);
			scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
			scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
		}
		if (ret > 0) {
			ret = scoutfs_data_wait(inode, &dw);
			if (ret == 0)
				ret = AOP_TRUNCATED_PAGE;
		}
		if (ret != 0)
			return ret;
	}

	ret = mpage_readpage(page, scoutfs_get_block);

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);

	return ret;
}

/*
 * This is used for opportunistic read-ahead which can throw the pages
 * away if it needs to.  If the caller didn't deal with offline extents
 * then we drop those pages rather than trying to wait.  Whoever is
 * staging offline extents should be doing it in enormous chunks so that
 * read-ahead can ramp up within each staged region.  The check for
 * offline extents is cheap when the inode has no offline extents.
 */
static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	struct page *page;
	struct page *tmp;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		goto out;

	list_for_each_entry_safe(page, tmp, pages, lru) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_CACHE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, NULL,
					      inode_lock);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			list_del(&page->lru);
			page_cache_release(page);
			if (--nr_pages == 0) {
				ret = 0;
				goto out;
			}
		}
	}

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);
out:
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	BUG_ON(!list_empty(pages));
	return ret;
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

/* fsdata allocated in write_begin and freed in write_end */
struct write_begin_data {
	struct list_head ind_locks;
	struct scoutfs_lock *lock;
};

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd;
	u64 ind_seq;
	int ret;

	trace_scoutfs_write_begin(sb, scoutfs_ino(inode), (__u64)pos, len);

	wbd = kmalloc(sizeof(struct write_begin_data), GFP_NOFS);
	if (!wbd)
		return -ENOMEM;

	INIT_LIST_HEAD(&wbd->ind_locks);
	*fsdata = wbd;

	wbd->lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!wbd->lock)) {
		ret = -EINVAL;
		goto out;
	}

	do {
		ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
		      scoutfs_inode_index_prepare(sb, &wbd->ind_locks, inode,
						  true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, &wbd->ind_locks,
							ind_seq,
							SIC_WRITE_BEGIN());
	} while (ret > 0);
	if (ret < 0)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode, wbd->lock);
	if (ret == 0)
		ret = block_write_begin(mapping, pos, len, flags, pagep,
					scoutfs_get_block);
	if (ret)
		scoutfs_release_trans(sb);
out:
	if (ret) {
		scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
		kfree(wbd);
	}
        return ret;
}

/* kinda like __filemap_fdatawrite_range! :P */
static int writepages_sync_none(struct address_space *mapping, loff_t start,
				loff_t end)
{
        struct writeback_control wbc = {
                .sync_mode = WB_SYNC_NONE,
                .nr_to_write = LONG_MAX,
                .range_start = start,
                .range_end = end,
        };

	return mapping->a_ops->writepages(mapping, &wbc);
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd = fsdata;
	int ret;

	trace_scoutfs_write_end(sb, scoutfs_ino(inode), page->index, (u64)pos,
				len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		if (!si->staging) {
			scoutfs_inode_set_data_seq(inode);
			scoutfs_inode_inc_data_version(inode);
		}

		scoutfs_update_inode_item(inode, wbd->lock, &wbd->ind_locks);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
	kfree(wbd);

	/*
	 * Currently transactions are kept very simple.  Only one is
	 * open at a time and commit excludes concurrent dirtying.  It
	 * writes out all dirty file data during commit.  This can lead
	 * to very long commit latencies with lots of dirty file data.
	 *
	 * This hack tries to minimize these writeback latencies while
	 * keeping concurrent large file strreaming writes from
	 * suffering too terribly.  Every N bytes we kick off background
	 * writbeack on the previous N bytes.  By the time transaction
	 * commit comes along it will find that dirty file blocks have
	 * already been written.
	 */
#define BACKGROUND_WRITEBACK_BYTES (16 * 1024 * 1024)
#define BACKGROUND_WRITEBACK_MASK (BACKGROUND_WRITEBACK_BYTES - 1)
	if (ret > 0 && ((pos + ret) & BACKGROUND_WRITEBACK_MASK) == 0)
		writepages_sync_none(mapping,
				     pos + ret - BACKGROUND_WRITEBACK_BYTES,
				     pos + ret - 1);

	return ret;
}

/*
 * Allocate one extent on behalf of fallocate.  The caller has given us
 * the largest extent we can add, its flags, and the flags of an
 * existing overlapping extent to remove.
 *
 * We allocate the largest extent that we can and return its length or
 * -errno.
 */
static s64 fallocate_one_extent(struct super_block *sb, u64 ino, u64 start,
				u64 len, u8 flags, u8 rem_flags,
				struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_extent fal;
	struct scoutfs_extent rem;
	struct scoutfs_extent fr;
	bool add_rem = false;
	bool add_fr = false;
	s64 ret;

	if (WARN_ON_ONCE(len == 0) ||
	    WARN_ON_ONCE(start + len < start)) {
		ret = -EINVAL;
		goto out;
	}

	ret = find_free_extent(sb, len, &fr);
	if (ret < 0)
		goto out;

	ret = scoutfs_extent_init(&fal, SCOUTFS_FILE_EXTENT_TYPE, ino,
				  start, fr.len, fr.start, flags);
	if (WARN_ON_ONCE(ret))
		goto out;

	ret = scoutfs_extent_remove(sb, data_extent_io, &fr, sbi->node_id_lock);
	if (ret)
		goto out;
	add_fr = true;

	/* remove a region of the existing extent */
	if (rem_flags) {
		scoutfs_extent_init(&rem, SCOUTFS_FILE_EXTENT_TYPE, ino,
				    fal.start, fal.len, 0, rem_flags);
		ret = scoutfs_extent_remove(sb, data_extent_io, &rem, lock);
		if (ret)
			goto out;
		add_rem = true;
	}

	ret = scoutfs_extent_add(sb, data_extent_io, &fal, lock);
	if (ret == 0)
		ret = fal.len;
out:
	scoutfs_extent_cleanup(ret < 0 && add_rem, scoutfs_extent_add, sb,
			       data_extent_io, &rem, lock,
			       SC_DATA_EXTENT_FALLOCATE_CLEANUP,
			       corrupt_data_extent_fallocate_cleanup, &fal);
	scoutfs_extent_cleanup(ret < 0 && add_fr, scoutfs_extent_add, sb,
			       data_extent_io, &fr, sbi->node_id_lock,
			       SC_DATA_EXTENT_FALLOCATE_CLEANUP,
			       corrupt_data_extent_alloc_cleanup, &fal);
	return ret;
}

/*
 * Modify the extents that map the blocks that store the len byte region
 * starting at offset.
 *
 * The caller has only prevented freezing by entering a fs write
 * context.  We're responsible for all other locking and consistency.
 */
long scoutfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	DECLARE_DATA_INFO(sb, datinf);
	struct scoutfs_extent ext;
	LIST_HEAD(ind_locks);
	u64 last_block;
	u64 iblock;
	s64 blocks;
	loff_t end;
	u8 rem_flags;
	u8 flags;
	int ret;

	mutex_lock(&inode->i_mutex);

	/* XXX support more flags */
        if (mode & ~(FALLOC_FL_KEEP_SIZE)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* catch wrapping */
	if (offset + len < offset) {
		ret = -EINVAL;
		goto out;
	}

	if (len == 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto out;

	inode_dio_wait(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len > i_size_read(inode))) {
                ret = inode_newsize_ok(inode, offset + len);
                if (ret)
                        goto out;
        }

	iblock = offset >> SCOUTFS_BLOCK_SHIFT;
	last_block = (offset + len - 1) >> SCOUTFS_BLOCK_SHIFT;

	while(iblock <= last_block) {

		scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
				    ino, iblock, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
		if (ret < 0 && ret != -ENOENT)
			goto out;

		blocks = last_block - iblock + 1;
		flags = SEF_UNWRITTEN;
		rem_flags = 0;

		if (ret == -ENOENT || ext.start > last_block) {
			/* no next extent or past us, all remaining blocks */

		} else if (iblock < ext.start) {
			/* sparse region until next extent */
			blocks = min_t(u64, blocks, ext.start - iblock);

		} else if (ext.map > 0) {
			/* skip past an allocated extent */
			blocks = min_t(u64, blocks,
				      (ext.start + ext.len) - iblock);
			iblock += blocks;
			blocks = 0;

		} else {
			/* allocating a portion of an unallocated extent */
			blocks = min_t(u64, blocks,
				       (ext.start + ext.len) - iblock);
			flags |= ext.flags;
			rem_flags = ext.flags;
			/* XXX corruption; why'd we store map == flags == 0? */
			if (rem_flags == 0) {
				ret = -EIO;
				goto out;
			}
		}

		ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false,
						    SIC_FALLOCATE_ONE());
		if (ret)
			goto out;

		if (blocks > 0) {
			down_write(&datinf->alloc_rwsem);
			blocks = fallocate_one_extent(sb, ino, iblock, blocks,
						      flags, rem_flags, lock);
			up_write(&datinf->alloc_rwsem);
			if (blocks < 0)
				ret = blocks;
			else
				ret = 0;
		}

		if (ret == 0 && !(mode & FALLOC_FL_KEEP_SIZE)) {
			end = (iblock + blocks) << SCOUTFS_BLOCK_SHIFT;
			if (end == 0 || end > offset + len)
				end = offset + len;
			if (end > i_size_read(inode))
				i_size_write(inode, end);
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		}
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);

		if (ret)
			goto out;

		iblock += blocks;
	}

out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	mutex_unlock(&inode->i_mutex);

	trace_scoutfs_data_fallocate(sb, ino, mode, offset, len, ret);
	return ret;
}

/*
 * A special case of initialzing a single large offline extent.  This
 * chooses not to deal with any existing extents.  It can only be used
 * on regular files with no data extents.  It's used to restore a file
 * with an offline extent which can then trigger staging.
 *
 * The caller has taken care of locking and holding a transaction.
 *
 * This could be an fallocate mode.
 */
int scoutfs_data_init_offline_extent(struct inode *inode, u64 size,
				     struct scoutfs_lock *lock)

{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_extent ext;
	u64 ino = scoutfs_ino(inode);
	u64 len;
	int ret;

	if (!S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE, ino, 0, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
	if (ret != -ENOENT) {
		if (ret == 0)
			ret = -EINVAL;
		goto out;
	}

	len = (size + SCOUTFS_BLOCK_SIZE - 1) >> SCOUTFS_BLOCK_SHIFT;
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    0, len, 0, SEF_OFFLINE);
	ret = scoutfs_extent_add(sb, data_extent_io, &ext, lock);
	if (ret == 0)
		scoutfs_inode_add_onoff(inode, 0, len);
out:
	return ret;
}


/*
 * Return all the file's extents whose blocks overlap with the caller's
 * byte region.  We set _LAST on the last extent and _UNKNOWN on offline
 * extents.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_extent ext;
	u64 blk_off;
	u64 logical = 0;
	u64 phys = 0;
	u64 size = 0;
	u32 flags = 0;
	int ret;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	/* XXX overkill? */
	mutex_lock(&inode->i_mutex);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &inode_lock);
	if (ret)
		goto out;

	blk_off = start >> SCOUTFS_BLOCK_SHIFT;

	for (;;) {
		scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
				    scoutfs_ino(inode), blk_off, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext, inode_lock);
		/* fiemap will return last and stop when we see enoent */
		if (ret < 0 && ret != -ENOENT)
			break;

		if (ret == 0)
			trace_scoutfs_data_fiemap_extent(sb, &ext);

		if (size) {
			if (ret == -ENOENT)
				flags |= FIEMAP_EXTENT_LAST;
			ret = fiemap_fill_next_extent(fieinfo, logical, phys,
						      size, flags);
			if (ret || (logical + size >= (start + len))) {
				if (ret == 1)
					ret = 0;
				break;
			}
		}

		logical = ext.start << SCOUTFS_BLOCK_SHIFT;
		phys = ext.map << SCOUTFS_BLOCK_SHIFT;
		size = ext.len << SCOUTFS_BLOCK_SHIFT;
		flags = 0;
		if (ext.flags & SEF_OFFLINE)
			flags |= FIEMAP_EXTENT_UNKNOWN;
		if (ext.flags & SEF_UNWRITTEN)
			flags |= FIEMAP_EXTENT_UNWRITTEN;

		blk_off = ext.start + ext.len;
	}

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
out:
	mutex_unlock(&inode->i_mutex);

	return ret;
}

/*
 * Insert a new waiter.  This supports multiple tasks waiting for the
 * same ino and iblock by also comparing waiters by their addresses.
 */
static void insert_offline_waiting(struct rb_root *root,
				   struct scoutfs_data_wait *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		cmp = scoutfs_cmp_u64s(ins->ino, dw->ino) ?:
		      scoutfs_cmp_u64s(ins->iblock, dw->iblock) ?:
		      scoutfs_cmp(ins, dw);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static struct scoutfs_data_wait *next_data_wait(struct rb_root *root, u64 ino,
						u64 iblock)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *next = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		/* go left when ino/iblock are equal to get first task */
		cmp = scoutfs_cmp_u64s(ino, dw->ino) ?:
		      scoutfs_cmp_u64s(iblock, dw->iblock);
		if (cmp <= 0) {
			node = &(*node)->rb_left;
			next = dw;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		}
	}

	return next;
}

static struct scoutfs_data_wait *dw_next(struct scoutfs_data_wait *dw)
{
	struct rb_node *node = rb_next(&dw->node);
	if (node)
		return container_of(node, struct scoutfs_data_wait, node);
	return NULL;
}

/*
 * Check if we should wait by looking for extents whose flags match.
 * Returns 0 if no extents were found or any error encountered.
 *
 * The caller must have locked the extents before calling, both across
 * mounts and within this mount.
 *
 * Returns 1 if any file extents in the caller's region matched.  If the
 * wait struct is provided then it is initialized to be woken when the
 * extents change after the caller unlocks after the check.  The caller
 * must come through _data_wait() to clean up the wait struct if we set
 * it up.
 */
int scoutfs_data_wait_check(struct inode *inode, loff_t pos, loff_t len,
			    u8 sef, u8 op, struct scoutfs_data_wait *dw,
			    struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	struct scoutfs_extent ext = {0,};
	u64 iblock;
	u64 last_block;
	u64 on;
	u64 off;
	int ret = 0;

	if (WARN_ON_ONCE(sef & SEF_UNKNOWN) ||
	    WARN_ON_ONCE(op & SCOUTFS_IOC_DWO_UNKNOWN) ||
	    WARN_ON_ONCE(dw && !RB_EMPTY_NODE(&dw->node)) ||
	    WARN_ON_ONCE(pos + len < pos)) {
		ret = -EINVAL;
		goto out;
	}

	if ((sef & SEF_OFFLINE)) {
		scoutfs_inode_get_onoff(inode, &on, &off);
		if (off == 0) {
			ret = 0;
			goto out;
		}
	}

	iblock = pos >> SCOUTFS_BLOCK_SHIFT;
	last_block = (pos + len - 1) >> SCOUTFS_BLOCK_SHIFT;

	while(iblock <= last_block) {
		scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
				    scoutfs_ino(inode), iblock, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		if (ext.start > last_block)
			break;

		if (sef & ext.flags) {
			if (dw) {
				dw->chg = atomic64_read(&wq->changed);
				dw->ino = scoutfs_ino(inode);
				dw->iblock = max(iblock, ext.start);
				dw->op = op;

				spin_lock(&rt->lock);
				insert_offline_waiting(&rt->root, dw);
				spin_unlock(&rt->lock);
			}

			ret = 1;
			break;
		}

		iblock = ext.start + ext.len;
	}

out:
	trace_scoutfs_data_wait_check(sb, scoutfs_ino(inode), pos, len,
				      sef, op, ext.start, ext.len, ext.flags,
				      ret);
	return ret;
}

bool scoutfs_data_wait_found(struct scoutfs_data_wait *dw)
{
	return !RB_EMPTY_NODE(&dw->node);
}

int scoutfs_data_wait_check_iov(struct inode *inode, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos, u8 sef,
				u8 op, struct scoutfs_data_wait *dw,
				struct scoutfs_lock *lock)
{
	unsigned long i;
	int ret = 0;

	for (i = 0; i < nr_segs; i++) {
		if (iov[i].iov_len == 0)
			continue;

		ret = scoutfs_data_wait_check(inode, pos, iov[i].iov_len, sef,
					      op, dw, lock);
		if (ret != 0)
			break;

		pos += iov[i].iov_len;
	}

	return ret;
}

int scoutfs_data_wait(struct inode *inode, struct scoutfs_data_wait *dw)
{
	DECLARE_DATA_WAIT_ROOT(inode->i_sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	int ret;

	ret = wait_event_interruptible(wq->waitq,
					atomic64_read(&wq->changed) != dw->chg);

	spin_lock(&rt->lock);
	rb_erase(&dw->node, &rt->root);
	RB_CLEAR_NODE(&dw->node);
	spin_unlock(&rt->lock);

	return ret;
}

void scoutfs_data_wait_changed(struct inode *inode)
{
	DECLARE_DATA_WAITQ(inode, wq);

	atomic64_inc(&wq->changed);
	wake_up(&wq->waitq);
}

int scoutfs_data_waiting(struct super_block *sb, u64 ino, u64 iblock,
			 struct scoutfs_ioctl_data_waiting_entry *dwe,
			 unsigned int nr)
{
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	struct scoutfs_data_wait *dw;
	int ret = 0;

	spin_lock(&rt->lock);

	dw = next_data_wait(&rt->root, ino, iblock);
	while (dw && ret < nr) {

		dwe->ino = dw->ino;
		dwe->iblock = dw->iblock;
		dwe->op = dw->op;

		while ((dw = dw_next(dw)) &&
		       (dw->ino == dwe->ino && dw->iblock == dwe->iblock)) {
			dwe->op |= dw->op;
		}

		dwe++;
		ret++;
	}

	spin_unlock(&rt->lock);

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
	.aio_read	= scoutfs_file_aio_read,
	.aio_write	= scoutfs_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= scoutfs_file_llseek,
	.fallocate	= scoutfs_fallocate,
};

/*
 * Return extents to the server if we're over the high water mark.  Each
 * work call sends one batch of extents so that the work can be easily
 * canceled to stop progress during unmount.
 */
static void scoutfs_data_return_server_extents_worker(struct work_struct *work)
{
	struct data_info *datinf = container_of(work, struct data_info,
						return_work);
	struct super_block *sb = datinf->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_net_extent_list *nexl;
	struct scoutfs_extent ext;
	u64 nr = 0;
	u64 free;
	int bytes;
	int ret;
	int err;

	trace_scoutfs_data_return_server_extents_enter(sb, 0, 0);

	bytes = SCOUTFS_NET_EXTENT_LIST_BYTES(SCOUTFS_NET_EXTENT_LIST_MAX_NR);
	nexl = kmalloc(bytes, GFP_NOFS);
	if (!nexl) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_hold_trans(sb, SIC_RETURN_EXTENTS());
	if (ret)
		goto out;

	down_write(&datinf->alloc_rwsem);

	free = atomic64_read(&datinf->node_free_blocks);

	while (nr < SCOUTFS_NET_EXTENT_LIST_MAX_NR &&
	       free > NODE_FREE_HIGH_WATER_BLOCKS) {

		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLOCKS_TYPE,
				    sbi->node_id, 0, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext,
					  sbi->node_id_lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		trace_scoutfs_data_return_server_extent(sb, &ext);

		ext.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
		ext.len = min(ext.len, free - NODE_FREE_HIGH_WATER_BLOCKS);

		ret = scoutfs_extent_remove(sb, data_extent_io, &ext,
					    sbi->node_id_lock);
		if (ret)
			break;

		nexl->extents[nr].start = cpu_to_le64(ext.start);
		nexl->extents[nr].len = cpu_to_le64(ext.len);

		nr++;
		free -= ext.len;
	}

	nexl->nr = cpu_to_le64(nr);

	up_write(&datinf->alloc_rwsem);

	if (nr > 0) {
		err = scoutfs_client_free_extents(sb, nexl);
		/* XXX leaked extents if free failed */
		if (ret == 0 && err < 0)
			ret = err;
	}

	scoutfs_release_trans(sb);
out:
	kfree(nexl);

	trace_scoutfs_data_return_server_extents_exit(sb, nr, ret);

	/* keep returning if we're still over the water mark */
	if (ret == 0 && (atomic64_read(&datinf->node_free_blocks) >
			 NODE_FREE_HIGH_WATER_BLOCKS))
		queue_work(datinf->workq, &datinf->return_work);
}

int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	datinf->sb = sb;
	init_rwsem(&datinf->alloc_rwsem);
	atomic64_set(&datinf->node_free_blocks, 0);
	INIT_WORK(&datinf->return_work,
		  scoutfs_data_return_server_extents_worker);

	datinf->workq = alloc_workqueue("scoutfs_data", WQ_UNBOUND, 1);
	if (!datinf->workq) {
		kfree(datinf);
		return -ENOMEM;
	}

	sbi->data_info = datinf;
	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		if (datinf->workq) {
			cancel_work_sync(&datinf->return_work);
			destroy_workqueue(datinf->workq);
			datinf->workq = NULL;
		}

		sbi->data_info = NULL;
		kfree(datinf);
	}
}
