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

/*
 * scoutfs uses extent items to track file data block mappings and free
 * blocks.
 *
 * Block allocation maintains a fixed number of allocation cursors that
 * remember the position of tasks within free regions.  This is very
 * simple and maintains contiguous allocations for simple streaming
 * writes.  It eventually won't be good enough and we'll spend
 * complexity on delalloc but we want to put that off as long as
 * possible.
 *
 * There's no unwritten extents.  As we dirty file data pages we track
 * their inodes.  Before we commit dirty metadata we write out all
 * tracked inodes.  This ensures that data is persistent before the
 * metadata that references it is visible.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - forced unmount with dirty data
 *  - direct IO
 *  - need trans around each bulk alloc
 */

/* more than enough for a few tasks per core on moderate hardware */
#define NR_CURSORS		4096
#define CURSOR_HASH_HEADS	(PAGE_SIZE / sizeof(void *) / 2)
#define CURSOR_HASH_BITS	ilog2(CURSOR_HASH_HEADS)

struct data_info {
	struct rw_semaphore alloc_rwsem;
	struct list_head cursor_lru;
	struct hlist_head cursor_hash[CURSOR_HASH_HEADS];
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

struct task_cursor {
	u64 blkno;
	struct hlist_node hnode;
	struct list_head list_head;
	struct task_struct *task;
	pid_t pid;
};

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
 */
static int data_extent_io(struct super_block *sb, int op,
			  struct scoutfs_extent *ext, void *data)
{
	struct scoutfs_lock *lock = data;
	struct scoutfs_file_extent fex;
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
		init_free_extent_key(&last, ext->type, ext->owner,
				     U64_MAX, U64_MAX);
		kvec_init(&val, NULL, 0);
	}

	if (op == SEI_NEXT) {
		expected = val.iov_len;
		ret = scoutfs_item_next(sb, &key, &last, &val, lock);
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
	struct scoutfs_extent next;
	struct scoutfs_extent rem;
	struct scoutfs_extent fr;
	struct scoutfs_extent ofl;
	bool rem_fr = false;
	bool add_rem = false;
	s64 ret;
	int err;

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

	/* nothing to do if the extent's already offline */
	if (offline && (rem.flags & SEF_OFFLINE)) {
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

	/* remove the mapping */
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

	scoutfs_inode_add_onoff(inode, rem.map ? -rem.len : 0,
				(rem.flags & SEF_OFFLINE ? -rem.len : 0) +
				(offline ? ofl.len : 0));
	ret = 1;
out:
	if (ret < 0) {
		err = 0;
		if (add_rem)
			err |= scoutfs_extent_add(sb, data_extent_io, &rem,
						  lock);
		if (rem_fr)
			err |= scoutfs_extent_remove(sb, data_extent_io, &fr,
						     sbi->node_id_lock);
		BUG_ON(err); /* inconsistency, could save/restore */

	} else if (ret > 0) {
		ret = rem.start + rem.len;
	}

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
 * This is the low level extent item manipulation code.  We hold and
 * release the transaction so the caller doesn't have to deal with
 * partial progress.
 *
 * If the inode is provided then we update its tracking of the online
 * and offline blocks.  If it's not provided then the inode is being
 * destroyed and we don't have to keep it updated.
 */
int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	s64 ret = 0;

	WARN_ON_ONCE(inode && !mutex_is_locked(&inode->i_mutex));

	/* clamp last to the last possible block? */
	if (last > SCOUTFS_BLOCK_MAX)
		last = SCOUTFS_BLOCK_MAX;

	trace_scoutfs_data_truncate_items(sb, iblock, last, offline);

	if (WARN_ON_ONCE(last < iblock))
		return -EINVAL;

	while (iblock <= last) {
		ret = scoutfs_hold_trans(sb, SIC_TRUNC_EXTENT());
		if (ret)
			break;

		down_write(&datinf->alloc_rwsem);
		ret = truncate_one_extent(sb, inode, ino, iblock, last,
					  offline, lock);
		up_write(&datinf->alloc_rwsem);
		scoutfs_release_trans(sb);

		if (ret <= 0)
			break;

		iblock = ret;
		ret = 0;
	}

	return ret;
}

static inline struct hlist_head *cursor_head(struct data_info *datinf,
					     struct task_struct *task,
					     pid_t pid)
{
	unsigned h = hash_ptr(task, CURSOR_HASH_BITS) ^
		     hash_long(pid, CURSOR_HASH_BITS);

	return &datinf->cursor_hash[h];
}

static struct task_cursor *search_head(struct hlist_head *head,
				       struct task_struct *task, pid_t pid)
{
	struct task_cursor *curs;

	hlist_for_each_entry(curs, head, hnode) {
		if (curs->task == task && curs->pid == pid)
			return curs;
	}

	return NULL;
}

static void destroy_cursors(struct data_info *datinf)
{
	struct task_cursor *curs;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < CURSOR_HASH_HEADS; i++) {
		hlist_for_each_entry_safe(curs, tmp, &datinf->cursor_hash[i],
					  hnode) {
			hlist_del_init(&curs->hnode);
			kfree(curs);
		}
	}
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
	struct task_struct *task = current;
	pid_t pid = current->pid;
	struct hlist_head *head;
	struct task_cursor *curs;

	head = cursor_head(datinf, task, pid);
	curs = search_head(head, task, pid);
	if (!curs) {
		curs = list_last_entry(&datinf->cursor_lru,
				       struct task_cursor, list_head);
		trace_scoutfs_data_get_cursor(curs, task, pid);
		hlist_del_init(&curs->hnode);
		curs->task = task;
		curs->pid = pid;
		hlist_add_head(&curs->hnode, head);
		curs->blkno = 0;
	}

	list_move(&curs->list_head, &datinf->cursor_lru);

	return curs;
}

static int get_server_extent(struct super_block *sb, u64 len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_extent ext;
	u64 start;
	int ret;

	ret = scoutfs_client_alloc_extent(sb, len, &start);
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
 * Allocate a single block for the logical block offset in the file.
 * The caller tells us if the block was offline or not.  We modify the
 * extent items and the caller will search for the resulting extent.
 *
 * We try to encourage contiguous allocation by having per-task cursors
 * that track large extents.  Each new allocating task will get a new
 * extent.
 */
#define CURSOR_BLOCKS		(1 * 1024 * 1024 / BLOCK_SIZE)
#define CURSOR_BLOCKS_MASK	(CURSOR_BLOCKS - 1)
#define CURSOR_BLOCKS_SEARCH	(CURSOR_BLOCKS + CURSOR_BLOCKS - 1)
#define CURSOR_BLOCKS_ALLOC	(CURSOR_BLOCKS * 64)
static int find_alloc_block(struct super_block *sb, struct inode *inode,
			    u64 iblock, bool was_offline,
			    struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_DATA_INFO(sb, datinf);
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_extent ext;
	struct scoutfs_extent ofl;
	struct scoutfs_extent fr;
	struct task_cursor *curs;
	bool add_ofl = false;
	bool add_fr = false;
	int err;
	int ret;

	down_write(&datinf->alloc_rwsem);

	curs = get_cursor(datinf);

	trace_scoutfs_data_find_alloc_block_curs(sb, curs, curs->blkno);

	/* see if our cursor is still free */
	if (curs->blkno) {
		/* look for the extent that overlaps our iblock */
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
				    sbi->node_id, curs->blkno, 1, 0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext,
					  sbi->node_id_lock);
		if (ret && ret != -ENOENT)
			goto out;

		if (ret == 0)
			trace_scoutfs_data_alloc_block_cursor(sb, &ext);

		/* find a new large extent if our cursor isn't free */
		if (ret < 0 || ext.start > curs->blkno)
			curs->blkno = 0;
	}

	/* try to find a new large extent, possibly asking for more */
	if (curs->blkno == 0) {
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLOCKS_TYPE,
				    sbi->node_id, 0, CURSOR_BLOCKS_SEARCH,
				    0, 0);
		ret = scoutfs_extent_next(sb, data_extent_io, &ext,
					  sbi->node_id_lock);
		if (ret == -ENOENT) {
			/* try to get allocation from the server if we're out */
			ret = get_server_extent(sb, CURSOR_BLOCKS_ALLOC);
			if (ret == 0)
				ret = scoutfs_extent_next(sb, data_extent_io,
							  &ext,
							  sbi->node_id_lock);
		}
		if (ret) {
			/* XXX should try to look for smaller free extents :/ */
			if (ret == -ENOENT)
				ret = -ENOSPC;
			goto out;
		}

		/*
		 * set our cursor to the aligned start of a large extent
		 * We'll then remove it and the next aligned free large
		 * extent will start much later.  This stops us from
		 * constantly setting cursors to the start of a large
		 * free extent that keeps have its start allocated.
		 */
		trace_scoutfs_data_alloc_block_free(sb, &ext);
		curs->blkno = ALIGN(ext.start, CURSOR_BLOCKS);
	}

	/* remove the free block we're using */
	scoutfs_extent_init(&fr, SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
			    sbi->node_id, curs->blkno, 1, 0, 0);
	ret = scoutfs_extent_remove(sb, data_extent_io, &fr, sbi->node_id_lock);
	if (ret)
		goto out;
	add_fr = true;

	/* remove an offline file extent */
	if (was_offline) {
		scoutfs_extent_init(&ofl, SCOUTFS_FILE_EXTENT_TYPE, ino,
				    iblock, 1, 0, SEF_OFFLINE);
		ret = scoutfs_extent_remove(sb, data_extent_io, &ofl, lock);
		if (ret)
			goto out;
		add_ofl = true;
	}

	/* add (and hopefully merge!) the new allocation */
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE, ino,
			    iblock, 1, curs->blkno, 0);
	trace_scoutfs_data_alloc_block(sb, &ext);
	ret = scoutfs_extent_add(sb, data_extent_io, &ext, lock);
	if (ret)
		goto out;

	scoutfs_inode_add_onoff(inode, 1, was_offline ? -1ULL : 0);

	/* set cursor to next block, clearing if we finish a large extent */
	BUILD_BUG_ON(!is_power_of_2(CURSOR_BLOCKS));
	curs->blkno++;
	if ((curs->blkno & CURSOR_BLOCKS_MASK) == 0)
		curs->blkno = 0;

	ret = 0;
out:
	if (ret) {
		err = 0;
		if (add_ofl)
			err |= scoutfs_extent_add(sb, data_extent_io, &ofl,
						  lock);
		if (add_fr)
			err |= scoutfs_extent_add(sb, data_extent_io, &fr,
						  sbi->node_id_lock);
		BUG_ON(err); /* inconsistency */
	}

	up_write(&datinf->alloc_rwsem);

	trace_scoutfs_data_find_alloc_block_ret(sb, ret);
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_extent ext;
	struct scoutfs_lock *lock;
	u64 offset;
	int ret;

	WARN_ON_ONCE(create && !mutex_is_locked(&inode->i_mutex));

	lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!lock))
		return -EINVAL;

restart:
	/* look for the extent that overlaps our iblock */
	scoutfs_extent_init(&ext, SCOUTFS_FILE_EXTENT_TYPE,
			    scoutfs_ino(inode), iblock, 1, 0, 0);
	ret = scoutfs_extent_next(sb, data_extent_io, &ext, lock);
	if (ret && ret != -ENOENT)
		goto out;

	if (ret == 0)
		trace_scoutfs_data_get_block_next(sb, &ext);

	/* didn't find an extent or it's past our iblock */
	if (ret == -ENOENT || ext.start > iblock)
		memset(&ext, 0, sizeof(ext));

	if (ext.len)
		trace_scoutfs_data_get_block_intersection(sb, &ext);

	/* fail read and write if it's offline and we're not staging */
	if ((ext.flags & SEF_OFFLINE) && !si->staging) {
		ret = -EINVAL;
		goto out;
	}

	/* try to allocate if we're writing */
	if (create && !ext.map) {
		/*
		 * XXX can blow the transaction here.. need to back off
		 * and try again if we've already done a bulk alloc in
		 * our transaction.
		 */
		ret = find_alloc_block(sb, inode, iblock,
				       ext.flags & SEF_OFFLINE, lock);
		if (ret)
			goto out;
		set_buffer_new(bh);
		/* restart the search now that it's been allocated */
		goto restart;
	}

	/* map the bh and set the size to as much of the extent as we can */
	if (ext.map) {
		offset = iblock - ext.start;
		map_bh(bh, inode->i_sb, ext.map + offset);
		bh->b_size = min_t(u64, bh->b_size,
				   (ext.len - offset) << SCOUTFS_BLOCK_SHIFT);
	}
	ret = 0;
out:
	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				ret, bh->b_blocknr, bh->b_size);
	return ret;
}

/*
 * This is almost never used.  We can't block on a cluster lock while
 * holding the page lock because lock invalidation gets the page lock
 * while blocking locks.  If we can't use an existing lock then we drop
 * the page lock and try again.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int flags;
	int ret;

	flags = SCOUTFS_LKF_REFRESH_INODE | SCOUTFS_LKF_NONBLOCK;
	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, flags, inode, &inode_lock);
	if (ret < 0) {
		unlock_page(page);
		if (ret == -EAGAIN) {
			flags &= ~SCOUTFS_LKF_NONBLOCK;
			ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, flags, inode,
					   &inode_lock);
			if (ret == 0) {
				scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
				ret = AOP_TRUNCATED_PAGE;
			}
		}
		return ret;
	}

	ret = mpage_readpage(page, scoutfs_get_block);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
	return ret;
}

static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret)
		return ret;

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
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
	loff_t i_size;
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

	/* stop at i_size, we don't allocate outside i_size */
	i_size = i_size_read(inode);
	if (i_size == 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, 0, inode, &inode_lock);
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
		flags = (ext.flags & SEF_OFFLINE) ? FIEMAP_EXTENT_UNKNOWN : 0;

		blk_off = ext.start + ext.len;
	}

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
out:
	mutex_unlock(&inode->i_mutex);

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
};


int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct hlist_head *head;
	struct data_info *datinf;
	struct task_cursor *curs;
	int i;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	init_rwsem(&datinf->alloc_rwsem);
	INIT_LIST_HEAD(&datinf->cursor_lru);

	for (i = 0; i < CURSOR_HASH_HEADS; i++)
		INIT_HLIST_HEAD(&datinf->cursor_hash[i]);

	/* just allocate all of these up front */
	for (i = 0; i < NR_CURSORS; i++) {
		curs = kzalloc(sizeof(struct task_cursor), GFP_KERNEL);
		if (!curs) {
			destroy_cursors(datinf);
			kfree(datinf);
			return -ENOMEM;
		}

		curs->pid = i;

		head = cursor_head(datinf, curs->task, curs->pid);
		hlist_add_head(&curs->hnode, head);

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
