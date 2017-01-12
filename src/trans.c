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
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/writeback.h>

#include "super.h"
#include "block.h"
#include "trans.h"
#include "buddy.h"
#include "filerw.h"
#include "bio.h"
#include "item.h"
#include "manifest.h"
#include "seg.h"
#include "alloc.h"
#include "treap.h"
#include "compact.h"
#include "scoutfs_trace.h"

/*
 * scoutfs blocks are written in atomic transactions.
 *
 * Writers hold transactions to dirty blocks.  The transaction can't be
 * written until these active writers release the transaction.  We don't
 * track the relationships between dirty blocks so there's only ever one
 * transaction being built.
 *
 * The copy of the on-disk super block in the fs sb info has its header
 * sequence advanced so that new dirty blocks inherit this dirty
 * sequence number.  It's only advanced once all those dirty blocks are
 * reachable after having first written them all out and then the new
 * super with that seq.  It's first incremented at mount.
 *
 * Unfortunately writers can nest.  We don't bother trying to special
 * case holding a transaction that you're already holding because that
 * requires per-task storage.  We just let anyone hold transactions
 * regardless of waiters waiting to write, which risks waiters waiting a
 * very long time.
 */

/*
 * This work func is responsible for writing out all the dirty blocks
 * that make up the current dirty transaction.  It prevents writers from
 * holding a transaction so it doesn't have to worry about blocks being
 * dirtied while it is working.
 *
 * In the course of doing its work this task might need to use write
 * functions that would try to hold the transaction.  We record the task
 * whose committing the transaction so that holding won't deadlock.
 *
 * Any dirty block had to have allocated a new blkno which would have
 * created dirty allocator metadata blocks.  We can avoid writing
 * entirely if we don't have any dirty metadata blocks.  This is
 * important because we don't try to serialize this work during
 * unmount.. we can execute as the vfs is shutting down.. we need to
 * decide that nothing is dirty without calling the vfs at all.
 *
 * We first try to sync the dirty inodes and write their dirty data blocks,
 * then we write all our dirty metadata blocks, and only when those succeed
 * do we write the new super that references all of these newly written blocks.
 *
 * If there are write errors then blocks are kept dirty in memory and will
 * be written again at the next sync.
 */
void scoutfs_trans_write_func(struct work_struct *work)
{
	struct scoutfs_sb_info *sbi = container_of(work, struct scoutfs_sb_info,
						   trans_write_work);
	struct super_block *sb = sbi->sb;
	struct scoutfs_bio_completion comp;
	struct scoutfs_segment *seg;
	bool advance = false;
	int ret = 0;

	scoutfs_bio_init_comp(&comp);
	sbi->trans_task = current;

	wait_event(sbi->trans_hold_wq,
		   atomic_cmpxchg(&sbi->trans_holds, 0, -1) == 0);

	/* XXX file data needs to be updated to the new item api */
#if 0
	scoutfs_filerw_free_alloc(sb);
#endif

	trace_printk("dirty bytes %ld manifest dirty %d alloc dirty %d\n",
		     scoutfs_item_dirty_bytes(sb),
		     scoutfs_manifest_has_dirty(sb),
		     scoutfs_alloc_has_dirty(sb));

	/*
	 * XXX this needs serious work to handle errors.
	 */
	while (scoutfs_item_dirty_bytes(sb)) {
		seg = NULL;
		ret = scoutfs_seg_alloc(sb, &seg) ?:
		      scoutfs_item_dirty_seg(sb, seg) ?:
		      scoutfs_manifest_lock(sb) ?:
		      scoutfs_seg_manifest_add(sb, seg, 0) ?:
		      scoutfs_manifest_unlock(sb) ?:
		      scoutfs_seg_submit_write(sb, seg, &comp);
		scoutfs_seg_put(seg);
		if (ret)
			goto out;
	}

	if (scoutfs_manifest_has_dirty(sb) || scoutfs_alloc_has_dirty(sb)) {
		ret = scoutfs_manifest_dirty_ring(sb) ?:
		      scoutfs_alloc_dirty_ring(sb) ?:
		      scoutfs_treap_submit_write(sb, &comp) ?:
		      scoutfs_bio_wait_comp(sb, &comp) ?:
		      scoutfs_write_dirty_super(sb);
		if (ret)
			goto out;

		advance = true;
	}

out:
	/* XXX this all needs serious work for dealing with errors */
	WARN_ON_ONCE(ret);

	spin_lock(&sbi->trans_write_lock);
	if (advance)
		scoutfs_advance_dirty_super(sb);
	sbi->trans_write_count++;
	sbi->trans_write_ret = ret;
	spin_unlock(&sbi->trans_write_lock);
	wake_up(&sbi->trans_write_wq);

	atomic_set(&sbi->trans_holds, 0);
	wake_up(&sbi->trans_hold_wq);

	sbi->trans_task = NULL;
}

struct write_attempt {
	u64 seq;
	u64 count;
	int ret;
};

/* this is called as a wait_event() condition so it can't change task state */
static int write_attempted(struct scoutfs_sb_info *sbi,
			   struct write_attempt *attempt)
{
	int done = 1;

	spin_lock(&sbi->trans_write_lock);
	if (le64_to_cpu(sbi->super.hdr.seq) > attempt->seq)
		attempt->ret = 0;
	else if (sbi->trans_write_count > attempt->count)
		attempt->ret = sbi->trans_write_ret;
	else
		done = 0;
	spin_unlock(&sbi->trans_write_lock);

	return done;
}

static void queue_trans_work(struct scoutfs_sb_info *sbi)
{
	queue_work(sbi->trans_write_workq, &sbi->trans_write_work);
}

/*
 * sync records the current dirty seq and write count and waits for
 * either to change.  If there's nothing to write or the write returned
 * an error then only the write count advances and sets the appropriate
 * return code.
 */
int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct write_attempt attempt;
	int ret;

	trace_printk("wait %d\n", wait);

	if (!wait) {
		queue_trans_work(sbi);
		return 0;
	}

	spin_lock(&sbi->trans_write_lock);
	attempt.seq = le64_to_cpu(sbi->super.hdr.seq);
	attempt.count = sbi->trans_write_count;
	spin_unlock(&sbi->trans_write_lock);

	queue_trans_work(sbi);

	ret = wait_event_interruptible(sbi->trans_write_wq,
				       write_attempted(sbi, &attempt));
	if (ret == 0)
		ret = attempt.ret;

	return ret;
}

int scoutfs_file_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	return scoutfs_sync_fs(file->f_inode->i_sb, 1);
}

/*
 * I think the holder that creates the most dirty item data is
 * symlinking, which can create all the entry items and a symlink target
 * item with a full 4k path.  We go a little nuts and just set it to two
 * blocks.
 *
 * XXX This divides the segment size to set the hard limit on the number of
 * concurrent holders so we'll want this to be more precise.
 */
#define MOST_DIRTY (2 * SCOUTFS_BLOCK_SIZE)

/*
 * We're able to hold the transaction if the current dirty item bytes
 * and the presumed worst case item dirtying of all the holders,
 * including us, all fit in a segment.
 */
static bool hold_acquired(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	long bytes;
	int with_us;
	int holds;
	int before;

	holds = atomic_read(&sbi->trans_holds);
	for (;;) {
		/* transaction is being committed */
		if (holds < 0)
			return false;

		/* only hold when there's no level 0 segments, XXX for now */
		if (scoutfs_manifest_level_count(sb, 0) > 0) {
			scoutfs_compact_kick(sb);
			return false;
		}

		/* see if we all would fill the segment */
		with_us = holds + 1;
		bytes = (with_us * MOST_DIRTY) + scoutfs_item_dirty_bytes(sb);
		if (bytes > SCOUTFS_SEGMENT_SIZE) {
			scoutfs_sync_fs(sb, 0);
			return false;
		}

		before = atomic_cmpxchg(&sbi->trans_holds, holds, with_us);
		if (before == holds)
			return true;
		holds = before;
	}
}

int scoutfs_hold_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (current == sbi->trans_task)
		return 0;

	return wait_event_interruptible(sbi->trans_hold_wq, hold_acquired(sb));
}

/*
 * As we release we'll almost certainly have dirtied less than the
 * worst case dirty assumption that holders might be throttled waiting
 * for.  We always try and wake blocked holders in case they now have
 * room to dirty.
 */
void scoutfs_release_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (current == sbi->trans_task)
		return;

	atomic_dec(&sbi->trans_holds);
	wake_up(&sbi->trans_hold_wq);
}

/*
 * This is called to wake people waiting on holders when the conditions
 * that they're waiting on change: levels being full, dirty count falling
 * under a segment, or holders falling to 0.
 */
void scoutfs_trans_wake_holders(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	wake_up(&sbi->trans_hold_wq);
}

int scoutfs_setup_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	sbi->trans_write_workq = alloc_workqueue("scoutfs_trans", 0, 1);
	if (!sbi->trans_write_workq)
		return -ENOMEM;

	return 0;
}

/*
 * kill_sb calls sync before getting here so we know that dirty data
 * should be in flight.  We just have to wait for it to quiesce.
 */
void scoutfs_shutdown_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (sbi->trans_write_workq) {
		flush_work(&sbi->trans_write_work);
		destroy_workqueue(sbi->trans_write_workq);
	}
}
