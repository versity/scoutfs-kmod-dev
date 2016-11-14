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
	bool advance = false;
	int ret = 0;
	bool have_umount;

	sbi->trans_task = current;

	wait_event(sbi->trans_hold_wq,
		   atomic_cmpxchg(&sbi->trans_holds, 0, -1) == 0);

	if (scoutfs_block_has_dirty(sb)) {
		/* XXX need writeback errors from inode address spaces? */

		/* XXX definitely don't understand this */
		have_umount = down_read_trylock(&sb->s_umount);

		sync_inodes_sb(sb);

		if (have_umount)
			up_read(&sb->s_umount);

		scoutfs_filerw_free_alloc(sb);

		ret = scoutfs_buddy_apply_pending(sb, false) ?:
		      scoutfs_block_write_dirty(sb) ?:
		      scoutfs_write_dirty_super(sb);
		if (ret) {
			scoutfs_buddy_apply_pending(sb, true);
		} else {
			scoutfs_buddy_committed(sb);
			advance = 1;
		}
	}

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

	if (!wait) {
		schedule_work(&sbi->trans_write_work);
		return 0;
	}

	spin_lock(&sbi->trans_write_lock);
	attempt.seq = le64_to_cpu(sbi->super.hdr.seq);
	attempt.count = sbi->trans_write_count;
	spin_unlock(&sbi->trans_write_lock);

	schedule_work(&sbi->trans_write_work);

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

int scoutfs_hold_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (current == sbi->trans_task)
		return 0;

	return wait_event_interruptible(sbi->trans_hold_wq,
				  atomic_add_unless(&sbi->trans_holds, 1, -1));
}

/*
 * As we release we ask the allocator how many blocks have been
 * allocated since the last transaction was successfully committed.  If
 * it's large enough we kick off a write.  This is mostly to reduce the
 * commit latency.  We also don't want to let the IO pipeline sit idle.
 * Once we have enough blocks to write efficiently we should do so.
 */
void scoutfs_release_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (current == sbi->trans_task)
		return;

	if (atomic_sub_return(1, &sbi->trans_holds) == 0) {
		if (scoutfs_buddy_alloc_count(sb) >= SCOUTFS_MAX_TRANS_BLOCKS)
			scoutfs_sync_fs(sb, 0);

		wake_up(&sbi->trans_hold_wq);
	}
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
