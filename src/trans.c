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

#include "super.h"
#include "block.h"
#include "trans.h"
#include "buddy.h"
#include "scoutfs_trace.h"

/*
 * scoutfs metadata blocks are written in atomic transactions.
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
 * It's critical that this not try to perform IO if there's nothing
 * dirty.  The sync at unmount can have this work scheduled after sync
 * returns and the unmount path starts to tear down supers and block
 * devices.  We have to safely detect that there's nothing to do using
 * nothing in the vfs.
 */
void scoutfs_trans_write_func(struct work_struct *work)
{
	struct scoutfs_sb_info *sbi = container_of(work, struct scoutfs_sb_info,
						   trans_write_work);
	struct super_block *sb = sbi->sb;
	bool advance = false;
	int ret = 0;

	wait_event(sbi->trans_hold_wq,
		   atomic_cmpxchg(&sbi->trans_holds, 0, -1) == 0);

	/* XXX probably want to write out dirty pages in inodes */

	if (scoutfs_has_dirty_blocks(sb)) {
		ret = scoutfs_dirty_buddy_chunks(sb) ?:
		      scoutfs_write_dirty_blocks(sb) ?:
		      scoutfs_write_dirty_super(sb);
		if (!ret)
			advance = 1;
	}


	spin_lock(&sbi->trans_write_lock);
	if (advance) {
		scoutfs_advance_dirty_super(sb);
		scoutfs_reset_buddy_chunks(sb);
	}
	sbi->trans_write_count++;
	sbi->trans_write_ret = ret;
	spin_unlock(&sbi->trans_write_lock);
	wake_up(&sbi->trans_write_wq);

	atomic_set(&sbi->trans_holds, 0);
	wake_up(&sbi->trans_hold_wq);
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

int scoutfs_hold_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return wait_event_interruptible(sbi->trans_hold_wq,
				  atomic_add_unless(&sbi->trans_holds, 1, -1));
}

void scoutfs_release_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (atomic_sub_return(1, &sbi->trans_holds) == 0)
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
