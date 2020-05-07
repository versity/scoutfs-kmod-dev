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
#include <linux/slab.h>

#include "super.h"
#include "trans.h"
#include "data.h"
#include "forest.h"
#include "counters.h"
#include "client.h"
#include "inode.h"
#include "radix.h"
#include "block.h"
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

/* sync dirty data at least this often */
#define TRANS_SYNC_DELAY (HZ * 10)

/*
 * XXX move the rest of the super trans_ fields here.
 */
struct trans_info {
	spinlock_t lock;
	unsigned reserved_items;
	unsigned reserved_vals;
	unsigned holders;
	bool writing;

	struct scoutfs_log_trees lt;
	struct scoutfs_radix_allocator alloc;
	struct scoutfs_block_writer wri;
};

#define DECLARE_TRANS_INFO(sb, name) \
	struct trans_info *name = SCOUTFS_SB(sb)->trans_info

static bool drained_holders(struct trans_info *tri)
{
	bool drained;

	spin_lock(&tri->lock);
	tri->writing = true;
	drained = tri->holders == 0;
	spin_unlock(&tri->lock);

	return drained;
}

static int commit_btrees(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);
	struct scoutfs_log_trees lt;

	lt = tri->lt;
	lt.meta_avail = tri->alloc.avail;
	lt.meta_freed = tri->alloc.freed;
	scoutfs_forest_get_btrees(sb, &lt);
	scoutfs_data_get_btrees(sb, &lt);

	return scoutfs_client_commit_log_trees(sb, &lt);
}

/*
 * This gets all the resources from the server that the client will
 * need during the transaction.
 */
int scoutfs_trans_get_log_trees(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);
	struct scoutfs_log_trees lt;
	int ret = 0;

	ret = scoutfs_client_get_log_trees(sb, &lt);
	if (ret == 0) {
		tri->lt = lt;
		scoutfs_radix_init_alloc(&tri->alloc, &lt.meta_avail,
					 &lt.meta_freed);
		scoutfs_block_writer_init(sb, &tri->wri);

		scoutfs_forest_init_btrees(sb, &tri->alloc, &tri->wri, &lt);
		scoutfs_data_init_btrees(sb, &tri->alloc, &tri->wri, &lt);
	}
	return ret;
}

bool scoutfs_trans_has_dirty(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);

	return scoutfs_block_writer_has_dirty(sb, &tri->wri);
}
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
						   trans_write_work.work);
	struct super_block *sb = sbi->sb;
	DECLARE_TRANS_INFO(sb, tri);
	int ret = 0;

	sbi->trans_task = current;

	wait_event(sbi->trans_hold_wq, drained_holders(tri));

	trace_scoutfs_trans_write_func(sb,
			scoutfs_block_writer_dirty_bytes(sb, &tri->wri));

	if (scoutfs_block_writer_has_dirty(sb, &tri->wri)) {
		if (sbi->trans_deadline_expired)
			scoutfs_inc_counter(sb, trans_commit_timer);

		scoutfs_inc_counter(sb, trans_commit_written);

		ret = scoutfs_inode_walk_writeback(sb, true) ?:
		      scoutfs_block_writer_write(sb, &tri->wri) ?:
		      scoutfs_inode_walk_writeback(sb, false) ?:
		      commit_btrees(sb) ?:
		      scoutfs_client_advance_seq(sb, &sbi->trans_seq) ?:
		      scoutfs_trans_get_log_trees(sb);
		if (ret)
			goto out;

	} else if (sbi->trans_deadline_expired) {
		/*
		 * If we're not writing data then we only advance the
		 * seq at the sync deadline interval.  This keeps idle
		 * mounts from pinning a seq and stopping readers of the
		 * seq indices but doesn't send a message for every sync
		 * syscall.
		 */
		ret = scoutfs_client_advance_seq(sb, &sbi->trans_seq);
	}

out:
	/* XXX this all needs serious work for dealing with errors */
	WARN_ON_ONCE(ret);

	spin_lock(&sbi->trans_write_lock);
	sbi->trans_write_count++;
	sbi->trans_write_ret = ret;
	spin_unlock(&sbi->trans_write_lock);
	wake_up(&sbi->trans_write_wq);

	spin_lock(&tri->lock);
	tri->writing = false;
	spin_unlock(&tri->lock);

	wake_up(&sbi->trans_hold_wq);

	sbi->trans_task = NULL;

	scoutfs_trans_restart_sync_deadline(sb);
}

struct write_attempt {
	u64 count;
	int ret;
};

/* this is called as a wait_event() condition so it can't change task state */
static int write_attempted(struct scoutfs_sb_info *sbi,
			   struct write_attempt *attempt)
{
	int done = 1;

	spin_lock(&sbi->trans_write_lock);
	if (sbi->trans_write_count > attempt->count)
		attempt->ret = sbi->trans_write_ret;
	else
		done = 0;
	spin_unlock(&sbi->trans_write_lock);

	return done;
}


/*
 * We always have delayed sync work pending but the caller wants it
 * to execute immediately.
 */
static void queue_trans_work(struct scoutfs_sb_info *sbi)
{
	sbi->trans_deadline_expired = false;
	mod_delayed_work(sbi->trans_write_workq, &sbi->trans_write_work, 0);
}

/*
 * Wait for a trans commit to finish and return its error code.  There
 * can already be one in flight that we end up waiting for the
 * completion of.  This is safe because dirtying and trans commits are
 * serialized.  There's no way that there could have been dirty data
 * before the caller got here that wouldn't be covered by a commit
 * that's in flight. 
 */
int scoutfs_trans_sync(struct super_block *sb, int wait)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct write_attempt attempt;
	int ret;


	if (!wait) {
		queue_trans_work(sbi);
		return 0;
	}

	spin_lock(&sbi->trans_write_lock);
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
	struct super_block *sb = file_inode(file)->i_sb;

	scoutfs_inc_counter(sb, trans_commit_fsync);
	return scoutfs_trans_sync(sb, 1);
}

void scoutfs_trans_restart_sync_deadline(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	sbi->trans_deadline_expired = true;
	mod_delayed_work(sbi->trans_write_workq, &sbi->trans_write_work,
			 TRANS_SYNC_DELAY);
}

/*
 * Each thread reserves space in the segment for their dirty items while
 * they hold the transaction.  This is calculated before the first
 * transaction hold is acquired.  It includes all the potential nested
 * item manipulation that could happen with the transaction held.
 * Including nested holds avoids having to deal with writing out partial
 * transactions while a caller still holds the transaction.
 */
#define SCOUTFS_RESERVATION_MAGIC 0xd57cd13b
struct scoutfs_reservation {
	unsigned magic;
	unsigned holders;
	struct scoutfs_item_count reserved;
	struct scoutfs_item_count actual;
};

/*
 * Try to hold the transaction.  If a caller already holds the trans then
 * we piggy back on their hold.  We wait if the writer is trying to
 * write out the transation.  And if our items won't fit then we kick off
 * a write.
 *
 * This is called as a condition for wait_event.  It is very limited in
 * the locking (blocking) it can do because the caller has set the task
 * state before testing the condition safely race with waking after
 * setting the condition.  Our checking the amount of dirty metadata
 * blocks and free data blocks is racy, but we don't mind the risk of
 * delaying or prematurely forcing commits.
 */
static bool acquired_hold(struct super_block *sb,
			  struct scoutfs_reservation *rsv,
			  const struct scoutfs_item_count *cnt)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);
	bool acquired = false;
	unsigned items;
	unsigned vals;

	spin_lock(&tri->lock);

	trace_scoutfs_trans_acquired_hold(sb, cnt, rsv, rsv->holders,
					  &rsv->reserved, &rsv->actual,
					  tri->holders, tri->writing,
					  tri->reserved_items,
					  tri->reserved_vals);

	/* use a caller's existing reservation */
	if (rsv->holders)
		goto hold;

	/* wait until the writing thread is finished */
	if (tri->writing)
		goto out;

	/* see if we can reserve space for our item count */
	items = tri->reserved_items + cnt->items;
	vals = tri->reserved_vals + cnt->vals;

	/* XXX arbitrarily limit to 8 meg transactions */
	if (scoutfs_block_writer_dirty_bytes(sb, &tri->wri) >=
			(8 * 1024 * 1024)) {
		scoutfs_inc_counter(sb, trans_commit_full);
		queue_trans_work(sbi);
		goto out;
	}

	/* Try to refill data allocator before premature enospc */
	if (scoutfs_data_alloc_free_bytes(sb) <= SCOUTFS_TRANS_DATA_ALLOC_LWM) {
		scoutfs_inc_counter(sb, trans_commit_data_alloc_low);
		queue_trans_work(sbi);
		goto out;
	}

	tri->reserved_items = items;
	tri->reserved_vals = vals;

	rsv->reserved.items = cnt->items;
	rsv->reserved.vals = cnt->vals;

hold:
	rsv->holders++;
	tri->holders++;
	acquired = true;

out:

	spin_unlock(&tri->lock);

	return acquired;
}

int scoutfs_hold_trans(struct super_block *sb,
		       const struct scoutfs_item_count cnt)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_reservation *rsv;
	int ret;

	/*
	 * Caller shouldn't provide garbage counts, nor counts that
	 * can't fit in segments by themselves.
	 */
	if (WARN_ON_ONCE(cnt.items <= 0 || cnt.vals < 0))
		return -EINVAL;

	if (current == sbi->trans_task)
		return 0;

	rsv = current->journal_info;
	if (rsv == NULL) {
		rsv = kzalloc(sizeof(struct scoutfs_reservation), GFP_NOFS);
		if (!rsv)
			return -ENOMEM;

		rsv->magic = SCOUTFS_RESERVATION_MAGIC;
		current->journal_info = rsv;
	}

	BUG_ON(rsv->magic != SCOUTFS_RESERVATION_MAGIC);

	ret = wait_event_interruptible(sbi->trans_hold_wq,
				       acquired_hold(sb, rsv, &cnt));
	if (ret && rsv->holders == 0) {
		current->journal_info = NULL;
		kfree(rsv);
	}
	return ret;
}

/*
 * Return true if the current task has a transaction held.  That is,
 * true if the current transaction can't finish and be written out if
 * the current task blocks.
 */
bool scoutfs_trans_held(void)
{
	struct scoutfs_reservation *rsv = current->journal_info;

	return rsv && rsv->magic == SCOUTFS_RESERVATION_MAGIC;
}

/*
 * Record a transaction holder's individual contribution to the dirty
 * items in the current transaction.  We're making sure that the
 * reservation matches the possible item manipulations while they hold
 * the reservation.
 *
 * It is possible and legitimate for an individual contribution to be
 * negative if they delete dirty items.  The item cache makes sure that
 * the total dirty item count doesn't fall below zero.
 */
void scoutfs_trans_track_item(struct super_block *sb, signed items,
			      signed vals)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_reservation *rsv = current->journal_info;

	if (current == sbi->trans_task)
		return;

	BUG_ON(!rsv || rsv->magic != SCOUTFS_RESERVATION_MAGIC);

	rsv->actual.items += items;
	rsv->actual.vals += vals;

	trace_scoutfs_trans_track_item(sb, items, vals, rsv->actual.items,
				       rsv->actual.vals, rsv->reserved.items,
				       rsv->reserved.vals);

	WARN_ON_ONCE(rsv->actual.items > rsv->reserved.items);
	WARN_ON_ONCE(rsv->actual.vals > rsv->reserved.vals);
}

/*
 * As we drop the last hold in the reservation we try and wake other
 * hold attempts that were waiting for space.  As we drop the last trans
 * holder we try to wake a writing thread that was waiting for us to
 * finish.
 */
void scoutfs_release_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_reservation *rsv;
	DECLARE_TRANS_INFO(sb, tri);
	bool wake = false;

	if (current == sbi->trans_task)
		return;

	rsv = current->journal_info;
	BUG_ON(!rsv || rsv->magic != SCOUTFS_RESERVATION_MAGIC);

	spin_lock(&tri->lock);

	trace_scoutfs_release_trans(sb, rsv, rsv->holders, &rsv->reserved,
				    &rsv->actual, tri->holders, tri->writing,
				    tri->reserved_items, tri->reserved_vals);

	BUG_ON(rsv->holders <= 0);
	BUG_ON(tri->holders <= 0);

	if (--rsv->holders == 0) {
		tri->reserved_items -= rsv->reserved.items;
		tri->reserved_vals -= rsv->reserved.vals;
		current->journal_info = NULL;
		kfree(rsv);
		wake = true;
	}

	if (--tri->holders == 0)
		wake = true;

	spin_unlock(&tri->lock);

	if (wake)
		wake_up(&sbi->trans_hold_wq);
}

int scoutfs_setup_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct trans_info *tri;

	tri = kzalloc(sizeof(struct trans_info), GFP_KERNEL);
	if (!tri)
		return -ENOMEM;

	spin_lock_init(&tri->lock);
	scoutfs_block_writer_init(sb, &tri->wri);

	sbi->trans_write_workq = alloc_workqueue("scoutfs_trans",
						 WQ_UNBOUND, 1);
	if (!sbi->trans_write_workq) {
		kfree(tri);
		return -ENOMEM;
	}

	sbi->trans_info = tri;

	return 0;
}

/*
 * kill_sb calls sync before getting here so we know that dirty data
 * should be in flight.  We just have to wait for it to quiesce.
 */
void scoutfs_shutdown_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);

	if (tri) {
		scoutfs_block_writer_forget_all(sb, &tri->wri);
		if (sbi->trans_write_workq) {
			cancel_delayed_work_sync(&sbi->trans_write_work);
			destroy_workqueue(sbi->trans_write_workq);
			/* trans work schedules after shutdown see null */
			sbi->trans_write_workq = NULL;
		}
		kfree(tri);
		sbi->trans_info = NULL;
	}
}
