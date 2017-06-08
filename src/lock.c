/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>

#include "super.h"
#include "lock.h"
#include "item.h"
#include "scoutfs_trace.h"
#include "msg.h"

#include "linux/dlm.h"

/*
 * Allocated once and pointed to by the lock info of all the supers with
 * the same fsid.  Freed as the last super unmounts.
 */
struct held_locks {
	spinlock_t lock;
	struct list_head list;
	unsigned int seq_cnt;
	wait_queue_head_t waitq;
};

/*
 * allocated per-super.  Stored in the global list for finding supers
 * with fsids and stored in a list with others with the same fsid for
 * invalidation.  Freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	dlm_lockspace_t *ls;
	char ls_name[DLM_LOCKSPACE_LEN];
	bool shutdown;
	struct held_locks *held;
	struct list_head id_head;
};

#define	RANGE_LOCK_RESOURCE	"fs_range"
#define	RANGE_LOCK_RESOURCE_LEN	(strlen(RANGE_LOCK_RESOURCE))


#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

/*
 * Invalidate caches on this because another node wants a lock
 * with the a lock with the given mode and range. We always have to
 * write out dirty overlapping items.  If they're writing then we need
 * to also invalidate all cached overlapping structures.
 */
static int invalidate_caches(struct super_block *sb, int mode,
			     struct scoutfs_key_buf *start,
			     struct scoutfs_key_buf *end)
{
	int ret;

	trace_scoutfs_lock_invalidate_sb(sb, mode, start, end);

	ret = scoutfs_item_writeback(sb, start, end);
	if (ret)
		return ret;

	if (mode == SCOUTFS_LOCK_MODE_WRITE)
		ret = scoutfs_item_invalidate(sb, start, end);

	return ret;
}

static void uninit_scoutfs_lock(struct held_locks *held,
				struct scoutfs_lock *lck)
{
	spin_lock(&held->lock);
	lck->rqmode = SCOUTFS_LOCK_MODE_IV;
	list_del_init(&lck->head);
	spin_unlock(&held->lock);
	lck->sequence = 0;
}

static void init_scoutfs_lock(struct super_block *sb, struct scoutfs_lock *lck,
			      struct scoutfs_key_buf *start,
			      struct scoutfs_key_buf *end)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct held_locks *held = linfo->held;

	memset(lck, 0, sizeof(*lck));
	INIT_LIST_HEAD(&lck->head);
	lck->sb = sb;
	lck->mode = SCOUTFS_LOCK_MODE_IV;

	if (start) {
		lck->start = start;
		lck->dlm_start.val = start->data;
		lck->dlm_start.len = start->key_len;
	}
	if (end) {
		lck->end = end;
		lck->dlm_end.val = end->data;
		lck->dlm_end.len = end->key_len;
	}

	spin_lock(&held->lock);
	lck->sequence = ++held->seq_cnt;
	spin_unlock(&held->lock);
}

static void scoutfs_ast(void *astarg)
{
	struct scoutfs_lock *lck = astarg;
	DECLARE_LOCK_INFO(lck->sb, linfo);
	struct held_locks *held = linfo->held;

	trace_scoutfs_ast(lck->sb, lck);

	spin_lock(&held->lock);
	lck->mode = lck->rqmode;
	lck->rqmode = SCOUTFS_LOCK_MODE_IV;
	spin_unlock(&held->lock);

	wake_up(&held->waitq);
}

static void scoutfs_rbast(void *astarg, int mode,
			 struct dlm_key *start, struct dlm_key *end)
{

}

static int lock_granted(struct held_locks *held, struct scoutfs_lock *lck,
			int mode)
{
	int ret;

	spin_lock(&held->lock);
	ret = !!(mode == lck->mode);
	spin_unlock(&held->lock);

	return ret;
}

/*
 * Acquire a coherent lock on the given range of keys.  While the lock
 * is held other lockers are serialized.  Cache coherency is maintained
 * by the locking infrastructure.  Lock acquisition causes writeout from
 * or invalidation of other caches.
 *
 * The caller provides the opaque lock structure used for storage and
 * their start and end pointers will be accessed while the lock is held.
 */
int scoutfs_lock_range(struct super_block *sb, int mode,
		       struct scoutfs_key_buf *start,
		       struct scoutfs_key_buf *end,
		       struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct held_locks *held = linfo->held;
	int ret;

	init_scoutfs_lock(sb, lck, start, end);

	trace_scoutfs_lock_range(sb, lck);

	spin_lock(&held->lock);
	if (linfo->shutdown) {
		spin_unlock(&held->lock);
		return -ESHUTDOWN;
	}

	list_add(&lck->head, &held->list);
	spin_unlock(&held->lock);

	lck->rqmode = mode;
	ret = dlm_lock_range(linfo->ls, mode, &lck->dlm_start, &lck->dlm_end,
			     &lck->lksb, DLM_LKF_NOORDER, RANGE_LOCK_RESOURCE,
			     RANGE_LOCK_RESOURCE_LEN, 0, scoutfs_ast, lck,
			     scoutfs_rbast);
	if (ret) {
		scoutfs_err(sb, "Error %d locking %s\n", ret,
			    RANGE_LOCK_RESOURCE);
		uninit_scoutfs_lock(held, lck);
		return ret;
	}

	wait_event(held->waitq, lock_granted(held, lck, mode));

	return 0;
}

void scoutfs_unlock_range(struct super_block *sb, struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct held_locks *held = linfo->held;
	int ret;

	trace_scoutfs_unlock_range(sb, lck);

	BUG_ON(!lck->sequence);

	/*
	 * Use write mode to invalidate all since we are completely
	 * dropping the lock. Once we keep the locks around then we
	 * can invalidate based on what level we're downconverting to
	 * (PR, NL).
	 */
	invalidate_caches(sb, SCOUTFS_LOCK_MODE_WRITE, lck->start, lck->end);

	lck->rqmode = DLM_LOCK_IV;
	ret = dlm_unlock(linfo->ls, lck->lksb.sb_lkid, 0, &lck->lksb, lck);
	if (ret) {
		scoutfs_err(sb, "Error %d unlocking %s\n", ret,
			    RANGE_LOCK_RESOURCE);
		goto out;
	}

	wait_event(held->waitq, lock_granted(held, lck, DLM_LOCK_IV));
out:
	uninit_scoutfs_lock(held, lck);
	/* lock was removed from held list, wake up umount process */
	wake_up(&held->waitq);
}

/*
 * The moment this is done we can have other mounts start asking
 * us to write back and invalidate, so do this very very late.
 */
static int init_lock_info(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct held_locks *held;
	struct lock_info *linfo;

	linfo = kzalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linfo)
		return -ENOMEM;

	held = kzalloc(sizeof(struct held_locks), GFP_KERNEL);
	if (!held) {
		kfree(linfo);
		return -ENOMEM;
	}

	spin_lock_init(&held->lock);
	INIT_LIST_HEAD(&held->list);
	init_waitqueue_head(&held->waitq);

	linfo->sb = sb;
	linfo->shutdown = false;
	linfo->held = held;
	INIT_LIST_HEAD(&linfo->id_head);
	linfo->ls = NULL;

	snprintf(linfo->ls_name, DLM_LOCKSPACE_LEN, "%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	sbi->lock_info = linfo;

	trace_printk("sb %p id %016llx allocated linfo %p held %p\n",
		     sb, le64_to_cpu(sbi->super.id), linfo, held);

	return 0;
}

static int can_complete_shutdown(struct held_locks *held)
{
	int ret;

	spin_lock(&held->lock);
	ret = !!list_empty(&held->list);
	spin_unlock(&held->lock);
	return ret;
}

/*
 * Cause all lock attempts from our super to fail, waking anyone who is
 * currently blocked attempting to lock.  Now that locks can't block we
 * can easily tear down subsystems that use locking before freeing lock
 * infrastructure.
 */
void scoutfs_lock_shutdown(struct super_block *sb)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct held_locks *held = linfo->held;

	if (linfo) {
		held = linfo->held;
		spin_lock(&held->lock);
		linfo->shutdown = true;
		spin_unlock(&held->lock);

		wake_up(&held->waitq);
	}
}

void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);
	struct held_locks *held;
	int ret;

	if (linfo) {
		held = linfo->held;
		wait_event(held->waitq, can_complete_shutdown(held));

		ret = dlm_release_lockspace(linfo->ls, 2);
		if (ret)
			scoutfs_info(sb, "Error %d releasing lockspace %s\n",
				     ret, linfo->ls_name);

		sbi->lock_info = NULL;

		trace_printk("sb %p id %016llx freeing linfo %p held %p\n",
			     sb, le64_to_cpu(sbi->super.id), linfo, held);

		kfree(held);
		kfree(linfo);
	}
}

int scoutfs_lock_setup(struct super_block *sb)
{
	struct lock_info *linfo;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	ret = init_lock_info(sb);
	if (ret)
		return ret;

	linfo = sbi->lock_info;
	/*
	 * Open coded '64' here is for lvb_len. We never use the LVB
	 * flag so this doesn't matter, but the dlm needs a non-zero
	 * multiple of 8
	 */
	ret = dlm_new_lockspace(linfo->ls_name, sbi->opts.cluster_name,
				DLM_LSFL_FS|DLM_LSFL_NEWEXCL, 64, NULL,
				NULL, NULL, &linfo->ls);
	if (ret)
		scoutfs_lock_destroy(sb);

	return ret;
}
