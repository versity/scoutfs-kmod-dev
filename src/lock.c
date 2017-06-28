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

#include "../dlm/interval_tree_generic.h"

#include "linux/dlm.h"

/*
 * allocated per-super, freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	dlm_lockspace_t *ls;
	char ls_name[DLM_LOCKSPACE_LEN];
	bool shutdown;
	struct list_head id_head;

	spinlock_t lock;
	unsigned int seq_cnt;
	wait_queue_head_t waitq;
	struct rb_root lock_tree;
	struct workqueue_struct *downconvert_wq;
	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long long lru_nr;
};

#define	RANGE_LOCK_RESOURCE	"fs_range"
#define	RANGE_LOCK_RESOURCE_LEN	(strlen(RANGE_LOCK_RESOURCE))

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

static void scoutfs_downconvert_func(struct work_struct *work);

#define START(lck) ((lck)->start)
#define LAST(lck)  ((lck)->end)
KEYED_INTERVAL_TREE_DEFINE(struct scoutfs_lock, interval_node,
			   struct scoutfs_key_buf *, subtree_last, START, LAST,
			   scoutfs_key_compare, static, scoutfs_lock);


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

static void free_scoutfs_lock(struct scoutfs_lock *lck)
{
	kfree(lck->start);
	kfree(lck->end);
	kfree(lck);
}

static void put_scoutfs_lock(struct super_block *sb, struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	unsigned int refs;

	if (lck) {
		spin_lock(&linfo->lock);
		BUG_ON(!lck->refcnt);
		refs = --lck->refcnt;
		if (!refs) {
			BUG_ON(lck->holders);
			BUG_ON(delayed_work_pending(&lck->dc_work));
			scoutfs_lock_remove(lck, &linfo->lock_tree);
			list_del(&lck->lru_entry);
			spin_unlock(&linfo->lock);
			free_scoutfs_lock(lck);
			return;
		}
		spin_unlock(&linfo->lock);
	}
}

static void init_scoutfs_lock(struct super_block *sb, struct scoutfs_lock *lck,
			      struct scoutfs_key_buf *start,
			      struct scoutfs_key_buf *end)
{
	DECLARE_LOCK_INFO(sb, linfo);

	RB_CLEAR_NODE(&lck->interval_node);
	lck->sb = sb;
	lck->mode = SCOUTFS_LOCK_MODE_IV;
	INIT_DELAYED_WORK(&lck->dc_work, scoutfs_downconvert_func);
	INIT_LIST_HEAD(&lck->lru_entry);

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

	spin_lock(&linfo->lock);
	lck->sequence = ++linfo->seq_cnt;
	spin_unlock(&linfo->lock);
}

static struct scoutfs_lock *alloc_scoutfs_lock(struct super_block *sb,
					       struct scoutfs_key_buf *start,
					       struct scoutfs_key_buf *end)

{
	struct scoutfs_key_buf *s, *e;
	struct scoutfs_lock *lck;

	s = scoutfs_key_dup(sb, start);
	if (!s)
		return NULL;
	e = scoutfs_key_dup(sb, end);
	if (!e) {
		kfree(s);
		return NULL;
	}
	lck = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (!lck) {
		kfree(e);
		kfree(s);
	}

	init_scoutfs_lock(sb, lck, s, e);
	return lck;
}

static struct scoutfs_lock *find_alloc_scoutfs_lock(struct super_block *sb,
						struct scoutfs_key_buf *start,
						struct scoutfs_key_buf *end)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *found, *new;

	new = NULL;
	spin_lock(&linfo->lock);
search:
	found = scoutfs_lock_iter_first(&linfo->lock_tree, start, end);
	if (!found) {
		if (!new) {
			spin_unlock(&linfo->lock);
			new = alloc_scoutfs_lock(sb, start, end);
			if (!new)
				return NULL;

			spin_lock(&linfo->lock);
			goto search;
		}
		new->refcnt = 1; /* Freed by shrinker or on umount */
		scoutfs_lock_insert(new, &linfo->lock_tree);
		found = new;
		new = NULL;
	}
	found->refcnt++;
	if (!list_empty(&found->lru_entry)) {
		list_del_init(&found->lru_entry);
		linfo->lru_nr--;
	}
	spin_unlock(&linfo->lock);

	kfree(new);
	return found;
}

static int shrink_lock_tree(struct shrinker *shrink, struct shrink_control *sc)
{
	struct lock_info *linfo = container_of(shrink, struct lock_info,
					       shrinker);
	struct scoutfs_lock *lck;
	struct scoutfs_lock *tmp;
	unsigned long flags;
	unsigned long nr;
	LIST_HEAD(list);

	nr = sc->nr_to_scan;
	if (!nr)
		goto out;

	spin_lock_irqsave(&linfo->lock, flags);
	list_for_each_entry_safe(lck, tmp, &linfo->lru_list, lru_entry) {
		if (nr-- == 0)
			break;

		WARN_ON(lck->holders);
		WARN_ON(lck->refcnt != 1);
		WARN_ON(lck->flags & SCOUTFS_LOCK_QUEUED);

		scoutfs_lock_remove(lck, &linfo->lock_tree);
		list_del(&lck->lru_entry);
		list_add_tail(&lck->lru_entry, &list);
		linfo->lru_nr--;
	}
	spin_unlock_irqrestore(&linfo->lock, flags);

	list_for_each_entry_safe(lck, tmp, &list, lru_entry) {
		trace_shrink_lock_tree(linfo->sb, lck);
		list_del(&lck->lru_entry);
		free_scoutfs_lock(lck);
	}
out:
	return min_t(unsigned long, linfo->lru_nr, INT_MAX);
}

static void free_lock_tree(struct super_block *sb)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct rb_node *node = rb_first(&linfo->lock_tree);

	while (node) {
		struct scoutfs_lock *lck;

		lck = rb_entry(node, struct scoutfs_lock, interval_node);
		node = rb_next(node);
		put_scoutfs_lock(sb, lck);
	}
}

static void scoutfs_ast(void *astarg)
{
	struct scoutfs_lock *lck = astarg;
	DECLARE_LOCK_INFO(lck->sb, linfo);

	trace_scoutfs_ast(lck->sb, lck);

	spin_lock(&linfo->lock);
	lck->mode = lck->rqmode;
	/* Clear blocking flag when we are granted an unlock request */
	if (lck->rqmode == DLM_LOCK_IV)
		lck->flags &= ~SCOUTFS_LOCK_BLOCKING;
	lck->rqmode = DLM_LOCK_IV;
	spin_unlock(&linfo->lock);

	wake_up(&linfo->waitq);
}

static void queue_blocking_work(struct lock_info *linfo,
				struct scoutfs_lock *lck, unsigned int seconds)
{
	assert_spin_locked(&linfo->lock);
	if (!(lck->flags & SCOUTFS_LOCK_QUEUED)) {
		/* Take a ref for the workqueue */
		lck->flags |= SCOUTFS_LOCK_QUEUED;
		lck->refcnt++;
	}
	mod_delayed_work(linfo->downconvert_wq, &lck->dc_work, seconds * HZ);
}

static void set_lock_blocking(struct lock_info *linfo, struct scoutfs_lock *lck,
			      unsigned int seconds)
{
	assert_spin_locked(&linfo->lock);
	lck->flags |= SCOUTFS_LOCK_BLOCKING;
	if (lck->holders == 0)
		queue_blocking_work(linfo, lck, seconds);
}

static void scoutfs_rbast(void *astarg, int mode,
			 struct dlm_key *start, struct dlm_key *end)
{
	struct scoutfs_lock *lck = astarg;
	struct lock_info *linfo = SCOUTFS_SB(lck->sb)->lock_info;

	trace_scoutfs_rbast(lck->sb, lck);

	spin_lock(&linfo->lock);
	set_lock_blocking(linfo, lck, 0);
	spin_unlock(&linfo->lock);
}

static int lock_granted(struct lock_info *linfo, struct scoutfs_lock *lck,
			int mode)
{
	int ret;

	spin_lock(&linfo->lock);
	ret = !!(mode == lck->mode);
	spin_unlock(&linfo->lock);

	return ret;
}

static int lock_blocking(struct lock_info *linfo, struct scoutfs_lock *lck)
{
	int ret;

	spin_lock(&linfo->lock);
	ret = !!(lck->flags & SCOUTFS_LOCK_BLOCKING);
	spin_unlock(&linfo->lock);

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
		       struct scoutfs_lock **ret_lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lck;
	int ret;

	lck = find_alloc_scoutfs_lock(sb, start, end);
	if (!lck)
		return -ENOMEM;

	trace_scoutfs_lock_range(sb, lck);

check_lock_state:
	spin_lock(&linfo->lock);
	if (linfo->shutdown) {
		spin_unlock(&linfo->lock);
		put_scoutfs_lock(sb, lck);
		return -ESHUTDOWN;
	}

	if (lck->flags & SCOUTFS_LOCK_BLOCKING) {
		spin_unlock(&linfo->lock);
		wait_event(linfo->waitq, !lock_blocking(linfo, lck));
		goto check_lock_state;
	}

	if (lck->mode > DLM_LOCK_IV) {
		if (lck->mode < mode) {
			/*
			 * We already have the lock but at a mode which is not
			 * compatible with what the caller wants. Set the lock
			 * blocking to let the downconvert thread do it's work
			 * so we can reacquire at the correct mode.
			 */
			set_lock_blocking(linfo, lck, 0);
			spin_unlock(&linfo->lock);
			goto check_lock_state;
		}
		lck->holders++;
		spin_unlock(&linfo->lock);
		goto out;
	}

	lck->rqmode = mode;
	lck->holders++;
	spin_unlock(&linfo->lock);

	ret = dlm_lock_range(linfo->ls, mode, &lck->dlm_start, &lck->dlm_end,
			     &lck->lksb, DLM_LKF_NOORDER, RANGE_LOCK_RESOURCE,
			     RANGE_LOCK_RESOURCE_LEN, 0, scoutfs_ast, lck,
			     scoutfs_rbast);
	if (ret) {
		scoutfs_err(sb, "Error %d locking %s\n", ret,
			    RANGE_LOCK_RESOURCE);
		put_scoutfs_lock(sb, lck);
		return ret;
	}

	wait_event(linfo->waitq, lock_granted(linfo, lck, mode));
out:
	*ret_lck = lck;
	return 0;
}

void scoutfs_unlock_range(struct super_block *sb, struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	unsigned int seconds = 60;

	trace_scoutfs_unlock_range(sb, lck);

	spin_lock(&linfo->lock);
	lck->holders--;
	if (lck->holders == 0) {
		if (lck->flags & SCOUTFS_LOCK_BLOCKING)
			seconds = 0;
		queue_blocking_work(linfo, lck, seconds);
	}
	spin_unlock(&linfo->lock);

	put_scoutfs_lock(sb, lck);
}

static void unlock_range(struct super_block *sb, struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linfo);
	int ret;

	trace_scoutfs_unlock_range(sb, lck);

	BUG_ON(!lck->sequence);

	spin_lock(&linfo->lock);
	lck->rqmode = DLM_LOCK_IV;
	spin_unlock(&linfo->lock);
	ret = dlm_unlock(linfo->ls, lck->lksb.sb_lkid, 0, &lck->lksb, lck);
	if (ret) {
		scoutfs_err(sb, "Error %d unlocking %s\n", ret,
			    RANGE_LOCK_RESOURCE);
		goto out;
	}

	wait_event(linfo->waitq, lock_granted(linfo, lck, DLM_LOCK_IV));
out:
	/* lock was removed from tree, wake up umount process */
	wake_up(&linfo->waitq);
}

static void scoutfs_downconvert_func(struct work_struct *work)
{
	struct scoutfs_lock *lck = container_of(work, struct scoutfs_lock,
						dc_work.work);
	struct super_block *sb = lck->sb;
	DECLARE_LOCK_INFO(sb, linfo);

	trace_scoutfs_downconvert_func(sb, lck);

	spin_lock(&linfo->lock);
	lck->flags &= ~SCOUTFS_LOCK_QUEUED;
	if (lck->holders)
		goto out; /* scoutfs_unlock_range will requeue for us */

	spin_unlock(&linfo->lock);

	WARN_ON_ONCE(lck->holders);
	WARN_ON_ONCE(lck->refcnt == 0);
	/*
	 * Use write mode to invalidate all since we are completely
	 * dropping the lock. Once we are dowconverting, we can
	 * invalidate based on what level we're downconverting to (PR,
	 * NL).
	 */
	invalidate_caches(sb, SCOUTFS_LOCK_MODE_WRITE, lck->start, lck->end);
	unlock_range(sb, lck);

	spin_lock(&linfo->lock);
	/* Check whether we can add the lock to the LRU list:
	 *
	 * First, check mode to be sure that the lock wasn't reacquired
	 * while we slept in unlock_range().
	 *
	 * Next, check refs. refcnt == 1 means the only holder is the
	 * lock tree so in particular we have nobody in
	 * scoutfs_lock_range concurrently trying to acquire a lock.
	 */
	if (lck->mode == SCOUTFS_LOCK_MODE_IV && lck->refcnt == 1 &&
	    list_empty(&lck->lru_entry)) {
		list_add_tail(&lck->lru_entry, &linfo->lru_list);
		linfo->lru_nr++;
	}
out:
	spin_unlock(&linfo->lock);
	put_scoutfs_lock(sb, lck);
}

/*
 * The moment this is done we can have other mounts start asking
 * us to write back and invalidate, so do this very very late.
 */
static int init_lock_info(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct lock_info *linfo;

	linfo = kzalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linfo)
		return -ENOMEM;

	spin_lock_init(&linfo->lock);
	init_waitqueue_head(&linfo->waitq);
	INIT_LIST_HEAD(&linfo->lru_list);
	linfo->shrinker.shrink = shrink_lock_tree;
	linfo->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&linfo->shrinker);
	linfo->sb = sb;
	linfo->shutdown = false;
	INIT_LIST_HEAD(&linfo->id_head);
	linfo->ls = NULL;

	snprintf(linfo->ls_name, DLM_LOCKSPACE_LEN, "%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	sbi->lock_info = linfo;

	trace_printk("sb %p id %016llx allocated linfo %p held %p\n",
		     sb, le64_to_cpu(sbi->super.id), linfo, linfo);

	return 0;
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

	if (linfo) {
		spin_lock(&linfo->lock);
		linfo->shutdown = true;
		spin_unlock(&linfo->lock);

		wake_up(&linfo->waitq);
	}
}

void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);
	int ret;

	if (linfo) {
		if (linfo->downconvert_wq)
			destroy_workqueue(linfo->downconvert_wq);
		unregister_shrinker(&linfo->shrinker);
		if (linfo->ls) {
			ret = dlm_release_lockspace(linfo->ls, 2);
			if (ret)
				scoutfs_info(sb, "Error %d releasing lockspace %s\n",
					     ret, linfo->ls_name);
		}

		free_lock_tree(sb);

		sbi->lock_info = NULL;

		trace_printk("sb %p id %016llx freeing linfo %p linfo %p\n",
			     sb, le64_to_cpu(sbi->super.id), linfo, linfo);

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
	linfo->downconvert_wq = alloc_workqueue("scoutfs_dc",
					       WQ_UNBOUND|WQ_HIGHPRI, 0);
	if (!linfo->downconvert_wq) {
		kfree(linfo);
		return -ENOMEM;
	}

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
