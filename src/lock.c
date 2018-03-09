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
#include <linux/dlm.h>
#include <linux/mm.h>
#include <linux/sort.h>
#include <linux/debugfs.h>
#include <linux/idr.h>
#include <linux/ctype.h>

#include "super.h"
#include "lock.h"
#include "item.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "cmp.h"
#include "inode.h"
#include "trans.h"
#include "counters.h"
#include "endian_swap.h"
#include "triggers.h"

/*
 * scoutfs manages internode item cache consistency using the kernel's
 * dlm service.  We map ranges of item keys to dlm locks and use each
 * lock's modes to govern what we can do with the items under the lock.
 *
 * The management of locks is based around state updates that queue work
 * which then acts on the state.  The work calls the dlm to change modes
 * and gets completion notification in callbacks.
 *
 * We free locks that aren't actively protecting items instead of
 * converting them to NL and leaving them around.  It gives us fewer
 * locks consuming resources and fewer locks to wade through to try and
 * diagnose a problem.
 *
 * So far we've only needed a minimal trylock.  We don't issue a NOQUEUE
 * request to the dlm which can eventually return -EAGAIN if it finds
 * contention.  We return -EAGAIN ourselves if a user can't immediately
 * match an existing granted lock.  This is fine for the only rare user
 * which can back out of its lock inversion and retry with a full
 * blocking lock.  This saves us from having to plumb per-waiter flags
 * down to dlm requests.
 */

#define GRACE_WORK_DELAY_JIFFIES	msecs_to_jiffies(2)
#define GRACE_UNLOCK_DEADLINE_KT	ms_to_ktime(2)

#define LN_FMT "%u.%u.%u.%llu.%llu"
#define LN_ARG(name) \
	(name)->scope, (name)->zone, (name)->type, le64_to_cpu((name)->first),\
	le64_to_cpu((name)->second)

/*
 * allocated per-super, freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	spinlock_t lock;
	bool shutdown;
	struct rb_root lock_tree;
	struct rb_root lock_range_tree;
	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long long lru_nr;
	struct workqueue_struct *workq;
	dlm_lockspace_t *lockspace;
	struct dentry *debug_locks_dentry;
	struct idr debug_locks_idr;
	atomic64_t next_refresh_gen;
};

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

static void scoutfs_lock_work(struct work_struct *work);
static void scoutfs_lock_grace_work(struct work_struct *work);

/*
 * invalidate cached data associated with an inode whose lock is going
 * away.
 */
static void invalidate_inode(struct super_block *sb, u64 ino)
{
	struct inode *inode;

	inode = scoutfs_ilookup(sb, ino);
	if (inode) {
		if (S_ISREG(inode->i_mode))
			truncate_inode_pages(inode->i_mapping, 0);
		iput(inode);
	}
}

/*
 * Invalidate caches associated with this lock.  We're going from the
 * previous mode to the next mode.
 */
static int lock_invalidate(struct super_block *sb, struct scoutfs_lock *lock,
			   int prev, int mode)
{
	struct scoutfs_key_buf *start = lock->start;
	struct scoutfs_key_buf *end = lock->end;
	struct scoutfs_lock_coverage *cov;
	struct scoutfs_lock_coverage *tmp;
	u64 ino, last;
	int ret;

	/* any transition from a mode allowed to dirty items has to write */
	if (prev == DLM_LOCK_CW || prev == DLM_LOCK_EX) {
		ret = scoutfs_item_writeback(sb, start, end);
		if (ret < 0)
			return ret;
		if (ret > 0) {
			scoutfs_add_counter(sb, lock_write_dirty_item, ret);
			ret = 0;
		}
	}

	/* invalidate items that we could have but won't be able to use */
	if (prev == DLM_LOCK_CW ||
            (prev == DLM_LOCK_PR && mode != DLM_LOCK_EX) ||
            (prev == DLM_LOCK_EX && mode != DLM_LOCK_PR)) {

retry:
		spin_lock(&lock->cov_list_lock);
		list_for_each_entry_safe(cov, tmp, &lock->cov_list, head) {
			if (!spin_trylock(&cov->cov_lock)) {
				spin_unlock(&lock->cov_list_lock);
				cpu_relax();
				goto retry;
			}
			list_del_init(&cov->head);
			cov->lock = NULL;
			spin_unlock(&cov->cov_lock);
		}
		spin_unlock(&lock->cov_list_lock);

		if (lock->name.zone == SCOUTFS_FS_ZONE) {
			ino = le64_to_cpu(lock->name.first);
			last = ino + SCOUTFS_LOCK_INODE_GROUP_NR - 1;
			while (ino <= last) {
				invalidate_inode(sb, ino);
				ino++;
			}
		}

		ret = scoutfs_item_invalidate(sb, start, end);
		if (ret > 0) {
			scoutfs_add_counter(sb, lock_invalidate_clean_item,
					    ret);
			ret = 0;
		}
	}

	return ret;
}

static void lock_free(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	struct super_block *sb = lock->sb;

	assert_spin_locked(&linfo->lock);

	trace_scoutfs_lock_free(sb, lock);
	scoutfs_inc_counter(sb, lock_free);

	BUG_ON(!linfo->shutdown && lock->granted_mode != DLM_LOCK_IV);
	BUG_ON(delayed_work_pending(&lock->grace_work));

	if (lock->debug_locks_id)
		idr_remove(&linfo->debug_locks_idr, lock->debug_locks_id);
	if (!RB_EMPTY_NODE(&lock->node))
		rb_erase(&lock->node, &linfo->lock_tree);
	if (!RB_EMPTY_NODE(&lock->range_node))
		rb_erase(&lock->range_node, &linfo->lock_range_tree);
	if (!list_empty(&lock->lru_head)) {
		list_del(&lock->lru_head);
		linfo->lru_nr--;
	}
	scoutfs_key_free(sb, lock->start);
	scoutfs_key_free(sb, lock->end);
	kfree(lock);
}

static struct scoutfs_lock *lock_alloc(struct super_block *sb,
				       struct scoutfs_lock_name *name,
				       struct scoutfs_key_buf *start,
				       struct scoutfs_key_buf *end)

{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	int id;

	if (WARN_ON_ONCE(!!start != !!end))
		return NULL;

	lock = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (lock == NULL)
		return NULL;

	scoutfs_inc_counter(sb, lock_alloc);

	idr_preload(GFP_NOFS);
	spin_lock(&linfo->lock);
	id = idr_alloc(&linfo->debug_locks_idr, lock, 1, INT_MAX, GFP_NOWAIT);
	if (id > 0)
		lock->debug_locks_id = id;
	spin_unlock(&linfo->lock);
	idr_preload_end();
	if (id <= 0) {
		lock_free(linfo, lock);
		return NULL;
	}

	RB_CLEAR_NODE(&lock->node);
	RB_CLEAR_NODE(&lock->range_node);
	INIT_LIST_HEAD(&lock->lru_head);

	spin_lock_init(&lock->cov_list_lock);
	INIT_LIST_HEAD(&lock->cov_list);

	if (start) {
		lock->start = scoutfs_key_dup(sb, start);
		lock->end = scoutfs_key_dup(sb, end);
		if (!lock->start || !lock->end) {
			lock_free(linfo, lock);
			return NULL;
		}
	}

	lock->sb = sb;
	lock->name = *name;
	init_waitqueue_head(&lock->waitq);
	INIT_WORK(&lock->work, scoutfs_lock_work);
	INIT_DELAYED_WORK(&lock->grace_work, scoutfs_lock_grace_work);
	lock->granted_mode = DLM_LOCK_IV;
	lock->bast_mode = DLM_LOCK_IV;
	lock->work_prev_mode = DLM_LOCK_IV;
	lock->work_mode = DLM_LOCK_IV;

	trace_scoutfs_lock_alloc(sb, lock);

	return lock;
}

static void lock_inc_count(unsigned int *counts, int mode)
{
	BUG_ON(mode < 0 || mode >= SCOUTFS_LOCK_NR_MODES);
	counts[mode]++;
}

static void lock_dec_count(unsigned int *counts, int mode)
{
	BUG_ON(mode < 0 || mode >= SCOUTFS_LOCK_NR_MODES);
	counts[mode]--;
}

/* only PR and EX modes read items to populate the cache. */
static bool lock_mode_can_read(int mode)
{
	return mode == DLM_LOCK_PR || mode == DLM_LOCK_EX;
}

/*
 * Returns true if a given user mode can be satisfied by a lock with the
 * given granted mode.  This is directional.  A PR user is satisfied by
 * an EX grant but not vice versa.
 */
static bool lock_modes_match(int granted, int user)
{
	return (granted == user) ||
	       (granted == DLM_LOCK_EX && user == DLM_LOCK_PR);
}

/*
 * Returns true if all the actively used modes are satisfied by a lock
 * of the given granted mode.
 */
static bool lock_counts_match(int granted, unsigned int *counts)
{
	int mode;

	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (counts[mode] && !lock_modes_match(granted, mode))
			return false;
	}

	return true;
}

/*
 * An idle lock has nothing going on and could be safely unlocked and freed.
 */
static bool lock_idle(struct scoutfs_lock *lock)
{
	int mode;

	if (lock->work_mode >= 0 || lock->grace_pending)
		return false;

	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (lock->waiters[mode] || lock->users[mode])
			return false;
	}

	return true;
}

/*
 * Ensure forward progress on the lock after the caller has changed the lock.
 *
 * This is the core of the state transition engine that makes locking
 * safe.  Each transition has to consider the users of the lock, pending
 * bast transitions, it's current mode, what mode it should be, and what
 * mode to leave it in during the transition.
 *
 * This can free the lock if it's idle!  Callers must not reference the
 * lock after calling this.
 */
static void lock_process(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	bool idle;
	int mode;

	assert_spin_locked(&linfo->lock);

	/* nothing to do if we're shutting down, stops rearming */
	if (linfo->shutdown)
		return;

	/* only idle locks are on the lru */
	idle = lock_idle(lock);
	if (list_empty(&lock->lru_head) && idle) {
		list_add_tail(&lock->lru_head, &linfo->lru_list);
		linfo->lru_nr++;

	} else if (!list_empty(&lock->lru_head) && !idle) {
		list_del_init(&lock->lru_head);
		linfo->lru_nr--;
	}

	/* errored locks are torn down */
	if (lock->error) {
		wake_up(&lock->waitq);
		goto out;
	}

	/*
	 * Wake any waiters who might be able to use the lock now.
	 * Notice that this ignores the presence of basts!  This lets us
	 * recursively acquire locks in one task without having to track
	 * per-task lock references.  It comes at the cost of fairness.
	 * Spinning overlapping users can delay a bast down conversion
	 * indefinitely.
	 */
	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (lock->waiters[mode] &&
		    lock_modes_match(lock->granted_mode, mode)) {
			wake_up(&lock->waitq);
			break;
		}
	}

	/*
	 * Try to down convert a lock in response to a bast once users
	 * are done with it.  We may have to wait for a grace period
	 * to expire after an unlock.
	 */
	if (lock->work_mode < 0 &&
	    lock->bast_mode >= 0 &&
	    lock_counts_match(lock->bast_mode, lock->users) &&
	    !lock->grace_pending) {

		if (ktime_before(ktime_get(), lock->grace_deadline)) {
			scoutfs_inc_counter(linfo->sb, lock_grace_enforced);
			queue_delayed_work(linfo->workq, &lock->grace_work,
					   GRACE_WORK_DELAY_JIFFIES);
			lock->grace_pending = true;
		} else {
			lock->work_prev_mode = lock->granted_mode;
			lock->work_mode = lock->bast_mode;
			lock->granted_mode = lock->bast_mode;
			lock->bast_mode = DLM_LOCK_IV;
			queue_work(linfo->workq, &lock->work);
		}
	}

	/*
	 * Convert on behalf of waiters who aren't satisfied by the
	 * current mode when it won't conflict with specific waiters,
	 * matching users, or pending bast conversions.  The new mode
	 * may or may not match the current granted mode so we may or
	 * may not need to block users during the transition.
	 *
	 * Remember that the presence of waiters doesn't necessarily
	 * mean that they're blocked.  Multiple lock attempts naturally
	 * line up to add themselves to the waiters count before each
	 * calls lock_wait() and is transitioned to a user.
	 */
	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (lock->work_mode < 0 &&
		    lock->waiters[mode] &&
		    (lock->granted_mode < 0 ||
		     !lock->waiters[lock->granted_mode]) &&
		    !lock_modes_match(lock->granted_mode, mode) &&
		    lock_counts_match(mode, lock->users) &&
		    (lock->bast_mode < 0 ||
		     lock_modes_match(lock->bast_mode, mode))) {

			lock->work_prev_mode = lock->granted_mode;
			lock->work_mode = mode;
			if (!lock_modes_match(mode, lock->granted_mode))
				lock->granted_mode = DLM_LOCK_NL;
			queue_work(linfo->workq, &lock->work);
			break;
		}
	}

out:
	/*
	 * We can free the lock once it's idle and it's either never
	 * been initially locked or has been unlocked, both of which we
	 * indicate with IV.
	 */
	if (lock_idle(lock) && lock->granted_mode == DLM_LOCK_IV)
		lock_free(linfo, lock);
}

static int cmp_lock_names(struct scoutfs_lock_name *a,
			  struct scoutfs_lock_name *b)
{
	return ((int)a->scope - (int)b->scope) ?:
	       ((int)a->zone - (int)b->zone) ?:
	       ((int)a->type - (int)b->type) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->first), le64_to_cpu(b->first)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->second), le64_to_cpu(b->second));
}

static bool insert_range_node(struct super_block *sb, struct scoutfs_lock *ins)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct rb_root *root = &linfo->lock_range_tree;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_lock *lock;
	int cmp;

	while (*node) {
		parent = *node;
		lock = container_of(*node, struct scoutfs_lock, range_node);

		cmp = scoutfs_key_compare_ranges(ins->start, ins->end,
						 lock->start, lock->end);
		if (WARN_ON_ONCE(cmp == 0)) {
			scoutfs_warn_sk(sb, "inserting lock %p name "LN_FMT" start "SK_FMT" end "SK_FMT" overlaps with existing lock %p name "LN_FMT" start "SK_FMT" end "SK_FMT"\n",
					ins, LN_ARG(&ins->name),
					SK_ARG(ins->start), SK_ARG(ins->end),
					lock, LN_ARG(&lock->name),
					SK_ARG(lock->start), SK_ARG(lock->end));
			return false;
		}

		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}


	rb_link_node(&ins->range_node, parent, node);
	rb_insert_color(&ins->range_node, root);

	return true;
}

static struct scoutfs_lock *lock_rb_walk(struct super_block *sb,
					 struct scoutfs_lock_name *name,
					 struct scoutfs_lock *ins)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *found;
	struct scoutfs_lock *lock;
	struct rb_node *parent;
	struct rb_node **node;
	int cmp;

	assert_spin_locked(&linfo->lock);

	node = &linfo->lock_tree.rb_node;
	parent = NULL;
	found = NULL;
	while (*node) {
		parent = *node;
		lock = container_of(*node, struct scoutfs_lock, node);

		cmp = cmp_lock_names(name, &lock->name);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			found = lock;
			break;
		}
		lock = NULL;
	}

	if (!found && ins) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, &linfo->lock_tree);
		found = ins;
	}

	return found;
}

/*
 * A dlm lock, conversion, or unlock call has finished.  We don't
 * strictly serialize the arrival of basts and our dlm calls.  It's
 * possible and safe for us to get a deadlock notification because we
 * tried to convert in conflict with a received bast.  We ignore the
 * result of the deadlock conversion and processing will retry and this
 * time prefer the bast.
 */
static void scoutfs_lock_ast(void *arg)
{
	struct scoutfs_lock *lock = arg;
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);
	int status = lock->lksb.sb_status;
	bool cached;
	bool dirty;

	scoutfs_inc_counter(sb, lock_ast);

	spin_lock(&linfo->lock);

	if (status == 0) {
		if (lock_mode_can_read(lock->work_mode) &&
		    !lock_mode_can_read(lock->work_prev_mode)) {
			lock->refresh_gen =
				atomic64_inc_return(&linfo->next_refresh_gen);
		}
		lock->granted_mode = lock->work_mode;

	} else if (status == -DLM_EUNLOCK) {
		lock->granted_mode = DLM_LOCK_IV;

	} else if (status == -EDEADLK) {
		/* dlm request conflicted with racing bast, try again */
		scoutfs_inc_counter(sb, lock_ast_edeadlk);

	} else if (!lock->error) {
		scoutfs_inc_counter(sb, lock_ast_error);
		lock->error = status;
	}

	lock->work_prev_mode = DLM_LOCK_IV;
	lock->work_mode = DLM_LOCK_IV;

	trace_scoutfs_lock_ast(sb, lock);

	/*
	 * Catch lock modes with cached items that violate the item
	 * cache consistency rules.
	 *
	 * We can never have dirty items if we're calling the dlm and
	 * changing lock modes.  We can't have cached items if we're not
	 * in the two modes that allow caching.
	 */
	cached = lock->start && scoutfs_item_range_cached(sb, lock->start,
							  lock->end, false);
	dirty = lock->start && scoutfs_item_range_cached(sb, lock->start,
							 lock->end, true);
	if (WARN_ON_ONCE(dirty ||
			 (cached && lock->granted_mode != DLM_LOCK_PR &&
				    lock->granted_mode != DLM_LOCK_EX))) {
		scoutfs_err_sk(sb, "lock item cache consistency violation, cached %u dirty %u: name "LN_FMT" start "SK_FMT" end "SK_FMT" refresh_gen %llu error %d granted %d bast %d prev %d work %d waiters: pr %u ex %u cw %u users: pr %u ex %u cw %u dlmlksb: status %d lkid 0x%x flags 0x%x\n",
			   cached, dirty,
			   LN_ARG(&lock->name), SK_ARG(lock->start),
			   SK_ARG(lock->end), lock->refresh_gen, lock->error,
			   lock->granted_mode, lock->bast_mode,
			   lock->work_prev_mode, lock->work_mode,
			   lock->waiters[DLM_LOCK_PR],
			   lock->waiters[DLM_LOCK_EX],
			   lock->waiters[DLM_LOCK_CW],
			   lock->users[DLM_LOCK_PR],
			   lock->users[DLM_LOCK_EX],
			   lock->users[DLM_LOCK_CW],
			   lock->lksb.sb_status,
			   lock->lksb.sb_lkid,
			   lock->lksb.sb_flags);
		BUG();
	}

	lock_process(linfo, lock);
	spin_unlock(&linfo->lock);
}

/*
 * A lock on this node has blocked a lock request on another node.
 *
 * We can down convert to a PR if we had an EX and they're trying to get
 * a PR but all other conflicts cause us to drop our lock and invalidate
 * our cache.
 */
static void scoutfs_lock_bast(void *arg, int blocked_mode)
{
	struct scoutfs_lock *lock = arg;
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);

	scoutfs_inc_counter(sb, lock_bast);

	spin_lock(&linfo->lock);

	if (lock->granted_mode == DLM_LOCK_EX && blocked_mode == DLM_LOCK_PR)
		lock->bast_mode = DLM_LOCK_PR;
	else
		lock->bast_mode = DLM_LOCK_NL;

	trace_scoutfs_lock_bast(sb, lock);
	lock_process(linfo, lock);

	spin_unlock(&linfo->lock);
}

/*
 * The actual work of sending lock requests to the dlm.  There's only
 * one of these per lock and the work_mode ensures that there's only one
 * transition in flight at a time.
 */
static void scoutfs_lock_work(struct work_struct *work)
{
	struct scoutfs_lock *lock = container_of(work, struct scoutfs_lock,
						 work);
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);
	int dlm_flags;
	int prev;
	int mode;
	int ret;

	spin_lock(&linfo->lock);

	/* don't try to call a released lockspace during shutdown */
	if (linfo->shutdown) {
		spin_unlock(&linfo->lock);
		return;
	}

	trace_scoutfs_lock_work(sb, lock);
	prev = lock->work_prev_mode;
	mode = lock->work_mode;

	spin_unlock(&linfo->lock);

	if (lock->start) {
		ret = lock_invalidate(sb, lock, prev, mode);
		BUG_ON(ret);
	}

	scoutfs_inc_counter(sb, lock_dlm_call);

	if (mode == DLM_LOCK_NL) {
		ret = dlm_unlock(linfo->lockspace, lock->lksb.sb_lkid, 0,
				 &lock->lksb, lock);
	} else {
		dlm_flags = DLM_LKF_NOORDER;
		if (prev >= 0)
			dlm_flags |= DLM_LKF_CONVERT;
		ret = dlm_lock(linfo->lockspace, mode, &lock->lksb, dlm_flags,
			       &lock->name, sizeof(lock->name), 0,
			       scoutfs_lock_ast, lock, scoutfs_lock_bast);
	}
	/*
	 * I don't think the lock error handling is correct yet.  It
	 * probably doesn't try to unlock a lock that saw an error.
	 */
	if (ret)
		scoutfs_inc_counter(sb, lock_dlm_call_error);
	BUG_ON(ret);

	spin_lock(&linfo->lock);

	if (ret < 0) {
		if (!lock->error)
			lock->error = ret;
		lock->work_prev_mode = DLM_LOCK_IV;
		lock->work_mode = DLM_LOCK_IV;
		lock_process(linfo, lock);
	}

	spin_unlock(&linfo->lock);
}

/*
 * The grace period has elapsed since a down conversion attempt too soon
 * after an unlock.  It can now be down converted.
 */
static void scoutfs_lock_grace_work(struct work_struct *work)
{
	struct scoutfs_lock *lock = container_of(work, struct scoutfs_lock,
						 grace_work.work);
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);

	BUG_ON(lock->grace_pending == false);

	spin_lock(&linfo->lock);
	trace_scoutfs_lock_grace_work(sb, lock);
	scoutfs_inc_counter(linfo->sb, lock_grace_expired);
	lock->grace_pending = false;
	lock_process(linfo, lock);
	spin_unlock(&linfo->lock);
}

/*
 * Wait for a lock attempt to be resolved.  We return as an active user
 * once our mode is satisfied by the lock or we can return errors.
 */
static bool lock_wait(struct lock_info *linfo, struct scoutfs_lock *lock,
		      int mode, int flags, int *ret)
{
	struct super_block *sb = linfo->sb;
	bool done;

	spin_lock(&linfo->lock);

	trace_scoutfs_lock_wait(sb, lock);

	if (lock_modes_match(lock->granted_mode, mode)) {
		/* the fast path where we can use the granted mode */
		lock_dec_count(lock->waiters, mode);
		lock_inc_count(lock->users, mode);
		*ret = 0;
		done = true;

	} else if (linfo->shutdown) {
		/* locking is going away */
		*ret = -ESHUTDOWN;
		done = true;

	} else if (lock->error) {
		/* something horrible has happened */
		*ret = lock->error;
		done = true;

	} else if (flags & SCOUTFS_LKF_NONBLOCK) {
		/* never wait for "nonblocking" callers */
		scoutfs_inc_counter(sb, lock_nonblock_eagain);
		*ret = -EAGAIN;
		done = true;

	} else {
		/* still waiting :/ */
		*ret = 0;
		done = false;
	}

	lock_process(linfo, lock);

	spin_unlock(&linfo->lock);

	return done;
}

/*
 * Acquire a coherent lock on the given range of keys.  On success the
 * caller can use the given mode to interact with the item cache.  While
 * holding the lock the cache won't be invalidated and other conflicting
 * lock users will be serialized.  The item cache can be invalidated
 * once the lock is unlocked.
 */
static int lock_name_keys(struct super_block *sb, int mode, int flags,
			  struct scoutfs_lock_name *name,
			  struct scoutfs_key_buf *start,
			  struct scoutfs_key_buf *end,
			  struct scoutfs_lock **ret_lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct scoutfs_lock *ins;
	int wait_ret;
	int ret;

	scoutfs_inc_counter(sb, lock_lock);

	*ret_lock = NULL;

	/* maybe catch _setup() order mistakes */
	if (WARN_ON_ONCE(!linfo || linfo->lockspace == NULL))
		return -ENOLCK;

	/* have to lock before entering transactions */
	if (WARN_ON_ONCE(scoutfs_trans_held()))
		return -EDEADLK;

	ins = NULL;
retry:
	spin_lock(&linfo->lock);

	/* don't create locks once we're shutdown */
	if (linfo->shutdown) {
		spin_unlock(&linfo->lock);
		ret = -ESHUTDOWN;
		goto out;
	}

	lock = lock_rb_walk(sb, name, ins);
	if (!lock) {
		spin_unlock(&linfo->lock);
		ins = lock_alloc(sb, name, start, end);
		if (!ins) {
			ret = -ENOMEM;
			goto out;
		}
		goto retry;

	} else if (lock == ins) {
		if (start && !insert_range_node(sb, ins)) {
			lock_free(linfo, ins);
			spin_unlock(&linfo->lock);
			ret = -EINVAL;
			goto out;
		}

	} else if (ins) {
		lock_free(linfo, ins);
	}

	lock_inc_count(lock->waiters, mode);
	spin_unlock(&linfo->lock);

	ret = wait_event_interruptible(lock->waitq,
				       lock_wait(linfo, lock, mode, flags,
					         &wait_ret));
	if (ret == 0)
		ret = wait_ret;
	if (ret) {
		scoutfs_inc_counter(sb, lock_lock_error);
		spin_lock(&linfo->lock);
		lock_dec_count(lock->waiters, mode);
		lock_process(linfo, lock);
		spin_unlock(&linfo->lock);
	} else {
		*ret_lock = lock;
	}
out:
	return ret;
}

int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_lock_name name;
	struct scoutfs_inode_key start_ikey;
	struct scoutfs_inode_key end_ikey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	ino &= ~(u64)SCOUTFS_LOCK_INODE_GROUP_MASK;

	name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	name.zone = SCOUTFS_FS_ZONE;
	name.type = SCOUTFS_INODE_TYPE;
	name.first = cpu_to_le64(ino);
	name.second = 0;

	start_ikey.zone = SCOUTFS_FS_ZONE;
	start_ikey.ino = cpu_to_be64(ino);
	start_ikey.type = 0;
	scoutfs_key_init(&start, &start_ikey, sizeof(start_ikey));

	end_ikey.zone = SCOUTFS_FS_ZONE;
	end_ikey.ino = cpu_to_be64(ino + SCOUTFS_LOCK_INODE_GROUP_NR - 1);
	end_ikey.type = ~0;
	scoutfs_key_init(&end, &end_ikey, sizeof(end_ikey));

	return lock_name_keys(sb, mode, flags, &name, &start, &end, ret_lock);
}

/*
 * Acquire a lock on an inode.
 *
 * _REFRESH_INODE indicates that the caller needs to have the vfs inode
 * fields current with respect to lock coverage.  dlmglue increases the
 * lock's refresh_gen once every time its mode is changed from a mode
 * that couldn't have the inode cached to one that could.
 */
int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **lock)
{
	int ret;

	ret = scoutfs_lock_ino(sb, mode, flags, scoutfs_ino(inode), lock);
	if (ret < 0)
		goto out;

	if (flags & SCOUTFS_LKF_REFRESH_INODE) {
		ret = scoutfs_inode_refresh(inode, *lock, flags);
		if (ret < 0) {
			scoutfs_unlock(sb, *lock, mode);
			*lock = NULL;
		}
	}

out:
	return ret;
}

struct lock_inodes_arg {
	struct inode *inode;
	struct scoutfs_lock **lockp;
};

/*
 * All args with inodes go to the front of the array and are then sorted
 * by their inode number.
 */
static int cmp_arg(const void *A, const void *B)
{
	const struct lock_inodes_arg *a = A;
	const struct lock_inodes_arg *b = B;

	if (a->inode && b->inode)
		return scoutfs_cmp_u64s(scoutfs_ino(a->inode),
					scoutfs_ino(b->inode));

	return a->inode ? -1 : b->inode ? 1 : 0;
}

static void swap_arg(void *A, void *B, int size)
{
	struct lock_inodes_arg *a = A;
	struct lock_inodes_arg *b = B;

	swap(*a, *b);
}

/*
 * Lock all the inodes in inode number order.  The inode arguments can
 * be in any order and can be duplicated or null.  This relies on core
 * lock matching to efficiently handle duplicate lock attempts of the
 * same group.  Callers can try to use the lock range keys for all the
 * locks they attempt to acquire without knowing that they map to the
 * same groups.
 *
 * On error no locks are held and all pointers are set to null.  Lock
 * pointers for null inodes are always set to null.
 *
 * (pretty great collision with d_lock() here)
 */
int scoutfs_lock_inodes(struct super_block *sb, int mode, int flags,
			struct inode *a, struct scoutfs_lock **a_lock,
			struct inode *b, struct scoutfs_lock **b_lock,
			struct inode *c, struct scoutfs_lock **c_lock,
			struct inode *d, struct scoutfs_lock **D_lock)
{
	struct lock_inodes_arg args[] = {
		{a, a_lock}, {b, b_lock}, {c, c_lock}, {d, D_lock},
	};
	int ret;
	int i;

	/* set all lock pointers to null and validating input */
	ret = 0;
	for (i = 0; i < ARRAY_SIZE(args); i++) {
		if (WARN_ON_ONCE(args[i].inode && !args[i].lockp))
			ret = -EINVAL;
		if (args[i].lockp)
			*args[i].lockp = NULL;
	}
	if (ret)
		return ret;

	/* sort by having an inode then inode number */
	sort(args, ARRAY_SIZE(args), sizeof(args[0]), cmp_arg, swap_arg);

	/* lock unique inodes */
	for (i = 0; i < ARRAY_SIZE(args) && args[i].inode; i++) {
		ret = scoutfs_lock_inode(sb, mode, flags, args[i].inode,
					 args[i].lockp);
		if (ret)
			break;
	}

	/* unlock on error */
	for (i = ARRAY_SIZE(args) - 1; ret < 0 && i >= 0; i--) {
		if (args[i].lockp && *args[i].lockp) {
			scoutfs_unlock(sb, *args[i].lockp, mode);
			*args[i].lockp = NULL;
		}
	}

	return ret;
}

/*
 * Acquire a cluster lock with a global scope in the lock space.
 */
int scoutfs_lock_global(struct super_block *sb, int mode, int flags, int type,
			struct scoutfs_lock **lock)
{
	struct scoutfs_lock_name name;

	memset(&name, 0, sizeof(name));
	name.scope = SCOUTFS_LOCK_SCOPE_GLOBAL;
	name.type = type;

	return lock_name_keys(sb, mode, flags, &name, NULL, NULL, lock);
}

/*
 * Set the caller's keys to the range of index item keys that are
 * covered by the lock which covers the given index item.
 *
 * We're trying to strike a balance between minimizing lock
 * communication by locking a large number of items and minimizing
 * contention and hold times by locking a small number of items.
 *
 * The seq indexes have natural batching and limits on the number of
 * keys per major value.
 *
 * This can also be used to find items that are covered by the same lock
 * because their starting keys are the same.
 */
void scoutfs_lock_get_index_item_range(u8 type, u64 major, u64 ino,
				       struct scoutfs_inode_index_key *start,
				       struct scoutfs_inode_index_key *end)
{
	u64 start_major = major & ~SCOUTFS_LOCK_SEQ_GROUP_MASK;
	u64 end_major = major | SCOUTFS_LOCK_SEQ_GROUP_MASK;

	BUG_ON(type != SCOUTFS_INODE_INDEX_META_SEQ_TYPE &&
	       type != SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE);

	if (start) {
		start->zone = SCOUTFS_INODE_INDEX_ZONE;
		start->type = type;
		start->major = cpu_to_be64(start_major);
		start->minor = 0;
		start->ino = 0;
	}

	if (end) {
		end->zone = SCOUTFS_INODE_INDEX_ZONE;
		end->type = type;
		end->major = cpu_to_be64(end_major);
		end->minor = 0;
		end->ino = cpu_to_be64(~0ULL);
	}
}

/*
 * Lock the given index item.  We use the index masks to name a reasonable
 * batch of logical items to lock and calculate the start and end
 * key values that are covered by the lock.
 *
 */
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_lock_name name;
	struct scoutfs_inode_index_key start_ikey;
	struct scoutfs_inode_index_key end_ikey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	scoutfs_lock_get_index_item_range(type, major, ino,
					  &start_ikey, &end_ikey);

	name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	name.zone = start_ikey.zone;
	name.type = start_ikey.type;
	name.first = be64_to_le64(start_ikey.major);
	name.second = be64_to_le64(start_ikey.ino);

	scoutfs_key_init(&start, &start_ikey, sizeof(start_ikey));
	scoutfs_key_init(&end, &end_ikey, sizeof(end_ikey));

	return lock_name_keys(sb, mode, 0, &name, &start, &end, ret_lock);
}

/*
 * The node_id lock protects a mount's private persistent items in the
 * node_id zone.  It's held for the duration of the mount.  It lets the
 * mount modify the node_id items at will and signals to other mounts
 * that we're still alive and our node_id items shouldn't be reclaimed.
 *
 * Being held for the entire mount prevents other nodes from reclaiming
 * our items, like free blocks, when it would make sense for them to be
 * able to.  Maybe we have a bunch free and they're trying to allocate
 * and are getting ENOSPC.
 */
int scoutfs_lock_node_id(struct super_block *sb, int mode, int flags,
			 u64 node_id, struct scoutfs_lock **lock)
{
	struct scoutfs_lock_name name;
	struct scoutfs_orphan_key start_okey;
	struct scoutfs_orphan_key end_okey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	name.zone = SCOUTFS_NODE_ZONE;
	name.type = 0;
	name.first = cpu_to_le64(node_id);
	name.second = 0;

	start_okey.zone = SCOUTFS_NODE_ZONE;
	start_okey.node_id = cpu_to_be64(node_id);
	start_okey.type = 0;
	start_okey.ino = 0;
	scoutfs_key_init(&start, &start_okey, sizeof(start_okey));

	end_okey.zone = SCOUTFS_NODE_ZONE;
	end_okey.node_id = cpu_to_be64(node_id);
	end_okey.type = ~0;
	end_okey.ino = cpu_to_be64(~0ULL);
	scoutfs_key_init(&end, &end_okey, sizeof(end_okey));

	return lock_name_keys(sb, mode, flags, &name, &start, &end, lock);
}

/*
 * As we unlock we start a grace period.  If a bast arrives before the
 * grace period we'll wait for another full grace period we downconvert
 * and invalidate the lock.  Each unlock resets the downconvert delay.
 */
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock, int mode)
{
	DECLARE_LOCK_INFO(sb, linfo);

	if (IS_ERR_OR_NULL(lock))
		return;

	scoutfs_inc_counter(sb, lock_unlock);

	spin_lock(&linfo->lock);
	trace_scoutfs_lock_unlock(sb, lock);

	lock_dec_count(lock->users, mode);
	lock->grace_deadline = ktime_add(ktime_get(), GRACE_UNLOCK_DEADLINE_KT);
	if (cancel_delayed_work(&lock->grace_work)) {
		scoutfs_inc_counter(linfo->sb, lock_grace_extended);
		queue_delayed_work(linfo->workq, &lock->grace_work,
				   GRACE_WORK_DELAY_JIFFIES);
	}

	lock_process(linfo, lock);
	spin_unlock(&linfo->lock);
}

void scoutfs_lock_init_coverage(struct scoutfs_lock_coverage *cov)
{
	spin_lock_init(&cov->cov_lock);
	cov->lock = NULL;
	INIT_LIST_HEAD(&cov->head);
}

/*
 * Record that the given coverage struct is protected by the given lock.
 * Once the lock is dropped the coverage list head will be removed and
 * callers can use that to see that the cov isn't covered any more.  The
 * cov might be on another lock so we're careful to remove it.
 */
void scoutfs_lock_add_coverage(struct super_block *sb,
			       struct scoutfs_lock *lock,
			       struct scoutfs_lock_coverage *cov)
{
	spin_lock(&cov->cov_lock);

	if (cov->lock) {
		spin_lock(&cov->lock->cov_list_lock);
		list_del_init(&cov->head);
		spin_unlock(&cov->lock->cov_list_lock);
		cov->lock = NULL;
	}

	cov->lock = lock;
	spin_lock(&cov->lock->cov_list_lock);
	list_add(&cov->head, &lock->cov_list);
	spin_unlock(&cov->lock->cov_list_lock);

	spin_unlock(&cov->cov_lock);
}

bool scoutfs_lock_is_covered(struct super_block *sb,
			     struct scoutfs_lock_coverage *cov)
{
	bool covered;

	spin_lock(&cov->cov_lock);
	covered = !list_empty_careful(&cov->head);
	spin_unlock(&cov->cov_lock);

	return covered;
}

void scoutfs_lock_del_coverage(struct super_block *sb,
			       struct scoutfs_lock_coverage *cov)
{
	spin_lock(&cov->cov_lock);
	if (cov->lock) {
		spin_lock(&cov->lock->cov_list_lock);
		list_del_init(&cov->head);
		spin_unlock(&cov->lock->cov_list_lock);
		cov->lock = NULL;
	}
	spin_unlock(&cov->cov_lock);
}

static int scoutfs_lock_shrink(struct shrinker *shrink,
			       struct shrink_control *sc)
{
	struct lock_info *linfo = container_of(shrink, struct lock_info,
					       shrinker);
	struct super_block *sb = linfo->sb;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	unsigned long nr;
	int ret;

	nr = sc->nr_to_scan;
	if (nr == 0)
		goto out;

	spin_lock(&linfo->lock);

	list_for_each_entry_safe(lock, tmp, &linfo->lru_list, lru_head) {

		if (nr-- == 0)
			break;

		trace_scoutfs_lock_shrink(sb, lock);
		scoutfs_inc_counter(sb, lock_shrink);

		WARN_ON_ONCE(!lock_idle(lock));

		lock->work_prev_mode = lock->granted_mode;
		lock->work_mode = DLM_LOCK_NL;
		lock->granted_mode = DLM_LOCK_NL;
		queue_work(linfo->workq, &lock->work);

		list_del_init(&lock->lru_head);
		linfo->lru_nr--;
	}
	spin_unlock(&linfo->lock);

out:
	ret = min_t(unsigned long, linfo->lru_nr, INT_MAX);
	trace_scoutfs_lock_shrink_exit(sb, sc->nr_to_scan, ret);
	return ret;
}

void scoutfs_free_unused_locks(struct super_block *sb, unsigned long nr)
{
	struct lock_info *linfo = SCOUTFS_SB(sb)->lock_info;
	struct shrink_control sc = {
		.gfp_mask = GFP_NOFS,
		.nr_to_scan = INT_MAX,
	};

	linfo->shrinker.shrink(&linfo->shrinker, &sc);
}

/* _stop is always called no matter what start returns */
static void *scoutfs_debug_locks_seq_start(struct seq_file *m, loff_t *pos)
	__acquires(linfo->lock)
{
	struct super_block *sb = m->private;
	DECLARE_LOCK_INFO(sb, linfo);
	int id;

	spin_lock(&linfo->lock);

	if (*pos >= INT_MAX)
		return NULL;

	id = *pos;
	return idr_get_next(&linfo->debug_locks_idr, &id);
}

static void *scoutfs_debug_locks_seq_next(struct seq_file *m, void *v,
					  loff_t *pos)
{
	struct super_block *sb = m->private;
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock = v;
	int id;

	id = lock->debug_locks_id + 1;
	lock = idr_get_next(&linfo->debug_locks_idr, &id);
	if (lock)
		*pos = lock->debug_locks_id;
	return lock;
}

static void scoutfs_debug_locks_seq_stop(struct seq_file *m, void *v)
	__releases(linfo->lock)
{
	struct super_block *sb = m->private;
	DECLARE_LOCK_INFO(sb, linfo);

	spin_unlock(&linfo->lock);
}

static int scoutfs_debug_locks_seq_show(struct seq_file *m, void *v)
{
	struct scoutfs_lock *lock = v;

	SK_PCPU(seq_printf(m, "name "LN_FMT" start "SK_FMT" end "SK_FMT" refresh_gen %llu error %d granted %d bast %d prev %d work %d waiters: pr %u ex %u cw %u users: pr %u ex %u cw %u dlmlksb: status %d lkid 0x%x flags 0x%x\n",
			   LN_ARG(&lock->name), SK_ARG(lock->start),
			   SK_ARG(lock->end), lock->refresh_gen, lock->error,
			   lock->granted_mode, lock->bast_mode,
			   lock->work_prev_mode, lock->work_mode,
			   lock->waiters[DLM_LOCK_PR],
			   lock->waiters[DLM_LOCK_EX],
			   lock->waiters[DLM_LOCK_CW],
			   lock->users[DLM_LOCK_PR],
			   lock->users[DLM_LOCK_EX],
			   lock->users[DLM_LOCK_CW],
			   lock->lksb.sb_status,
			   lock->lksb.sb_lkid,
			   lock->lksb.sb_flags));

	return 0;
}

static const struct seq_operations scoutfs_debug_locks_seq_ops = {
	.start =	scoutfs_debug_locks_seq_start,
	.next =		scoutfs_debug_locks_seq_next,
	.stop =		scoutfs_debug_locks_seq_stop,
	.show =		scoutfs_debug_locks_seq_show,
};

static int scoutfs_debug_locks_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &scoutfs_debug_locks_seq_ops);
	if (ret == 0) {
		m = file->private_data;
		m->private = inode->i_private;
	}
	return ret;
}

static const struct file_operations scoutfs_debug_locks_fops = {
	.open	=	scoutfs_debug_locks_open,
	.release =	seq_release,
	.read =		seq_read,
	.llseek =	seq_lseek,
};

/*
 * We're going to be destroying the locks soon.  We shouldn't have any
 * normal task holders that would have prevented unmount.  We can have
 * internal threads blocked in locks.  We force all currently blocked
 * and future lock calls to return -ESHUTDOWN.
 */
void scoutfs_lock_shutdown(struct super_block *sb)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct rb_node *node;

	if (!linfo)
		return;

	trace_scoutfs_lock_shutdown(sb, linfo);

	spin_lock(&linfo->lock);

	linfo->shutdown = true;
	for (node = rb_first(&linfo->lock_tree); node; node = rb_next(node)) {
		lock = rb_entry(node, struct scoutfs_lock, node);
		wake_up(&lock->waitq);
	}

	spin_unlock(&linfo->lock);
}

/*
 * By the time we get here the caller should have called _shutdown() and
 * then called into all the subsystems that held locks to drop them.
 * There should be no active users of locks and all future lock calls
 * should fail.
 *
 * Our job is to make sure nothing references the locks and free them.
 */
void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct rb_node *node;
	int mode;
	int ret;

	if (!linfo)
		return;

	BUG_ON(!linfo->shutdown);

	trace_scoutfs_lock_destroy(sb, linfo);

	/* stop the shrinker from queueing work */
	unregister_shrinker(&linfo->shrinker);

	/* make sure that no one's actively using locks */
	spin_lock(&linfo->lock);
	for (node = rb_first(&linfo->lock_tree); node; node = rb_next(node)) {
		lock = rb_entry(node, struct scoutfs_lock, node);

		for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
			if (lock->waiters[mode] || lock->users[mode]) {
				scoutfs_warn_sk(sb, "lock name "LN_FMT" start "SK_FMT" end "SK_FMT" has mode %d user after shutdown",
						LN_ARG(&lock->name),
						SK_ARG(lock->start),
						SK_ARG(lock->end), mode);
				break;
			}
		}

		if (cancel_delayed_work(&lock->grace_work))
			lock->grace_pending = false;

	}
	spin_unlock(&linfo->lock);

	/* stop the dlm from calling our asts or basts to queue work */
	if (linfo->lockspace) {
		/*
		 * fs/dlm has a harmless but unannotated inversion between their
		 * connection and socket locking that triggers during shutdown
		 * and disables lockdep.
		 */
		lockdep_off();
		ret = dlm_release_lockspace(linfo->lockspace, 2);
		lockdep_on();
		if (ret)
			scoutfs_warn(sb, "dlm lockspace leave failure: %d",
				     ret);
	}

	if (linfo->workq) {
		/* pending grace work queues normal work */
		flush_workqueue(linfo->workq);
		/* now all work won't queue itself */
		destroy_workqueue(linfo->workq);
	}

	/* XXX does anything synchronize with open debugfs fds? */
	debugfs_remove(linfo->debug_locks_dentry);

	/* free our stale locks that now describe released dlm locks */
	spin_lock(&linfo->lock);
	node = rb_first(&linfo->lock_tree);
	while (node) {
		lock = rb_entry(node, struct scoutfs_lock, node);
		node = rb_next(node);
		lock_free(linfo, lock);
	}
	spin_unlock(&linfo->lock);

	idr_destroy(&linfo->debug_locks_idr);
	kfree(linfo);
	sbi->lock_info = NULL;
}

int scoutfs_lock_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	char name[DLM_LOCKSPACE_LEN];
	struct lock_info *linfo;
	int ret;

	/* we use >= 0 to test iv and use modes as an array index */
	BUILD_BUG_ON(DLM_LOCK_IV >= 0);
	BUILD_BUG_ON(DLM_LOCK_NL >= SCOUTFS_LOCK_NR_MODES);
	BUILD_BUG_ON(DLM_LOCK_PR >= SCOUTFS_LOCK_NR_MODES);
	BUILD_BUG_ON(DLM_LOCK_EX >= SCOUTFS_LOCK_NR_MODES);
	BUILD_BUG_ON(DLM_LOCK_CW >= SCOUTFS_LOCK_NR_MODES);

	linfo = kzalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linfo)
		return -ENOMEM;

	linfo->sb = sb;
	spin_lock_init(&linfo->lock);
	linfo->lock_tree = RB_ROOT;
	linfo->lock_range_tree = RB_ROOT;
	linfo->shrinker.shrink = scoutfs_lock_shrink;
	linfo->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&linfo->shrinker);
	INIT_LIST_HEAD(&linfo->lru_list);
	idr_init(&linfo->debug_locks_idr);
	atomic64_set(&linfo->next_refresh_gen, 0);

	sbi->lock_info = linfo;
	trace_scoutfs_lock_setup(sb, linfo);

	linfo->debug_locks_dentry = debugfs_create_file("locks",
					S_IFREG|S_IRUSR, sbi->debug_root, sb,
					&scoutfs_debug_locks_fops);
	if (!linfo->debug_locks_dentry) {
		ret = -ENOMEM;
		goto out;
	}

	linfo->workq = alloc_workqueue("scoutfs_lock_work",
				       WQ_UNBOUND|WQ_HIGHPRI, 0);
	if (!linfo->workq) {
		ret = -ENOMEM;
		goto out;
	}

	snprintf(name, DLM_LOCKSPACE_LEN, "scoutfs_fsid_%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	ret = dlm_new_lockspace(name, sbi->opts.cluster_name,
				DLM_LSFL_FS | DLM_LSFL_NEWEXCL, 8,
				NULL, NULL, NULL, &linfo->lockspace);
	if (ret)
		scoutfs_warn(sb, "dlm lockspace [%s, %s] join failure: %d",
			     sbi->opts.cluster_name, name, ret);
out:
	if (ret)
		scoutfs_lock_destroy(sb);

	return ret;
}
