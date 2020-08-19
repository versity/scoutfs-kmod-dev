/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
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
#include <linux/preempt_mask.h> /* a rhel shed.h needed preempt_offset? */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sort.h>
#include <linux/ctype.h>

#include "super.h"
#include "lock.h"
#include "forest.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "cmp.h"
#include "inode.h"
#include "trans.h"
#include "counters.h"
#include "endian_swap.h"
#include "triggers.h"
#include "tseq.h"
#include "client.h"
#include "data.h"
#include "xattr.h"
#include "item.h"

/*
 * scoutfs uses a lock service to manage item cache consistency between
 * nodes.  We map ranges of item keys to locks and use each lock's modes
 * to govern what can be done with the items under the lock.  Locks are
 * held by mounts who populate, write out, and invalidate their caches
 * as they acquire and release locks.
 *
 * The locking client in a mount sends lock requests to the server.  The
 * server eventually responds with a response that grants access to the
 * lock.  The server then sends a revoke request to the client which
 * tells it the mode that it should reduce the lock to.  If it removes
 * all access to the lock (by revoking it down to a null mode) then the
 * lock is freed.
 *
 * Memory pressure on the client can cause the client to request a null
 * mode from the server so that once its granted the lock can be freed.
 *
 * So far we've only needed a minimal trylock.  We return -EAGAIN if a
 * lock attempt can't immediately match an existing granted lock.  This
 * is fine for the only rare user which can back out of its lock
 * inversion and retry with a full blocking lock.
 *
 * Lock recovery is initiated by the server when it recognizes that
 * we're reconnecting to it while a previous server left a persistenr
 * record of us.  We resend all our pending requests which are deferred
 * until recovery finishes.  The server sends us a recovery request and
 * we respond with all our locks.  Our resent requests are processed
 * relative to that lock state we resend.
 */

#define GRACE_PERIOD_KT	ms_to_ktime(2)

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
	struct work_struct grant_work;
	struct list_head grant_list;
	struct delayed_work inv_dwork;
	struct list_head inv_list;
	struct work_struct shrink_work;
	struct list_head shrink_list;
	atomic64_t next_refresh_gen;
	struct dentry *tseq_dentry;
	struct scoutfs_tseq_tree tseq_tree;
};

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

static bool lock_mode_invalid(int mode)
{
	return (unsigned)mode >= SCOUTFS_LOCK_INVALID;
}

static bool lock_mode_can_read(int mode)
{
	return mode == SCOUTFS_LOCK_READ || mode == SCOUTFS_LOCK_WRITE;
}

static bool lock_mode_can_write(int mode)
{
	return mode == SCOUTFS_LOCK_WRITE || mode == SCOUTFS_LOCK_WRITE_ONLY;
}

/*
 * Returns true if a lock with the granted mode can satisfy a requested
 * mode.  This is directional.  A read lock is satisfied by a write lock
 * but not vice versa.
 */
static bool lock_modes_match(int granted, int requested)
{
	return (granted == requested) ||
	       (granted == SCOUTFS_LOCK_WRITE &&
		requested == SCOUTFS_LOCK_READ);
}

/*
 * invalidate cached data associated with an inode whose lock is going
 * away.
 */
static void invalidate_inode(struct super_block *sb, u64 ino)
{
	struct inode *inode;

	inode = scoutfs_ilookup(sb, ino);
	if (inode) {
		scoutfs_inc_counter(sb, lock_invalidate_inode);
		if (S_ISREG(inode->i_mode)) {
			truncate_inode_pages(inode->i_mapping, 0);
			scoutfs_data_wait_changed(inode);
		}
		iput(inode);
	}
}

/*
 * Invalidate caches associated with this lock.  Either we're
 * invalidating a write to a read or we're invalidating to null.  We
 * always have to write out dirty items if there are any.  We can only
 * leave cached items behind in the case of invalidating to a read lock.
 */
static int lock_invalidate(struct super_block *sb, struct scoutfs_lock *lock,
			   int prev, int mode)
{
	struct scoutfs_lock_coverage *cov;
	struct scoutfs_lock_coverage *tmp;
	u64 ino, last;
	int ret = 0;

	trace_scoutfs_lock_invalidate(sb, lock);

	/* verify assertion made by comment above */
	BUG_ON(!(prev == SCOUTFS_LOCK_WRITE && mode == SCOUTFS_LOCK_READ) &&
	         mode != SCOUTFS_LOCK_NULL);

	/* sync when a write lock could have dirtied the current transaction */
	if (lock_mode_can_write(prev) &&
	    (lock->dirty_trans_seq == scoutfs_trans_sample_seq(sb))) {
		scoutfs_inc_counter(sb, lock_invalidate_sync);
		ret = scoutfs_trans_sync(sb, 1);
		if (ret < 0)
			return ret;
	}

	/* have to invalidate if we're not in the only usable case */
	if (!(prev == SCOUTFS_LOCK_WRITE && mode == SCOUTFS_LOCK_READ)) {
retry:
		/* remove cov items to tell users that their cache is stale */
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
			scoutfs_inc_counter(sb, lock_invalidate_coverage);
		}
		spin_unlock(&lock->cov_list_lock);

		if (lock->start.sk_zone == SCOUTFS_FS_ZONE) {
			ino = le64_to_cpu(lock->start.ski_ino);
			last = le64_to_cpu(lock->end.ski_ino);
			while (ino <= last) {
				invalidate_inode(sb, ino);
				ino++;
			}
		}

		scoutfs_item_invalidate(sb, &lock->start, &lock->end);
	}

	return ret;
}

static void lock_free(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	struct super_block *sb = lock->sb;

	assert_spin_locked(&linfo->lock);

	trace_scoutfs_lock_free(sb, lock);
	scoutfs_inc_counter(sb, lock_free);

	/* manually checking lock_idle gives identifying line numbers */
	BUG_ON(lock->request_pending);
	BUG_ON(lock->invalidate_pending);
	BUG_ON(lock->waiters[SCOUTFS_LOCK_READ]);
	BUG_ON(lock->waiters[SCOUTFS_LOCK_WRITE]);
	BUG_ON(lock->waiters[SCOUTFS_LOCK_WRITE_ONLY]);
	BUG_ON(lock->users[SCOUTFS_LOCK_READ]);
	BUG_ON(lock->users[SCOUTFS_LOCK_WRITE]);
	BUG_ON(lock->users[SCOUTFS_LOCK_WRITE_ONLY]);
	BUG_ON(!linfo->shutdown && lock->mode != SCOUTFS_LOCK_NULL);
	BUG_ON(!RB_EMPTY_NODE(&lock->node));
	BUG_ON(!RB_EMPTY_NODE(&lock->range_node));
	BUG_ON(!list_empty(&lock->lru_head));
	BUG_ON(!list_empty(&lock->grant_head));
	BUG_ON(!list_empty(&lock->inv_head));
	BUG_ON(!list_empty(&lock->shrink_head));
	BUG_ON(!list_empty(&lock->cov_list));

	scoutfs_forest_clear_lock(sb, lock);
	kfree(lock);
}

static struct scoutfs_lock *lock_alloc(struct super_block *sb,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end)

{
	struct scoutfs_lock *lock;

	if (WARN_ON_ONCE(!start || !end))
		return NULL;

	lock = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (lock == NULL)
		return NULL;

	scoutfs_inc_counter(sb, lock_alloc);

	RB_CLEAR_NODE(&lock->node);
	RB_CLEAR_NODE(&lock->range_node);
	INIT_LIST_HEAD(&lock->lru_head);
	INIT_LIST_HEAD(&lock->grant_head);
	INIT_LIST_HEAD(&lock->inv_head);
	INIT_LIST_HEAD(&lock->shrink_head);
	spin_lock_init(&lock->cov_list_lock);
	INIT_LIST_HEAD(&lock->cov_list);

	lock->start = *start;
	lock->end = *end;
	lock->sb = sb;
	init_waitqueue_head(&lock->waitq);
	lock->mode = SCOUTFS_LOCK_NULL;

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
 * Returns true if there are any mode counts that match with the desired
 * mode.  There can be other non-matching counts as well but we're only
 * testing for the existence of any matching counts.
 */
static bool lock_count_match_exists(int desired, unsigned int *counts)
{
	int mode;

	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (counts[mode] && lock_modes_match(desired, mode))
			return true;
	}

	return false;
}

/*
 * An idle lock has nothing going on.  It can be present in the lru and
 * can be freed by the final put when it has a null mode.
 */
static bool lock_idle(struct scoutfs_lock *lock)
{
	int mode;

	if (lock->request_pending || lock->invalidate_pending)
		return false;

	for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
		if (lock->waiters[mode] || lock->users[mode])
			return false;
	}

	return true;
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

		cmp = scoutfs_key_compare_ranges(&ins->start, &ins->end,
						 &lock->start, &lock->end);
		if (WARN_ON_ONCE(cmp == 0)) {
			scoutfs_warn(sb, "inserting lock start "SK_FMT" end "SK_FMT" overlaps with existing lock start "SK_FMT" end "SK_FMT,
				     SK_ARG(&ins->start), SK_ARG(&ins->end),
				     SK_ARG(&lock->start), SK_ARG(&lock->end));
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

/* returns true if the lock was inserted at its start key */
static bool lock_insert(struct super_block *sb, struct scoutfs_lock *ins)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct rb_node *parent;
	struct rb_node **node;
	int cmp;

	assert_spin_locked(&linfo->lock);

	node = &linfo->lock_tree.rb_node;
	parent = NULL;
	while (*node) {
		parent = *node;
		lock = container_of(*node, struct scoutfs_lock, node);

		cmp = scoutfs_key_compare(&ins->start, &lock->start);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else if (cmp > 0)
			node = &(*node)->rb_right;
		else
			return false;
	}

	if (!insert_range_node(sb, ins))
		return false;

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, &linfo->lock_tree);

	scoutfs_tseq_add(&linfo->tseq_tree, &ins->tseq_entry);

	return true;
}

static void lock_remove(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	assert_spin_locked(&linfo->lock);

	rb_erase(&lock->node, &linfo->lock_tree);
	RB_CLEAR_NODE(&lock->node);
	rb_erase(&lock->range_node, &linfo->lock_range_tree);
	RB_CLEAR_NODE(&lock->range_node);

	scoutfs_tseq_del(&linfo->tseq_tree, &lock->tseq_entry);
}

static struct scoutfs_lock *lock_lookup(struct super_block *sb,
					struct scoutfs_key *start,
					struct scoutfs_lock **next)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct rb_node *node = linfo->lock_tree.rb_node;
	struct scoutfs_lock *lock;
	int cmp;

	assert_spin_locked(&linfo->lock);

	if (next)
		*next = NULL;

	while (node) {
		lock = container_of(node, struct scoutfs_lock, node);

		cmp = scoutfs_key_compare(start, &lock->start);
		if (cmp < 0) {
			if (next)
				*next = lock;
			node = node->rb_left;
		} else if (cmp > 0) {
			node = node->rb_right;
		} else {
			return lock;
		}
	}

	return NULL;
}

static void __lock_del_lru(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	assert_spin_locked(&linfo->lock);

	if (!list_empty(&lock->lru_head)) {
		list_del_init(&lock->lru_head);
		linfo->lru_nr--;
	}
}

/*
 * Get a lock and remove it from the lru.  The caller must set state on
 * the lock that indicates that it's busy before dropping the lock.
 * Then later they call add_lru_or_free once they've cleared that state.
 */
static struct scoutfs_lock *get_lock(struct super_block *sb,
				     struct scoutfs_key *start)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;

	assert_spin_locked(&linfo->lock);

	lock = lock_lookup(sb, start, NULL);
	if (lock)
		__lock_del_lru(linfo, lock);

	return lock;
}

/*
 * Get a lock, creating it if it doesn't exist.  The caller must treat
 * the lock like it came from get lock (mark sate, drop lock, clear
 * state, put lock).  Allocated locks aren't on the lru.
 */
static struct scoutfs_lock *create_lock(struct super_block *sb,
				 	struct scoutfs_key *start,
					struct scoutfs_key *end)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;

	assert_spin_locked(&linfo->lock);

	lock = get_lock(sb, start);
	if (!lock) {
		spin_unlock(&linfo->lock);
		lock = lock_alloc(sb, start, end);
		spin_lock(&linfo->lock);

		if (lock) {
			if (!lock_insert(sb, lock)) {
				lock_free(linfo, lock);
				lock = get_lock(sb, start);
			}
		}
	}

	return lock;
}

/*
 * The caller is done using a lock and has cleared state that used to
 * indicate that the lock wasn't idle.  If it really is idle then we
 * either free it if it's null or put it back on the lru.
 */
static void put_lock(struct lock_info *linfo,struct scoutfs_lock *lock)
{
	assert_spin_locked(&linfo->lock);

	if (lock_idle(lock)) {
		if (lock->mode != SCOUTFS_LOCK_NULL) {
			list_add_tail(&lock->lru_head, &linfo->lru_list);
			linfo->lru_nr++;
		} else {
			lock_remove(linfo, lock);
			lock_free(linfo, lock);
		}
	}
}

/*
 * Locks have a grace period that extends after activity and prevents
 * invalidation.  It's intended to let nodes do reasonable batches of
 * work as locks ping pong between nodes that are doing conflicting
 * work.
 */
static void extend_grace(struct super_block *sb, struct scoutfs_lock *lock)
{
	ktime_t now = ktime_get();

	if (ktime_after(now, lock->grace_deadline))
		scoutfs_inc_counter(sb, lock_grace_set);
	else
		scoutfs_inc_counter(sb, lock_grace_extended);

	lock->grace_deadline = ktime_add(now, GRACE_PERIOD_KT);
}

static void queue_grant_work(struct lock_info *linfo)
{
	assert_spin_locked(&linfo->lock);

	if (!list_empty(&linfo->grant_list) && !linfo->shutdown)
		queue_work(linfo->workq, &linfo->grant_work);
}

/*
 * We immediately queue work on the assumption that the caller might
 * have made a change (set a lock mode) which can let one of the
 * invalidating locks make forward progress, even if other locks are
 * waiting for their grace period to elapse.  It's a trade-off between
 * invalidation latency and burning cpu repeatedly finding that locks
 * are still in their grace period.
 */
static void queue_inv_work(struct lock_info *linfo)
{
	assert_spin_locked(&linfo->lock);

	if (!list_empty(&linfo->inv_list) && !linfo->shutdown)
		mod_delayed_work(linfo->workq, &linfo->inv_dwork, 0);
}

/*
 * The given lock is processing a received a grant response.  Trigger a
 * bug if the cache is inconsistent.
 *
 * We only have two modes that can create dirty items.  We can't have
 * dirty items when transitioning from write_only to write because the
 * writer can't trust the cached items in the cache for reading.  And we
 * don't currently transition directly from write to write_only, we
 * first go through null.  So if we have dirty items as we're granted a
 * mode it's always incorrect.
 *
 * And we can't have cached items that we're going to use for reading if
 * the previous mode didn't allow reading.
 *
 * Inconsistencies have come from all sorts of bugs: invalidation missed
 * items, the cache was populated outside of locking coverage, lock
 * holders performed the wrong item operations under their lock,
 * overlapping locks, out of order granting or invalidating, etc.
 */
static void bug_on_inconsistent_grant_cache(struct super_block *sb,
					    struct scoutfs_lock *lock,
					    int old_mode, int new_mode)
{
	bool cached;
	bool dirty;

	cached = scoutfs_item_range_cached(sb, &lock->start, &lock->end,
					   &dirty);
	if (dirty ||
	    (cached && (!lock_mode_can_read(old_mode) ||
			!lock_mode_can_read(new_mode)))) {
		scoutfs_err(sb, "granted lock item cache inconsistency, cached %u dirty %u old_mode %d new_mode %d: start "SK_FMT" end "SK_FMT" refresh_gen %llu mode %u waiters: rd %u wr %u wo %u users: rd %u wr %u wo %u",
			   cached, dirty, old_mode, new_mode, SK_ARG(&lock->start),
			   SK_ARG(&lock->end), lock->refresh_gen, lock->mode,
			   lock->waiters[SCOUTFS_LOCK_READ],
			   lock->waiters[SCOUTFS_LOCK_WRITE],
			   lock->waiters[SCOUTFS_LOCK_WRITE_ONLY],
			   lock->users[SCOUTFS_LOCK_READ],
			   lock->users[SCOUTFS_LOCK_WRITE],
			   lock->users[SCOUTFS_LOCK_WRITE_ONLY]);
		BUG();
	}
}

/*
 * Each lock has received a grant response message from the server.
 *
 * Grant responses can be reordered with incoming invalidation requests
 * from the server so we have to be careful to only set the new mode
 * once the old mode matches.
 *
 * We extend the grace period as we grant the lock if there is a waiting
 * locker who can use the lock.  This stops invalidation from pulling
 * the granted lock out from under the requester, resulting in a lot of
 * churn with no forward progress.  Using the grace period avoids having
 * to identify a specific waiter and give it an acquired lock.  It's
 * also very similar to waking up the locker and having it win the race
 * against the invalidation.  In that case they'd extend the grace
 * period anyway as they unlock.
 */
static void lock_grant_worker(struct work_struct *work)
{
	struct lock_info *linfo = container_of(work, struct lock_info,
					       grant_work);
	struct super_block *sb = linfo->sb;
	struct scoutfs_net_lock_grant_response *gr;
	struct scoutfs_net_lock *nl;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;

	scoutfs_inc_counter(sb, lock_grant_work);

	spin_lock(&linfo->lock);

	list_for_each_entry_safe(lock, tmp, &linfo->grant_list, grant_head) {
		gr = &lock->grant_resp;
		nl = &lock->grant_resp.nl;

		/* wait for reordered invalidation to finish */
		if (lock->mode != nl->old_mode)
			continue;

		bug_on_inconsistent_grant_cache(sb, lock, nl->old_mode,
						nl->new_mode);

		if (!lock_mode_can_read(nl->old_mode) &&
		    lock_mode_can_read(nl->new_mode)) {
			lock->refresh_gen =
				atomic64_inc_return(&linfo->next_refresh_gen);
		}

		lock->request_pending = 0;
		lock->mode = nl->new_mode;
		lock->write_version = le64_to_cpu(nl->write_version);
		lock->roots = gr->roots;

		if (lock_count_match_exists(nl->new_mode, lock->waiters))
			extend_grace(sb, lock);

		trace_scoutfs_lock_granted(sb, lock);
		list_del_init(&lock->grant_head);
		wake_up(&lock->waitq);
		put_lock(linfo, lock);
	}

	/* invalidations might be waiting for our reordered grant */
	queue_inv_work(linfo);
	spin_unlock(&linfo->lock);
}

/*
 * The client is receiving a grant response message from the server.  We
 * find the lock, record the response, and add it to the list for grant
 * work to process.
 */
int scoutfs_lock_grant_response(struct super_block *sb,
				struct scoutfs_net_lock_grant_response *gr)
{
	struct scoutfs_net_lock *nl = &gr->nl;
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;

	scoutfs_inc_counter(sb, lock_grant_response);

	spin_lock(&linfo->lock);

	/* lock must already be busy with request_pending */
	lock = lock_lookup(sb, &nl->key, NULL);
	BUG_ON(!lock);
	trace_scoutfs_lock_grant_response(sb, lock);
	BUG_ON(!lock->request_pending);

	lock->grant_resp = *gr;
	list_add_tail(&lock->grant_head, &linfo->grant_list);
	queue_grant_work(linfo);

	spin_unlock(&linfo->lock);

	return 0;
}

/*
 * Each lock has received a lock invalidation request from the server
 * which specifies a new mode for the lock.  The server will only send
 * one invalidation request at a time for each lock.
 *
 * This is an unsolicited request from the server so it can arrive at
 * any time after we make the server aware of the lock by initially
 * requesting it.  We wait for users of the current mode to unlock
 * before invalidating.
 *
 * This can arrive on behalf of our request for a mode that conflicts
 * with our current mode.  We have to proceed while we have a request
 * pending.  We can also be racing with shrink requests being sent while
 * we're invalidating.
 *
 * This can be processed concurrently and experience reordering with a
 * grant response sent back-to-back from the server.  We carefully only
 * invalidate once the lock mode matches what the server told us to
 * invalidate.
 *
 * We delay invalidation processing until a grace period has elapsed
 * since the last unlock.  The intent is to let users do a reasonable
 * batch of work before dropping the lock.  Continuous unlocking can
 * continuously extend the deadline.
 *
 * Before we start invalidating the lock we set the lock to the new
 * mode, preventing further incompatible users of the old mode from
 * using the lock while we're invalidating.
 *
 * This does a lot of serialized inode invalidation in one context and
 * performs a lot of repeated calls to sync.  It would be nice to get
 * some concurrent inode invalidation and to more carefully only call
 * sync when needed.
 */
static void lock_invalidate_worker(struct work_struct *work)
{
	struct lock_info *linfo = container_of(work, struct lock_info,
					       inv_dwork.work);
	struct super_block *sb = linfo->sb;
	struct scoutfs_net_lock *nl;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	unsigned long delay = MAX_JIFFY_OFFSET;
	ktime_t now = ktime_get();
	ktime_t deadline;
	LIST_HEAD(ready);
	u64 net_id;
	int ret;

	scoutfs_inc_counter(sb, lock_invalidate_work);

	spin_lock(&linfo->lock);

	list_for_each_entry_safe(lock, tmp, &linfo->inv_list, inv_head) {
		nl = &lock->inv_nl;

		/* skip if grace hasn't elapsed, record earliest */
		deadline = lock->grace_deadline;
		if (ktime_before(now, deadline)) {
			delay = min(delay,
				    nsecs_to_jiffies(ktime_to_ns(
						ktime_sub(deadline, now))));
			scoutfs_inc_counter(linfo->sb, lock_grace_wait);
			continue;
		}

		/* wait for reordered grant to finish */
		if (lock->mode != nl->old_mode)
			continue;

		/* wait until incompatible holders unlock */
		if (!lock_counts_match(nl->new_mode, lock->users))
			continue;

		/* set the new mode, no incompatible users during inval */
		lock->mode = nl->new_mode;

		/* move everyone that's ready to our private list */
		list_move_tail(&lock->inv_head, &ready);
	}

	spin_unlock(&linfo->lock);

	if (list_empty(&ready))
		goto out;

	/* invalidate once the lock is read */
	list_for_each_entry(lock, &ready, inv_head) {
		nl = &lock->inv_nl;
		net_id = lock->inv_net_id;

		ret = lock_invalidate(sb, lock, nl->old_mode, nl->new_mode);
		BUG_ON(ret);

		/* respond with the key and modes from the request */
		ret = scoutfs_client_lock_response(sb, net_id, nl);
		BUG_ON(ret);

		scoutfs_inc_counter(sb, lock_invalidate_response);
	}

	/* and finish all the invalidated locks */
	spin_lock(&linfo->lock);

	list_for_each_entry_safe(lock, tmp, &ready, inv_head) {
		list_del_init(&lock->inv_head);

		lock->invalidate_pending = 0;
		trace_scoutfs_lock_invalidated(sb, lock);
		wake_up(&lock->waitq);
		put_lock(linfo, lock);
	}

	/* grant might have been waiting for invalidate request */
	queue_grant_work(linfo);
	spin_unlock(&linfo->lock);

out:
	/* queue delayed work if invalidations waiting on grace deadline */
	if (delay != MAX_JIFFY_OFFSET)
		queue_delayed_work(linfo->workq, &linfo->inv_dwork, delay);
}

/*
 * Record an incoming invalidate request from the server and add its lock
 * to the list for processing.
 *
 * This is trusting the server and will crash if it's sent bad requests :/
 */
int scoutfs_lock_invalidate_request(struct super_block *sb, u64 net_id,
				    struct scoutfs_net_lock *nl)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;

	scoutfs_inc_counter(sb, lock_invalidate_request);

	spin_lock(&linfo->lock);
	lock = get_lock(sb, &nl->key);
	BUG_ON(!lock);
	if (lock) {
		BUG_ON(lock->invalidate_pending);
		lock->invalidate_pending = 1;
		lock->inv_nl = *nl;
		lock->inv_net_id = net_id;
		list_add_tail(&lock->inv_head, &linfo->inv_list);
		trace_scoutfs_lock_invalidate_request(sb, lock);
		queue_inv_work(linfo);
	}
	spin_unlock(&linfo->lock);

	return 0;
}

/*
 * The server is asking us to send them as many locks as we can starting
 * with the given key.  We'll send a response with 0 locks to indicate
 * that we've sent all our locks.  This is called in client processing
 * so the client won't try to reconnect to another server until we
 * return.
 */
int scoutfs_lock_recover_request(struct super_block *sb, u64 net_id,
				 struct scoutfs_key *key)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_net_lock_recover *nlr;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *next;
	struct rb_node *node;
	int ret;
	int i;

	scoutfs_inc_counter(sb, lock_recover_request);

	nlr = kmalloc(offsetof(struct scoutfs_net_lock_recover,
			       locks[SCOUTFS_NET_LOCK_MAX_RECOVER_NR]),
		      GFP_NOFS);
	if (!nlr)
		return -ENOMEM;

	spin_lock(&linfo->lock);

	lock = lock_lookup(sb, key, &next) ?: next;

	for (i = 0; lock && i < SCOUTFS_NET_LOCK_MAX_RECOVER_NR; i++) {

		nlr->locks[i].key = lock->start;
		nlr->locks[i].old_mode = lock->mode;
		nlr->locks[i].new_mode = lock->mode;

		node = rb_next(&lock->node);
		if (node)
			lock = rb_entry(node, struct scoutfs_lock, node);
		else
			lock = NULL;
	}

	nlr->nr = cpu_to_le16(i);

	spin_unlock(&linfo->lock);

	ret = scoutfs_client_lock_recover_response(sb, net_id, nlr);
	kfree(nlr);
	return ret;
}

static bool lock_wait_cond(struct super_block *sb, struct scoutfs_lock *lock,
			   int mode)
{
	DECLARE_LOCK_INFO(sb, linfo);
	bool wake;

	spin_lock(&linfo->lock);
	wake = linfo->shutdown || lock_modes_match(lock->mode, mode) ||
	       !lock->request_pending;
	spin_unlock(&linfo->lock);

	if (!wake)
		scoutfs_inc_counter(sb, lock_wait);

	return wake;
}

static bool lock_flags_invalid(int flags)
{
	return flags & SCOUTFS_LKF_INVALID;
}

/*
 * Acquire a coherent lock on the given range of keys.  On success the
 * caller can use the given mode to interact with the item cache.  While
 * holding the lock the cache won't be invalidated and other conflicting
 * lock users will be serialized.  The item cache can be invalidated
 * once the lock is unlocked.
 *
 * If we don't have a granted lock then we send a request for our
 * desired mode if there isn't one in flight already.  This can be
 * racing with an invalidation request from the server.  The server
 * won't process our request until it receives our invalidation
 * response.
 */
static int lock_key_range(struct super_block *sb, int mode, int flags,
			  struct scoutfs_key *start, struct scoutfs_key *end,
			  struct scoutfs_lock **ret_lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct scoutfs_net_lock nl;
	bool should_send;
	int ret;

	scoutfs_inc_counter(sb, lock_lock);

	*ret_lock = NULL;

	if (WARN_ON_ONCE(!start || !end) ||
	    WARN_ON_ONCE(lock_mode_invalid(mode)) ||
	    WARN_ON_ONCE(lock_flags_invalid(flags)))
		return -EINVAL;

	/* maybe catch _setup() and _shutdown order mistakes */
	if (WARN_ON_ONCE(!linfo || linfo->shutdown))
		return -ENOLCK;

	/* have to lock before entering transactions */
	if (WARN_ON_ONCE(scoutfs_trans_held()))
		return -EDEADLK;

	spin_lock(&linfo->lock);

	/* drops and re-acquires lock if it allocates */
	lock = create_lock(sb, start, end);
	if (!lock) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* the waiters count is only used by debugging output */
	lock_inc_count(lock->waiters, mode);

	for (;;) {
		if (linfo->shutdown) {
			ret = -ESHUTDOWN;
			break;
		}

		/* the fast path where we can use the granted mode */
		if (lock_modes_match(lock->mode, mode)) {
			lock_inc_count(lock->users, mode);
			*ret_lock = lock;
			ret = 0;
			break;
		}

		/* non-blocking callers don't wait or send requests */
		if (flags & SCOUTFS_LKF_NONBLOCK) {
			scoutfs_inc_counter(sb, lock_nonblock_eagain);
			ret = -EAGAIN;
			break;
		}

		if (!lock->request_pending) {
			lock->request_pending = 1;
			should_send = true;
		} else {
			should_send = false;
		}

		spin_unlock(&linfo->lock);

		if (should_send) {
			nl.key = lock->start;
			nl.old_mode = lock->mode;
			nl.new_mode = mode;

			ret = scoutfs_client_lock_request(sb, &nl);
			if (ret) {
				spin_lock(&linfo->lock);
				lock->request_pending = 0;
				break;
			}
			scoutfs_inc_counter(sb, lock_grant_request);
		}

		trace_scoutfs_lock_wait(sb, lock);

		ret = wait_event_interruptible(lock->waitq,
					       lock_wait_cond(sb, lock, mode));
		spin_lock(&linfo->lock);
		if (ret)
			break;
	}

	lock_dec_count(lock->waiters, mode);

	if (ret == 0)
		trace_scoutfs_lock_locked(sb, lock);
	wake_up(&lock->waitq);
	put_lock(linfo, lock);

out_unlock:
	spin_unlock(&linfo->lock);

	if (ret && ret != -EAGAIN && ret != -ERESTARTSYS)
		scoutfs_inc_counter(sb, lock_lock_error);

	return ret;
}

int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_key start;
	struct scoutfs_key end;

	scoutfs_key_set_zeros(&start);
	start.sk_zone = SCOUTFS_FS_ZONE;
	start.ski_ino = cpu_to_le64(ino & ~(u64)SCOUTFS_LOCK_INODE_GROUP_MASK);

	scoutfs_key_set_ones(&end);
	end.sk_zone = SCOUTFS_FS_ZONE;
	end.ski_ino = cpu_to_le64(ino | SCOUTFS_LOCK_INODE_GROUP_MASK);

	return lock_key_range(sb, mode, flags, &start, &end, ret_lock);
}

/*
 * Acquire a lock on an inode.
 *
 * _REFRESH_INODE indicates that the caller needs to have the vfs inode
 * fields current with respect to lock coverage.  The lock's refresh_gen
 * is incremented as new locks are acquired and then indicates that an
 * old inode with a smaller refresh_gen needs to be refreshed.
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
 * The rename lock is magical because it's global.
 */
int scoutfs_lock_rename(struct super_block *sb, int mode, int flags,
			struct scoutfs_lock **lock)
{
	struct scoutfs_key key = {
		.sk_zone = SCOUTFS_LOCK_ZONE,
		.sk_type = SCOUTFS_RENAME_TYPE,
	};

	return lock_key_range(sb, mode, flags, &key, &key, lock);
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
				       struct scoutfs_key *start,
				       struct scoutfs_key *end)
{
	u64 start_major = major & ~SCOUTFS_LOCK_SEQ_GROUP_MASK;
	u64 end_major = major | SCOUTFS_LOCK_SEQ_GROUP_MASK;

	BUG_ON(type != SCOUTFS_INODE_INDEX_META_SEQ_TYPE &&
	       type != SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE);

	if (start)
		scoutfs_inode_init_index_key(start, type, start_major, 0, 0);

	if (end)
		scoutfs_inode_init_index_key(end, type, end_major, U32_MAX,
					     U64_MAX);
}

/*
 * Lock the given index item.  We use the index masks to calculate the
 * start and end key values that are covered by the lock.
 */
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_key start;
	struct scoutfs_key end;

	scoutfs_lock_get_index_item_range(type, major, ino, &start, &end);

	return lock_key_range(sb, mode, 0, &start, &end, ret_lock);
}

/*
 * The rid lock protects a mount's private persistent items in the rid
 * zone.  It's held for the duration of the mount.  It lets the mount
 * modify the rid items at will and signals to other mounts that we're
 * still alive and our rid items shouldn't be reclaimed.
 *
 * Being held for the entire mount prevents other nodes from reclaiming
 * our items, like free blocks, when it would make sense for them to be
 * able to.  Maybe we have a bunch free and they're trying to allocate
 * and are getting ENOSPC.
 */
int scoutfs_lock_rid(struct super_block *sb, int mode, int flags,
		     u64 rid, struct scoutfs_lock **lock)
{
	struct scoutfs_key start;
	struct scoutfs_key end;

	scoutfs_key_set_zeros(&start);
	start.sk_zone = SCOUTFS_RID_ZONE;
	start.sko_rid = cpu_to_le64(rid);

	scoutfs_key_set_ones(&end);
	end.sk_zone = SCOUTFS_RID_ZONE;
	end.sko_rid = cpu_to_le64(rid);

	return lock_key_range(sb, mode, flags, &start, &end, lock);
}

/*
 * As we unlock we always extend the grace period to give the caller
 * another pass at the lock before its invalidated.
 */
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock, int mode)
{
	DECLARE_LOCK_INFO(sb, linfo);

	if (IS_ERR_OR_NULL(lock))
		return;

	scoutfs_inc_counter(sb, lock_unlock);

	spin_lock(&linfo->lock);

	lock_dec_count(lock->users, mode);
	extend_grace(sb, lock);
	if (lock_mode_can_write(mode))
		lock->dirty_trans_seq = scoutfs_trans_sample_seq(sb);

	trace_scoutfs_lock_unlock(sb, lock);
	wake_up(&lock->waitq);
	queue_inv_work(linfo);
	put_lock(linfo, lock);

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

/*
 * Returns true if the given lock protects the given access of the given
 * key.  The lock must have a current granted mode that is compatible
 * with the access mode and the access key must be in the lock's key
 * range.
 *
 * This is called by lock holders who's use of the lock must be preventing
 * the mode and keys from changing.
 */
bool scoutfs_lock_protected(struct scoutfs_lock *lock, struct scoutfs_key *key,
			    int mode)
{
	signed char lock_mode = ACCESS_ONCE(lock->mode);

	return lock_modes_match(lock_mode, mode) &&
	       scoutfs_key_compare_ranges(key, key,
					  &lock->start, &lock->end) == 0;
}

/*
 * The shrink callback got the lock, marked it request_pending, and put
 * it on the shrink list.  We send a null request and the lock will be
 * freed by the response once all users drain.  If this races with
 * invalidation then the server will only send the grant response once
 * the invalidation is finished.
 */
static void lock_shrink_worker(struct work_struct *work)
{
	struct lock_info *linfo = container_of(work, struct lock_info,
					       shrink_work);
	struct super_block *sb = linfo->sb;
	struct scoutfs_net_lock nl;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	LIST_HEAD(list);
	int ret;

	scoutfs_inc_counter(sb, lock_shrink_work);

	spin_lock(&linfo->lock);
	list_splice_init(&linfo->shrink_list, &list);
	spin_unlock(&linfo->lock);

	list_for_each_entry_safe(lock, tmp, &list, shrink_head) {
		list_del_init(&lock->shrink_head);

		/* unlocked lock access, but should be stable since we queued */
		nl.key = lock->start;
		nl.old_mode = lock->mode;
		nl.new_mode = SCOUTFS_LOCK_NULL;

		ret = scoutfs_client_lock_request(sb, &nl);
		if (ret) {
			/* oh well, not freeing */
			scoutfs_inc_counter(sb, lock_shrink_aborted);

			spin_lock(&linfo->lock);

			lock->request_pending = 0;
			wake_up(&lock->waitq);
			put_lock(linfo, lock);

			spin_unlock(&linfo->lock);
		}
	}
}

/*
 * Start the shrinking process for locks on the lru.  If a lock is on
 * the lru then it can't have any active users.  We don't want to block
 * or allocate here so all we do is get the lock, mark it request
 * pending, and kick off the work.  The work sends a null request and
 * eventually the lock is freed by its response.
 *
 * Only a racing lock attempt that isn't matched can prevent the lock
 * from being freed.  It'll block waiting to send its request for its
 * mode which will prevent the lock from being freed when the null
 * response arrives.
 */
static int scoutfs_lock_shrink(struct shrinker *shrink,
			       struct shrink_control *sc)
{
	struct lock_info *linfo = container_of(shrink, struct lock_info,
					       shrinker);
	struct super_block *sb = linfo->sb;
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	unsigned long nr;
	bool added = false;
	int ret;

	nr = sc->nr_to_scan;
	if (nr == 0)
		goto out;

	spin_lock(&linfo->lock);

restart:
	list_for_each_entry_safe(lock, tmp, &linfo->lru_list, lru_head) {

		BUG_ON(!lock_idle(lock));
		BUG_ON(lock->mode == SCOUTFS_LOCK_NULL);
		BUG_ON(!list_empty(&lock->shrink_head));

		if (linfo->shutdown || nr-- == 0)
			break;

		__lock_del_lru(linfo, lock);
		lock->request_pending = 1;
		list_add_tail(&lock->shrink_head, &linfo->shrink_list);
		added = true;

		scoutfs_inc_counter(sb, lock_shrink_attempted);
		trace_scoutfs_lock_shrink(sb, lock);

		/* could have bazillions of idle locks */
		if (cond_resched_lock(&linfo->lock))
			goto restart;
	}

	spin_unlock(&linfo->lock);

	if (added)
		queue_work(linfo->workq, &linfo->shrink_work);

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

static void lock_tseq_show(struct seq_file *m, struct scoutfs_tseq_entry *ent)
{
	struct scoutfs_lock *lock =
		container_of(ent, struct scoutfs_lock, tseq_entry);

	seq_printf(m, "start "SK_FMT" end "SK_FMT" refresh_gen %llu mode %d waiters: rd %u wr %u wo %u users: rd %u wr %u wo %u\n",
			   SK_ARG(&lock->start), SK_ARG(&lock->end),
			   lock->refresh_gen, lock->mode,
			   lock->waiters[SCOUTFS_LOCK_READ],
			   lock->waiters[SCOUTFS_LOCK_WRITE],
			   lock->waiters[SCOUTFS_LOCK_WRITE_ONLY],
			   lock->users[SCOUTFS_LOCK_READ],
			   lock->users[SCOUTFS_LOCK_WRITE],
			   lock->users[SCOUTFS_LOCK_WRITE_ONLY]);
}

/*
 * The caller is going to be calling _destroy soon and, critically, is
 * about to shutdown networking before calling us so that we don't get
 * any callbacks while we're destroying.  We have to ensure that we
 * won't call networking after this returns.
 *
 * Internal fs threads can be using locking, and locking can have async
 * work pending.  We use ->shutdown to force callers to return
 * -ESHUTDOWN and to prevent the future queueing of work that could call
 * networking.  Locks whose work is stopped will be torn down by _destroy.
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

	flush_work(&linfo->grant_work);
	flush_delayed_work(&linfo->inv_dwork);
	flush_work(&linfo->shrink_work);
}

/*
 * By the time we get here the caller should have called _shutdown() and
 * then called into all the subsystems that held locks to drop them.
 * There should be no active users of locks and all future lock calls
 * should fail.
 *
 * The client networking connection will have been shutdown so we don't
 * get any request or response processing calls.
 *
 * Our job is to make sure nothing references the remaining locks and
 * free them.
 */
void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct rb_node *node;
	int mode;

	if (!linfo)
		return;

	trace_scoutfs_lock_destroy(sb, linfo);

	/* stop the shrinker from queueing work */
	unregister_shrinker(&linfo->shrinker);

	/* make sure that no one's actively using locks */
	spin_lock(&linfo->lock);
	for (node = rb_first(&linfo->lock_tree); node; node = rb_next(node)) {
		lock = rb_entry(node, struct scoutfs_lock, node);

		for (mode = 0; mode < SCOUTFS_LOCK_NR_MODES; mode++) {
			if (lock->waiters[mode] || lock->users[mode]) {
				scoutfs_warn(sb, "lock start "SK_FMT" end "SK_FMT" has mode %d user after shutdown",
						SK_ARG(&lock->start),
						SK_ARG(&lock->end), mode);
				break;
			}
		}
	}
	spin_unlock(&linfo->lock);

	if (linfo->workq) {
		/* pending grace work queues normal work */
		flush_workqueue(linfo->workq);
		/* now all work won't queue itself */
		destroy_workqueue(linfo->workq);
	}

	/* XXX does anything synchronize with open debugfs fds? */
	debugfs_remove(linfo->tseq_dentry);

	/*
	 * Usually lock_free is only called once locks are idle but all
	 * locks are idle by definition during shutdown.  We need to
	 * manually update the lock's state to reflect that we've given
	 * up on pending work that would otherwise prevent free from
	 * being called (and would trip assertions in our manual calling
	 * of free).
	 */
	spin_lock(&linfo->lock);
	node = rb_first(&linfo->lock_tree);
	while (node) {
		lock = rb_entry(node, struct scoutfs_lock, node);
		node = rb_next(node);
		lock->request_pending = 0;
		if (!list_empty(&lock->lru_head))
			__lock_del_lru(linfo, lock);
		if (!list_empty(&lock->grant_head))
			list_del_init(&lock->grant_head);
		if (!list_empty(&lock->inv_head))
			list_del_init(&lock->inv_head);
		if (!list_empty(&lock->shrink_head))
			list_del_init(&lock->shrink_head);
		lock_remove(linfo, lock);
		lock_free(linfo, lock);
	}
	spin_unlock(&linfo->lock);

	kfree(linfo);
	sbi->lock_info = NULL;
}

int scoutfs_lock_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct lock_info *linfo;
	int ret;

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
	INIT_WORK(&linfo->grant_work, lock_grant_worker);
	INIT_LIST_HEAD(&linfo->grant_list);
	INIT_DELAYED_WORK(&linfo->inv_dwork, lock_invalidate_worker);
	INIT_LIST_HEAD(&linfo->inv_list);
	INIT_WORK(&linfo->shrink_work, lock_shrink_worker);
	INIT_LIST_HEAD(&linfo->shrink_list);
	atomic64_set(&linfo->next_refresh_gen, 0);
	scoutfs_tseq_tree_init(&linfo->tseq_tree, lock_tseq_show);

	sbi->lock_info = linfo;
	trace_scoutfs_lock_setup(sb, linfo);

	linfo->tseq_dentry = scoutfs_tseq_create("client_locks",
						 sbi->debug_root,
						 &linfo->tseq_tree);
	if (!linfo->tseq_dentry) {
		ret = -ENOMEM;
		goto out;
	}

	linfo->workq = alloc_workqueue("scoutfs_lock_client_work",
				       WQ_NON_REENTRANT | WQ_UNBOUND |
				       WQ_HIGHPRI, 0);
	if (!linfo->workq) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_lock_destroy(sb);

	return ret;
}
