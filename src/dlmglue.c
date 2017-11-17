/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * dlmglue.c
 *
 * Code which implements an OCFS2 specific interface to our DLM.
 *
 * Copyright (C) 2003, 2004 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/dlm.h>

#include "dlmglue.h"

#ifdef TRACE_DLMGLUE
#define mlog(mask, fmt, args...) trace_printk(fmt , ##args)
#define mlog_errno(st) do {						\
	int _st = (st);							\
	if (_st != -ERESTARTSYS && _st != -EINTR &&			\
	    _st != AOP_TRUNCATED_PAGE && _st != -ENOSPC)		\
		mlog(ML_ERROR, "status = %lld\n", (long long)_st);	\
} while (0)
#else
#define mlog(mask, fmt, args...)
#define mlog_errno(st)
#endif
#define mlog_bug_on_msg(cond, fmt, args...) do {			\
	if (cond) {							\
		printk(KERN_ERR "bug expression: " #cond "\n");	\
		printk(KERN_ERR fmt, ##args);				\
		BUG();							\
	}								\
} while (0)

struct ocfs2_mask_waiter {
	struct list_head	mw_item;
	int			mw_status;
	struct completion	mw_complete;
	unsigned long		mw_mask;
	unsigned long		mw_goal;
#ifdef CONFIG_OCFS2_FS_STATS
	ktime_t			mw_lock_start;
#endif
};

struct ocfs2_unblock_ctl {
	int requeue;
	enum ocfs2_unblock_action unblock_action;
};

#if 0 && CONFIG_DEBUG_LOCK_ALLOC
/* Lockdep class keys */
struct lock_class_key lockdep_keys[OCFS2_NUM_LOCK_TYPES];
#endif

static inline struct ocfs2_lock_res *ocfs2_lksb_to_lock_res(struct ocfs2_dlm_lksb *lksb)
{
	return container_of(lksb, struct ocfs2_lock_res, l_lksb);
}

static inline struct ocfs2_super *ocfs2_get_lockres_osb(struct ocfs2_lock_res *lockres)
{
	if (lockres->l_ops->get_osb)
		return lockres->l_ops->get_osb(lockres);

	return (struct ocfs2_super *)lockres->l_priv;
}

static inline void lockres_name(struct ocfs2_lock_res *lockres, char *buf,
				unsigned int len)
{
	if (lockres->l_ops->print)
		lockres->l_ops->print(lockres, buf, len);
	else
		snprintf(buf, len, "%s", lockres->l_name);
}

static inline int ocfs2_may_continue_on_blocked_lock(struct ocfs2_lock_res *lockres,
						     int wanted);
static void __ocfs2_cluster_unlock(struct ocfs2_super *osb,
				   struct ocfs2_lock_res *lockres,
				   int level, unsigned long caller_ip);
void ocfs2_cluster_unlock(struct ocfs2_super *osb,
			  struct ocfs2_lock_res *lockres, int level)
{
	__ocfs2_cluster_unlock(osb, lockres, level, _RET_IP_);
}

static inline void ocfs2_generic_handle_downconvert_action(struct ocfs2_lock_res *lockres);
static inline void ocfs2_generic_handle_convert_action(struct ocfs2_lock_res *lockres);
static inline void ocfs2_generic_handle_attach_action(struct ocfs2_lock_res *lockres);
static int ocfs2_generic_handle_bast(struct ocfs2_lock_res *lockres, int level);
static void ocfs2_schedule_blocked_lock(struct ocfs2_super *osb,
					struct ocfs2_lock_res *lockres);
static inline void ocfs2_recover_from_dlm_error(struct ocfs2_lock_res *lockres,
						int convert);
#if 0
#define ocfs2_log_dlm_error(_func, _err, _lockres) do {			\
	if ((_lockres)->l_type != OCFS2_LOCK_TYPE_DENTRY)				\
		mlog(ML_ERROR, "DLM error %d while calling %s on resource %s\n",	\
		     _err, _func, _lockres->l_name);					\
	else										\
		mlog(ML_ERROR, "DLM error %d while calling %s on resource %.*s%08x\n",	\
		     _err, _func, OCFS2_DENTRY_LOCK_INO_START - 1, (_lockres)->l_name,	\
		     (unsigned int)ocfs2_get_dentry_lock_ino(_lockres));		\
} while (0)
#endif
#define ocfs2_log_dlm_error(_func, _err, _lockres) do {			\
	mlog(ML_ERROR, "DLM error %d while calling %s on resource %s\n",	\
	     _err, _func, (_lockres)->l_name);		\
} while (0)

static int ocfs2_downconvert_thread(void *arg);
static void ocfs2_downconvert_on_unlock(struct ocfs2_super *osb,
					struct ocfs2_lock_res *lockres);
static unsigned int ocfs2_prepare_downconvert(struct ocfs2_lock_res *lockres,
					      int new_level);
static int ocfs2_downconvert_lock(struct ocfs2_super *osb,
				  struct ocfs2_lock_res *lockres,
				  int new_level,
				  int lvb,
				  unsigned int generation);
static int ocfs2_prepare_cancel_convert(struct ocfs2_super *osb,
				        struct ocfs2_lock_res *lockres);
static int ocfs2_cancel_convert(struct ocfs2_super *osb,
				struct ocfs2_lock_res *lockres);

static DEFINE_SPINLOCK(ocfs2_dlm_tracking_lock);

static void ocfs2_add_lockres_tracking(struct ocfs2_lock_res *res,
				       struct ocfs2_dlm_debug *dlm_debug)
{
	mlog(0, "Add tracking for lockres %s\n", res->l_name);

	spin_lock(&ocfs2_dlm_tracking_lock);
	BUG_ON(!list_empty(&res->l_debug_list));
	list_add(&res->l_debug_list, &dlm_debug->d_lockres_tracking);
	spin_unlock(&ocfs2_dlm_tracking_lock);
}

static void ocfs2_remove_lockres_tracking(struct ocfs2_lock_res *res)
{
	spin_lock(&ocfs2_dlm_tracking_lock);
	if (!list_empty(&res->l_debug_list))
		list_del_init(&res->l_debug_list);
	spin_unlock(&ocfs2_dlm_tracking_lock);
}

#ifdef CONFIG_OCFS2_FS_STATS
static void ocfs2_init_lock_stats(struct ocfs2_lock_res *res)
{
	res->l_lock_refresh = 0;
	memset(&res->l_lock_prmode, 0, sizeof(struct ocfs2_lock_stats));
	memset(&res->l_lock_exmode, 0, sizeof(struct ocfs2_lock_stats));
}

static void ocfs2_update_lock_stats(struct ocfs2_lock_res *res, int level,
				    struct ocfs2_mask_waiter *mw, int ret)
{
	u32 usec;
	ktime_t kt;
	struct ocfs2_lock_stats *stats;

	if (level == DLM_LOCK_PR)
		stats = &res->l_lock_prmode;
	else if (level == DLM_LOCK_EX)
		stats = &res->l_lock_exmode;
	else if (level == DLM_LOCK_CW)
		stats = &res->l_lock_cwmode;
	else
		return;

	kt = ktime_sub(ktime_get(), mw->mw_lock_start);
	usec = ktime_to_us(kt);

	stats->ls_gets++;
	stats->ls_total += ktime_to_ns(kt);
	/* overflow */
	if (unlikely(stats->ls_gets == 0)) {
		stats->ls_gets++;
		stats->ls_total = ktime_to_ns(kt);
	}

	if (stats->ls_max < usec)
		stats->ls_max = usec;

	if (ret)
		stats->ls_fail++;
}

static inline void ocfs2_track_lock_refresh(struct ocfs2_lock_res *lockres)
{
	lockres->l_lock_refresh++;
}

static inline void ocfs2_init_start_time(struct ocfs2_mask_waiter *mw)
{
	mw->mw_lock_start = ktime_get();
}
#else
static inline void ocfs2_init_lock_stats(struct ocfs2_lock_res *res)
{
}
static inline void ocfs2_update_lock_stats(struct ocfs2_lock_res *res,
			   int level, struct ocfs2_mask_waiter *mw, int ret)
{
}
static inline void ocfs2_track_lock_refresh(struct ocfs2_lock_res *lockres)
{
}
static inline void ocfs2_init_start_time(struct ocfs2_mask_waiter *mw)
{
}
#endif

void ocfs2_lock_res_init_common(struct ocfs2_super *osb,
				struct ocfs2_lock_res *res,
				struct ocfs2_lock_res_ops *ops,
				void *priv)
{
	res->l_ops           = ops;
	res->l_priv          = priv;

	res->l_level         = DLM_LOCK_IV;
	res->l_requested     = DLM_LOCK_IV;
	res->l_blocking      = DLM_LOCK_IV;
	res->l_action        = OCFS2_AST_INVALID;
	res->l_unlock_action = OCFS2_UNLOCK_INVALID;

	res->l_flags         = OCFS2_LOCK_INITIALIZED;

	ocfs2_add_lockres_tracking(res, osb->osb_dlm_debug);

	ocfs2_init_lock_stats(res);
#if 0 && CONFIG_DEBUG_LOCK_ALLOC
	if (type != OCFS2_LOCK_TYPE_OPEN)
		lockdep_init_map(&res->l_lockdep_map, ocfs2_lock_type_strings[type],
				 &lockdep_keys[type], 0);
	else
		res->l_lockdep_map.key = NULL;
#endif
}

void ocfs2_lock_res_init_once(struct ocfs2_lock_res *res)
{
	/* This also clears out the lock status block */
	memset(res, 0, sizeof(struct ocfs2_lock_res));
	spin_lock_init(&res->l_lock);
	init_waitqueue_head(&res->l_event);
	INIT_LIST_HEAD(&res->l_blocked_list);
	INIT_LIST_HEAD(&res->l_mask_waiters);
	INIT_LIST_HEAD(&res->l_holders);
	INIT_LIST_HEAD(&res->l_debug_list);
}

void ocfs2_lock_res_free(struct ocfs2_lock_res *res)
{
	if (!(res->l_flags & OCFS2_LOCK_INITIALIZED))
		return;

	ocfs2_remove_lockres_tracking(res);

	mlog_bug_on_msg(!list_empty(&res->l_blocked_list),
			"Lockres %s is on the blocked list\n",
			res->l_name);
	mlog_bug_on_msg(!list_empty(&res->l_mask_waiters),
			"Lockres %s has mask waiters pending\n",
			res->l_name);
	mlog_bug_on_msg(spin_is_locked(&res->l_lock),
			"Lockres %s is locked\n",
			res->l_name);
	mlog_bug_on_msg(res->l_ro_holders,
			"Lockres %s has %u ro holders\n",
			res->l_name, res->l_ro_holders);
	mlog_bug_on_msg(res->l_ex_holders,
			"Lockres %s has %u ex holders\n",
			res->l_name, res->l_ex_holders);

	/* Need to clear out the lock status block for the dlm */
	memset(&res->l_lksb, 0, sizeof(res->l_lksb));

	res->l_flags = 0UL;
}

/*
 * Keep a list of processes who have interest in a lockres.
 * Note: this is now only uesed for check recursive cluster locking.
 */
static inline void ocfs2_add_holder(struct ocfs2_lock_res *lockres,
				   struct ocfs2_lock_holder *oh)
{
	INIT_LIST_HEAD(&oh->oh_list);
	oh->oh_owner_pid = get_pid(task_pid(current));

	spin_lock(&lockres->l_lock);
	list_add_tail(&oh->oh_list, &lockres->l_holders);
	spin_unlock(&lockres->l_lock);
}

static inline void ocfs2_remove_holder(struct ocfs2_lock_res *lockres,
				       struct ocfs2_lock_holder *oh)
{
	spin_lock(&lockres->l_lock);
	list_del(&oh->oh_list);
	spin_unlock(&lockres->l_lock);

	put_pid(oh->oh_owner_pid);
}

static inline int ocfs2_is_locked_by_me(struct ocfs2_lock_res *lockres)
{
	struct ocfs2_lock_holder *oh;
	struct pid *pid;

	/* look in the list of holders for one with the current task as owner */
	spin_lock(&lockres->l_lock);
	pid = task_pid(current);
	list_for_each_entry(oh, &lockres->l_holders, oh_list) {
		if (oh->oh_owner_pid == pid) {
			spin_unlock(&lockres->l_lock);
			return 1;
		}
	}
	spin_unlock(&lockres->l_lock);

	return 0;
}

static inline void ocfs2_inc_holders(struct ocfs2_lock_res *lockres,
				     int level)
{
	BUG_ON(!lockres);

	switch(level) {
	case DLM_LOCK_EX:
		lockres->l_ex_holders++;
		break;
	case DLM_LOCK_PR:
		lockres->l_ro_holders++;
		break;
	case DLM_LOCK_CW:
		lockres->l_cw_holders++;
		break;
	default:
		BUG();
	}
}

static inline void ocfs2_dec_holders(struct ocfs2_lock_res *lockres,
				     int level)
{
	BUG_ON(!lockres);

	switch(level) {
	case DLM_LOCK_EX:
		BUG_ON(!lockres->l_ex_holders);
		lockres->l_ex_holders--;
		break;
	case DLM_LOCK_PR:
		BUG_ON(!lockres->l_ro_holders);
		lockres->l_ro_holders--;
		break;
	case DLM_LOCK_CW:
		BUG_ON(!lockres->l_cw_holders);
		lockres->l_cw_holders--;
		break;
	default:
		BUG();
	}
}

/*
 * Compatibility matrix indexed by lock level - idea borrowed from
 * fs/dlm/lock.c. Going across is the level our lock holds, going down
 * is the level we're asked to convert to. The UN column and PD
 * columns are unused and act as padding.
 */
static const int level_compat_matrix[8][8] = {
	/* Lockres granted level */
      /* UN NL CR CW PR PW EX PD */
        {0, 0, 0, 0, 0, 0, 0, 0},       /* UN */
        {0, 1, 1, 1, 1, 1, 1, 0},       /* NL */
        {0, 0, 1, 1, 1, 1, 1, 0},       /* CR */
        {0, 0, 0, 1, 0, 1, 1, 0},       /* CW */ /* <-- Wanted levels */
        {0, 0, 0, 0, 1, 1, 1, 0},       /* PR */
        {0, 0, 0, 0, 0, 1, 1, 0},       /* PW */
        {0, 0, 0, 0, 0, 0, 1, 0},       /* EX */
        {0, 0, 0, 0, 0, 0, 0, 0}        /* PD */
};

static inline int __levels_compat(int lockres_level, int wanted)
{
	return level_compat_matrix[wanted + 1][lockres_level + 1];
}

static inline int levels_compat(struct ocfs2_lock_res *lockres, int wanted)
{
	return __levels_compat(lockres->l_level, wanted);
}

/*
 * WARNING: We have to adjust this function when adding lock levels to
 * dlmglue
 *
 * Given a lock blocking 'lockres' at 'level', what new level should
 * we downconvert to. This function will never return a level which
 * would result in an upconvert.
 */
static inline int ocfs2_downconvert_level(struct ocfs2_lock_res *lockres,
					  int level)
{
	int new_level = DLM_LOCK_EX;

	if (level == DLM_LOCK_EX)
		new_level = DLM_LOCK_NL;
	else if (level == DLM_LOCK_PR) {
		if (lockres->l_level == DLM_LOCK_EX)
			new_level = DLM_LOCK_PR;
		else
			new_level = DLM_LOCK_NL;
	} else if (level == DLM_LOCK_CW)
		new_level = DLM_LOCK_CW;
	return new_level;
}

#define H_EX 0x1
#define H_PR 0x2
#define H_CW 0x4
#define H_ANY (H_EX|H_PR|H_CW)
static int lockres_has_holders(struct ocfs2_lock_res *lockres, int which)
{
	if (which & H_EX && lockres->l_ex_holders)
		return 1;
	if (which & H_PR && lockres->l_ro_holders)
		return 1;
	if (which & H_CW && lockres->l_cw_holders)
		return 1;
	return 0;
}

static void lockres_set_flags(struct ocfs2_lock_res *lockres,
			      unsigned long newflags)
{
	struct ocfs2_mask_waiter *mw, *tmp;

 	assert_spin_locked(&lockres->l_lock);

	lockres->l_flags = newflags;

	list_for_each_entry_safe(mw, tmp, &lockres->l_mask_waiters, mw_item) {
		if ((lockres->l_flags & mw->mw_mask) != mw->mw_goal)
			continue;

		list_del_init(&mw->mw_item);
		mw->mw_status = 0;
		complete(&mw->mw_complete);
	}
}
static void lockres_or_flags(struct ocfs2_lock_res *lockres, unsigned long or)
{
	lockres_set_flags(lockres, lockres->l_flags | or);
}
static void lockres_clear_flags(struct ocfs2_lock_res *lockres,
				unsigned long clear)
{
	lockres_set_flags(lockres, lockres->l_flags & ~clear);
}

/*
 * Make sure that a lock gets a strictly increasing number only once
 * each time it needs to be refreshed.  The gen needs to be larger than
 * any previous gen the locked resources has seen so we maintain the gen
 * in the super.  The caller has serialized on the lock but lots of
 * locks can all be racing on the super.
 *
 * This is used by callers to have a single read-only indicator that
 * they need to refresh their resource while they have it locked.
 */
static void lockres_inc_refresh_gen(struct ocfs2_lock_res *lockres)
{
	struct ocfs2_super *osb = ocfs2_get_lockres_osb(lockres);

	lockres->l_refresh_gen = atomic64_inc_return(&osb->refresh_gen);
}

static inline void ocfs2_generic_handle_downconvert_action(struct ocfs2_lock_res *lockres)
{
	int dc_level = ocfs2_downconvert_level(lockres, lockres->l_blocking);

	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_BUSY));
	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_ATTACHED));
	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_BLOCKED));
	BUG_ON(lockres->l_blocking <= DLM_LOCK_NL);

	lockres->l_level = lockres->l_requested;
	if (levels_compat(lockres, dc_level)) {
		lockres->l_blocking = DLM_LOCK_NL;
		lockres_clear_flags(lockres, OCFS2_LOCK_BLOCKED);
	}
	lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
}

static inline void ocfs2_generic_handle_convert_action(struct ocfs2_lock_res *lockres)
{
	int old_level = lockres->l_level;

	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_BUSY));
	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_ATTACHED));

	/*
	 * Converting from NL to any mode, or upconverting between
	 * incompatible modes will require a refresh.
	 */
	lockres->l_level = lockres->l_requested;
	if (lockres->l_ops->flags & LOCK_TYPE_REQUIRES_REFRESH) {
		if (old_level == DLM_LOCK_NL ||
		    (old_level == DLM_LOCK_CW &&
		     lockres->l_level != DLM_LOCK_NL)) {
			lockres_or_flags(lockres, OCFS2_LOCK_NEEDS_REFRESH);
			lockres_inc_refresh_gen(lockres);
		}
	}

	/*
	 * We set the OCFS2_LOCK_UPCONVERT_FINISHING flag before clearing
	 * the OCFS2_LOCK_BUSY flag to prevent the dc thread from
	 * downconverting the lock before the upconvert has fully completed.
	 * Do not prevent the dc thread from downconverting if NONBLOCK lock
	 * had already returned.
	 */
	if (!(lockres->l_flags & OCFS2_LOCK_NONBLOCK_FINISHED))
		lockres_or_flags(lockres, OCFS2_LOCK_UPCONVERT_FINISHING);
	else
		lockres_clear_flags(lockres, OCFS2_LOCK_NONBLOCK_FINISHED);

	lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
}

static inline void ocfs2_generic_handle_attach_action(struct ocfs2_lock_res *lockres)
{
	BUG_ON((!(lockres->l_flags & OCFS2_LOCK_BUSY)));
	BUG_ON(lockres->l_flags & OCFS2_LOCK_ATTACHED);

	if (lockres->l_requested > DLM_LOCK_NL &&
	    !(lockres->l_flags & OCFS2_LOCK_LOCAL) &&
	    lockres->l_ops->flags & LOCK_TYPE_REQUIRES_REFRESH) {
		lockres_or_flags(lockres, OCFS2_LOCK_NEEDS_REFRESH);
		lockres_inc_refresh_gen(lockres);
	}

	lockres->l_level = lockres->l_requested;
	lockres_or_flags(lockres, OCFS2_LOCK_ATTACHED);
	lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
}

static int ocfs2_generic_handle_bast(struct ocfs2_lock_res *lockres,
				     int level)
{
	int needs_downconvert = 0;

	assert_spin_locked(&lockres->l_lock);

	if (level > lockres->l_blocking) {
		/* only schedule a downconvert if we haven't already scheduled
		 * one that goes low enough to satisfy the level we're
		 * blocking.  this also catches the case where we get
		 * duplicate BASTs */
		if (ocfs2_downconvert_level(lockres, level) <
		    ocfs2_downconvert_level(lockres, lockres->l_blocking))
			needs_downconvert = 1;

		lockres->l_blocking = level;
	}

	mlog(ML_BASTS, "lockres %s, block %d, level %d, l_block %d, dwn %d\n",
	     lockres->l_name, level, lockres->l_level, lockres->l_blocking,
	     needs_downconvert);

	if (needs_downconvert)
		lockres_or_flags(lockres, OCFS2_LOCK_BLOCKED);
	mlog(0, "needs_downconvert = %d\n", needs_downconvert);
	return needs_downconvert;
}

static void set_lock_blocking(struct ocfs2_lock_res *lockres, int level)
{
	struct ocfs2_super *osb = ocfs2_get_lockres_osb(lockres);
	int needs_downconvert;

	needs_downconvert = ocfs2_generic_handle_bast(lockres, level);
	if (needs_downconvert)
		ocfs2_schedule_blocked_lock(osb, lockres);
}

/*
 * OCFS2_LOCK_PENDING and l_pending_gen.
 *
 * Why does OCFS2_LOCK_PENDING exist?  To close a race between setting
 * OCFS2_LOCK_BUSY and calling ocfs2_dlm_lock().  See ocfs2_unblock_lock()
 * for more details on the race.
 *
 * OCFS2_LOCK_PENDING closes the race quite nicely.  However, it introduces
 * a race on itself.  In o2dlm, we can get the ast before ocfs2_dlm_lock()
 * returns.  The ast clears OCFS2_LOCK_BUSY, and must therefore clear
 * OCFS2_LOCK_PENDING at the same time.  When ocfs2_dlm_lock() returns,
 * the caller is going to try to clear PENDING again.  If nothing else is
 * happening, __lockres_clear_pending() sees PENDING is unset and does
 * nothing.
 *
 * But what if another path (eg downconvert thread) has just started a
 * new locking action?  The other path has re-set PENDING.  Our path
 * cannot clear PENDING, because that will re-open the original race
 * window.
 *
 * [Example]
 *
 * ocfs2_meta_lock()
 *  ocfs2_cluster_lock()
 *   set BUSY
 *   set PENDING
 *   drop l_lock
 *   ocfs2_dlm_lock()
 *    ocfs2_locking_ast()		ocfs2_downconvert_thread()
 *     clear PENDING			 ocfs2_unblock_lock()
 *					  take_l_lock
 *					  !BUSY
 *					  ocfs2_prepare_downconvert()
 *					   set BUSY
 *					   set PENDING
 *					  drop l_lock
 *   take l_lock
 *   clear PENDING
 *   drop l_lock
 *			<window>
 *					  ocfs2_dlm_lock()
 *
 * So as you can see, we now have a window where l_lock is not held,
 * PENDING is not set, and ocfs2_dlm_lock() has not been called.
 *
 * The core problem is that ocfs2_cluster_lock() has cleared the PENDING
 * set by ocfs2_prepare_downconvert().  That wasn't nice.
 *
 * To solve this we introduce l_pending_gen.  A call to
 * lockres_clear_pending() will only do so when it is passed a generation
 * number that matches the lockres.  lockres_set_pending() will return the
 * current generation number.  When ocfs2_cluster_lock() goes to clear
 * PENDING, it passes the generation it got from set_pending().  In our
 * example above, the generation numbers will *not* match.  Thus,
 * ocfs2_cluster_lock() will not clear the PENDING set by
 * ocfs2_prepare_downconvert().
 */

/* Unlocked version for ocfs2_locking_ast() */
static void __lockres_clear_pending(struct ocfs2_lock_res *lockres,
				    unsigned int generation,
				    struct ocfs2_super *osb)
{
	assert_spin_locked(&lockres->l_lock);

	/*
	 * The ast and locking functions can race us here.  The winner
	 * will clear pending, the loser will not.
	 */
	if (!(lockres->l_flags & OCFS2_LOCK_PENDING) ||
	    (lockres->l_pending_gen != generation))
		return;

	lockres_clear_flags(lockres, OCFS2_LOCK_PENDING);
	lockres->l_pending_gen++;

	/*
	 * The downconvert thread may have skipped us because we
	 * were PENDING.  Wake it up.
	 */
	if (lockres->l_flags & OCFS2_LOCK_BLOCKED)
		ocfs2_wake_downconvert_thread(osb);
}

/* Locked version for callers of ocfs2_dlm_lock() */
static void lockres_clear_pending(struct ocfs2_lock_res *lockres,
				  unsigned int generation,
				  struct ocfs2_super *osb)
{
	unsigned long flags;

	spin_lock_irqsave(&lockres->l_lock, flags);
	__lockres_clear_pending(lockres, generation, osb);
	spin_unlock_irqrestore(&lockres->l_lock, flags);
}

static unsigned int lockres_set_pending(struct ocfs2_lock_res *lockres)
{
	assert_spin_locked(&lockres->l_lock);
	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_BUSY));

	lockres_or_flags(lockres, OCFS2_LOCK_PENDING);

	return lockres->l_pending_gen;
}

static void ocfs2_blocking_ast(struct ocfs2_dlm_lksb *lksb, int level)
{
	struct ocfs2_lock_res *lockres = ocfs2_lksb_to_lock_res(lksb);
	struct ocfs2_super *osb = ocfs2_get_lockres_osb(lockres);
	int needs_downconvert;
	unsigned long flags;

	BUG_ON(level <= DLM_LOCK_NL);

	mlog(ML_BASTS, "BAST fired for lockres %s, blocking %d, level %d\n",
	     lockres->l_name, level, lockres->l_level);

	/*
	 * We can skip the bast for locks which don't enable caching -
	 * they'll be dropped at the earliest possible time anyway.
	 */
	if (lockres->l_flags & OCFS2_LOCK_NOCACHE)
		return;

	spin_lock_irqsave(&lockres->l_lock, flags);
	needs_downconvert = ocfs2_generic_handle_bast(lockres, level);
	if (needs_downconvert)
		ocfs2_schedule_blocked_lock(osb, lockres);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	wake_up(&lockres->l_event);

	ocfs2_wake_downconvert_thread(osb);
}

static void ocfs2_locking_ast(struct ocfs2_dlm_lksb *lksb)
{
	struct ocfs2_lock_res *lockres = ocfs2_lksb_to_lock_res(lksb);
	struct ocfs2_super *osb = ocfs2_get_lockres_osb(lockres);
	unsigned long flags;
	int status;

	spin_lock_irqsave(&lockres->l_lock, flags);

	status = ocfs2_dlm_lock_status(&lockres->l_lksb);

	if (status == -EAGAIN) {
		lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
		goto out;
	}

	if (status) {
		mlog(ML_ERROR, "lockres %s: lksb status value of %d!\n",
		     lockres->l_name, status);
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		return;
	}

	mlog(ML_BASTS, "AST fired for lockres %s, action %d, unlock %d, "
	     "level %d => %d\n", lockres->l_name, lockres->l_action,
	     lockres->l_unlock_action, lockres->l_level, lockres->l_requested);

	switch(lockres->l_action) {
	case OCFS2_AST_ATTACH:
		ocfs2_generic_handle_attach_action(lockres);
		lockres_clear_flags(lockres, OCFS2_LOCK_LOCAL);
		break;
	case OCFS2_AST_CONVERT:
		ocfs2_generic_handle_convert_action(lockres);
		break;
	case OCFS2_AST_DOWNCONVERT:
		ocfs2_generic_handle_downconvert_action(lockres);
		break;
	default:
		mlog(ML_ERROR, "lockres %s: AST fired with invalid action: %u, "
		     "flags 0x%lx, unlock: %u\n",
		     lockres->l_name, lockres->l_action, lockres->l_flags,
		     lockres->l_unlock_action);
		BUG();
	}
out:
	/* set it to something invalid so if we get called again we
	 * can catch it. */
	lockres->l_action = OCFS2_AST_INVALID;

	/* Did we try to cancel this lock?  Clear that state */
	if (lockres->l_unlock_action == OCFS2_UNLOCK_CANCEL_CONVERT)
		lockres->l_unlock_action = OCFS2_UNLOCK_INVALID;

	/*
	 * We may have beaten the locking functions here.  We certainly
	 * know that dlm_lock() has been called :-)
	 * Because we can't have two lock calls in flight at once, we
	 * can use lockres->l_pending_gen.
	 */
	__lockres_clear_pending(lockres, lockres->l_pending_gen,  osb);

	wake_up(&lockres->l_event);
	spin_unlock_irqrestore(&lockres->l_lock, flags);
}

static void ocfs2_unlock_ast(struct ocfs2_dlm_lksb *lksb, int error)
{
	struct ocfs2_lock_res *lockres = ocfs2_lksb_to_lock_res(lksb);
	unsigned long flags;

	mlog(ML_BASTS, "UNLOCK AST fired for lockres %s, action = %d\n",
	     lockres->l_name, lockres->l_unlock_action);

	spin_lock_irqsave(&lockres->l_lock, flags);
	if (error) {
		mlog(ML_ERROR, "Dlm passes error %d for lock %s, "
		     "unlock_action %d\n", error, lockres->l_name,
		     lockres->l_unlock_action);
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		return;
	}

	switch(lockres->l_unlock_action) {
	case OCFS2_UNLOCK_CANCEL_CONVERT:
		mlog(0, "Cancel convert success for %s\n", lockres->l_name);
		lockres->l_action = OCFS2_AST_INVALID;
		/* Downconvert thread may have requeued this lock, we
		 * need to wake it. */
		if (lockres->l_flags & OCFS2_LOCK_BLOCKED)
			ocfs2_wake_downconvert_thread(ocfs2_get_lockres_osb(lockres));
		break;
	case OCFS2_UNLOCK_DROP_LOCK:
		lockres->l_level = DLM_LOCK_IV;
		break;
	default:
		BUG();
	}

	lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
	lockres->l_unlock_action = OCFS2_UNLOCK_INVALID;
	wake_up(&lockres->l_event);
	spin_unlock_irqrestore(&lockres->l_lock, flags);
}

/*
 * This is the filesystem locking protocol.  It provides the lock handling
 * hooks for the underlying DLM.  It has a maximum version number.
 * The version number allows interoperability with systems running at
 * the same major number and an equal or smaller minor number.
 *
 * Whenever the filesystem does new things with locks (adds or removes a
 * lock, orders them differently, does different things underneath a lock),
 * the version must be changed.  The protocol is negotiated when joining
 * the dlm domain.  A node may join the domain if its major version is
 * identical to all other nodes and its minor version is greater than
 * or equal to all other nodes.  When its minor version is greater than
 * the other nodes, it will run at the minor version specified by the
 * other nodes.
 *
 * If a locking change is made that will not be compatible with older
 * versions, the major number must be increased and the minor version set
 * to zero.  If a change merely adds a behavior that can be disabled when
 * speaking to older versions, the minor version must be increased.  If a
 * change adds a fully backwards compatible change (eg, LVB changes that
 * are just ignored by older versions), the version does not need to be
 * updated.
 */
static struct ocfs2_locking_protocol lproto = {
#if 0
	.lp_max_version = {
		.pv_major = OCFS2_LOCKING_PROTOCOL_MAJOR,
		.pv_minor = OCFS2_LOCKING_PROTOCOL_MINOR,
	},
#endif
	.lp_lock_ast		= ocfs2_locking_ast,
	.lp_blocking_ast	= ocfs2_blocking_ast,
	.lp_unlock_ast		= ocfs2_unlock_ast,
};

#if 0
void ocfs2_set_locking_protocol(void)
{
	ocfs2_stack_glue_set_max_proto_version(&lproto.lp_max_version);
}
#endif

static inline void ocfs2_recover_from_dlm_error(struct ocfs2_lock_res *lockres,
						int convert)
{
	unsigned long flags;

	spin_lock_irqsave(&lockres->l_lock, flags);
	lockres_clear_flags(lockres, OCFS2_LOCK_BUSY);
	lockres_clear_flags(lockres, OCFS2_LOCK_UPCONVERT_FINISHING);
	if (convert)
		lockres->l_action = OCFS2_AST_INVALID;
	else
		lockres->l_unlock_action = OCFS2_UNLOCK_INVALID;
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	wake_up(&lockres->l_event);
}

#if 0
/* Note: If we detect another process working on the lock (i.e.,
 * OCFS2_LOCK_BUSY), we'll bail out returning 0. It's up to the caller
 * to do the right thing in that case.
 */
static int ocfs2_lock_create(struct ocfs2_super *osb,
			     struct ocfs2_lock_res *lockres,
			     int level,
			     u32 dlm_flags)
{
	int ret = 0;
	unsigned long flags;
	unsigned int gen;

	mlog(0, "lock %s, level = %d, flags = %u\n", lockres->l_name, level,
	     dlm_flags);

	spin_lock_irqsave(&lockres->l_lock, flags);
	if ((lockres->l_flags & OCFS2_LOCK_ATTACHED) ||
	    (lockres->l_flags & OCFS2_LOCK_BUSY)) {
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		goto bail;
	}

	lockres->l_action = OCFS2_AST_ATTACH;
	lockres->l_requested = level;
	lockres_or_flags(lockres, OCFS2_LOCK_BUSY);
	gen = lockres_set_pending(lockres);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	ret = ocfs2_dlm_lock(osb->cconn,
			     level,
			     &lockres->l_lksb,
			     dlm_flags,
			     lockres->l_name,
			     OCFS2_LOCK_ID_MAX_LEN - 1);
	lockres_clear_pending(lockres, gen, osb);
	if (ret) {
		ocfs2_log_dlm_error("ocfs2_dlm_lock", ret, lockres);
		ocfs2_recover_from_dlm_error(lockres, 1);
	}

	mlog(0, "lock %s, return from ocfs2_dlm_lock\n", lockres->l_name);

bail:
	return ret;
}
#endif

static inline int ocfs2_check_wait_flag(struct ocfs2_lock_res *lockres,
					int flag)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&lockres->l_lock, flags);
	ret = lockres->l_flags & flag;
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	return ret;
}

static inline void ocfs2_wait_on_busy_lock(struct ocfs2_lock_res *lockres)

{
	wait_event(lockres->l_event,
		   !ocfs2_check_wait_flag(lockres, OCFS2_LOCK_BUSY));
}

static inline void ocfs2_wait_on_refreshing_lock(struct ocfs2_lock_res *lockres)

{
	wait_event(lockres->l_event,
		   !ocfs2_check_wait_flag(lockres, OCFS2_LOCK_REFRESHING));
}

/* predict what lock level we'll be dropping down to on behalf
 * of another node, and return true if the currently wanted
 * level will be compatible with it. */
static inline int ocfs2_may_continue_on_blocked_lock(struct ocfs2_lock_res *lockres,
						     int wanted)
{
	BUG_ON(!(lockres->l_flags & OCFS2_LOCK_BLOCKED));

	return wanted <= ocfs2_downconvert_level(lockres, lockres->l_blocking);
}

/* the caller doesn't have to wait on a blocked lock if their wanted level
 * is compatible with it and there are already holders of the lock */
static inline int lockres_allow_recursion(struct ocfs2_lock_res *lockres,
					  int wanted)
{
	return (lockres->l_ops->flags & LOCK_TYPE_RECURSIVE) &&
	       levels_compat(lockres, wanted) &&
	       lockres_has_holders(lockres, H_ANY);
}

static void ocfs2_init_mask_waiter(struct ocfs2_mask_waiter *mw)
{
	INIT_LIST_HEAD(&mw->mw_item);
	init_completion(&mw->mw_complete);
	ocfs2_init_start_time(mw);
}

static int ocfs2_wait_for_mask(struct ocfs2_mask_waiter *mw)
{
	wait_for_completion(&mw->mw_complete);
	/* Re-arm the completion in case we want to wait on it again */
	reinit_completion(&mw->mw_complete);
	return mw->mw_status;
}

static void lockres_add_mask_waiter(struct ocfs2_lock_res *lockres,
				    struct ocfs2_mask_waiter *mw,
				    unsigned long mask,
				    unsigned long goal)
{
	BUG_ON(!list_empty(&mw->mw_item));

	assert_spin_locked(&lockres->l_lock);

	list_add_tail(&mw->mw_item, &lockres->l_mask_waiters);
	mw->mw_mask = mask;
	mw->mw_goal = goal;
}

/* returns 0 if the mw that was removed was already satisfied, -EBUSY
 * if the mask still hadn't reached its goal */
static int __lockres_remove_mask_waiter(struct ocfs2_lock_res *lockres,
				      struct ocfs2_mask_waiter *mw)
{
	int ret = 0;

	assert_spin_locked(&lockres->l_lock);
	if (!list_empty(&mw->mw_item)) {
		if ((lockres->l_flags & mw->mw_mask) != mw->mw_goal)
			ret = -EBUSY;

		list_del_init(&mw->mw_item);
		init_completion(&mw->mw_complete);
	}

	return ret;
}

#if 0
static int lockres_remove_mask_waiter(struct ocfs2_lock_res *lockres,
				      struct ocfs2_mask_waiter *mw)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&lockres->l_lock, flags);
	ret = __lockres_remove_mask_waiter(lockres, mw);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	return ret;

}

static int ocfs2_wait_for_mask_interruptible(struct ocfs2_mask_waiter *mw,
					     struct ocfs2_lock_res *lockres)
{
	int ret;

	ret = wait_for_completion_interruptible(&mw->mw_complete);
	if (ret)
		lockres_remove_mask_waiter(lockres, mw);
	else
		ret = mw->mw_status;
	/* Re-arm the completion in case we want to wait on it again */
	reinit_completion(&mw->mw_complete);
	return ret;
}
#endif

static inline int cw_incompat_convert(struct ocfs2_lock_res *lockres,
				      int level)
{
	/* Have CW, want PR/EX */
	if (lockres->l_level == DLM_LOCK_CW &&
	    (level == DLM_LOCK_PR || level == DLM_LOCK_EX))
		return 1;
	/* Have EX/PR, want CW */
	if (level == DLM_LOCK_CW &&
	    (lockres->l_level == DLM_LOCK_PR || lockres->l_level == DLM_LOCK_EX))
		return 1;
	return 0;
}

static int __ocfs2_cluster_lock(struct ocfs2_super *osb,
				struct ocfs2_lock_res *lockres,
				int level,
				u32 lkm_flags,
				int arg_flags,
				int l_subclass,
				unsigned long caller_ip)
{
	struct ocfs2_mask_waiter mw;
	int wait, catch_signals = !(osb->s_mount_opt & OCFS2_MOUNT_NOINTR);
	int ret = 0; /* gcc doesn't realize wait = 1 guarantees ret is set */
	unsigned long flags;
	unsigned int gen;
	int noqueue_attempted = 0;
	int dlm_locked = 0;
	int kick_dc = 0;

	if (!(lockres->l_flags & OCFS2_LOCK_INITIALIZED)) {
		mlog_errno(-EINVAL);
		return -EINVAL;
	}

	ocfs2_init_mask_waiter(&mw);

	if (lockres->l_ops->flags & LOCK_TYPE_USES_LVB)
		lkm_flags |= DLM_LKF_VALBLK;

again:
	wait = 0;

	spin_lock_irqsave(&lockres->l_lock, flags);

	if (catch_signals && signal_pending(current)) {
		ret = -ERESTARTSYS;
		goto unlock;
	}

	mlog_bug_on_msg(lockres->l_flags & OCFS2_LOCK_FREEING,
			"Cluster lock called on freeing lockres %s! flags "
			"0x%lx\n", lockres->l_name, lockres->l_flags);

	/* We only compare against the currently granted level
	 * here. If the lock is blocked waiting on a downconvert,
	 * we'll get caught below. */
	if (lockres->l_flags & OCFS2_LOCK_BUSY &&
	    !levels_compat(lockres, level)) {
		/* is someone sitting in dlm_lock? If so, wait on
		 * them. */
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BUSY, 0);
		wait = 1;
		goto unlock;
	}

	if (lockres->l_flags & OCFS2_LOCK_UPCONVERT_FINISHING) {
		/*
		 * We've upconverted. If the lock now has a level we can
		 * work with, we take it. If, however, the lock is not at the
		 * required level, we go thru the full cycle. One way this could
		 * happen is if a process requesting an upconvert to PR is
		 * closely followed by another requesting upconvert to an EX.
		 * If the process requesting EX lands here, we want it to
		 * continue attempting to upconvert and let the process
		 * requesting PR take the lock.
		 * If multiple processes request upconvert to PR, the first one
		 * here will take the lock. The others will have to go thru the
		 * OCFS2_LOCK_BLOCKED check to ensure that there is no pending
		 * downconvert request.
		 */
		if (levels_compat(lockres, level))
			goto update_holders;
	}

	if (lockres->l_flags & OCFS2_LOCK_BLOCKED &&
	    !lockres_allow_recursion(lockres, level) &&
	    !ocfs2_may_continue_on_blocked_lock(lockres, level)) {
		/* is the lock is currently blocked on behalf of
		 * another node */
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BLOCKED, 0);
		wait = 1;
		goto unlock;
	}

	/*
	 * Convert from PR/EX to CW and vice-versa. Those levels are
	 * not compatible with each other. As a result, we have to
	 * wait for holders on the lock to drain. The easiest way to
	 * do this is by forcing a downconvert. We can then allow the
	 * process to come back and reacquire the lock at the correct
	 * level.
	 */
	if (cw_incompat_convert(lockres, level)) {
		/* ocfs2_unblock_lock will drop to NL, then we can upconvert. */
		set_lock_blocking(lockres, DLM_LOCK_EX);
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BLOCKED, 0);
		wait = 1;
		goto unlock;
	}

	/* NL->Anything, PR->EX conditions are handled here */
	if (level > lockres->l_level) {
		if (noqueue_attempted > 0) {
			ret = -EAGAIN;
			goto unlock;
		}
		if (lkm_flags & DLM_LKF_NOQUEUE)
			noqueue_attempted = 1;

		if (lockres->l_action != OCFS2_AST_INVALID)
			mlog(ML_ERROR, "lockres %s has action %u pending\n",
			     lockres->l_name, lockres->l_action);

		if (!(lockres->l_flags & OCFS2_LOCK_ATTACHED)) {
			lockres->l_action = OCFS2_AST_ATTACH;
			lkm_flags &= ~DLM_LKF_CONVERT;
		} else {
			lockres->l_action = OCFS2_AST_CONVERT;
			lkm_flags |= DLM_LKF_CONVERT;
		}

		lockres->l_requested = level;
		lockres_or_flags(lockres, OCFS2_LOCK_BUSY);
		gen = lockres_set_pending(lockres);
		spin_unlock_irqrestore(&lockres->l_lock, flags);

		BUG_ON(level == DLM_LOCK_IV);
		BUG_ON(level == DLM_LOCK_NL);

		mlog(ML_BASTS, "lockres %s, convert from %d to %d\n",
		     lockres->l_name, lockres->l_level, level);

		/* call dlm_lock to upgrade lock now */
		ret = ocfs2_dlm_lock(osb->cconn,
				     level,
				     &lockres->l_lksb,
				     lkm_flags,
				     lockres->l_name,
				     OCFS2_LOCK_ID_MAX_LEN - 1);
		lockres_clear_pending(lockres, gen, osb);
		if (ret) {
			if (!(lkm_flags & DLM_LKF_NOQUEUE) ||
			    (ret != -EAGAIN)) {
				ocfs2_log_dlm_error("ocfs2_dlm_lock",
						    ret, lockres);
			}
			ocfs2_recover_from_dlm_error(lockres, 1);
			goto out;
		}
		dlm_locked = 1;

		mlog(0, "lock %s, successful return from ocfs2_dlm_lock\n",
		     lockres->l_name);

		/* At this point we've gone inside the dlm and need to
		 * complete our work regardless. */
		catch_signals = 0;

		/* wait for busy to clear and carry on */
		goto again;
	}

update_holders:
	/* Ok, if we get here then we're good to go. */
	ocfs2_inc_holders(lockres, level);

	ret = 0;
unlock:
	lockres_clear_flags(lockres, OCFS2_LOCK_UPCONVERT_FINISHING);

	/* ocfs2_unblock_lock reques on seeing OCFS2_LOCK_UPCONVERT_FINISHING */
	kick_dc = (lockres->l_flags & OCFS2_LOCK_BLOCKED);

	spin_unlock_irqrestore(&lockres->l_lock, flags);
	if (kick_dc)
		ocfs2_wake_downconvert_thread(osb);
out:
	/*
	 * This is helping work around a lock inversion between the page lock
	 * and dlm locks.  One path holds the page lock while calling aops
	 * which block acquiring dlm locks.  The voting thread holds dlm
	 * locks while acquiring page locks while down converting data locks.
	 * This block is helping an aop path notice the inversion and back
	 * off to unlock its page lock before trying the dlm lock again.
	 */
	if (wait && arg_flags & OCFS2_LOCK_NONBLOCK &&
	    mw.mw_mask & (OCFS2_LOCK_BUSY|OCFS2_LOCK_BLOCKED)) {
		wait = 0;
		spin_lock_irqsave(&lockres->l_lock, flags);
		if (__lockres_remove_mask_waiter(lockres, &mw)) {
			if (dlm_locked)
				lockres_or_flags(lockres,
					OCFS2_LOCK_NONBLOCK_FINISHED);
			spin_unlock_irqrestore(&lockres->l_lock, flags);
			ret = -EAGAIN;
		} else {
			spin_unlock_irqrestore(&lockres->l_lock, flags);
			goto again;
		}
	}
	if (wait) {
		ret = ocfs2_wait_for_mask(&mw);
		if (ret == 0)
			goto again;
		mlog_errno(ret);
	}
	ocfs2_update_lock_stats(lockres, level, &mw, ret);

#if 0 && CONFIG_DEBUG_LOCK_ALLOC
	if (!ret && lockres->l_lockdep_map.key != NULL) {
		if (level == DLM_LOCK_PR)
			rwsem_acquire_read(&lockres->l_lockdep_map, l_subclass,
				!!(arg_flags & OCFS2_META_LOCK_NOQUEUE),
				caller_ip);
		else
			rwsem_acquire(&lockres->l_lockdep_map, l_subclass,
				!!(arg_flags & OCFS2_META_LOCK_NOQUEUE),
				caller_ip);
	}
#endif
	return ret;
}

int ocfs2_cluster_lock(struct ocfs2_super *osb,
		       struct ocfs2_lock_res *lockres,
		       int level,
		       u32 lkm_flags,
		       int arg_flags)
{
	return __ocfs2_cluster_lock(osb, lockres, level, lkm_flags, arg_flags,
				    0, _RET_IP_);
}


static void __ocfs2_cluster_unlock(struct ocfs2_super *osb,
				   struct ocfs2_lock_res *lockres,
				   int level,
				   unsigned long caller_ip)
{
	unsigned long flags;

	spin_lock_irqsave(&lockres->l_lock, flags);
	ocfs2_dec_holders(lockres, level);
	ocfs2_downconvert_on_unlock(osb, lockres);
	spin_unlock_irqrestore(&lockres->l_lock, flags);
#if 0 && CONFIG_DEBUG_LOCK_ALLOC
	if (lockres->l_lockdep_map.key != NULL)
		rwsem_release(&lockres->l_lockdep_map, 1, caller_ip);
#endif
}

#if 0
static int ocfs2_create_new_lock(struct ocfs2_super *osb,
				 struct ocfs2_lock_res *lockres,
				 int ex,
				 int local)
{
	int level =  ex ? DLM_LOCK_EX : DLM_LOCK_PR;
	unsigned long flags;
	u32 lkm_flags = local ? DLM_LKF_LOCAL : 0;

	spin_lock_irqsave(&lockres->l_lock, flags);
	BUG_ON(lockres->l_flags & OCFS2_LOCK_ATTACHED);
	lockres_or_flags(lockres, OCFS2_LOCK_LOCAL);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	return ocfs2_lock_create(osb, lockres, level, lkm_flags);
}
#endif

#if 0
static int ocfs2_flock_handle_signal(struct ocfs2_lock_res *lockres,
				     int level)
{
	int ret;
	struct ocfs2_super *osb = ocfs2_get_lockres_osb(lockres);
	unsigned long flags;
	struct ocfs2_mask_waiter mw;

	ocfs2_init_mask_waiter(&mw);

retry_cancel:
	spin_lock_irqsave(&lockres->l_lock, flags);
	if (lockres->l_flags & OCFS2_LOCK_BUSY) {
		ret = ocfs2_prepare_cancel_convert(osb, lockres);
		if (ret) {
			spin_unlock_irqrestore(&lockres->l_lock, flags);
			ret = ocfs2_cancel_convert(osb, lockres);
			if (ret < 0) {
				mlog_errno(ret);
				goto out;
			}
			goto retry_cancel;
		}
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BUSY, 0);
		spin_unlock_irqrestore(&lockres->l_lock, flags);

		ocfs2_wait_for_mask(&mw);
		goto retry_cancel;
	}

	ret = -ERESTARTSYS;
	/*
	 * We may still have gotten the lock, in which case there's no
	 * point to restarting the syscall.
	 */
	if (lockres->l_level == level)
		ret = 0;

	mlog(0, "Cancel returning %d. flags: 0x%lx, level: %d, act: %d\n", ret,
	     lockres->l_flags, lockres->l_level, lockres->l_action);

	spin_unlock_irqrestore(&lockres->l_lock, flags);

out:
	return ret;
}

/*
 * ocfs2_file_lock() and ocfs2_file_unlock() map to a single pair of
 * flock() calls. The locking approach this requires is sufficiently
 * different from all other cluster lock types that we implement a
 * separate path to the "low-level" dlm calls. In particular:
 *
 * - No optimization of lock levels is done - we take at exactly
 *   what's been requested.
 *
 * - No lock caching is employed. We immediately downconvert to
 *   no-lock at unlock time. This also means flock locks never go on
 *   the blocking list).
 *
 * - Since userspace can trivially deadlock itself with flock, we make
 *   sure to allow cancellation of a misbehaving applications flock()
 *   request.
 *
 * - Access to any flock lockres doesn't require concurrency, so we
 *   can simplify the code by requiring the caller to guarantee
 *   serialization of dlmglue flock calls.
 */
int ocfs2_file_lock(struct file *file, int ex, int trylock)
{
	int ret, level = ex ? DLM_LOCK_EX : DLM_LOCK_PR;
	unsigned int lkm_flags = trylock ? DLM_LKF_NOQUEUE : 0;
	unsigned long flags;
	struct ocfs2_file_private *fp = file->private_data;
	struct ocfs2_lock_res *lockres = &fp->fp_flock;
	struct ocfs2_super *osb = OCFS2_SB(file->f_mapping->host->i_sb);
	struct ocfs2_mask_waiter mw;

	ocfs2_init_mask_waiter(&mw);

	if ((lockres->l_flags & OCFS2_LOCK_BUSY) ||
	    (lockres->l_level > DLM_LOCK_NL)) {
		mlog(ML_ERROR,
		     "File lock \"%s\" has busy or locked state: flags: 0x%lx, "
		     "level: %u\n", lockres->l_name, lockres->l_flags,
		     lockres->l_level);
		return -EINVAL;
	}

	spin_lock_irqsave(&lockres->l_lock, flags);
	if (!(lockres->l_flags & OCFS2_LOCK_ATTACHED)) {
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BUSY, 0);
		spin_unlock_irqrestore(&lockres->l_lock, flags);

		/*
		 * Get the lock at NLMODE to start - that way we
		 * can cancel the upconvert request if need be.
		 */
		ret = ocfs2_lock_create(osb, lockres, DLM_LOCK_NL, 0);
		if (ret < 0) {
			mlog_errno(ret);
			goto out;
		}

		ret = ocfs2_wait_for_mask(&mw);
		if (ret) {
			mlog_errno(ret);
			goto out;
		}
		spin_lock_irqsave(&lockres->l_lock, flags);
	}

	lockres->l_action = OCFS2_AST_CONVERT;
	lkm_flags |= DLM_LKF_CONVERT;
	lockres->l_requested = level;
	lockres_or_flags(lockres, OCFS2_LOCK_BUSY);

	lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BUSY, 0);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	ret = ocfs2_dlm_lock(osb->cconn, level, &lockres->l_lksb, lkm_flags,
			     lockres->l_name, OCFS2_LOCK_ID_MAX_LEN - 1);
	if (ret) {
		if (!trylock || (ret != -EAGAIN)) {
			ocfs2_log_dlm_error("ocfs2_dlm_lock", ret, lockres);
			ret = -EINVAL;
		}

		ocfs2_recover_from_dlm_error(lockres, 1);
		lockres_remove_mask_waiter(lockres, &mw);
		goto out;
	}

	ret = ocfs2_wait_for_mask_interruptible(&mw, lockres);
	if (ret == -ERESTARTSYS) {
		/*
		 * Userspace can cause deadlock itself with
		 * flock(). Current behavior locally is to allow the
		 * deadlock, but abort the system call if a signal is
		 * received. We follow this example, otherwise a
		 * poorly written program could sit in kernel until
		 * reboot.
		 *
		 * Handling this is a bit more complicated for Ocfs2
		 * though. We can't exit this function with an
		 * outstanding lock request, so a cancel convert is
		 * required. We intentionally overwrite 'ret' - if the
		 * cancel fails and the lock was granted, it's easier
		 * to just bubble success back up to the user.
		 */
		ret = ocfs2_flock_handle_signal(lockres, level);
	} else if (!ret && (level > lockres->l_level)) {
		/* Trylock failed asynchronously */
		BUG_ON(!trylock);
		ret = -EAGAIN;
	}

out:

	mlog(0, "Lock: \"%s\" ex: %d, trylock: %d, returns: %d\n",
	     lockres->l_name, ex, trylock, ret);
	return ret;
}

void ocfs2_file_unlock(struct file *file)
{
	int ret;
	unsigned int gen;
	unsigned long flags;
	struct ocfs2_file_private *fp = file->private_data;
	struct ocfs2_lock_res *lockres = &fp->fp_flock;
	struct ocfs2_super *osb = OCFS2_SB(file->f_mapping->host->i_sb);
	struct ocfs2_mask_waiter mw;

	ocfs2_init_mask_waiter(&mw);

	if (!(lockres->l_flags & OCFS2_LOCK_ATTACHED))
		return;

	if (lockres->l_level == DLM_LOCK_NL)
		return;

	mlog(0, "Unlock: \"%s\" flags: 0x%lx, level: %d, act: %d\n",
	     lockres->l_name, lockres->l_flags, lockres->l_level,
	     lockres->l_action);

	spin_lock_irqsave(&lockres->l_lock, flags);
	/*
	 * Fake a blocking ast for the downconvert code.
	 */
	lockres_or_flags(lockres, OCFS2_LOCK_BLOCKED);
	lockres->l_blocking = DLM_LOCK_EX;

	gen = ocfs2_prepare_downconvert(lockres, DLM_LOCK_NL);
	lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_BUSY, 0);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	ret = ocfs2_downconvert_lock(osb, lockres, DLM_LOCK_NL, 0, gen);
	if (ret) {
		mlog_errno(ret);
		return;
	}

	ret = ocfs2_wait_for_mask(&mw);
	if (ret)
		mlog_errno(ret);
}
#endif

static void ocfs2_downconvert_on_unlock(struct ocfs2_super *osb,
					struct ocfs2_lock_res *lockres)
{
	int kick = 0;

	/* If we know that another node is waiting on our lock, kick
	 * the downconvert thread * pre-emptively when we reach a release
	 * condition. */
	if (lockres->l_flags & OCFS2_LOCK_BLOCKED) {
		switch(lockres->l_blocking) {
		case DLM_LOCK_EX:
			if (!lockres_has_holders(lockres, H_ANY))
				kick = 1;
			break;
		case DLM_LOCK_PR:
			if (!lockres_has_holders(lockres, H_EX|H_CW))
				kick = 1;
			break;
		case DLM_LOCK_CW:
			if (!lockres_has_holders(lockres, H_EX|H_PR))
				kick = 1;
			break;
		default:
			BUG();
		}
	}

	if (kick)
		ocfs2_wake_downconvert_thread(osb);
}

#if 0
/* Determine whether a lock resource needs to be refreshed, and
 * arbitrate who gets to refresh it.
 *
 *   0 means no refresh needed.
 *
 *   > 0 means you need to refresh this and you MUST call
 *   ocfs2_complete_lock_res_refresh afterwards. */
static int ocfs2_should_refresh_lock_res(struct ocfs2_lock_res *lockres)
{
	unsigned long flags;
	int status = 0;

refresh_check:
	spin_lock_irqsave(&lockres->l_lock, flags);
	if (!(lockres->l_flags & OCFS2_LOCK_NEEDS_REFRESH)) {
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		goto bail;
	}

	if (lockres->l_flags & OCFS2_LOCK_REFRESHING) {
		spin_unlock_irqrestore(&lockres->l_lock, flags);

		ocfs2_wait_on_refreshing_lock(lockres);
		goto refresh_check;
	}

	/* Ok, I'll be the one to refresh this lock. */
	lockres_or_flags(lockres, OCFS2_LOCK_REFRESHING);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	status = 1;
bail:
	mlog(0, "status %d\n", status);
	return status;
}
#endif

/* If status is non zero, I'll mark it as not being in refresh
 * anymroe, but i won't clear the needs refresh flag. */
static inline void ocfs2_complete_lock_res_refresh(struct ocfs2_lock_res *lockres,
						   int status)
{
	unsigned long flags;

	spin_lock_irqsave(&lockres->l_lock, flags);
	lockres_clear_flags(lockres, OCFS2_LOCK_REFRESHING);
	if (!status)
		lockres_clear_flags(lockres, OCFS2_LOCK_NEEDS_REFRESH);
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	wake_up(&lockres->l_event);
}

u64 ocfs2_lock_refresh_gen(struct ocfs2_lock_res *lockres)
{
	return lockres->l_refresh_gen;
}

/* Reference counting of the dlm debug structure. We want this because
 * open references on the debug inodes can live on after a mount, so
 * we can't rely on the ocfs2_super to always exist. */
static void ocfs2_dlm_debug_free(struct kref *kref)
{
	struct ocfs2_dlm_debug *dlm_debug;

	dlm_debug = container_of(kref, struct ocfs2_dlm_debug, d_refcnt);

	kfree(dlm_debug);
}

void ocfs2_put_dlm_debug(struct ocfs2_dlm_debug *dlm_debug)
{
	if (dlm_debug)
		kref_put(&dlm_debug->d_refcnt, ocfs2_dlm_debug_free);
}

static void ocfs2_get_dlm_debug(struct ocfs2_dlm_debug *debug)
{
	kref_get(&debug->d_refcnt);
}

struct ocfs2_dlm_debug *ocfs2_new_dlm_debug(void)
{
	struct ocfs2_dlm_debug *dlm_debug;

	dlm_debug = kmalloc(sizeof(struct ocfs2_dlm_debug), GFP_KERNEL);
	if (!dlm_debug) {
		mlog_errno(-ENOMEM);
		goto out;
	}

	kref_init(&dlm_debug->d_refcnt);
	INIT_LIST_HEAD(&dlm_debug->d_lockres_tracking);
	dlm_debug->d_locking_state = NULL;
out:
	return dlm_debug;
}

/* Access to this is arbitrated for us via seq_file->sem. */
struct ocfs2_dlm_seq_priv {
	struct ocfs2_dlm_debug *p_dlm_debug;
	struct ocfs2_lock_res p_iter_res;
	struct ocfs2_lock_res p_tmp_res;
};

static struct ocfs2_lock_res *ocfs2_dlm_next_res(struct ocfs2_lock_res *start,
						 struct ocfs2_dlm_seq_priv *priv)
{
	struct ocfs2_lock_res *iter, *ret = NULL;
	struct ocfs2_dlm_debug *dlm_debug = priv->p_dlm_debug;

	assert_spin_locked(&ocfs2_dlm_tracking_lock);

	list_for_each_entry(iter, &start->l_debug_list, l_debug_list) {
		/* discover the head of the list */
		if (&iter->l_debug_list == &dlm_debug->d_lockres_tracking) {
			mlog(0, "End of list found, %p\n", ret);
			break;
		}

		/* We track our "dummy" iteration lockres' by a NULL
		 * l_ops field. */
		if (iter->l_ops != NULL) {
			ret = iter;
			break;
		}
	}

	return ret;
}

static void *ocfs2_dlm_seq_start(struct seq_file *m, loff_t *pos)
{
	struct ocfs2_dlm_seq_priv *priv = m->private;
	struct ocfs2_lock_res *iter;

	spin_lock(&ocfs2_dlm_tracking_lock);
	iter = ocfs2_dlm_next_res(&priv->p_iter_res, priv);
	if (iter) {
		/* Since lockres' have the lifetime of their container
		 * (which can be inodes, ocfs2_supers, etc) we want to
		 * copy this out to a temporary lockres while still
		 * under the spinlock. Obviously after this we can't
		 * trust any pointers on the copy returned, but that's
		 * ok as the information we want isn't typically held
		 * in them. */
		priv->p_tmp_res = *iter;
		iter = &priv->p_tmp_res;
	}
	spin_unlock(&ocfs2_dlm_tracking_lock);

	return iter;
}

static void ocfs2_dlm_seq_stop(struct seq_file *m, void *v)
{
}

static void *ocfs2_dlm_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ocfs2_dlm_seq_priv *priv = m->private;
	struct ocfs2_lock_res *iter = v;
	struct ocfs2_lock_res *dummy = &priv->p_iter_res;

	spin_lock(&ocfs2_dlm_tracking_lock);
	iter = ocfs2_dlm_next_res(iter, priv);
	list_del_init(&dummy->l_debug_list);
	if (iter) {
		list_add(&dummy->l_debug_list, &iter->l_debug_list);
		priv->p_tmp_res = *iter;
		iter = &priv->p_tmp_res;
	}
	spin_unlock(&ocfs2_dlm_tracking_lock);

	return iter;
}

/*
 * Version is used by debugfs.ocfs2 to determine the format being used
 *
 * New in version 2
 *	- Lock stats printed
 * New in version 3
 *	- Max time in lock stats is in usecs (instead of nsecs)
 */
#define OCFS2_DLM_DEBUG_STR_VERSION 3
static int ocfs2_dlm_seq_show(struct seq_file *m, void *v)
{
	int i;
	char *lvb;
	struct ocfs2_lock_res *lockres = v;
	char lockname[256];

	if (!lockres)
		return -EINVAL;

	lockres_name(lockres, lockname, 256);

	seq_printf(m, "0x%x\t%s\t", OCFS2_DLM_DEBUG_STR_VERSION, lockname);

	seq_printf(m, "%d\t"
		   "0x%lx\t"
		   "0x%x\t"
		   "0x%x\t"
		   "%u\t"
		   "%u\t"
		   "%d\t"
		   "%d\t",
		   lockres->l_level,
		   lockres->l_flags,
		   lockres->l_action,
		   lockres->l_unlock_action,
		   lockres->l_ro_holders,
		   lockres->l_ex_holders,
		   lockres->l_requested,
		   lockres->l_blocking);

	/* Dump the raw LVB */
	lvb = ocfs2_dlm_lvb(&lockres->l_lksb);
	for(i = 0; i < DLM_LVB_LEN; i++)
		seq_printf(m, "0x%x\t", lvb[i]);

#ifdef CONFIG_OCFS2_FS_STATS
# define lock_num_cwmode(_l)		((_l)->l_lock_cwmode.ls_gets)
# define lock_num_prmode(_l)		((_l)->l_lock_prmode.ls_gets)
# define lock_num_exmode(_l)		((_l)->l_lock_exmode.ls_gets)
# define lock_num_cwmode_failed(_l)	((_l)->l_lock_cwmode.ls_fail)
# define lock_num_prmode_failed(_l)	((_l)->l_lock_prmode.ls_fail)
# define lock_num_exmode_failed(_l)	((_l)->l_lock_exmode.ls_fail)
# define lock_total_cwmode(_l)		((_l)->l_lock_cwmode.ls_total)
# define lock_total_prmode(_l)		((_l)->l_lock_prmode.ls_total)
# define lock_total_exmode(_l)		((_l)->l_lock_exmode.ls_total)
# define lock_max_cwmode(_l)		((_l)->l_lock_cwmode.ls_max)
# define lock_max_prmode(_l)		((_l)->l_lock_prmode.ls_max)
# define lock_max_exmode(_l)		((_l)->l_lock_exmode.ls_max)
# define lock_refresh(_l)		((_l)->l_lock_refresh)
#else
# define lock_num_cwmode(_l)		(0)
# define lock_num_prmode(_l)		(0)
# define lock_num_exmode(_l)		(0)
# define lock_num_cwmode_failed(_l)	(0)
# define lock_num_prmode_failed(_l)	(0)
# define lock_num_exmode_failed(_l)	(0)
# define lock_total_cwmode(_l)		(0ULL)
# define lock_total_prmode(_l)		(0ULL)
# define lock_total_exmode(_l)		(0ULL)
# define lock_max_cwmode(_l)		(0)
# define lock_max_prmode(_l)		(0)
# define lock_max_exmode(_l)		(0)
# define lock_refresh(_l)		(0)
#endif
	/* The following seq_print was added in version 2 of this output */
	seq_printf(m, "%u\t"
		   "%u\t"
		   "%u\t"
		   "%u\t"
		   "%llu\t"
		   "%llu\t"
		   "%u\t"
		   "%u\t"
		   "%u\t",
		   lock_num_prmode(lockres),
		   lock_num_exmode(lockres),
		   lock_num_prmode_failed(lockres),
		   lock_num_exmode_failed(lockres),
		   lock_total_prmode(lockres),
		   lock_total_exmode(lockres),
		   lock_max_prmode(lockres),
		   lock_max_exmode(lockres),
		   lock_refresh(lockres));

	seq_printf(m, "%u\t"
		   "%u\t"
		   "%u\t"
		   "%llu\t"
		   "%u\t",
		   lockres->l_cw_holders,
		   lock_num_cwmode(lockres),
		   lock_num_cwmode_failed(lockres),
		   lock_total_cwmode(lockres),
		   lock_max_cwmode(lockres));

	/* End the line */
	seq_printf(m, "\n");
	return 0;
}

static const struct seq_operations ocfs2_dlm_seq_ops = {
	.start =	ocfs2_dlm_seq_start,
	.stop =		ocfs2_dlm_seq_stop,
	.next =		ocfs2_dlm_seq_next,
	.show =		ocfs2_dlm_seq_show,
};

static int ocfs2_dlm_debug_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct ocfs2_dlm_seq_priv *priv = seq->private;
	struct ocfs2_lock_res *res = &priv->p_iter_res;

	ocfs2_remove_lockres_tracking(res);
	ocfs2_put_dlm_debug(priv->p_dlm_debug);
	return seq_release_private(inode, file);
}

static int ocfs2_dlm_debug_open(struct inode *inode, struct file *file)
{
	struct ocfs2_dlm_seq_priv *priv;
	struct ocfs2_super *osb;

	priv = __seq_open_private(file, &ocfs2_dlm_seq_ops, sizeof(*priv));
	if (!priv) {
		mlog_errno(-ENOMEM);
		return -ENOMEM;
	}

	osb = inode->i_private;
	ocfs2_get_dlm_debug(osb->osb_dlm_debug);
	priv->p_dlm_debug = osb->osb_dlm_debug;
	INIT_LIST_HEAD(&priv->p_iter_res.l_debug_list);

	ocfs2_add_lockres_tracking(&priv->p_iter_res,
				   priv->p_dlm_debug);

	return 0;
}

static const struct file_operations ocfs2_dlm_debug_fops = {
	.open =		ocfs2_dlm_debug_open,
	.release =	ocfs2_dlm_debug_release,
	.read =		seq_read,
	.llseek =	seq_lseek,
};

static int ocfs2_dlm_init_debug(struct ocfs2_super *osb,
				struct dentry *debug_root)
{
	int ret = 0;
	struct ocfs2_dlm_debug *dlm_debug = osb->osb_dlm_debug;

	dlm_debug->d_locking_state = debugfs_create_file("locking_state",
							 S_IFREG|S_IRUSR,
							 debug_root,
							 osb,
							 &ocfs2_dlm_debug_fops);
	if (!dlm_debug->d_locking_state) {
		ret = -EINVAL;
		mlog(ML_ERROR,
		     "Unable to create locking state debugfs file.\n");
		goto out;
	}

	ocfs2_get_dlm_debug(dlm_debug);
out:
	return ret;
}

static void ocfs2_dlm_shutdown_debug(struct ocfs2_super *osb)
{
	struct ocfs2_dlm_debug *dlm_debug = osb->osb_dlm_debug;

	if (dlm_debug) {
		debugfs_remove(dlm_debug->d_locking_state);
		ocfs2_put_dlm_debug(dlm_debug);
	}
}

static void ocfs2_do_node_down(int node_num, void *data)
{
}

int ocfs2_dlm_init(struct ocfs2_super *osb, char *cluster_stack,
		   char *cluster_name, char *ls_name, struct dentry *debug_root)
{
	int status = 0;
	struct ocfs2_cluster_connection *conn = NULL;

#if 0
	if (ocfs2_mount_local(osb)) {
		osb->node_num = 0;
		goto local;
	}
#endif

	status = ocfs2_dlm_init_debug(osb, debug_root);
	if (status < 0) {
		mlog_errno(status);
		goto bail;
	}

	/* launch downconvert thread */
	osb->dc_task = kthread_run(ocfs2_downconvert_thread, osb, "scoutdc-%s",
				   ls_name);
	if (IS_ERR(osb->dc_task)) {
		status = PTR_ERR(osb->dc_task);
		osb->dc_task = NULL;
		mlog_errno(status);
		goto bail;
	}

	/* for now, uuid == domain */
	status = ocfs2_cluster_connect(cluster_stack,
				       cluster_name,
				       strlen(cluster_name),
				       ls_name,
				       strlen(ls_name),
				       &lproto, ocfs2_do_node_down, osb,
				       &conn);
	if (status) {
		mlog_errno(status);
		goto bail;
	}

#if 0
	status = ocfs2_cluster_this_node(conn, &osb->node_num);
	if (status < 0) {
		mlog_errno(status);
		mlog(ML_ERROR,
		     "could not find this host's node number\n");
		ocfs2_cluster_disconnect(conn, 0);
		goto bail;
	}

local:
	ocfs2_super_lock_res_init(&osb->osb_super_lockres, osb);
	ocfs2_rename_lock_res_init(&osb->osb_rename_lockres, osb);
	ocfs2_nfs_sync_lock_res_init(&osb->osb_nfs_sync_lockres, osb);
	ocfs2_orphan_scan_lock_res_init(&osb->osb_orphan_scan.os_lockres, osb);
#endif
	osb->cconn = conn;
bail:
	if (status < 0) {
		ocfs2_dlm_shutdown_debug(osb);
		if (osb->dc_task)
			kthread_stop(osb->dc_task);
	}

	return status;
}

void ocfs2_dlm_shutdown(struct ocfs2_super *osb,
			int hangup_pending)
{
//	ocfs2_drop_osb_locks(osb);

	/*
	 * Now that we have dropped all locks and ocfs2_dismount_volume()
	 * has disabled recovery, the DLM won't be talking to us.  It's
	 * safe to tear things down before disconnecting the cluster.
	 */

	if (osb->dc_task) {
		kthread_stop(osb->dc_task);
		osb->dc_task = NULL;
	}

#if 0
	ocfs2_lock_res_free(&osb->osb_super_lockres);
	ocfs2_lock_res_free(&osb->osb_rename_lockres);
	ocfs2_lock_res_free(&osb->osb_nfs_sync_lockres);
	ocfs2_lock_res_free(&osb->osb_orphan_scan.os_lockres);
#endif

	ocfs2_cluster_disconnect(osb->cconn, hangup_pending);
	osb->cconn = NULL;

	ocfs2_dlm_shutdown_debug(osb);
}

static int ocfs2_drop_lock(struct ocfs2_super *osb,
			   struct ocfs2_lock_res *lockres)
{
	int ret;
	unsigned long flags;
	u32 lkm_flags = 0;

	/* We didn't get anywhere near actually using this lockres. */
	if (!(lockres->l_flags & OCFS2_LOCK_INITIALIZED))
		goto out;

	if (lockres->l_ops->flags & LOCK_TYPE_USES_LVB)
		lkm_flags |= DLM_LKF_VALBLK;

	spin_lock_irqsave(&lockres->l_lock, flags);

	mlog_bug_on_msg(!(lockres->l_flags & OCFS2_LOCK_FREEING),
			"lockres %s, flags 0x%lx\n",
			lockres->l_name, lockres->l_flags);

	while (lockres->l_flags & OCFS2_LOCK_BUSY) {
		mlog(0, "waiting on busy lock \"%s\": flags = %lx, action = "
		     "%u, unlock_action = %u\n",
		     lockres->l_name, lockres->l_flags, lockres->l_action,
		     lockres->l_unlock_action);

		spin_unlock_irqrestore(&lockres->l_lock, flags);

		/* XXX: Today we just wait on any busy
		 * locks... Perhaps we need to cancel converts in the
		 * future? */
		ocfs2_wait_on_busy_lock(lockres);

		spin_lock_irqsave(&lockres->l_lock, flags);
	}

	if (lockres->l_ops->flags & LOCK_TYPE_USES_LVB) {
		if (lockres->l_flags & OCFS2_LOCK_ATTACHED &&
		    lockres->l_level == DLM_LOCK_EX &&
		    !(lockres->l_flags & OCFS2_LOCK_NEEDS_REFRESH))
			lockres->l_ops->set_lvb(lockres);
	}

	if (lockres->l_flags & OCFS2_LOCK_BUSY)
		mlog(ML_ERROR, "destroying busy lock: \"%s\"\n",
		     lockres->l_name);
	if (lockres->l_flags & OCFS2_LOCK_BLOCKED)
		mlog(0, "destroying blocked lock: \"%s\"\n", lockres->l_name);

	if (!(lockres->l_flags & OCFS2_LOCK_ATTACHED)) {
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		goto out;
	}

	lockres_clear_flags(lockres, OCFS2_LOCK_ATTACHED);

	/* make sure we never get here while waiting for an ast to
	 * fire. */
	BUG_ON(lockres->l_action != OCFS2_AST_INVALID);

	/* is this necessary? */
	lockres_or_flags(lockres, OCFS2_LOCK_BUSY);
	lockres->l_unlock_action = OCFS2_UNLOCK_DROP_LOCK;
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	mlog(0, "lock %s\n", lockres->l_name);

	ret = ocfs2_dlm_unlock(osb->cconn, &lockres->l_lksb, lkm_flags);
	if (ret) {
		ocfs2_log_dlm_error("ocfs2_dlm_unlock", ret, lockres);
		mlog(ML_ERROR, "lockres flags: %lu\n", lockres->l_flags);
		ocfs2_dlm_dump_lksb(&lockres->l_lksb);
		BUG();
	}
	mlog(0, "lock %s, successful return from ocfs2_dlm_unlock\n",
	     lockres->l_name);

	ocfs2_wait_on_busy_lock(lockres);
out:
	return 0;
}

static void ocfs2_process_blocked_lock(struct ocfs2_super *osb,
				       struct ocfs2_lock_res *lockres);

/* Mark the lockres as being dropped. It will no longer be
 * queued if blocking, but we still may have to wait on it
 * being dequeued from the downconvert thread before we can consider
 * it safe to drop.
 *
 * You can *not* attempt to call cluster_lock on this lockres anymore. */
void ocfs2_mark_lockres_freeing(struct ocfs2_super *osb,
				struct ocfs2_lock_res *lockres)
{
	int status;
	struct ocfs2_mask_waiter mw;
	unsigned long flags, flags2;

	ocfs2_init_mask_waiter(&mw);

	spin_lock_irqsave(&lockres->l_lock, flags);
	lockres->l_flags |= OCFS2_LOCK_FREEING;
	if (lockres->l_flags & OCFS2_LOCK_QUEUED && current == osb->dc_task) {
		/*
		 * We know the downconvert is queued but not in progress
		 * because we are the downconvert thread and processing
		 * different lock. So we can just remove the lock from the
		 * queue. This is not only an optimization but also a way
		 * to avoid the following deadlock:
		 *   ocfs2_dentry_post_unlock()
		 *     ocfs2_dentry_lock_put()
		 *       ocfs2_drop_dentry_lock()
		 *         iput()
		 *           ocfs2_evict_inode()
		 *             ocfs2_clear_inode()
		 *               ocfs2_mark_lockres_freeing()
		 *                 ... blocks waiting for OCFS2_LOCK_QUEUED
		 *                 since we are the downconvert thread which
		 *                 should clear the flag.
		 */
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		spin_lock_irqsave(&osb->dc_task_lock, flags2);
		list_del_init(&lockres->l_blocked_list);
		osb->blocked_lock_count--;
		spin_unlock_irqrestore(&osb->dc_task_lock, flags2);
		/*
		 * Warn if we recurse into another post_unlock call.  Strictly
		 * speaking it isn't a problem but we need to be careful if
		 * that happens (stack overflow, deadlocks, ...) so warn if
		 * ocfs2 grows a path for which this can happen.
		 */
		WARN_ON_ONCE(lockres->l_ops->post_unlock);
		/* Since the lock is freeing we don't do much in the fn below */
		ocfs2_process_blocked_lock(osb, lockres);
		return;
	}
	while (lockres->l_flags & OCFS2_LOCK_QUEUED) {
		lockres_add_mask_waiter(lockres, &mw, OCFS2_LOCK_QUEUED, 0);
		spin_unlock_irqrestore(&lockres->l_lock, flags);

		mlog(0, "Waiting on lockres %s\n", lockres->l_name);

		status = ocfs2_wait_for_mask(&mw);
		if (status)
			mlog_errno(status);

		spin_lock_irqsave(&lockres->l_lock, flags);
	}
	spin_unlock_irqrestore(&lockres->l_lock, flags);
}

void ocfs2_simple_drop_lockres(struct ocfs2_super *osb,
			       struct ocfs2_lock_res *lockres)
{
	int ret;

	ocfs2_mark_lockres_freeing(osb, lockres);
	ret = ocfs2_drop_lock(osb, lockres);
	if (ret)
		mlog_errno(ret);
}

static unsigned int ocfs2_prepare_downconvert(struct ocfs2_lock_res *lockres,
					      int new_level)
{
	assert_spin_locked(&lockres->l_lock);

	BUG_ON(lockres->l_blocking <= DLM_LOCK_NL);

	if (lockres->l_level <= new_level) {
		mlog(ML_ERROR, "lockres %s, lvl %d <= %d, blcklst %d, mask %d, "
		     "flags 0x%lx, hold %d %d, act %d %d, req %d, "
		     "block %d, pgen %d\n", lockres->l_name, lockres->l_level,
		     new_level, list_empty(&lockres->l_blocked_list),
		     list_empty(&lockres->l_mask_waiters),
		     lockres->l_flags, lockres->l_ro_holders,
		     lockres->l_ex_holders, lockres->l_action,
		     lockres->l_unlock_action, lockres->l_requested,
		     lockres->l_blocking, lockres->l_pending_gen);
		BUG();
	}

	mlog(ML_BASTS, "lockres %s, level %d => %d, blocking %d\n",
	     lockres->l_name, lockres->l_level, new_level, lockres->l_blocking);

	lockres->l_action = OCFS2_AST_DOWNCONVERT;
	lockres->l_requested = new_level;
	lockres_or_flags(lockres, OCFS2_LOCK_BUSY);
	return lockres_set_pending(lockres);
}

static int ocfs2_downconvert_lock(struct ocfs2_super *osb,
				  struct ocfs2_lock_res *lockres,
				  int new_level,
				  int lvb,
				  unsigned int generation)
{
	int ret;
	u32 dlm_flags = DLM_LKF_CONVERT;

	mlog(ML_BASTS, "lockres %s, level %d => %d\n", lockres->l_name,
	     lockres->l_level, new_level);

	/*
	 * On DLM_LKF_VALBLK, fsdlm behaves differently with o2cb. It always
	 * expects DLM_LKF_VALBLK being set if the LKB has LVB, so that
	 * we can recover correctly from node failure. Otherwise, we may get
	 * invalid LVB in LKB, but without DLM_SBF_VALNOTVALID being set.
	 */
	if (!ocfs2_is_o2cb_active() &&
	    lockres->l_ops->flags & LOCK_TYPE_USES_LVB)
		lvb = 1;

	if (lvb)
		dlm_flags |= DLM_LKF_VALBLK;

	ret = ocfs2_dlm_lock(osb->cconn,
			     new_level,
			     &lockres->l_lksb,
			     dlm_flags,
			     lockres->l_name,
			     OCFS2_LOCK_ID_MAX_LEN - 1);
	lockres_clear_pending(lockres, generation, osb);
	if (ret) {
		ocfs2_log_dlm_error("ocfs2_dlm_lock", ret, lockres);
		ocfs2_recover_from_dlm_error(lockres, 1);
		goto bail;
	}

	ret = 0;
bail:
	return ret;
}

/* returns 1 when the caller should unlock and call ocfs2_dlm_unlock */
static int ocfs2_prepare_cancel_convert(struct ocfs2_super *osb,
				        struct ocfs2_lock_res *lockres)
{
	assert_spin_locked(&lockres->l_lock);

	if (lockres->l_unlock_action == OCFS2_UNLOCK_CANCEL_CONVERT) {
		/* If we're already trying to cancel a lock conversion
		 * then just drop the spinlock and allow the caller to
		 * requeue this lock. */
		mlog(ML_BASTS, "lockres %s, skip convert\n", lockres->l_name);
		return 0;
	}

	/* were we in a convert when we got the bast fire? */
	BUG_ON(lockres->l_action != OCFS2_AST_CONVERT &&
	       lockres->l_action != OCFS2_AST_DOWNCONVERT);
	/* set things up for the unlockast to know to just
	 * clear out the ast_action and unset busy, etc. */
	lockres->l_unlock_action = OCFS2_UNLOCK_CANCEL_CONVERT;

	mlog_bug_on_msg(!(lockres->l_flags & OCFS2_LOCK_BUSY),
			"lock %s, invalid flags: 0x%lx\n",
			lockres->l_name, lockres->l_flags);

	mlog(ML_BASTS, "lockres %s\n", lockres->l_name);

	return 1;
}

static int ocfs2_cancel_convert(struct ocfs2_super *osb,
				struct ocfs2_lock_res *lockres)
{
	int ret;

	ret = ocfs2_dlm_unlock(osb->cconn, &lockres->l_lksb,
			       DLM_LKF_CANCEL);
	if (ret) {
		ocfs2_log_dlm_error("ocfs2_dlm_unlock", ret, lockres);
		ocfs2_recover_from_dlm_error(lockres, 0);
	}

	mlog(ML_BASTS, "lockres %s\n", lockres->l_name);

	return ret;
}

static int ocfs2_unblock_lock(struct ocfs2_super *osb,
			      struct ocfs2_lock_res *lockres,
			      struct ocfs2_unblock_ctl *ctl)
{
	unsigned long flags;
	int blocking;
	int new_level;
	int level;
	int ret = 0;
	int set_lvb = 0;
	unsigned int gen;

	spin_lock_irqsave(&lockres->l_lock, flags);

recheck:
	/*
	 * Is it still blocking? If not, we have no more work to do.
	 */
	if (!(lockres->l_flags & OCFS2_LOCK_BLOCKED)) {
		BUG_ON(lockres->l_blocking != DLM_LOCK_NL);
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		ret = 0;
		goto leave;
	}

	if (lockres->l_flags & OCFS2_LOCK_BUSY) {
		/* XXX
		 * This is a *big* race.  The OCFS2_LOCK_PENDING flag
		 * exists entirely for one reason - another thread has set
		 * OCFS2_LOCK_BUSY, but has *NOT* yet called dlm_lock().
		 *
		 * If we do ocfs2_cancel_convert() before the other thread
		 * calls dlm_lock(), our cancel will do nothing.  We will
		 * get no ast, and we will have no way of knowing the
		 * cancel failed.  Meanwhile, the other thread will call
		 * into dlm_lock() and wait...forever.
		 *
		 * Why forever?  Because another node has asked for the
		 * lock first; that's why we're here in unblock_lock().
		 *
		 * The solution is OCFS2_LOCK_PENDING.  When PENDING is
		 * set, we just requeue the unblock.  Only when the other
		 * thread has called dlm_lock() and cleared PENDING will
		 * we then cancel their request.
		 *
		 * All callers of dlm_lock() must set OCFS2_DLM_PENDING
		 * at the same time they set OCFS2_DLM_BUSY.  They must
		 * clear OCFS2_DLM_PENDING after dlm_lock() returns.
		 */
		if (lockres->l_flags & OCFS2_LOCK_PENDING) {
			mlog(ML_BASTS, "lockres %s, ReQ: Pending\n",
			     lockres->l_name);
			goto leave_requeue;
		}

		ctl->requeue = 1;
		ret = ocfs2_prepare_cancel_convert(osb, lockres);
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		if (ret) {
			ret = ocfs2_cancel_convert(osb, lockres);
			if (ret < 0)
				mlog_errno(ret);
		}
		goto leave;
	}

	/*
	 * This prevents livelocks. OCFS2_LOCK_UPCONVERT_FINISHING flag is
	 * set when the ast is received for an upconvert just before the
	 * OCFS2_LOCK_BUSY flag is cleared. Now if the fs received a bast
	 * on the heels of the ast, we want to delay the downconvert just
	 * enough to allow the up requestor to do its task. Because this
	 * lock is in the blocked queue, the lock will be downconverted
	 * as soon as the requestor is done with the lock.
	 */
	if (lockres->l_flags & OCFS2_LOCK_UPCONVERT_FINISHING)
		goto leave_requeue;

	/*
	 * How can we block and yet be at NL?  We were trying to upconvert
	 * from NL and got canceled.  The code comes back here, and now
	 * we notice and clear BLOCKING.
	 */
	if (lockres->l_level == DLM_LOCK_NL) {
		BUG_ON(lockres_has_holders(lockres, H_ANY));
		mlog(ML_BASTS, "lockres %s, Aborting dc\n", lockres->l_name);
		lockres->l_blocking = DLM_LOCK_NL;
		lockres_clear_flags(lockres, OCFS2_LOCK_BLOCKED);
		spin_unlock_irqrestore(&lockres->l_lock, flags);
		goto leave;
	}

	/* if we're blocking an exclusive and we have *any* holders,
	 * then requeue. */
	if (lockres->l_blocking == DLM_LOCK_EX &&
	    lockres_has_holders(lockres, H_ANY)) {
		mlog(ML_BASTS, "lockres %s, ReQ: EX/PR/CW Holders %u,%u\n",
		     lockres->l_name, lockres->l_ex_holders,
		     lockres->l_ro_holders, lockres->l_cw_holders);
		goto leave_requeue;
	}

	/* If it's a PR we're blocking, then only
	 * requeue if we've got any EX or CW holders */
	if (lockres->l_blocking == DLM_LOCK_PR &&
	    lockres_has_holders(lockres, H_CW|H_EX)) {
		mlog(ML_BASTS, "lockres %s, ReQ: EX/CW Holders %u,%u\n",
		     lockres->l_name, lockres->l_ex_holders,
		     lockres->l_cw_holders);
		goto leave_requeue;
	}

	/*
	 * Same logic as above, we're checking for any holders that
	 * are incompatible with CW.
	 */
	if (lockres->l_blocking == DLM_LOCK_CW
	    && lockres_has_holders(lockres, H_EX|H_PR)) {
		mlog(ML_BASTS, "lockres %s, ReQ: EX/PR Holders %u,%u\n",
		     lockres->l_name, lockres->l_ex_holders,
		     lockres->l_ro_holders);
		goto leave_requeue;
	}

	/*
	 * Can we get a lock in this state if the holder counts are
	 * zero? The meta data unblock code used to check this.
	 */
	if ((lockres->l_ops->flags & LOCK_TYPE_REQUIRES_REFRESH)
	    && (lockres->l_flags & OCFS2_LOCK_REFRESHING)) {
		mlog(ML_BASTS, "lockres %s, ReQ: Lock Refreshing\n",
		     lockres->l_name);
		goto leave_requeue;
	}

	new_level = ocfs2_downconvert_level(lockres, lockres->l_blocking);

	if (lockres->l_ops->check_downconvert
	    && !lockres->l_ops->check_downconvert(lockres, new_level)) {
		mlog(ML_BASTS, "lockres %s, ReQ: Checkpointing\n",
		     lockres->l_name);
		goto leave_requeue;
	}

	/* If we get here, then we know that there are no more
	 * incompatible holders (and anyone asking for an incompatible
	 * lock is blocked). We can now downconvert the lock */
	if (!lockres->l_ops->downconvert_worker)
		goto downconvert;

	/* Some lockres types want to do a bit of work before
	 * downconverting a lock. Allow that here. The worker function
	 * may sleep, so we save off a copy of what we're blocking as
	 * it may change while we're not holding the spin lock. */
	blocking = lockres->l_blocking;
	level = lockres->l_level;
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	ctl->unblock_action = lockres->l_ops->downconvert_worker(lockres, blocking);

	if (ctl->unblock_action == UNBLOCK_STOP_POST) {
		mlog(ML_BASTS, "lockres %s, UNBLOCK_STOP_POST\n",
		     lockres->l_name);
		goto leave;
	}

	spin_lock_irqsave(&lockres->l_lock, flags);
	if ((blocking != lockres->l_blocking) || (level != lockres->l_level)) {
		/* If this changed underneath us, then we can't drop
		 * it just yet. */
		mlog(ML_BASTS, "lockres %s, block=%d:%d, level=%d:%d, "
		     "Recheck\n", lockres->l_name, blocking,
		     lockres->l_blocking, level, lockres->l_level);
		goto recheck;
	}

downconvert:
	ctl->requeue = 0;

	if (lockres->l_ops->flags & LOCK_TYPE_USES_LVB) {
		if (lockres->l_level == DLM_LOCK_EX)
			set_lvb = 1;

		/*
		 * We only set the lvb if the lock has been fully
		 * refreshed - otherwise we risk setting stale
		 * data. Otherwise, there's no need to actually clear
		 * out the lvb here as it's value is still valid.
		 */
		if (set_lvb && !(lockres->l_flags & OCFS2_LOCK_NEEDS_REFRESH))
			lockres->l_ops->set_lvb(lockres);
	}

	gen = ocfs2_prepare_downconvert(lockres, new_level);
	spin_unlock_irqrestore(&lockres->l_lock, flags);
	ret = ocfs2_downconvert_lock(osb, lockres, new_level, set_lvb,
				     gen);

leave:
	if (ret)
		mlog_errno(ret);
	return ret;

leave_requeue:
	spin_unlock_irqrestore(&lockres->l_lock, flags);
	ctl->requeue = 1;

	return 0;
}

static void ocfs2_process_blocked_lock(struct ocfs2_super *osb,
				       struct ocfs2_lock_res *lockres)
{
	int status;
	struct ocfs2_unblock_ctl ctl = {0, 0,};
	unsigned long flags;

	/* Our reference to the lockres in this function can be
	 * considered valid until we remove the OCFS2_LOCK_QUEUED
	 * flag. */

	BUG_ON(!lockres);
	BUG_ON(!lockres->l_ops);

	mlog(ML_BASTS, "lockres %s blocked\n", lockres->l_name);

	/* Detect whether a lock has been marked as going away while
	 * the downconvert thread was processing other things. A lock can
	 * still be marked with OCFS2_LOCK_FREEING after this check,
	 * but short circuiting here will still save us some
	 * performance. */
	spin_lock_irqsave(&lockres->l_lock, flags);
	if (lockres->l_flags & OCFS2_LOCK_FREEING)
		goto unqueue;
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	status = ocfs2_unblock_lock(osb, lockres, &ctl);
	if (status < 0)
		mlog_errno(status);

	spin_lock_irqsave(&lockres->l_lock, flags);
unqueue:
	if (lockres->l_flags & OCFS2_LOCK_FREEING || !ctl.requeue) {
		lockres_clear_flags(lockres, OCFS2_LOCK_QUEUED);
	} else
		ocfs2_schedule_blocked_lock(osb, lockres);

	mlog(ML_BASTS, "lockres %s, requeue = %s.\n", lockres->l_name,
	     ctl.requeue ? "yes" : "no");
	spin_unlock_irqrestore(&lockres->l_lock, flags);

	if (ctl.unblock_action != UNBLOCK_CONTINUE
	    && lockres->l_ops->post_unlock)
		lockres->l_ops->post_unlock(osb, lockres);
}

static void ocfs2_schedule_blocked_lock(struct ocfs2_super *osb,
					struct ocfs2_lock_res *lockres)
{
	unsigned long flags;

	assert_spin_locked(&lockres->l_lock);

	if (lockres->l_flags & OCFS2_LOCK_FREEING) {
		/* Do not schedule a lock for downconvert when it's on
		 * the way to destruction - any nodes wanting access
		 * to the resource will get it soon. */
		mlog(ML_BASTS, "lockres %s won't be scheduled: flags 0x%lx\n",
		     lockres->l_name, lockres->l_flags);
		return;
	}

	lockres_or_flags(lockres, OCFS2_LOCK_QUEUED);

	spin_lock_irqsave(&osb->dc_task_lock, flags);
	if (list_empty(&lockres->l_blocked_list)) {
		list_add_tail(&lockres->l_blocked_list,
			      &osb->blocked_lock_list);
		osb->blocked_lock_count++;
	}
	spin_unlock_irqrestore(&osb->dc_task_lock, flags);
}

static void ocfs2_downconvert_thread_do_work(struct ocfs2_super *osb)
{
	unsigned long processed;
	unsigned long flags;
	struct ocfs2_lock_res *lockres;

	spin_lock_irqsave(&osb->dc_task_lock, flags);
	/* grab this early so we know to try again if a state change and
	 * wake happens part-way through our work  */
	osb->dc_work_sequence = osb->dc_wake_sequence;

	processed = osb->blocked_lock_count;
	/*
	 * blocked lock processing in this loop might call iput which can
	 * remove items off osb->blocked_lock_list. Downconvert up to
	 * 'processed' number of locks, but stop short if we had some
	 * removed in ocfs2_mark_lockres_freeing when downconverting.
	 */
	while (processed && !list_empty(&osb->blocked_lock_list)) {
		lockres = list_entry(osb->blocked_lock_list.next,
				     struct ocfs2_lock_res, l_blocked_list);
		list_del_init(&lockres->l_blocked_list);
		osb->blocked_lock_count--;
		spin_unlock_irqrestore(&osb->dc_task_lock, flags);

		BUG_ON(!processed);
		processed--;

		ocfs2_process_blocked_lock(osb, lockres);

		spin_lock_irqsave(&osb->dc_task_lock, flags);
	}
	spin_unlock_irqrestore(&osb->dc_task_lock, flags);
}

static int ocfs2_downconvert_thread_lists_empty(struct ocfs2_super *osb)
{
	int empty = 0;
	unsigned long flags;

	spin_lock_irqsave(&osb->dc_task_lock, flags);
	if (list_empty(&osb->blocked_lock_list))
		empty = 1;

	spin_unlock_irqrestore(&osb->dc_task_lock, flags);
	return empty;
}

static int ocfs2_downconvert_thread_should_wake(struct ocfs2_super *osb)
{
	int should_wake = 0;
	unsigned long flags;

	spin_lock_irqsave(&osb->dc_task_lock, flags);
	if (osb->dc_work_sequence != osb->dc_wake_sequence)
		should_wake = 1;
	spin_unlock_irqrestore(&osb->dc_task_lock, flags);

	return should_wake;
}

static int ocfs2_downconvert_thread(void *arg)
{
	int status = 0;
	struct ocfs2_super *osb = arg;

	/* only quit once we've been asked to stop and there is no more
	 * work available */
	while (!(kthread_should_stop() &&
		ocfs2_downconvert_thread_lists_empty(osb))) {

		wait_event_interruptible(osb->dc_event,
					 ocfs2_downconvert_thread_should_wake(osb) ||
					 kthread_should_stop());

		mlog(0, "downconvert_thread: awoken\n");

		ocfs2_downconvert_thread_do_work(osb);
	}

	osb->dc_task = NULL;
	return status;
}

void ocfs2_wake_downconvert_thread(struct ocfs2_super *osb)
{
	unsigned long flags;

	spin_lock_irqsave(&osb->dc_task_lock, flags);
	/* make sure the voting thread gets a swipe at whatever changes
	 * the caller may have made to the voting state */
	osb->dc_wake_sequence++;
	spin_unlock_irqrestore(&osb->dc_task_lock, flags);
	wake_up(&osb->dc_event);
}

int ocfs2_init_super(struct ocfs2_super *osb, int flags)
{
	memset(osb, 0, sizeof(*osb));

	osb->osb_dlm_debug = ocfs2_new_dlm_debug();
	if (!osb->osb_dlm_debug)
		return -ENOMEM;

	spin_lock_init(&osb->dc_task_lock);
	init_waitqueue_head(&osb->dc_event);
	INIT_LIST_HEAD(&osb->blocked_lock_list);
	osb->s_mount_opt = flags;
	atomic64_set(&osb->refresh_gen, 0);

	return 0;
}
