/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * dlmglue.h
 *
 * description here
 *
 * Copyright (C) 2002, 2004 Oracle.  All rights reserved.
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


#ifndef DLMGLUE_H
#define DLMGLUE_H

#include "stackglue.h"

/* Max length of lockid name */
#define OCFS2_LOCK_ID_MAX_LEN  32

enum ocfs2_ast_action {
	OCFS2_AST_INVALID = 0,
	OCFS2_AST_ATTACH,
	OCFS2_AST_CONVERT,
	OCFS2_AST_DOWNCONVERT,
};

/* actions for an unlockast function to take. */
enum ocfs2_unlock_action {
	OCFS2_UNLOCK_INVALID = 0,
	OCFS2_UNLOCK_CANCEL_CONVERT,
	OCFS2_UNLOCK_DROP_LOCK,
};

/* ocfs2_lock_res->l_flags flags. */
#define OCFS2_LOCK_ATTACHED      (0x00000001) /* we have initialized
					       * the lvb */
#define OCFS2_LOCK_BUSY          (0x00000002) /* we are currently in
					       * dlm_lock */
#define OCFS2_LOCK_BLOCKED       (0x00000004) /* blocked waiting to
					       * downconvert*/
#define OCFS2_LOCK_LOCAL         (0x00000008) /* newly created inode */
#define OCFS2_LOCK_NEEDS_REFRESH (0x00000010)
#define OCFS2_LOCK_REFRESHING    (0x00000020)
#define OCFS2_LOCK_INITIALIZED   (0x00000040) /* track initialization
					       * for shutdown paths */
#define OCFS2_LOCK_FREEING       (0x00000080) /* help dlmglue track
					       * when to skip queueing
					       * a lock because it's
					       * about to be
					       * dropped. */
#define OCFS2_LOCK_QUEUED        (0x00000100) /* queued for downconvert */
#define OCFS2_LOCK_NOCACHE       (0x00000200) /* don't use a holder count */
#define OCFS2_LOCK_PENDING       (0x00000400) /* This lockres is pending a
						 call to dlm_lock.  Only
						 exists with BUSY set. */
#define OCFS2_LOCK_UPCONVERT_FINISHING (0x00000800) /* blocks the dc thread
						     * from downconverting
						     * before the upconvert
						     * has completed */

#define OCFS2_LOCK_NONBLOCK_FINISHED (0x00001000) /* NONBLOCK cluster
						   * lock has already
						   * returned, do not block
						   * dc thread from
						   * downconverting */

struct ocfs2_lock_res_ops;

typedef void (*ocfs2_lock_callback)(int status, unsigned long data);

#ifdef CONFIG_OCFS2_FS_STATS
struct ocfs2_lock_stats {
	u64		ls_total;	/* Total wait in NSEC */
	u32		ls_gets;	/* Num acquires */
	u32		ls_fail;	/* Num failed acquires */

	/* Storing max wait in usecs saves 24 bytes per inode */
	u32		ls_max;		/* Max wait in USEC */
};
#endif

struct ocfs2_lock_res {
	void                    *l_priv;
	struct ocfs2_lock_res_ops *l_ops;


	struct list_head         l_blocked_list;
	struct list_head         l_mask_waiters;
	struct list_head	 l_holders;

	unsigned long		 l_flags;
	char                     l_name[OCFS2_LOCK_ID_MAX_LEN];
	unsigned int             l_ro_holders;
	unsigned int             l_ex_holders;
	signed char		 l_level;
	signed char		 l_requested;
	signed char		 l_blocking;

	/* used from AST/BAST funcs. */
	/* Data packed - enum type ocfs2_ast_action */
	unsigned char            l_action;
	/* Data packed - enum type ocfs2_unlock_action */
	unsigned char            l_unlock_action;
	unsigned int             l_pending_gen;

	spinlock_t               l_lock;

	struct ocfs2_dlm_lksb    l_lksb;

	wait_queue_head_t        l_event;

	struct list_head         l_debug_list;

#ifdef CONFIG_OCFS2_FS_STATS
	struct ocfs2_lock_stats  l_lock_prmode;		/* PR mode stats */
	u32                      l_lock_refresh;	/* Disk refreshes */
	struct ocfs2_lock_stats  l_lock_exmode;		/* EX mode stats */
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	 l_lockdep_map;
#endif
};

struct ocfs2_dlm_debug {
	struct kref d_refcnt;
	struct dentry *d_locking_state;
	struct list_head d_lockres_tracking;
};

/* The cluster stack fields */
#define OCFS2_STACK_LABEL_LEN		4
#define OCFS2_CLUSTER_NAME_LEN		16

struct ocfs2_super
{
	struct ocfs2_cluster_connection *cconn;
	struct ocfs2_dlm_debug *osb_dlm_debug;

	/* Downconvert thread */
	spinlock_t dc_task_lock;
	struct task_struct *dc_task;
	wait_queue_head_t dc_event;
	unsigned long dc_wake_sequence;
	unsigned long dc_work_sequence;

	/*
	 * Any thread can add locks to the list, but the downconvert
	 * thread is the only one allowed to remove locks. Any change
	 * to this rule requires updating
	 * ocfs2_downconvert_thread_do_work().
	 */
	struct list_head blocked_lock_list;
	unsigned long blocked_lock_count;

	unsigned long s_mount_opt;
};
/* For s_mount_opt */
#define OCFS2_MOUNT_NOINTR (1 << 2)

/*
 * Return value from ->downconvert_worker functions.
 *
 * These control the precise actions of ocfs2_unblock_lock()
 * and ocfs2_process_blocked_lock()
 *
 */
enum ocfs2_unblock_action {
	UNBLOCK_CONTINUE	= 0, /* Continue downconvert */
	UNBLOCK_CONTINUE_POST	= 1, /* Continue downconvert, fire
				      * ->post_unlock callback */
	UNBLOCK_STOP_POST	= 2, /* Do not downconvert, fire
				      * ->post_unlock() callback. */
};

/*
 * OCFS2 Lock Resource Operations
 *
 * These fine tune the behavior of the generic dlmglue locking infrastructure.
 *
 * The most basic of lock types can point ->l_priv to their respective
 * struct ocfs2_super and allow the default actions to manage things.
 *
 * Right now, each lock type also needs to implement an init function,
 * and trivial lock/unlock wrappers. ocfs2_simple_drop_lockres()
 * should be called when the lock is no longer needed (i.e., object
 * destruction time).
 */
struct ocfs2_lock_res_ops {
	/*
	 * Translate an ocfs2_lock_res * into an ocfs2_super *. Define
	 * this callback if ->l_priv is not an ocfs2_super pointer
	 */
	struct ocfs2_super * (*get_osb)(struct ocfs2_lock_res *);

	/*
	 * Optionally called in the downconvert thread after a
	 * successful downconvert. The lockres will not be referenced
	 * after this callback is called, so it is safe to free
	 * memory, etc.
	 *
	 * The exact semantics of when this is called are controlled
	 * by ->downconvert_worker()
	 */
	void (*post_unlock)(struct ocfs2_super *, struct ocfs2_lock_res *);

	/*
	 * Allow a lock type to add checks to determine whether it is
	 * safe to downconvert a lock. Return 0 to re-queue the
	 * downconvert at a later time, nonzero to continue.
	 *
	 * For most locks, the default checks that there are no
	 * incompatible holders are sufficient.
	 *
	 * Called with the lockres spinlock held.
	 */
	int (*check_downconvert)(struct ocfs2_lock_res *, int);

	/*
	 * Allows a lock type to populate the lock value block. This
	 * is called on downconvert, and when we drop a lock.
	 *
	 * Locks that want to use this should set LOCK_TYPE_USES_LVB
	 * in the flags field.
	 *
	 * Called with the lockres spinlock held.
	 */
	void (*set_lvb)(struct ocfs2_lock_res *);

	/*
	 * Called from the downconvert thread when it is determined
	 * that a lock will be downconverted. This is called without
	 * any locks held so the function can do work that might
	 * schedule (syncing out data, etc).
	 *
	 * This should return any one of the ocfs2_unblock_action
	 * values, depending on what it wants the thread to do.
	 */
	int (*downconvert_worker)(struct ocfs2_lock_res *, int);

	/*
	 * LOCK_TYPE_* flags which describe the specific requirements
	 * of a lock type. Descriptions of each individual flag follow.
	 */
	int flags;
};

/*
 * Some locks want to "refresh" potentially stale data when a
 * meaningful (PRMODE or EXMODE) lock level is first obtained. If this
 * flag is set, the OCFS2_LOCK_NEEDS_REFRESH flag will be set on the
 * individual lockres l_flags member from the ast function. It is
 * expected that the locking wrapper will clear the
 * OCFS2_LOCK_NEEDS_REFRESH flag when done.
 */
#define LOCK_TYPE_REQUIRES_REFRESH 0x1

/*
 * Indicate that a lock type makes use of the lock value block. The
 * ->set_lvb lock type callback must be defined.
 */
#define LOCK_TYPE_USES_LVB		0x2

struct ocfs2_lock_holder {
	struct list_head oh_list;
	struct pid *oh_owner_pid;
};

/* ocfs2_inode_lock_full() 'arg_flags' flags */
/* don't wait on recovery. */
#define OCFS2_META_LOCK_RECOVERY	(0x01)
/* Instruct the dlm not to queue ourselves on the other node. */
#define OCFS2_META_LOCK_NOQUEUE		(0x02)
/* don't block waiting for the downconvert thread, instead return -EAGAIN */
#define OCFS2_LOCK_NONBLOCK		(0x04)
/* just get back disk inode bh if we've got cluster lock. */
#define OCFS2_META_LOCK_GETBH		(0x08)

/* Locking subclasses of inode cluster lock */
enum {
	OI_LS_NORMAL = 0,
	OI_LS_PARENT,
	OI_LS_RENAME1,
	OI_LS_RENAME2,
	OI_LS_REFLINK_TARGET,
};

int ocfs2_cluster_lock(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres,
		       int level, u32 lkm_flags, int arg_flags);
void ocfs2_cluster_unlock(struct ocfs2_super *osb,
			  struct ocfs2_lock_res *lockres, int level);

int ocfs2_init_super(struct ocfs2_super *osb, int flags);
void ocfs2_uninit_super(struct ocfs2_super *osb);

int ocfs2_dlm_init(struct ocfs2_super *osb, char *cluster_stack,
		   char *cluster_name, char *ls_name, struct dentry *debug_root);
void ocfs2_dlm_shutdown(struct ocfs2_super *osb, int hangup_pending);
void ocfs2_lock_res_init_once(struct ocfs2_lock_res *res);
void ocfs2_lock_res_init_common(struct ocfs2_super *osb,
				struct ocfs2_lock_res *res,
				struct ocfs2_lock_res_ops *ops,
				void *priv);
void ocfs2_lock_res_free(struct ocfs2_lock_res *res);

void ocfs2_mark_lockres_freeing(struct ocfs2_super *osb,
				struct ocfs2_lock_res *lockres);
void ocfs2_simple_drop_lockres(struct ocfs2_super *osb,
			       struct ocfs2_lock_res *lockres);

/* for the downconvert thread */
void ocfs2_wake_downconvert_thread(struct ocfs2_super *osb);

struct ocfs2_dlm_debug *ocfs2_new_dlm_debug(void);
void ocfs2_put_dlm_debug(struct ocfs2_dlm_debug *dlm_debug);

#if 0
/* To set the locking protocol on module initialization */
void ocfs2_set_locking_protocol(void);

/* The _tracker pair is used to avoid cluster recursive locking */
int ocfs2_inode_lock_tracker(struct inode *inode,
			     struct buffer_head **ret_bh,
			     int ex,
			     struct ocfs2_lock_holder *oh);
void ocfs2_inode_unlock_tracker(struct inode *inode,
				int ex,
				struct ocfs2_lock_holder *oh,
				int had_lock);
#endif
#endif	/* DLMGLUE_H */
