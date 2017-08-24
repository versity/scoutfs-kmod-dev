/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * stackglue.c
 *
 * Code which implements an OCFS2 specific interface to underlying
 * cluster stacks.
 *
 * Copyright (C) 2007, 2009 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sysctl.h>

#include "stackglue.h"

static void fsdlm_lock_ast_wrapper(void *astarg)
{
	struct ocfs2_dlm_lksb *lksb = astarg;
	int status = lksb->lksb_fsdlm.sb_status;

	/*
	 * For now we're punting on the issue of other non-standard errors
	 * where we can't tell if the unlock_ast or lock_ast should be called.
	 * The main "other error" that's possible is EINVAL which means the
	 * function was called with invalid args, which shouldn't be possible
	 * since the caller here is under our control.  Other non-standard
	 * errors probably fall into the same category, or otherwise are fatal
	 * which means we can't carry on anyway.
	 */

	if (status == -DLM_EUNLOCK || status == -DLM_ECANCEL)
		lksb->lksb_conn->cc_proto->lp_unlock_ast(lksb, 0);
	else
		lksb->lksb_conn->cc_proto->lp_lock_ast(lksb);
}

static void fsdlm_blocking_ast_wrapper(void *astarg, int level)
{
	struct ocfs2_dlm_lksb *lksb = astarg;

	lksb->lksb_conn->cc_proto->lp_blocking_ast(lksb, level);
}

static int user_dlm_lock(struct ocfs2_cluster_connection *conn,
			 int mode,
			 struct ocfs2_dlm_lksb *lksb,
			 u32 flags,
			 void *name,
			 unsigned int namelen)
{
	int ret;

	if (!lksb->lksb_fsdlm.sb_lvbptr)
		lksb->lksb_fsdlm.sb_lvbptr = (char *)lksb +
					     sizeof(struct dlm_lksb);

	ret = dlm_lock(conn->cc_lockspace, mode, &lksb->lksb_fsdlm,
		       flags|DLM_LKF_NODLCKWT, name, namelen, 0,
		       fsdlm_lock_ast_wrapper, lksb,
		       fsdlm_blocking_ast_wrapper);
	return ret;
}

/*
 * The ocfs2_dlm_lock() and ocfs2_dlm_unlock() functions take no argument
 * for the ast and bast functions.  They will pass the lksb to the ast
 * and bast.  The caller can wrap the lksb with their own structure to
 * get more information.
 */
int ocfs2_dlm_lock(struct ocfs2_cluster_connection *conn,
		   int mode,
		   struct ocfs2_dlm_lksb *lksb,
		   u32 flags,
		   void *name,
		   unsigned int namelen)
{
	if (!lksb->lksb_conn)
		lksb->lksb_conn = conn;
	else
		BUG_ON(lksb->lksb_conn != conn);
	return user_dlm_lock(conn, mode, lksb, flags, name, namelen);
}

static int user_dlm_unlock(struct ocfs2_cluster_connection *conn,
			   struct ocfs2_dlm_lksb *lksb,
			   u32 flags)
{
	int ret;

	ret = dlm_unlock(conn->cc_lockspace, lksb->lksb_fsdlm.sb_lkid,
			 flags, &lksb->lksb_fsdlm, lksb);
	return ret;
}

int ocfs2_dlm_unlock(struct ocfs2_cluster_connection *conn,
		     struct ocfs2_dlm_lksb *lksb,
		     u32 flags)
{
	BUG_ON(lksb->lksb_conn == NULL);

	return user_dlm_unlock(conn, lksb, flags);
}

static int user_dlm_lock_status(struct ocfs2_dlm_lksb *lksb)
{
	return lksb->lksb_fsdlm.sb_status;
}

int ocfs2_dlm_lock_status(struct ocfs2_dlm_lksb *lksb)
{
	return user_dlm_lock_status(lksb);
}

static int user_dlm_lvb_valid(struct ocfs2_dlm_lksb *lksb)
{
	int invalid = lksb->lksb_fsdlm.sb_flags & DLM_SBF_VALNOTVALID;

	return !invalid;
}

int ocfs2_dlm_lvb_valid(struct ocfs2_dlm_lksb *lksb)
{
	return user_dlm_lvb_valid(lksb);
}

static void *user_dlm_lvb(struct ocfs2_dlm_lksb *lksb)
{
	if (!lksb->lksb_fsdlm.sb_lvbptr)
		lksb->lksb_fsdlm.sb_lvbptr = (char *)lksb +
					     sizeof(struct dlm_lksb);
	return (void *)(lksb->lksb_fsdlm.sb_lvbptr);
}

void *ocfs2_dlm_lvb(struct ocfs2_dlm_lksb *lksb)
{
	return user_dlm_lvb(lksb);
}

void ocfs2_dlm_dump_lksb(struct ocfs2_dlm_lksb *lksb)
{
}

static int user_plock(struct ocfs2_cluster_connection *conn,
		      u64 ino,
		      struct file *file,
		      int cmd,
		      struct file_lock *fl)
{
	/*
	 * This more or less just demuxes the plock request into any
	 * one of three dlm calls.
	 *
	 * Internally, fs/dlm will pass these to a misc device, which
	 * a userspace daemon will read and write to.
	 *
	 * For now, cancel requests (which happen internally only),
	 * are turned into unlocks. Most of this function taken from
	 * gfs2_lock.
	 */

	if (cmd == F_CANCELLK) {
		cmd = F_SETLK;
		fl->fl_type = F_UNLCK;
	}

	if (IS_GETLK(cmd))
		return dlm_posix_get(conn->cc_lockspace, ino, file, fl);
	else if (fl->fl_type == F_UNLCK)
		return dlm_posix_unlock(conn->cc_lockspace, ino, file, fl);
	else
		return dlm_posix_lock(conn->cc_lockspace, ino, file, cmd, fl);
}

int ocfs2_plock(struct ocfs2_cluster_connection *conn, u64 ino,
		struct file *file, int cmd, struct file_lock *fl)
{
	return user_plock(conn, ino, file, cmd, fl);
}

static struct dlm_lockspace_ops *ocfs2_ls_ops = NULL;

static int user_cluster_connect(struct ocfs2_cluster_connection *conn)
{
	dlm_lockspace_t *fsdlm;
//	struct ocfs2_live_connection *lc;
	int rc, ops_rv;

	BUG_ON(conn == NULL);

#if 0
	lc = kzalloc(sizeof(struct ocfs2_live_connection), GFP_KERNEL);
	if (!lc)
		return -ENOMEM;

	init_waitqueue_head(&lc->oc_wait);
	init_completion(&lc->oc_sync_wait);
	atomic_set(&lc->oc_this_node, 0);
	conn->cc_private = lc;
	lc->oc_type = NO_CONTROLD;
#endif

	rc = dlm_new_lockspace(conn->cc_name, conn->cc_cluster_name,
			       DLM_LSFL_FS | DLM_LSFL_NEWEXCL, DLM_LVB_LEN,
			       ocfs2_ls_ops, conn, &ops_rv, &fsdlm);
	if (rc) {
		if (rc == -EEXIST || rc == -EPROTO)
			printk(KERN_ERR "scoutfs: Unable to create the "
				"lockspace %s (%d), because a scoutfs-utils "
				"program is running on this file system "
				"with the same name lockspace\n",
				conn->cc_name, rc);
		goto out;
	}

	if (ops_rv == -EOPNOTSUPP) {
		/*
		 * If we get this return code, we're on a very old
		 * version of fs/dlm that doesn't have recovery
		 * callbacks enabled.
		 */
//		lc->oc_type = WITH_CONTROLD;
		printk(KERN_NOTICE "scoutfs: You seem to be using an older "
				"version of dlm_controld and/or scoutfs-utils."
				" Please consider upgrading.\n");
	} else if (ops_rv) {
		rc = ops_rv;
		goto out;
	}
	conn->cc_lockspace = fsdlm;

#if 0
	rc = ocfs2_live_connection_attach(conn, lc);
	if (rc)
		goto out;

	if (lc->oc_type == NO_CONTROLD) {
		rc = get_protocol_version(conn);
		if (rc) {
			printk(KERN_ERR "ocfs2: Could not determine"
					" locking version\n");
			user_cluster_disconnect(conn);
			goto out;
		}
		wait_event(lc->oc_wait, (atomic_read(&lc->oc_this_node) > 0));
	}

	/*
	 * running_proto must have been set before we allowed any mounts
	 * to proceed.
	 */
	if (fs_protocol_compare(&running_proto, &conn->cc_version)) {
		printk(KERN_ERR
		       "Unable to mount with fs locking protocol version "
		       "%u.%u because negotiated protocol is %u.%u\n",
		       conn->cc_version.pv_major, conn->cc_version.pv_minor,
		       running_proto.pv_major, running_proto.pv_minor);
		rc = -EPROTO;
		ocfs2_live_connection_drop(lc);
		lc = NULL;
	}
#endif
out:
#if 0
	if (rc)
		kfree(lc);
#endif
	return rc;
}

int ocfs2_cluster_connect(const char *stack_name,
			  const char *cluster_name,
			  int cluster_name_len,
			  const char *group,
			  int grouplen,
			  struct ocfs2_locking_protocol *lproto,
			  void (*recovery_handler)(int node_num,
						   void *recovery_data),
			  void *recovery_data,
			  struct ocfs2_cluster_connection **conn)
{
	int rc = 0;
	struct ocfs2_cluster_connection *new_conn;

	BUG_ON(group == NULL);
	BUG_ON(conn == NULL);
	BUG_ON(recovery_handler == NULL);

	if (grouplen > GROUP_NAME_MAX) {
		rc = -EINVAL;
		goto out;
	}

#if 0
	if (memcmp(&lproto->lp_max_version, &locking_max_version,
		   sizeof(struct ocfs2_protocol_version))) {
		rc = -EINVAL;
		goto out;
	}
#endif
	new_conn = kzalloc(sizeof(struct ocfs2_cluster_connection),
			   GFP_KERNEL);
	if (!new_conn) {
		rc = -ENOMEM;
		goto out;
	}

	strlcpy(new_conn->cc_name, group, GROUP_NAME_MAX + 1);
	new_conn->cc_namelen = grouplen;
	if (cluster_name_len)
		strlcpy(new_conn->cc_cluster_name, cluster_name,
			CLUSTER_NAME_MAX + 1);
	new_conn->cc_cluster_name_len = cluster_name_len;
	new_conn->cc_recovery_handler = recovery_handler;
	new_conn->cc_recovery_data = recovery_data;

	new_conn->cc_proto = lproto;
	/* Start the new connection at our maximum compatibility level */
	new_conn->cc_version = lproto->lp_max_version;

#if 0
	/* This will pin the stack driver if successful */
	rc = ocfs2_stack_driver_get(stack_name);
	if (rc)
		goto out_free;
#endif

	rc = user_cluster_connect(new_conn);
	if (rc) {
//		ocfs2_stack_driver_put();
		goto out_free;
	}

	*conn = new_conn;

out_free:
	if (rc)
		kfree(new_conn);

out:
	return rc;
}

static int user_cluster_disconnect(struct ocfs2_cluster_connection *conn)
{
	dlm_release_lockspace(conn->cc_lockspace, 2);
	conn->cc_lockspace = NULL;
	conn->cc_private = NULL;
	return 0;
}

/* If hangup_pending is 0, the stack driver will be dropped */
int ocfs2_cluster_disconnect(struct ocfs2_cluster_connection *conn,
			     int hangup_pending)
{
	int ret;

	BUG_ON(conn == NULL);

	ret = user_cluster_disconnect(conn);

	/* XXX Should we free it anyway? */
	if (!ret) {
		kfree(conn);
#if 0
		if (!hangup_pending)
			ocfs2_stack_driver_put();
#endif
	}

	return ret;
}
