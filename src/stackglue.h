/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * stackglue.h
 *
 * Glue to the underlying cluster stack.
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
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


#ifndef STACKGLUE_H
#define STACKGLUE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/dlmconstants.h>

#include <linux/dlm.h>
#include <linux/dlm_plock.h>

#define DLM_LVB_LEN  64

/* Needed for plock-related prototypes */
struct file;
struct file_lock;

/* Scoutfs never uses this flag, we define it to zero to avoid errors */
#define DLM_LKF_LOCAL		0

/*
 * This shadows DLM_LOCKSPACE_LEN in fs/dlm/dlm_internal.h.  That probably
 * wants to be in a public header.
 */
#define GROUP_NAME_MAX		64

/* This shadows  OCFS2_CLUSTER_NAME_LEN */
#define CLUSTER_NAME_MAX	16

/*
 * ocfs2_protocol_version changes when ocfs2 does something different in
 * its inter-node behavior.  See dlmglue.c for more information.
 */
struct ocfs2_protocol_version {
	u8 pv_major;
	u8 pv_minor;
};

/*
 * The dlm_lockstatus struct includes lvb space, but the dlm_lksb struct only
 * has a pointer to separately allocated lvb space.  This struct exists only to
 * include in the lksb union to make space for a combined dlm_lksb and lvb.
 */
struct fsdlm_lksb_plus_lvb {
	struct dlm_lksb lksb;
	char lvb[DLM_LVB_LEN];
};

/*
 * A union of all lock status structures.  We define it here so that the
 * size of the union is known.  Lock status structures are embedded in
 * ocfs2 inodes.
 */
struct ocfs2_cluster_connection;
struct ocfs2_dlm_lksb {
	 union {
		 struct dlm_lksb lksb_fsdlm;
		 struct fsdlm_lksb_plus_lvb padding;
	 };
	 struct ocfs2_cluster_connection *lksb_conn;
};

/*
 * The ocfs2_locking_protocol defines the handlers called on ocfs2's behalf.
 */
struct ocfs2_locking_protocol {
	struct ocfs2_protocol_version lp_max_version;
	void (*lp_lock_ast)(struct ocfs2_dlm_lksb *lksb);
	void (*lp_blocking_ast)(struct ocfs2_dlm_lksb *lksb, int level);
	void (*lp_unlock_ast)(struct ocfs2_dlm_lksb *lksb, int error);
};

/*
 * A cluster connection.  Mostly opaque to ocfs2, the connection holds
 * state for the underlying stack.  ocfs2 does use cc_version to determine
 * locking compatibility.
 */
struct ocfs2_cluster_connection {
	char cc_name[GROUP_NAME_MAX + 1];
	int cc_namelen;
	char cc_cluster_name[CLUSTER_NAME_MAX + 1];
	int cc_cluster_name_len;
	struct ocfs2_protocol_version cc_version;
	struct ocfs2_locking_protocol *cc_proto;
	void (*cc_recovery_handler)(int node_num, void *recovery_data);
	void *cc_recovery_data;
	void *cc_lockspace;
	void *cc_private;
};

/* In ocfs2_downconvert_lock(), we need to know which stack we are using */
static inline int ocfs2_is_o2cb_active(void)
{
	return 0;
}

/* Used by the filesystem */
int ocfs2_cluster_connect(const char *stack_name,
			  const char *cluster_name,
			  int cluster_name_len,
			  const char *group,
			  int grouplen,
			  struct ocfs2_locking_protocol *lproto,
			  void (*recovery_handler)(int node_num,
						   void *recovery_data),
			  void *recovery_data,
			  struct ocfs2_cluster_connection **conn);
int ocfs2_cluster_disconnect(struct ocfs2_cluster_connection *conn,
			     int hangup_pending);

struct ocfs2_lock_res;
int ocfs2_dlm_lock(struct ocfs2_cluster_connection *conn,
		   int mode,
		   struct ocfs2_dlm_lksb *lksb,
		   u32 flags,
		   void *name,
		   unsigned int namelen);
int ocfs2_dlm_unlock(struct ocfs2_cluster_connection *conn,
		     struct ocfs2_dlm_lksb *lksb,
		     u32 flags);

int ocfs2_dlm_lock_status(struct ocfs2_dlm_lksb *lksb);
int ocfs2_dlm_lvb_valid(struct ocfs2_dlm_lksb *lksb);
void *ocfs2_dlm_lvb(struct ocfs2_dlm_lksb *lksb);
void ocfs2_dlm_dump_lksb(struct ocfs2_dlm_lksb *lksb);

int ocfs2_plock(struct ocfs2_cluster_connection *conn, u64 ino,
		struct file *file, int cmd, struct file_lock *fl);

#endif  /* STACKGLUE_H */
