/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <asm/barrier.h>

#include "format.h"
#include "counters.h"
#include "inode.h"
#include "btree.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "client.h"
#include "net.h"
#include "endian_swap.h"
#include "quorum.h"

/*
 * The client is responsible for maintaining a connection to the server.
 * This includes managing quorum elections that determine which client
 * should run the server that all the clients connect to.
 */

#define CLIENT_CONNECT_DELAY_MS		(MSEC_PER_SEC / 10)
#define CLIENT_CONNECT_TIMEOUT_MS	(1 * MSEC_PER_SEC)
#define CLIENT_QUORUM_TIMEOUT_MS	(5 * MSEC_PER_SEC)

struct client_info {
	struct super_block *sb;

	struct scoutfs_net_connection *conn;
	atomic_t shutting_down;

	struct workqueue_struct *workq;
	struct delayed_work connect_dwork;

	u64 server_term;
	u64 greeting_umb;

	bool sending_farewell;
	int farewell_error;
	struct completion farewell_comp;
};

/*
 * Ask for a new run of allocated inode numbers.  The server can return
 * fewer than @count.  It will success with nr == 0 if we've run out.
 */
int scoutfs_client_alloc_inodes(struct super_block *sb, u64 count,
				u64 *ino, u64 *nr)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_inode_alloc ial;
	__le64 lecount = cpu_to_le64(count);
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_ALLOC_INODES,
				       &lecount, sizeof(lecount),
				       &ial, sizeof(ial));
	if (ret == 0) {
		*ino = le64_to_cpu(ial.ino);
		*nr = le64_to_cpu(ial.nr);

		if (*nr == 0)
			ret = -ENOSPC;
		else if (*ino + *nr < *ino)
			ret = -EINVAL;
	}

	return ret;
}

int scoutfs_client_get_log_trees(struct super_block *sb,
				 struct scoutfs_log_trees *lt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_LOG_TREES,
					NULL, 0, lt, sizeof(*lt));
}

int scoutfs_client_commit_log_trees(struct super_block *sb,
				    struct scoutfs_log_trees *lt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_COMMIT_LOG_TREES,
					lt, sizeof(*lt), NULL, 0);
}

int scoutfs_client_get_fs_roots(struct super_block *sb,
				struct scoutfs_btree_root *fs_root,
				struct scoutfs_btree_root *logs_root)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_fs_roots nfr;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_FS_ROOTS,
					NULL, 0, &nfr, sizeof(nfr));
	if (ret == 0) {
		*fs_root = nfr.fs_root;
		*logs_root = nfr.logs_root;
	}
	return 0;
}

int scoutfs_client_advance_seq(struct super_block *sb, u64 *seq)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	__le64 before = cpu_to_le64p(seq);
	__le64 after;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_ADVANCE_SEQ,
				       &before, sizeof(before),
				       &after, sizeof(after));
	if (ret == 0)
		*seq = le64_to_cpu(after);

	return ret;
}

int scoutfs_client_get_last_seq(struct super_block *sb, u64 *seq)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	__le64 last_seq;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_GET_LAST_SEQ,
				       NULL, 0, &last_seq, sizeof(last_seq));
	if (ret == 0)
		*seq = le64_to_cpu(last_seq);

	return ret;
}

int scoutfs_client_statfs(struct super_block *sb,
			  struct scoutfs_net_statfs *nstatfs)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_STATFS, NULL, 0,
					nstatfs,
					sizeof(struct scoutfs_net_statfs));
}

/* process an incoming grant response from the server */
static int client_lock_response(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				void *resp, unsigned int resp_len,
				int error, void *data)
{
	if (resp_len != sizeof(struct scoutfs_net_lock_grant_response))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_grant_response(sb, resp);
}

/* Send a lock request to the server. */
int scoutfs_client_lock_request(struct super_block *sb,
				struct scoutfs_net_lock *nl)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_submit_request(sb, client->conn,
					  SCOUTFS_NET_CMD_LOCK,
					  nl, sizeof(*nl),
					  client_lock_response, NULL, NULL);
}

/* Send a lock response to the server. */
int scoutfs_client_lock_response(struct super_block *sb, u64 net_id,
				struct scoutfs_net_lock *nl)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_response(sb, client->conn, SCOUTFS_NET_CMD_LOCK,
				    net_id, 0, nl, sizeof(*nl));
}

/* Send a lock recover response to the server. */
int scoutfs_client_lock_recover_response(struct super_block *sb, u64 net_id,
					 struct scoutfs_net_lock_recover *nlr)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	u16 bytes = offsetof(struct scoutfs_net_lock_recover,
			     locks[le16_to_cpu(nlr->nr)]);

	return scoutfs_net_response(sb, client->conn,
				    SCOUTFS_NET_CMD_LOCK_RECOVER,
				    net_id, 0, nlr, bytes);
}

/* The client is receiving a invalidation request from the server */
static int client_lock(struct super_block *sb,
		       struct scoutfs_net_connection *conn, u8 cmd, u64 id,
		       void *arg, u16 arg_len)
{
	if (arg_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_invalidate_request(sb, id, arg);
}

/* The server is asking us for the client's locks starting with the given key */
static int client_lock_recover(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	if (arg_len != sizeof(struct scoutfs_key))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_recover_request(sb, id, arg);
}

/*
 * Process a greeting response in the client from the server.  This is
 * called for every connected socket on the connection.  Each response
 * contains the remote server's elected term which can be used to
 * identify server failover.
 */
static int client_greeting(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   void *resp, unsigned int resp_len, int error,
			   void *data)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_net_greeting *gr = resp;
	bool new_server;
	int ret;

	if (error) {
		ret = error;
		goto out;
	}

	if (resp_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto out;
	}

	if (gr->fsid != super->hdr.fsid) {
		scoutfs_warn(sb, "server sent fsid 0x%llx, client has 0x%llx",
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->hdr.fsid));
		ret = -EINVAL;
		goto out;
	}

	if (gr->format_hash != super->format_hash) {
		scoutfs_warn(sb, "server sent format 0x%llx, client has 0x%llx",
			     le64_to_cpu(gr->format_hash),
			     le64_to_cpu(super->format_hash));
		ret = -EINVAL;
		goto out;
	}

	new_server = le64_to_cpu(gr->server_term) != client->server_term;
	scoutfs_net_client_greeting(sb, conn, new_server);

	client->server_term = le64_to_cpu(gr->server_term);
	client->greeting_umb = le64_to_cpu(gr->unmount_barrier);
	ret = 0;
out:
	return ret;
}

/*
 * This work is responsible for maintaining a connection from the client
 * to the server.  It's queued on mount and disconnect and we requeue
 * the work if the work fails and we're not shutting down.
 *
 * In the typical case a mount reads the super blocks and finds the
 * address of the currently running server and connects to it.
 * Non-voting clients who can't connect will keep trying alternating
 * reading the address and getting connect timeouts.
 *
 * Voting mounts will try to elect a leader if they can't connect to the
 * server.  When a quorum can't connect and are able to elect a leader
 * then a new server is started.  The new server will write its address
 * in the super and everyone will be able to connect.
 *
 * There's a tricky bit of coordination required to safely unmount.
 * Clients need to tell the server that they won't be coming back with a
 * farewell request.  Once a client receives its farewell response it
 * can exit.  But a majority of clients need to stick around to elect a
 * server to process all their farewell requests.  This is coordinated
 * by having the greeting tell the server that a client is a voter.  The
 * server then holds on to farewell requests from voters until only
 * requests from the final quorum remain.  These farewell responses are
 * only sent after updating an unmount barrier in the super to indicate
 * to the final quorum that they can safely exit without having received
 * a farewell response over the network.
 */
static void scoutfs_client_connect_worker(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  connect_dwork.work);
	struct super_block *sb = client->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = NULL;
	struct mount_options *opts = &sbi->opts;
	const bool am_voter = opts->server_addr.sin_addr.s_addr != 0;
	struct scoutfs_net_greeting greet;
	struct sockaddr_in sin;
	ktime_t timeout_abs;
	u64 elected_term;
	int ret;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!super) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	/* can safely unmount if we see that server processed our farewell */
	if (am_voter && client->sending_farewell &&
	    (le64_to_cpu(super->unmount_barrier) > client->greeting_umb)) {
		client->farewell_error = 0;
		complete(&client->farewell_comp);
		ret = 0;
		goto out;
	}

	/* try to connect to the super's server address */
	scoutfs_addr_to_sin(&sin, &super->server_addr);
	if (sin.sin_addr.s_addr != 0 && sin.sin_port != 0)
		ret = scoutfs_net_connect(sb, client->conn, &sin,
					  CLIENT_CONNECT_TIMEOUT_MS);
	else
		ret = -ENOTCONN;

	/* voters try to elect a leader if they couldn't connect */
	if (ret < 0) {
		/* non-voters will keep retrying */
		if (!am_voter)
			goto out;

		/* make sure local server isn't writing super during votes */
		scoutfs_server_stop(sb);

		timeout_abs = ktime_add_ms(ktime_get(),
					   CLIENT_QUORUM_TIMEOUT_MS);

		ret = scoutfs_quorum_election(sb, timeout_abs,
					le64_to_cpu(super->quorum_server_term),
					&elected_term);
		/* start the server if we were asked to */
		if (elected_term > 0)
			ret = scoutfs_server_start(sb, &opts->server_addr,
						   elected_term);
		ret = -ENOTCONN;
		goto out;
	}

	/* send a greeting to verify endpoints of each connection */
	greet.fsid = super->hdr.fsid;
	greet.format_hash = super->format_hash;
	greet.server_term = cpu_to_le64(client->server_term);
	greet.unmount_barrier = cpu_to_le64(client->greeting_umb);
	greet.rid = cpu_to_le64(sbi->rid);
	greet.flags = 0;
	if (client->sending_farewell)
		greet.flags |= cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_FAREWELL);
	if (am_voter)
		greet.flags |= cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_VOTER);

	ret = scoutfs_net_submit_request(sb, client->conn,
					 SCOUTFS_NET_CMD_GREETING,
					 &greet, sizeof(greet),
					 client_greeting, NULL, NULL);
	if (ret)
		scoutfs_net_shutdown(sb, client->conn);
out:
	kfree(super);

	/* always have a small delay before retrying to avoid storms */
	if (ret && !atomic_read(&client->shutting_down))
		queue_delayed_work(client->workq, &client->connect_dwork,
				   msecs_to_jiffies(CLIENT_CONNECT_DELAY_MS));
}

static scoutfs_net_request_t client_req_funcs[] = {
	[SCOUTFS_NET_CMD_LOCK]			= client_lock,
	[SCOUTFS_NET_CMD_LOCK_RECOVER]		= client_lock_recover,
};

/*
 * Called when either a connect attempt or established connection times
 * out and fails.
 */
static void client_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn, void *info,
			       u64 rid)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (!atomic_read(&client->shutting_down))
		queue_delayed_work(client->workq, &client->connect_dwork, 0);
}

int scoutfs_client_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client;
	int ret;

	client = kzalloc(sizeof(struct client_info), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto out;
	}
	sbi->client_info = client;

	client->sb = sb;
	atomic_set(&client->shutting_down, 0);
	INIT_DELAYED_WORK(&client->connect_dwork,
			  scoutfs_client_connect_worker);
	init_completion(&client->farewell_comp);

	client->conn = scoutfs_net_alloc_conn(sb, NULL, client_notify_down, 0,
					      client_req_funcs, "client");
	if (!client->conn) {
		ret = -ENOMEM;
		goto out;
	}

	client->workq = alloc_workqueue("scoutfs_client_workq", WQ_UNBOUND, 1);
	if (!client->workq) {
		ret = -ENOMEM;
		goto out;
	}

	queue_delayed_work(client->workq, &client->connect_dwork, 0);
	ret = 0;

out:
	if (ret)
		scoutfs_client_destroy(sb);
	return ret;
}

/* Once we get a response from the server we can shut down */
static int client_farewell_response(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    void *resp, unsigned int resp_len,
				    int error, void *data)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (resp_len != 0)
		return -EINVAL;

	client->farewell_error = error;
	complete(&client->farewell_comp);

	return 0;
}

/*
 * There must be no more callers to the client request functions by the
 * time we get here.
 *
 * If we've connected to a server then we send them a farewell request
 * so that they don't wait for us to reconnect and trigger a timeout.
 *
 * This decision is a little racy.  The server considers us connected
 * when it records a persistent record of our rid as it processes our
 * greeting.  We can disconnect before receiving the greeting response
 * and leave without sending a farewell.  So given that awkward initial
 * race, we also have a bit of a race where we just test the server_term
 * to see if we've ever gotten a greeting reply from any server.  We
 * don't try to synchronize with pending connection attempts.
 *
 * The consequences of aborting a mount at just the wrong time and
 * disconnecting without the farewell handshake depend on what the
 * server does to timed out clients.  At best it'll spit out a warning
 * message that a client disconnected but it won't fence us if we didn't
 * have any persistent state.
 */
void scoutfs_client_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_connection *conn;
	int ret;

	if (client == NULL)
		return;

	if (client->server_term != 0) {
		client->sending_farewell = true;
		ret = scoutfs_net_submit_request(sb, client->conn,
						 SCOUTFS_NET_CMD_FAREWELL,
						 NULL, 0,
						 client_farewell_response,
						 NULL, NULL);
		if (ret == 0) {
			ret = wait_for_completion_interruptible(
							&client->farewell_comp);
			if (ret == 0)
				ret = client->farewell_error;
		}
		if (ret) {
			scoutfs_inc_counter(sb, client_farewell_error);
			scoutfs_warn(sb, "client saw farewell error %d, server might see client connection time out", ret);
		}
	}

	/* stop notify_down from queueing connect work */
	atomic_set(&client->shutting_down, 1);

	/* make sure worker isn't using the conn */
	cancel_delayed_work_sync(&client->connect_dwork);

	/* make racing conn use explode */
	conn = client->conn;
	client->conn = NULL;
	scoutfs_net_free_conn(sb, conn);

	if (client->workq)
		destroy_workqueue(client->workq);
	kfree(client);
	sbi->client_info = NULL;
}
