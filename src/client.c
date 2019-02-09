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
#include "manifest.h"
#include "seg.h"
#include "compact.h"
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
	struct completion node_id_comp;
	atomic_t shutting_down;

	struct workqueue_struct *workq;
	struct work_struct connect_work;

	struct scoutfs_quorum_elected_info qei;
	u64 old_elected_nr;

	u64 server_term;

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

/*
 * Ask the server for an extent of at most @blocks blocks.  It can return
 * smaller extents.
 */
int scoutfs_client_alloc_extent(struct super_block *sb, u64 blocks, u64 *start,
				u64 *len)

{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	__le64 leblocks = cpu_to_le64(blocks);
	struct scoutfs_net_extent nex;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_ALLOC_EXTENT,
				       &leblocks, sizeof(leblocks),
				       &nex, sizeof(nex));
	if (ret == 0) {
		if (nex.len == 0) {
			ret = -ENOSPC;
		} else {
			*start = le64_to_cpu(nex.start);
			*len = le64_to_cpu(nex.len);
		}
	}

	return ret;
}

int scoutfs_client_free_extents(struct super_block *sb,
				struct scoutfs_net_extent_list *nexl)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	unsigned int bytes;

	bytes = SCOUTFS_NET_EXTENT_LIST_BYTES(le64_to_cpu(nexl->nr));

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_FREE_EXTENTS,
					nexl, bytes, NULL, 0);
}

int scoutfs_client_alloc_segno(struct super_block *sb, u64 *segno)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	__le64 lesegno;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_ALLOC_SEGNO,
				       NULL, 0, &lesegno, sizeof(lesegno));
	if (ret == 0) {
		if (lesegno == 0)
			ret = -ENOSPC;
		else
			*segno = le64_to_cpu(lesegno);
	}

	return ret;
}

int scoutfs_client_record_segment(struct super_block *sb,
				  struct scoutfs_segment *seg, u8 level)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_manifest_entry net_ment;
	struct scoutfs_manifest_entry ment;

	scoutfs_seg_init_ment(&ment, level, seg);
	scoutfs_init_ment_to_net(&net_ment, &ment);

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_RECORD_SEGMENT,
					&net_ment, sizeof(net_ment), NULL, 0);
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

int scoutfs_client_get_manifest_root(struct super_block *sb,
				     struct scoutfs_btree_root *root)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_MANIFEST_ROOT,
					NULL, 0, root,
					sizeof(struct scoutfs_btree_root));
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
	if (resp_len != sizeof(struct scoutfs_net_lock))
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
 * called for every connected socket on the connection.  The first
 * response will have the node_id that the server assigned the client.
 */
static int client_greeting(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   void *resp, unsigned int resp_len, int error,
			   void *data)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
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

	if (sbi->node_id != 0 && le64_to_cpu(gr->node_id) != sbi->node_id) {
		scoutfs_warn(sb, "server sent node_id %llu, client has %llu",
			     le64_to_cpu(gr->node_id),
			     sbi->node_id);
		ret = -EINVAL;
		goto out;
	}

	if (sbi->node_id == 0 && gr->node_id == 0) {
		scoutfs_warn(sb, "server sent node_id 0, client also has 0");
		ret = -EINVAL;
		goto out;
	}

	if (sbi->node_id == 0) {
		sbi->node_id = le64_to_cpu(gr->node_id);
		complete(&client->node_id_comp);
	}

	new_server = le64_to_cpu(gr->server_term) != client->server_term;
	scoutfs_net_client_greeting(sb, conn, new_server);

	client->server_term = le64_to_cpu(gr->server_term);
	ret = 0;
out:
	return ret;
}

/*
 * If the previous election told us to start the server then stop it
 * and wipe the old election info.  If we're not fast enough to clear
 * the election block then the next server might fence us.  Should
 * be very unlikely as election requires multiple RMW cycles.
 */
static void stop_our_server(struct super_block *sb,
			    struct scoutfs_quorum_elected_info *qei)
{
	if (qei->run_server) {
		scoutfs_server_stop(sb);
		scoutfs_quorum_clear_elected(sb, qei);
		memset(qei, 0, sizeof(*qei));
	}
}

/*
 * This work is responsible for managing leader elections, running the
 * server, and connecting clients to the server.
 *
 * In the typical case a mount reads the quorum blocks and finds the
 * address of the currently running server and connects to it.
 *
 * More rarely clients who aren't connected and are configured to
 * participate in quorum need to elect the new leader.  The elected info
 * filled by quorum tells us if we were elected to run the server.
 *
 * This leads to the possibility that the mount who is running the
 * server had its mount disconnect.  This is only weirdly different from
 * other clients disconnecting and trying to reconnect because of the
 * way quorum slots are reconfigured and reclaimed.  If we connect to a
 * server with the new quorum config then we can't have any old servers
 * running in the stale old quorum slot.  The simplest way to do this is
 * to *always* stop the server if we're running it and we got
 * disconnected.  It's a big hammer, but it's reliable, and arguably if
 * *we* couldn't' use *our* server then something bad is happening and
 * someone else should be the server.
 *
 * This only executes on mount, error, or as a connection disconnects
 * and there's only ever one executing.
 */
static void scoutfs_client_connect_worker(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  connect_work);
	struct super_block *sb = client->sb;
	struct scoutfs_quorum_elected_info *qei = &client->qei;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct mount_options *opts = &sbi->opts;
	struct scoutfs_net_greeting greet;
	ktime_t timeout_abs;
	int ret;

	/* don't try quorum and connecting while our mount runs a server */
	stop_our_server(sb, qei);

	timeout_abs = ktime_add_ms(ktime_get(), CLIENT_QUORUM_TIMEOUT_MS);

	ret = scoutfs_quorum_election(sb, opts->uniq_name,
				      client->old_elected_nr,
			              timeout_abs, qei);
	if (ret)
		goto out;

	if (qei->run_server) {
		ret = scoutfs_server_start(sb, &qei->sin, qei->elected_nr);
		if (ret) {
			/* forget that we tried to start the server */
			memset(qei, 0, sizeof(*qei));
			goto out;
		}
	}

	/* always give the server some time before connecting */
	msleep(CLIENT_CONNECT_DELAY_MS);

	ret = scoutfs_net_connect(sb, client->conn, &qei->sin,
				  CLIENT_CONNECT_TIMEOUT_MS);
	if (ret) {
		/* we couldn't connect, try electing a new server */
		client->old_elected_nr = qei->elected_nr;
		goto out;
	}

	/* trust this server again if it's still around after we disconnect */
	client->old_elected_nr = 0;

	/* send a greeting to verify endpoints of each connection */
	greet.fsid = super->hdr.fsid;
	greet.format_hash = super->format_hash;
	greet.server_term = cpu_to_le64(client->server_term);
	greet.node_id = cpu_to_le64(sbi->node_id);
	greet.flags = 0;
	if (client->sending_farewell)
		greet.flags |= cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_FAREWELL);

	ret = scoutfs_net_submit_request(sb, client->conn,
					 SCOUTFS_NET_CMD_GREETING,
					 &greet, sizeof(greet),
					 client_greeting, NULL, NULL);
	if (ret)
		scoutfs_net_shutdown(sb, client->conn);
out:
	if (ret && !atomic_read(&client->shutting_down))
		queue_work(client->workq, &client->connect_work);
}

/*
 * Perform a compaction in the client as requested by the server.  The
 * server has protected the input segments and allocated the output
 * segnos for us.  This executes in work queued by the client's net
 * connection.  It only reads and write segments.  The server will
 * update the manifest and allocators while processing the response.  An
 * error response includes the compaction id so that the server can
 * clean it up.
 *
 * If we get duplicate requests across a reconnected socket we can have
 * two workers performing the same compaction simultaneously.  This
 * isn't particularly efficient but it's rare and won't corrupt the
 * output.  Our response can be lost if the socket is shutdown while
 * it's in flight, the server deals with this.
 */
static int client_compact(struct super_block *sb,
			  struct scoutfs_net_connection *conn,
			  u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_net_compact_response *resp = NULL;
	struct scoutfs_net_compact_request *req;
	int ret;

	if (arg_len != sizeof(struct scoutfs_net_compact_request)) {
		ret = -EINVAL;
		goto out;
	}
	req = arg;

	trace_scoutfs_client_compact_start(sb, le64_to_cpu(req->id),
					   req->last_level, req->flags);

	resp = kzalloc(sizeof(struct scoutfs_net_compact_response), GFP_NOFS);
	if (!resp) {
		ret = -ENOMEM;
	} else {
		resp->id = req->id;
		ret = scoutfs_compact(sb, req, resp);
	}

	trace_scoutfs_client_compact_stop(sb, le64_to_cpu(req->id), ret);

	if (ret < 0)
		ret = scoutfs_net_response(sb, conn, cmd, id, ret,
					   &req->id, sizeof(req->id));
	else
		ret = scoutfs_net_response(sb, conn, cmd, id, 0,
					   resp, sizeof(*resp));
	kfree(resp);
out:
	return ret;
}

static scoutfs_net_request_t client_req_funcs[] = {
	[SCOUTFS_NET_CMD_COMPACT]		= client_compact,
	[SCOUTFS_NET_CMD_LOCK]			= client_lock,
	[SCOUTFS_NET_CMD_LOCK_RECOVER]		= client_lock_recover,
};

/*
 * Called when either a connect attempt or established connection times
 * out and fails.
 */
static void client_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn, void *info,
			       u64 node_id)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (!atomic_read(&client->shutting_down))
		queue_work(client->workq, &client->connect_work);
}

/*
 * Wait for the first connected socket on the connection that assigns
 * the node_id that will be used for the rest of the life time of the
 * mount.
 */
int scoutfs_client_wait_node_id(struct super_block *sb)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return wait_for_completion_interruptible(&client->node_id_comp);
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
	init_completion(&client->node_id_comp);
	atomic_set(&client->shutting_down, 0);
	INIT_WORK(&client->connect_work, scoutfs_client_connect_worker);
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

	queue_work(client->workq, &client->connect_work);
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
 * when it assigns us a node_id as it processes the greeting.  We can
 * disconnect before receiving the response and leave without sending a
 * farewell.  So given that awkward initial race, we also have a bit of
 * a race where we just test the server_term to see if we've ever gotten
 * a greeting reply from any server.  We don't try to synchronize with
 * pending connection attempts.
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
	cancel_work_sync(&client->connect_work);

	/* make racing conn use explode */
	conn = client->conn;
	client->conn = NULL;
	scoutfs_net_free_conn(sb, conn);

	/* stop running the server if we were, harmless otherwise */
	stop_our_server(sb, &client->qei);

	if (client->workq)
		destroy_workqueue(client->workq);
	kfree(client);
	sbi->client_info = NULL;
}
