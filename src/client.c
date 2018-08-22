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

/*
 * The client always maintains a connection to the server.  It reads the
 * super to get the address it should try and connect to.
 */

/*
 * Connection timeouts have to allow for enough time for servers to
 * reboot.  Figure order minutes at the outside.
 */
#define CONN_RETRY_MIN_MS	10UL
#define CONN_RETRY_MAX_MS	(5UL * MSEC_PER_SEC)
#define CONN_RETRY_LIMIT_J	(5 * 60 * HZ)

struct client_info {
	struct super_block *sb;

	struct scoutfs_net_connection *conn;
	struct completion node_id_comp;
	atomic_t shutting_down;

	struct workqueue_struct *workq;
	struct delayed_work connect_dwork;

	/* connection timeouts are tracked across attempts */
	unsigned long conn_retry_ms;
};

static void reset_connect_timeout(struct client_info *client)
{
	client->conn_retry_ms = CONN_RETRY_MIN_MS;
}

static void grow_connect_timeout(struct client_info *client)
{
	client->conn_retry_ms = min(client->conn_retry_ms * 2,
				    CONN_RETRY_MAX_MS);
}

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
	int ret = 0;

	if (error) {
		ret = error;
		goto out;
	}

	if (resp_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto out;
	}

	if (gr->fsid != super->id) {
		scoutfs_warn(sb, "server sent fsid 0x%llx, client has 0x%llx",
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->id));
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
		scoutfs_warn(sb, "server sent node_id 0, client also has 0\n");
		ret = -EINVAL;
		goto out;
	}

	if (sbi->node_id == 0) {
		sbi->node_id = le64_to_cpu(gr->node_id);
		complete(&client->node_id_comp);
	}

out:
	return ret;
}

/*
 * Attempt to connect to the listening address that the server wrote in
 * the super block.  We keep trying indefinitely with an increasing
 * delay if we fail to either read the address or connect to it.
 *
 * We're careful to only ever have one connection attempt in flight.  We
 * only queue this work on mount, on error, or from the notify_down
 * callback.
 */
static void scoutfs_client_connect_worker(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  connect_dwork.work);
	struct super_block *sb = client->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_net_greeting greet;
	struct scoutfs_super_block super;
	struct sockaddr_in sin;
	int ret;

	ret = scoutfs_read_super(sb, &super);
	if (ret)
		goto out;

	if (super.server_addr.addr == cpu_to_le32(INADDR_ANY)) {
		ret = -EADDRNOTAVAIL;
		goto out;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = le32_to_be32(super.server_addr.addr);
	sin.sin_port = le16_to_be16(super.server_addr.port);

	ret = scoutfs_net_connect(sb, client->conn, &sin,
				  client->conn_retry_ms);
	if (ret)
		goto out;

	reset_connect_timeout(client);

	/* send a greeting to verify endpoints of each connection */
	greet.fsid = super.id;
	greet.format_hash = super.format_hash;
	greet.node_id = cpu_to_le64(sbi->node_id);

	ret = scoutfs_net_submit_request(sb, client->conn,
					 SCOUTFS_NET_CMD_GREETING,
					 &greet, sizeof(greet),
					 client_greeting, NULL, NULL);
	if (ret)
		scoutfs_net_shutdown(sb, client->conn);

out:
	if (ret && !atomic_read(&client->shutting_down)) {
		queue_delayed_work(client->workq, &client->connect_dwork,
				   msecs_to_jiffies(client->conn_retry_ms));
		grow_connect_timeout(client);
	}
}

/*
 * Called when either a connect attempt or established connection times
 * out and fails.
 */
static void client_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn, void *info,
			       u64 node_id)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (!atomic_read(&client->shutting_down)) {
		queue_delayed_work(client->workq, &client->connect_dwork,
				   msecs_to_jiffies(client->conn_retry_ms));
		grow_connect_timeout(client);
	}
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
	INIT_DELAYED_WORK(&client->connect_dwork,
			  scoutfs_client_connect_worker);

	/* client doesn't process any incoming requests yet */
	client->conn = scoutfs_net_alloc_conn(sb, NULL, client_notify_down, 0,
					      NULL, "client");
	if (!client->conn) {
		ret = -ENOMEM;
		goto out;
	}

	client->workq = alloc_workqueue("scoutfs_client_workq", WQ_UNBOUND, 1);
	if (!client->workq) {
		ret = -ENOMEM;
		goto out;
	}

	reset_connect_timeout(client);
	/* delay initial connect to give a local server some time to setup */
	queue_delayed_work(client->workq, &client->connect_dwork,
			   msecs_to_jiffies(client->conn_retry_ms));
	ret = 0;

out:
	if (ret)
		scoutfs_client_destroy(sb);
	return ret;
}

/*
 * There must be no more callers to the client request functions by the
 * time we get here.
 */
void scoutfs_client_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_connection *conn;

	if (client) {
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
}
