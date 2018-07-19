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
#include "server.h"
#include "client.h"
#include "net.h"
#include "endian_swap.h"

/*
 * The client always maintains a connection to the server.  It reads the
 * super to get the address it should try and connect to.
 */

#define SIN_FMT		"%pIS:%u"
#define SIN_ARG(sin)	sin, be16_to_cpu((sin)->sin_port)

#if 0
/*
 * Have a pretty aggressive keepalive timeout of around 10 seconds.  The
 * TCP keepalives are being processed out of task context so they should
 * be responsive even when mounts are under load.  We also derive the
 * connect timeout from this.
 */
#define KEEPCNT			3
#define KEEPIDLE		7
#define KEEPINTVL		1
#endif


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
	atomic_t shutting_down;

	struct workqueue_struct *workq;
	struct delayed_work connect_dwork;

	/* connection timeouts are tracked across attempts */
	unsigned long conn_retry_ms;
};

#if 0
struct waiting_sender {
	struct rb_node node;
	struct task_struct *task;

	u64 id;
	void *rx;
	size_t rx_size;
	int result;
};

static struct waiting_sender *walk_sender_tree(struct client_info *client,
					       u64 id,
					       struct waiting_sender *ins)
{
	struct rb_node **node = &client->sender_root.rb_node;
	struct waiting_sender *found = NULL;
	struct waiting_sender *sender;
	struct rb_node *parent = NULL;

	assert_spin_locked(&client->recv_lock);

	while (*node) {
		parent = *node;
		sender = container_of(*node, struct waiting_sender, node);

		if (id < sender->id) {
			node = &(*node)->rb_left;
		} else if (id > sender->id) {
			node = &(*node)->rb_right;
		} else {
			found = sender;
			break;
		}
	}

	if (ins) {
		/* ids are never reused and assigned under lock */
		BUG_ON(found);
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, &client->sender_root);
		found = ins;
	}

	return found;
}

/*
 * This work is queued once the socket is created.  It blocks trying to
 * receive replies to sent messages.  If the sender is still around it
 * receives the reply data into their buffer.  If the sender has left
 * then it silently drops the reply.
 *
 * This exits once someone shuts down the socket.  If this sees a fatal
 * error it shuts down the socket which causes senders to reconnect.
 */
static void scoutfs_client_recv_func(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  recv_work);
	struct waiting_sender *sender;
	struct scoutfs_net_header nh;
	void *rx = NULL;
	u16 data_len;
	int ret;

	for (;;) {
		/* receive the header */
		ret = scoutfs_sock_recvmsg(client->sock, &nh, sizeof(nh));
		if (ret)
			break;

		data_len = le16_to_cpu(nh.data_len);

		trace_scoutfs_client_recv_reply(client->sb,
						&client->sockname,
						&client->peername, &nh);

		/* receive the payload */
		kfree(rx);
		rx = kmalloc(data_len, GFP_NOFS);
		if (!rx) {
			ret = -ENOMEM;
			break;
		}

		/* recv failure can be server crashing, not fatal */
		ret = scoutfs_sock_recvmsg(client->sock, rx, data_len);
		if (ret) {
			break;
		}

		/* give the payload to a sender if there is one */
		spin_lock(&client->recv_lock);
		sender = walk_sender_tree(client, le64_to_cpu(nh.id), NULL);
		if (sender) {
			/* protocol mismatch is fatal */
			if (sender->rx_size < data_len) {
				sender->result = -EIO;
			} else {
				memcpy(sender->rx, rx, data_len);
				sender->result = 0;
			}
			smp_mb(); /* store result before waking */
			wake_up_process(sender->task);
		}
		spin_unlock(&client->recv_lock);
	}

	/* make senders reconnect if we see an rx error */
	if (ret) {
		/* XXX would need to break out send */
		kernel_sock_shutdown(client->sock, SHUT_RDWR);
		client->recv_shutdown = true;
	}

	kfree(rx);
}
#endif

static void reset_connect_timeout(struct client_info *client)
{
	client->conn_retry_ms = CONN_RETRY_MIN_MS;
}

static void grow_connect_timeout(struct client_info *client)
{
	client->conn_retry_ms = min(client->conn_retry_ms * 2,
				    CONN_RETRY_MAX_MS);
}

#if 0
/*
 * Clients who try to send and don't see a connected socket call here to
 * connect to the server.  They get the server address and try to
 * connect.
 *
 * Each sending client will always try to connect once.  After that
 * it'll sleep and retry connecting at increasing intervals.  After long
 * enough it will return an error.  Future attempts will retry once then
 * return errors.
 */
static int client_connect(struct client_info *client)
{
	struct super_block *sb = client->sb;
	struct scoutfs_super_block super;
	struct scoutfs_net_greeting greet;
	struct sockaddr_in *sin;
	struct socket *sock = NULL;
	struct timeval tv;
	struct kvec kv;
	int retries;
	int addrlen;
	int optval;
	int ret;

	BUG_ON(!mutex_is_locked(&client->send_mutex));

	for(retries = 0; ; retries++) {
		if (sock) {
			sock_release(sock);
			sock = NULL;
		}

		if (retries) {
			/* we tried, and we're past limit, return error */
			if (time_after(jiffies, client->conn_retry_limit_j)) {
				ret = -ENOTCONN;
				break;
			}

			msleep_interruptible(client->conn_retry_ms);

			client->conn_retry_ms = min(client->conn_retry_ms * 2,
						    CONN_RETRY_MAX_MS);
		}

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		ret = scoutfs_read_super(sb, &super);
		if (ret)
			continue;

		if (super.server_addr.addr == cpu_to_le32(INADDR_ANY))
			continue;

		sin = &client->peername;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = le32_to_be32(super.server_addr.addr);
		sin->sin_port = le16_to_be16(super.server_addr.port);

		ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP,
				       &sock);
		if (ret)
			continue;

		optval = 1;
		ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
					(char *)&optval, sizeof(optval));
		if (ret)
			continue;

		/* use short timeout for connect itself */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
					(char *)&tv, sizeof(tv));
		if (ret)
			continue;

		client->sock = sock;

		ret = kernel_connect(sock, (struct sockaddr *)sin,
				     sizeof(struct sockaddr_in), 0);
		if (ret)
			continue;

		greet.fsid = super.id;
		greet.format_hash = super.format_hash;
		kv.iov_base = &greet;
		kv.iov_len = sizeof(greet);
		ret = scoutfs_sock_sendmsg(sock, &kv, 1);
		if (ret)
			continue;

		ret = scoutfs_sock_recvmsg(sock, &greet, sizeof(greet));
		if (ret)
			continue;

		if (greet.fsid != super.id) {
			scoutfs_warn(sb, "server "SIN_FMT" has fsid 0x%llx, expected 0x%llx",
				     SIN_ARG(&client->peername),
				     le64_to_cpu(greet.fsid),
				     le64_to_cpu(super.id));
			continue;
		}

		if (greet.format_hash != super.format_hash) {
			scoutfs_warn(sb, "server "SIN_FMT" has format hash 0x%llx, expected 0x%llx",
				     SIN_ARG(&client->peername),
				     le64_to_cpu(greet.format_hash),
				     le64_to_cpu(super.format_hash));
			continue;
		}

		/* but use a keepalive timeout instead of send timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		ret = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
					(char *)&tv, sizeof(tv));
		if (ret)
			continue;

		optval = KEEPCNT;
		ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
					(char *)&optval, sizeof(optval));
		if (ret)
			continue;

		optval = KEEPIDLE;
		ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE,
					(char *)&optval, sizeof(optval));
		if (ret)
			continue;

		optval = KEEPINTVL;
		ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
					(char *)&optval, sizeof(optval));
		if (ret)
			continue;

		optval = 1;
		ret = kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
					(char *)&optval, sizeof(optval));
		if (ret)
			continue;

		addrlen = sizeof(struct sockaddr_in);
		ret = kernel_getsockname(sock,
					 (struct sockaddr *)&client->sockname,
					 &addrlen);
		if (ret)
			continue;

		scoutfs_info(sb, "client connected "SIN_FMT" -> "SIN_FMT,
			     SIN_ARG(&client->sockname),
			     SIN_ARG(&client->peername));

		client->sock_gen++;
		client->recv_shutdown = false;
		reset_connect_timeouts(client);
		queue_work(client->recv_wq, &client->recv_work);
		wake_up(&client->waitq);
		ret = 0;
		break;
	}

	if (ret && sock)
		sock_release(sock);

	return ret;
}

/* either a sender or unmount is destroying the socket */
static void shutdown_sock_sync(struct client_info *client)
{
	struct super_block *sb = client->sb;
	struct socket *sock = client->sock;

	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		cancel_work_sync(&client->recv_work);
		sock_release(sock);
		client->sock = NULL;

		scoutfs_info(sb, "client disconnected "SIN_FMT" -> "SIN_FMT,
			     SIN_ARG(&client->sockname),
			     SIN_ARG(&client->peername));
	}
}

/*
 * Senders sleep waiting for a reply to come down the connection out
 * which they just sent a request.  They need to wake up when the recv
 * work has given them a reply or when it's given up and the sender
 * needs to reconnect and resend.
 *
 * This is a condition for wait_event.  The barrier orders the task
 * state store before loading the sender and client fields.
 */
static int sender_should_wake(struct client_info *client,
			      struct waiting_sender *sender)
{
	smp_mb();
	return sender->result != -EINPROGRESS || client->recv_shutdown;
}

/*
 * Block sending a request and then waiting for the reply.  All senders
 * are responsible for connecting sockets and sending their requests.
 * recv work blocks receiving from the socket and waking senders if
 * they're reply has been copied to their buffer.  If the socket sees an
 * error the recv work will shutdown and wake us to reconnect.
 */
static int client_request(struct client_info *client, int type, void *data,
			  unsigned data_len, void *rx, size_t rx_size)
{
	struct waiting_sender sender;
	struct scoutfs_net_header nh;
	struct kvec kv[2];
	unsigned kv_len;
	u64 sent_to_gen = ~0ULL;
	int ret = 0;

	if (WARN_ON_ONCE(!data && data_len))
		return -EINVAL;

	spin_lock(&client->recv_lock);

	sender.task = current;
	sender.id = client->next_id++;
	sender.rx = rx;
	sender.rx_size = rx_size;
	sender.result = -EINPROGRESS;

	nh.id = cpu_to_le64(sender.id);
	nh.data_len = cpu_to_le16(data_len);
	nh.type = type;
	nh.status = SCOUTFS_NET_STATUS_REQUEST;

	walk_sender_tree(client, sender.id, &sender);

	spin_unlock(&client->recv_lock);

	mutex_lock(&client->send_mutex);

	while (sender.result == -EINPROGRESS) {

		if (!client->sock) {
			ret = client_connect(client);
			if (ret < 0)
				break;
		}

		if (sent_to_gen != client->sock_gen) {
			kv[0].iov_base = &nh;
			kv[0].iov_len = sizeof(nh);
			kv[1].iov_base = data;
			kv[1].iov_len = data_len;
			kv_len = data ? 2 : 1;

			trace_scoutfs_client_send_request(client->sb,
							  &client->sockname,
							  &client->peername,
							  &nh);

			ret = scoutfs_sock_sendmsg(client->sock, kv, kv_len);
			if (ret) {
				shutdown_sock_sync(client);
				continue;
			}

			sent_to_gen = client->sock_gen;
		}

		mutex_unlock(&client->send_mutex);

		ret = wait_event_interruptible(client->waitq,
					sender_should_wake(client, &sender));
		if (ret < 0 && sender.result == -EINPROGRESS) {
			sender.result = ret;
			ret = 0;
		}

		mutex_lock(&client->send_mutex);

		/* finish tearing down the socket if recv shutdown */
		if (client->sock && client->recv_shutdown) {
			shutdown_sock_sync(client);
			continue;
		}
	}

	mutex_unlock(&client->send_mutex);

	/* only we remove senders, recv only uses senders under the lock */
	spin_lock(&client->recv_lock);
	rb_erase(&sender.node, &client->sender_root);
	spin_unlock(&client->recv_lock);

	if (ret == 0)
		ret = sender.result;

	return ret;
}
#endif

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
 * Attempt to connect to the listening address that the server wrote in
 * the super block.  We keep trying indefinitely with an increasing
 * delay if we fail to either read the address or connect to it.
 *
 * We're careful to only ever have one connection attempt in flight.  We
 * only queue this work on mount, on error, or from the connection
 * callback.
 */
static void scoutfs_client_connect_worker(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  connect_dwork.work);
	struct super_block *sb = client->sb;
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

	scoutfs_net_connect(sb, client->conn, &sin, client->conn_retry_ms);
	ret = 0;
out:
	if (ret && !atomic_read(&client->shutting_down)) {
		queue_delayed_work(client->workq, &client->connect_dwork,
				   msecs_to_jiffies(client->conn_retry_ms));
		grow_connect_timeout(client);
	}
}

static void client_notify_up(struct super_block *sb,
			     struct scoutfs_net_connection *conn)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	reset_connect_timeout(client);
}

/*
 * Called when either a connect attempt or established connection times
 * out and fails.
 */
static void client_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (!atomic_read(&client->shutting_down)) {
		queue_delayed_work(client->workq, &client->connect_dwork,
				   msecs_to_jiffies(client->conn_retry_ms));
		grow_connect_timeout(client);
	}
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

	/* client doesn't process any incoming requests yet */
	client->conn = scoutfs_net_alloc_conn(sb, client_notify_up,
					      client_notify_down, NULL,
					      "client");
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
