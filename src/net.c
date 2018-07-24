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
#include <linux/slab.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/log2.h>

#include "format.h"
#include "counters.h"
#include "inode.h"
#include "btree.h"
#include "manifest.h"
#include "seg.h"
#include "compact.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "net.h"
#include "endian_swap.h"
#include "tseq.h"

/*
 * scoutfs networking reliably delivers requests and responses between
 * nodes.
 *
 * Nodes decide to be either a connecting client or a listening server.
 * Both set up a connection and specify the set of request commands they
 * can process.
 *
 * The networking core maintains reliable request processing as the
 * nodes reconnect.  Requests are resent as connections are
 * re-established until a response is received.  Responses are resent
 * until an ack is received.  The connections are not bound to the
 * addresses of the underlying socket transports and can reliably
 * deliver messages across renumbering.
 *
 * XXX:
 *  - assign node_ids and validate with the greeting
 *  - defer accepted conn destruction until reconnect timeout
 *  - trace command and response data payloads
 *  - checksum message contents?
 *  - explicit shutdown message to free accepted, timeout and fence otherwise
 *  - shutdown server if accept can't alloc resources for new conn?
 */

/*
 * A connection's shutdown work executes in its own workqueue so that the
 * work can free the connection's workq.
 */
struct net_info {
	struct workqueue_struct *shutdown_workq;
	struct dentry *conn_tseq_dentry;
	struct scoutfs_tseq_tree conn_tseq_tree;
};

struct scoutfs_net_connection {
	struct super_block *sb;
	scoutfs_net_notify_t notify_up;
	scoutfs_net_notify_t notify_down;
	scoutfs_net_request_t *req_funcs;

	spinlock_t lock;

	unsigned long valid_greeting:1,	/* other commands can proceed */
		      established:1,	/* added sends queue send work */
		      shutting_down:1;	/* shutdown work has been queued */

	struct sockaddr_in connect_sin;
	unsigned long connect_timeout_ms;

	struct socket *sock;
	struct sockaddr_in sockname;
	struct sockaddr_in peername;

	struct list_head accepted_head;
	struct scoutfs_net_connection *listening_conn;
	struct list_head accepted_list;
	wait_queue_head_t accepted_waitq;

	u64 next_send_id;
	u64 last_proc_id;
	struct list_head send_queue;
	struct list_head resend_queue;

	struct workqueue_struct *workq;
	struct work_struct listen_work;
	struct work_struct connect_work;
	struct work_struct send_work;
	struct work_struct recv_work;
	struct work_struct shutdown_work;
	/* message_recv proc_work also executes in the conn workq */

	struct scoutfs_tseq_entry tseq_entry;
};

/*
 * Messages to be sent are allocated and put on the send queue.
 *
 * Request and response messages are put on the resend queue until their
 * response or ack messages are received, respectively, and they can be
 * freed.
 *
 * The send worker is the only context that references messages while
 * not holding the lock.  It does this while blocking sending the
 * message down the socket.  To free messages we mark them dead and have
 * the send worker free them while under the lock so that we don't have
 * to risk freeing messages from under the unlocked send worker.
 */
struct message_send {
	struct list_head head;
	scoutfs_net_response_t resp_func;
	void *resp_data;
	unsigned long dead:1;
	struct scoutfs_net_header nh;
};

/*
 * Incoming received messages are processed in concurrent blocking work
 * contexts.
 */
struct message_recv {
	struct scoutfs_net_connection *conn;
	struct work_struct proc_work;
	struct scoutfs_net_header nh;
};

#define DEFINE_CONN_FROM_WORK(name, work, member)			\
	struct scoutfs_net_connection *name =				\
		container_of(work, struct scoutfs_net_connection, member)

/* Total message bytes including header and payload */
static int nh_bytes(unsigned int data_len)
{
	return offsetof(struct scoutfs_net_header, data[data_len]);
}

static struct message_send *search_list(struct scoutfs_net_connection *conn,
					struct list_head *list,
					u8 msg, u8 cmd, u64 id)
{
	struct message_send *msend;

	assert_spin_locked(&conn->lock);

	list_for_each_entry(msend, list, head) {
		if (msend->nh.msg == msg && msend->nh.cmd == cmd &&
		    le64_to_cpu(msend->nh.id) == id)
			return msend;
	}

	return NULL;
}

/*
 * Find an active send on the lists.  It's almost certainly waiting on
 * the resend queue but it could be actively being sent.
 */
static struct message_send *find_send(struct scoutfs_net_connection *conn,
				      u8 msg, u8 cmd, u64 id)
{
	struct message_send *msend;

	msend = search_list(conn, &conn->resend_queue, msg, cmd, id) ?:
		search_list(conn, &conn->send_queue, msg, cmd, id);
	if (msend && msend->dead)
		msend = NULL;
	return msend;
}

/*
 * Complete a send message by moving it to the send queue and marking it
 * to be freed.
 *
 * Request messages have their response function called.  Their response
 * processing can return an error if the response is invalid.  The
 * request message is still removed and freed in that case.
 */
static int complete_send(struct scoutfs_net_connection *conn,
			 struct message_send *msend,
			 void *resp, unsigned int resp_len, int error)
{
	struct super_block *sb = conn->sb;
	int ret = 0;

	if (WARN_ON_ONCE(msend->dead) ||
	    WARN_ON_ONCE(list_empty(&msend->head)))
		return -EINVAL;

	assert_spin_locked(&conn->lock);

	if (msend->resp_func)
		ret = msend->resp_func(sb, conn, resp, resp_len, error,
				       msend->resp_data);
	msend->dead = 1;
	list_move(&msend->head, &conn->send_queue);
	queue_work(conn->workq, &conn->send_work);

	return ret;
}


/*
 * Translate a positive error on the wire to a negative host errno.
 */
static inline int net_err_to_host(u8 net_err)
{
#undef EXPAND_NET_ERRNO
#define EXPAND_NET_ERRNO(which) [SCOUTFS_NET_ERR_##which] = which,
	static u8 host_errnos[] = {
		EXPAND_EACH_NET_ERRNO
	};

	if (net_err == SCOUTFS_NET_ERR_NONE)
		return 0;

	if (net_err < ARRAY_SIZE(host_errnos) && host_errnos[net_err])
		return -host_errnos[net_err];

	return -EINVAL;
}

/*
 * Translate a negative host errno to a positive error on the wire.
 *
 * The caller is our kernel run time which should have been careful with
 * errnos.  But mistakes happen so let's holler and translate unknown
 * errors.  A fun bit of trivia: sparse's array bounds detection once
 * got confused by conditions in WARN_ON_ONCE();
 */
static inline u8 net_err_from_host(struct super_block *sb, int error)
{
#undef EXPAND_NET_ERRNO
#define EXPAND_NET_ERRNO(which) [which] = SCOUTFS_NET_ERR_##which,
	static u8 net_errs[] = {
		EXPAND_EACH_NET_ERRNO
	};
	int ind = -error;

	if (error == 0)
		return SCOUTFS_NET_ERR_NONE;

	if (error > 0 || ind >= ARRAY_SIZE(net_errs) || net_errs[ind] == 0) {
		static bool warned;
		if (!warned) {
			warned = 1;
			scoutfs_warn(sb, "host errno %d sent as EINVAL\n",
				     error);
		}

		return -EINVAL;
	}

	return net_errs[ind];
}

/*
 * Shutdown the connection.   This is called by many contexts including
 * work that most complete to finish shutting down.  We queue specific
 * shutdown work that can wait on all the connection's other work.
 * We're sure to only queue the shutdown work once.
 */
static void shutdown_conn_locked(struct scoutfs_net_connection *conn)
{
	struct super_block *sb = conn->sb;
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;

	assert_spin_locked(&conn->lock);

	if (!conn->shutting_down) {
		conn->established = 0;
		conn->shutting_down = 1;
		queue_work(ninf->shutdown_workq, &conn->shutdown_work);
	}
}

static void shutdown_conn(struct scoutfs_net_connection *conn)
{
	spin_lock(&conn->lock);
	shutdown_conn_locked(conn);
	spin_unlock(&conn->lock);
}

/*
 * Allocate a message and put it on the send queue.
 *
 * A 0 id means that we'll assign the next id from the connection once
 * we hold the lock and is only valid for sending requests.
 *
 * This can race with connections that are either starting up and
 * shutting down.  We only directly queue the send work if the
 * connection has passed the greeting and isn't being shut down.  At all
 * other times we add new sends to the resend queue.
 */
static int submit_send(struct super_block *sb,
		       struct scoutfs_net_connection *conn,
		       u8 msg, u8 cmd, u64 id, u8 net_err,
		       void *data, u16 data_len,
		       scoutfs_net_response_t resp_func, void *resp_data,
		       u64 *id_ret)
{
	struct message_send *msend;

	if (WARN_ON_ONCE(msg >= SCOUTFS_NET_MSG_UNKNOWN) ||
	    WARN_ON_ONCE(cmd >= SCOUTFS_NET_CMD_UNKNOWN) ||
	    WARN_ON_ONCE(net_err >= SCOUTFS_NET_ERR_UNKNOWN) ||
	    WARN_ON_ONCE(data_len > SCOUTFS_NET_MAX_DATA_LEN) ||
	    WARN_ON_ONCE(data_len && (!data || net_err)) ||
	    WARN_ON_ONCE(net_err && (msg != SCOUTFS_NET_MSG_RESPONSE)) ||
	    WARN_ON_ONCE(id == 0 && msg != SCOUTFS_NET_MSG_REQUEST) ||
	    WARN_ON_ONCE((cmd == SCOUTFS_NET_CMD_GREETING) !=
		         (id == SCOUTFS_NET_ID_GREETING)))
		return -EINVAL;

	msend = kmalloc(offsetof(struct message_send,
				 nh.data[data_len]), GFP_NOFS);
	if (!msend)
		return -ENOMEM;

	spin_lock(&conn->lock);

	msend->resp_func = resp_func;
	msend->resp_data = resp_data;
	msend->dead = 0;

	if (id == 0)
		id = conn->next_send_id++;
	msend->nh.id = cpu_to_le64(id);
	msend->nh.msg = msg;
	msend->nh.cmd = cmd;
	msend->nh.error = net_err;
	msend->nh.data_len = cpu_to_le16(data_len);
	if (data_len)
		memcpy(msend->nh.data, data, data_len);

	if (conn->established &&
	    (conn->valid_greeting || cmd == SCOUTFS_NET_CMD_GREETING)) {
		list_add_tail(&msend->head, &conn->send_queue);
		queue_work(conn->workq, &conn->send_work);
	} else {
		list_add_tail(&msend->head, &conn->resend_queue);
	}

	if (id_ret)
		*id_ret = le64_to_cpu(msend->nh.id);

	spin_unlock(&conn->lock);

	return 0;
}

/*
 * Messages can flow once we receive a valid greeting from our peer.
 * Response callers are already called under the lock, request callers
 * need to acquire it.
 *
 * At this point greeting request processing has queued the greeting
 * response message on the send queue.  All the sends waiting to be
 * resent need to be added to the end of the send queue after the
 * greeting response.  Greeting acks are sent differently and can be
 * received after resend messages.
 */
static void saw_valid_greeting(struct scoutfs_net_connection *conn)
{
	struct super_block *sb = conn->sb;

	assert_spin_locked(&conn->lock);

	conn->valid_greeting = 1;
	if (conn->notify_up)
		conn->notify_up(sb, conn);
	list_splice_tail_init(&conn->resend_queue, &conn->send_queue);
	queue_work(conn->workq, &conn->send_work);
}

static int greeting_response(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     void *resp, unsigned int resp_len, int error,
			     void *data)
{
	struct scoutfs_net_greeting *gr = resp;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
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
		scoutfs_warn(sb, "server "SIN_FMT" has fsid 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->id));
		ret = -EINVAL;
		goto out;
	}

	if (gr->format_hash != super->format_hash) {
		scoutfs_warn(sb, "server "SIN_FMT" has format hash 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(gr->format_hash),
			     le64_to_cpu(super->format_hash));
		ret = -EINVAL;
		goto out;
	}

	saw_valid_greeting(conn);

out:
	return ret;
}

/*
 * Process an incoming greeting request.  We try to send responses to
 * failed greetings so that the sender can log some detail before
 * shutting down.  A failure to send a greeting response shuts down the
 * connection.
 */
static int greeting_request(struct super_block *sb,
			    struct scoutfs_net_connection *conn,
			    u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_net_greeting *gr = arg;
	struct scoutfs_net_greeting greet;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	int ret = 0;

	if (arg_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto out;
	}

	if (gr->fsid != super->id) {
		scoutfs_warn(sb, "client "SIN_FMT" has fsid 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->id));
		ret = -EINVAL;
		goto out;
	}

	if (gr->format_hash != super->format_hash) {
		scoutfs_warn(sb, "client "SIN_FMT" has format hash 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(gr->format_hash),
			     le64_to_cpu(super->format_hash));
		ret = -EINVAL;
		goto out;
	}

	greet.fsid = super->id;
	greet.format_hash = super->format_hash;
out:
	ret = scoutfs_net_response(sb, conn, cmd, id, ret,
				   &greet, sizeof(greet));
	if (ret == 0) {
		spin_lock(&conn->lock);
		saw_valid_greeting(conn);
		spin_unlock(&conn->lock);
	}
	return ret;
}


/*
 * Process an incoming response.  The greeting should ensure that the
 * sender won't send us unknown commands.  We return an error if we see
 * an unknown command because the greeting should agree on an understood
 * protocol.  The request function sends a response and returns an error
 * if they couldn't.
 */
static int process_request(struct scoutfs_net_connection *conn,
			   struct message_recv *mrecv)
{
	struct super_block *sb = conn->sb;
	scoutfs_net_request_t req_func = NULL;

	if (conn->listening_conn != NULL &&
	    mrecv->nh.cmd == SCOUTFS_NET_CMD_GREETING) {
		req_func = greeting_request;
	} else if (mrecv->nh.cmd < SCOUTFS_NET_CMD_UNKNOWN) {
		req_func = conn->req_funcs[mrecv->nh.cmd];
	} if (req_func == NULL) {
		scoutfs_inc_counter(sb, net_unknown_request);
		return -EINVAL;
	}

	return req_func(sb, conn, mrecv->nh.cmd, le64_to_cpu(mrecv->nh.id),
			mrecv->nh.data, le16_to_cpu(mrecv->nh.data_len));
}

/*
 * An incoming response finds the queued request and calls its response
 * function.  We call the function and remove it from the lists before
 * trying to send the ack so that we only call the response function
 * once.  Future duplicate responses will just resend the ack in
 * response.
 */
static int process_response(struct scoutfs_net_connection *conn,
			    struct message_recv *mrecv)
{
	struct super_block *sb = conn->sb;
	struct message_send *msend;
	int ret = 0;

	spin_lock(&conn->lock);

	msend = find_send(conn, SCOUTFS_NET_MSG_REQUEST, mrecv->nh.cmd,
			  le64_to_cpu(mrecv->nh.id));
	if (msend)
		ret = complete_send(conn, msend, mrecv->nh.data,
				    le16_to_cpu(mrecv->nh.data_len),
				    net_err_to_host(mrecv->nh.error));
	else
		scoutfs_inc_counter(sb, net_dropped_response);

	spin_unlock(&conn->lock);

	if (ret == 0)
		ret = submit_send(sb, conn, SCOUTFS_NET_MSG_ACK, mrecv->nh.cmd,
				  le64_to_cpu(mrecv->nh.id), 0, NULL, 0, NULL,
				  NULL, NULL);
	return ret;
}

/*
 * An incoming ack frees the pending response.
 */
static void process_ack(struct scoutfs_net_connection *conn,
			struct message_recv *mrecv)
{
	struct super_block *sb = conn->sb;
	struct message_send *msend;

	spin_lock(&conn->lock);

	msend = find_send(conn, SCOUTFS_NET_MSG_RESPONSE, mrecv->nh.cmd,
			  le64_to_cpu(mrecv->nh.id));
	if (msend)
		complete_send(conn, msend, NULL, 0, 0);
	else
		scoutfs_inc_counter(sb, net_dropped_ack);

	spin_unlock(&conn->lock);
}

/*
 * Process an incoming received message in its own concurrent blocking
 * work context.
 */
static void scoutfs_net_proc_worker(struct work_struct *work)
{
	struct message_recv *mrecv = container_of(work, struct message_recv,
						  proc_work);
	struct scoutfs_net_connection *conn = mrecv->conn;
	struct super_block *sb = conn->sb;
	int ret;

	trace_scoutfs_net_proc_work_enter(sb, 0, 0);

	switch (mrecv->nh.msg) {
		case SCOUTFS_NET_MSG_REQUEST:
			ret = process_request(conn, mrecv);
			break;
		case SCOUTFS_NET_MSG_RESPONSE:
			ret = process_response(conn, mrecv);
			break;
		case SCOUTFS_NET_MSG_ACK:
			process_ack(conn, mrecv);
			ret = 0;
			break;
		default:
			scoutfs_inc_counter(sb, net_unknown_message);
			ret = -ENOMSG;
			break;
	}

	/* process_one_work explicitly allows freeing work in its func */
	kfree(mrecv);

	/* shut down the connection if processing returns fatal errors */
	if (ret)
		shutdown_conn(conn);

	trace_scoutfs_net_proc_work_exit(sb, 0, ret);
}

static int recvmsg_full(struct socket *sock, void *buf, unsigned len)
{
	struct msghdr msg;
	struct kvec kv;
	int ret;

	while (len) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = (struct iovec *)&kv;
		msg.msg_iovlen = 1;
		msg.msg_flags = MSG_NOSIGNAL;
		kv.iov_base = buf;
		kv.iov_len = len;

		ret = kernel_recvmsg(sock, &msg, &kv, 1, len, msg.msg_flags);
		if (ret <= 0)
			return -ECONNABORTED;

		len -= ret;
		buf += ret;
	}

	return 0;
}

static bool invalid_message(struct scoutfs_net_header *nh)
{
	/* ids must be non-zero */
	if (nh->id == 0)
		return true;

	/* greeting messages must have the greeting id */
	if ((nh->cmd == SCOUTFS_NET_CMD_GREETING) !=
	    (le64_to_cpu(nh->id) == SCOUTFS_NET_ID_GREETING))
		return true;

	/* greeting should negotiate understood protocol */
	if (nh->msg >= SCOUTFS_NET_MSG_UNKNOWN ||
	    nh->cmd >= SCOUTFS_NET_CMD_UNKNOWN ||
	    nh->error >= SCOUTFS_NET_ERR_UNKNOWN)
		return true;

	/* errors can't have payloads */
	if (nh->data_len != 0 && nh->error != SCOUTFS_NET_ERR_NONE)
		return true;

	/* payloads have a limit */
	if (le16_to_cpu(nh->data_len) > SCOUTFS_NET_MAX_DATA_LEN)
		return true;

	/* only responses can carry errors */
	if (nh->error != SCOUTFS_NET_ERR_NONE &&
	    nh->msg != SCOUTFS_NET_MSG_RESPONSE)
		return true;

	return false;
}

/*
 * Always block receiving from the socket.  Errors trigger shutting down
 * the connection.
 */
static void scoutfs_net_recv_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, recv_work);
	struct super_block *sb = conn->sb;
	struct socket *sock = conn->sock;
	struct scoutfs_net_header nh;
	struct message_recv *mrecv;
	unsigned int data_len;
	int ret;

	trace_scoutfs_net_recv_work_enter(sb, 0, 0);

	for (;;) {
		/* receive the header */
		ret = recvmsg_full(sock, &nh, sizeof(nh));
		if (ret)
			break;

		/* receiving an invalid message breaks the connection */
		if (invalid_message(&nh)) {
			scoutfs_inc_counter(sb, net_recv_invalid_message);
			ret = -EBADMSG;
			break;
		}

		data_len = le16_to_cpu(nh.data_len);

		scoutfs_inc_counter(sb, net_recv_messages);
		scoutfs_add_counter(sb, net_recv_bytes, nh_bytes(data_len));
		trace_scoutfs_net_recv_message(sb, &conn->sockname,
					       &conn->peername, &nh);

		/* invalid message checked data len */
		mrecv = kmalloc(offsetof(struct message_recv,
					 nh.data[data_len]), GFP_NOFS);
		if (!mrecv) {
			ret = -ENOMEM;
			break;
		}

		mrecv->conn = conn;
		INIT_WORK(&mrecv->proc_work, scoutfs_net_proc_worker);
		mrecv->nh = nh;

		/* receive the data payload */
		ret = recvmsg_full(sock, mrecv->nh.data, data_len);
		if (ret) {
			kfree(mrecv);
			break;
		}

		/*
		 * Check and maintain the last processed id for
		 * non-greeting requests before introducing reordering
		 * by queueing concurrent work.
		 */
		spin_lock(&conn->lock);
		if (mrecv->nh.msg == SCOUTFS_NET_MSG_REQUEST &&
		    mrecv->nh.cmd != SCOUTFS_NET_CMD_GREETING) {
			if (le64_to_cpu(mrecv->nh.id) <= conn->last_proc_id) {
				scoutfs_inc_counter(sb, net_dropped_request);
				kfree(mrecv);
				mrecv = NULL;
			} else {
				conn->last_proc_id = le64_to_cpu(mrecv->nh.id);
			}
		}
		spin_unlock(&conn->lock);

		if (mrecv)
			queue_work(conn->workq, &mrecv->proc_work);
	}

	if (ret)
		scoutfs_inc_counter(sb, net_recv_error);

	/* recv stopping always shuts down the connection */
	shutdown_conn(conn);

	trace_scoutfs_net_recv_work_exit(sb, 0, ret);
}

static int sendmsg_full(struct socket *sock, void *buf, unsigned len)
{
	struct msghdr msg;
	struct kvec kv;
	int ret;

	while (len) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = (struct iovec *)&kv;
		msg.msg_iovlen = 1;
		msg.msg_flags = MSG_NOSIGNAL;
		kv.iov_base = buf;
		kv.iov_len = len;

		ret = kernel_sendmsg(sock, &msg, &kv, 1, len);
		if (ret <= 0)
			return -ECONNABORTED;

		len -= ret;
		buf += ret;
	}

	return 0;
}

/*
 * Each connection has a single worker that sends queued messages down
 * the connection's socket.  The work is queued whenever a message is
 * put on the send queue.  The worker uses blocking sends so that we
 * don't have to worry about resuming partial sends or hooking into
 * data_ready.  Send errors shut down the connection.
 *
 * The worker is responsible for freeing messages so that other contexts
 * don't have to worry about freeing a message while we're blocked
 * sending it without the lock held.
 */
static void scoutfs_net_send_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, send_work);
	struct super_block *sb = conn->sb;
	struct message_send *msend;
	int ret = 0;
	int len;

	trace_scoutfs_net_send_work_enter(sb, 0, 0);

	spin_lock(&conn->lock);

	while ((msend = list_first_entry_or_null(&conn->send_queue,
						 struct message_send, head))) {

		if (msend->dead) {
			list_del_init(&msend->head);
			kfree(msend);
			continue;
		}

		spin_unlock(&conn->lock);

		len = nh_bytes(le16_to_cpu(msend->nh.data_len));

		scoutfs_inc_counter(sb, net_send_messages);
		scoutfs_add_counter(sb, net_send_bytes, len);
		trace_scoutfs_net_send_message(sb, &conn->sockname,
					       &conn->peername, &msend->nh);

		ret = sendmsg_full(conn->sock, &msend->nh, len);

		spin_lock(&conn->lock);

		if (ret)
			break;

		/* acks are always freed, others will be resent if not dead */
		if (msend->nh.msg == SCOUTFS_NET_MSG_ACK)
			msend->dead = 1;
		else if (!msend->dead)
			list_move_tail(&msend->head, &conn->resend_queue);
	}

	spin_unlock(&conn->lock);

	if (ret) {
		scoutfs_inc_counter(sb, net_send_error);
		shutdown_conn(conn);
	}

	trace_scoutfs_net_send_work_exit(sb, 0, ret);
}

static void destroy_conn(struct scoutfs_net_connection *conn)
{
	struct super_block *sb = conn->sb;
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *listener;
	struct message_send *msend;
	struct message_send *tmp;

	WARN_ON_ONCE(conn->sock != NULL);
	WARN_ON_ONCE(!list_empty(&conn->accepted_list));

	/* free all messages, refactor and complete for forced unmount? */
	list_splice_init(&conn->resend_queue, &conn->send_queue);
	list_for_each_entry_safe(msend, tmp, &conn->send_queue, head) {
		list_del_init(&msend->head);
		kfree(msend);
	}

	/* accepted sockets are removed from their listener's list */
	if (conn->listening_conn) {
		listener = conn->listening_conn;

		spin_lock(&listener->lock);
		list_del_init(&conn->accepted_head);
		if (list_empty(&listener->accepted_list))
			wake_up(&listener->accepted_waitq);
		spin_unlock(&listener->lock);
	}

	destroy_workqueue(conn->workq);
	scoutfs_tseq_del(&ninf->conn_tseq_tree, &conn->tseq_entry);
	kfree(conn);
}

/*
 * Have a pretty aggressive keepalive timeout of around 10 seconds.  The
 * TCP keepalives are being processed out of task context so they should
 * be responsive even when mounts are under load.
 */
#define KEEPCNT			3
#define KEEPIDLE		7
#define KEEPINTVL		1
static int sock_opts_and_names(struct scoutfs_net_connection *conn,
			       struct socket *sock)
{
	struct timeval tv;
	int addrlen;
	int optval;
	int ret;

	/* but use a keepalive timeout instead of send timeout */
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
				(char *)&tv, sizeof(tv));
	if (ret)
		goto out;

	optval = KEEPCNT;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
				(char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	optval = KEEPIDLE;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE,
				(char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	optval = KEEPINTVL;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
				(char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	optval = 1;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
				(char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	optval = 1;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
				(char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	addrlen = sizeof(struct sockaddr_in);
	ret = kernel_getsockname(sock, (struct sockaddr *)&conn->sockname,
				 &addrlen);
	if (ret == 0 && addrlen != sizeof(struct sockaddr_in))
		ret = -EAFNOSUPPORT;
	if (ret)
		goto out;

	addrlen = sizeof(struct sockaddr_in);
	ret = kernel_getpeername(sock, (struct sockaddr *)&conn->peername,
				 &addrlen);
	if (ret == 0 && addrlen != sizeof(struct sockaddr_in))
		ret = -EAFNOSUPPORT;
	if (ret)
		goto out;
out:
	return ret;
}

/*
 * Each bound and listening connection has long running work that blocks
 * accepting new connections.  The listening socket has been setup by
 * the time this is queued.
 *
 * Any errors on the listening sock tear down all the connections that
 * were accepted.
 */
static void scoutfs_net_listen_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, listen_work);
	struct super_block *sb = conn->sb;
	struct scoutfs_net_connection *acc_conn;
	DECLARE_WAIT_QUEUE_HEAD(waitq);
	struct socket *acc_sock;
	LIST_HEAD(conn_list);
	int ret;

	trace_scoutfs_net_listen_work_enter(sb, 0, 0);

	for (;;) {
		ret = kernel_accept(conn->sock, &acc_sock, 0);
		if (ret < 0)
			break;

		/* inherit accepted request funcs from listening conn */
		acc_conn = scoutfs_net_alloc_conn(sb, NULL, NULL,
						  conn->req_funcs, "accepted");
		if (!acc_conn) {
			sock_release(acc_sock);
			ret = -ENOMEM;
			continue;
		}

		ret = sock_opts_and_names(acc_conn, acc_sock);
		if (ret) {
			sock_release(acc_sock);
			destroy_conn(acc_conn);
			continue;
		}

		scoutfs_info(sb, "server accepted "SIN_FMT" -> "SIN_FMT,
			     SIN_ARG(&acc_conn->sockname),
			     SIN_ARG(&acc_conn->peername));

		/* acc_conn isn't visible, conn unlock orders stores */
		spin_lock(&conn->lock);

		acc_conn->sock = acc_sock;
		acc_conn->listening_conn = conn;
		acc_conn->established = 1;
		list_add_tail(&acc_conn->accepted_head, &conn->accepted_list);

		spin_unlock(&conn->lock);

		queue_work(acc_conn->workq, &acc_conn->recv_work);
	}

	/* listening stopping shuts down connection */
	shutdown_conn(conn);

	trace_scoutfs_net_listen_work_exit(sb, 0, ret);
}

/*
 * Try once to connect to the caller's address.  This is racing with
 * shutdown if the caller frees the connection while we're connecting.
 * Shutdown will wait for our executing work to finish.
 */
static void scoutfs_net_connect_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, connect_work);
	struct super_block *sb = conn->sb;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_net_greeting greet;
	struct socket *sock;
	struct timeval tv;
	int ret;

	trace_scoutfs_net_connect_work_enter(sb, 0, 0);

	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret)
		goto out;

	/* caller specified connect timeout */
	tv.tv_sec = conn->connect_timeout_ms / MSEC_PER_SEC;
	tv.tv_usec = (conn->connect_timeout_ms % MSEC_PER_SEC) * USEC_PER_MSEC;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
				(char *)&tv, sizeof(tv));
	if (ret) {
		sock_release(sock);
		goto out;
	}

	/* shutdown now owns sock, can break blocking connect */
	spin_lock(&conn->lock);
	conn->sock = sock;
	spin_unlock(&conn->lock);

	ret = kernel_connect(sock, (struct sockaddr *)&conn->connect_sin,
			     sizeof(struct sockaddr_in), 0);
	if (ret)
		goto out;

	ret = sock_opts_and_names(conn, sock);
	if (ret)
		goto out;

	/* greeting is about to queue send work */
	spin_lock(&conn->lock);
	conn->established = 1;
	spin_unlock(&conn->lock);

	queue_work(conn->workq, &conn->recv_work);

	/* queue a new updated greeting send */
	greet.fsid = super->id;
	greet.format_hash = super->format_hash;

	ret = submit_send(sb, conn, SCOUTFS_NET_MSG_REQUEST,
			  SCOUTFS_NET_CMD_GREETING, SCOUTFS_NET_ID_GREETING, 0,
			  &greet, sizeof(greet), greeting_response, NULL, NULL);
	if (ret)
		goto out;

	scoutfs_info(sb, "client connected "SIN_FMT" -> "SIN_FMT,
		     SIN_ARG(&conn->sockname),
		     SIN_ARG(&conn->peername));
out:
	if (ret)
		shutdown_conn(conn);

	trace_scoutfs_net_connect_work_exit(sb, 0, ret);
}

static bool empty_accepted_list(struct scoutfs_net_connection *conn)
{
	bool empty;

	spin_lock(&conn->lock);
	empty = list_empty(&conn->accepted_list);
	spin_unlock(&conn->lock);

	return empty;
}

/* listening and their accepting sockets have a fixed locking order */
enum {
	CONN_LOCK_LISTENER,
	CONN_LOCK_ACCEPTED,
};

/*
 * Safely shut down an active connection.  This can be triggered by
 * errors in workers or by an external call to free the connection.  The
 * shutting down flag ensures that this only executes once for each live
 * socket.
 *
 * Our reliability guarantee requires request processing to make forward
 * progress once we've received and recorded a request id.   We wait for
 * processing work that is in flight and its sends will be queued for
 * resending because the connection is not established while it's
 * shutting down.
 */
static void scoutfs_net_shutdown_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, shutdown_work);
	struct super_block *sb = conn->sb;
	struct scoutfs_net_connection *acc_conn;
	struct message_send *msend;

	trace_scoutfs_net_shutdown_work_enter(sb, 0, 0);

	/* connected and accepted conns print a message */
	if (conn->peername.sin_port != 0)
		scoutfs_info(sb, "%s "SIN_FMT" -> "SIN_FMT,
			     conn->listening_conn ? "server closing" :
			                            "client disconnected",
			     SIN_ARG(&conn->sockname),
			     SIN_ARG(&conn->peername));

	/* ensure that sockets return errors, wakes blocked socket work */
	if (conn->sock)
		kernel_sock_shutdown(conn->sock, SHUT_RDWR);

	/* wait for socket and proc work to finish, includes chained work */
	drain_workqueue(conn->workq);

	/* tear down the sock now that all work is done */
	if (conn->sock) {
		sock_release(conn->sock);
		conn->sock = NULL;
	}

	/* listening connections shut down all the connections they accepted */
	spin_lock_nested(&conn->lock, CONN_LOCK_LISTENER);
	list_for_each_entry(acc_conn, &conn->accepted_list, accepted_head) {
		spin_lock_nested(&acc_conn->lock, CONN_LOCK_ACCEPTED);
		shutdown_conn_locked(acc_conn);
		spin_unlock(&acc_conn->lock);
	}
	spin_unlock(&conn->lock);
	wait_event(conn->accepted_waitq, empty_accepted_list(conn));

	spin_lock(&conn->lock);

	/* all queued sends will be resent, protocol handles dupes */
	list_splice_tail_init(&conn->send_queue, &conn->resend_queue);

	/* clear greeting state for next negotiation */
	conn->valid_greeting = 0;
	msend = find_send(conn, SCOUTFS_NET_MSG_REQUEST,
			  SCOUTFS_NET_CMD_GREETING, SCOUTFS_NET_ID_GREETING) ?:
		find_send(conn, SCOUTFS_NET_MSG_RESPONSE,
			  SCOUTFS_NET_CMD_GREETING, SCOUTFS_NET_ID_GREETING) ?:
		find_send(conn, SCOUTFS_NET_MSG_ACK,
			  SCOUTFS_NET_CMD_GREETING, SCOUTFS_NET_ID_GREETING);
	if (msend)
		complete_send(conn, msend, NULL, 0, 0);

	spin_unlock(&conn->lock);

	memset(&conn->peername, 0, sizeof(conn->peername));

	/* tell the caller that the connection is down */
	if (conn->notify_down)
		conn->notify_down(sb, conn);

	/* accepted conns are destroyed */
	if (conn->listening_conn) {
		destroy_conn(conn);
	} else {
		spin_lock(&conn->lock);
		conn->shutting_down = 0;
		spin_unlock(&conn->lock);
	}

	trace_scoutfs_net_shutdown_work_exit(sb, 0, 0);
}

struct scoutfs_net_connection *
scoutfs_net_alloc_conn(struct super_block *sb,
		       scoutfs_net_notify_t notify_up,
		       scoutfs_net_notify_t notify_down,
		       scoutfs_net_request_t *req_funcs, char *name_suffix)
{
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *conn;

	/* we handle greetings, the caller shouldn't attempt to */
	if (WARN_ON_ONCE(req_funcs != NULL &&
			 req_funcs[SCOUTFS_NET_CMD_GREETING] != NULL))
		return NULL;

	conn = kzalloc(sizeof(struct scoutfs_net_connection), GFP_NOFS);
	if (!conn)
		return NULL;

	conn->workq = alloc_workqueue("scoutfs_net_%s",
				      WQ_UNBOUND | WQ_NON_REENTRANT, 0,
				      name_suffix);
	if (!conn->workq) {
		kfree(conn);
		return NULL;
	}

	conn->sb = sb;
	conn->notify_up = notify_up;
	conn->notify_down = notify_down;
	conn->req_funcs = req_funcs;
	spin_lock_init(&conn->lock);
	conn->sockname.sin_family = AF_INET;
	conn->peername.sin_family = AF_INET;
	INIT_LIST_HEAD(&conn->accepted_head);
	INIT_LIST_HEAD(&conn->accepted_list);
	init_waitqueue_head(&conn->accepted_waitq);
	conn->next_send_id = SCOUTFS_NET_ID_GREETING + 1;
	INIT_LIST_HEAD(&conn->send_queue);
	INIT_LIST_HEAD(&conn->resend_queue);
	INIT_WORK(&conn->listen_work, scoutfs_net_listen_worker);
	INIT_WORK(&conn->connect_work, scoutfs_net_connect_worker);
	INIT_WORK(&conn->send_work, scoutfs_net_send_worker);
	INIT_WORK(&conn->recv_work, scoutfs_net_recv_worker);
	INIT_WORK(&conn->shutdown_work, scoutfs_net_shutdown_worker);

	scoutfs_tseq_add(&ninf->conn_tseq_tree, &conn->tseq_entry);

	return conn;
}

/*
 * Shutdown the connection.  Once this returns no network traffic
 * or work will be executing.  The caller can then connect or bind and
 * listen again.  Additional shutdown calls will already find it shutdown.
 */
void scoutfs_net_shutdown(struct super_block *sb,
			  struct scoutfs_net_connection *conn)
{
	shutdown_conn(conn);
	flush_work(&conn->shutdown_work);
}

/*
 * Destroy the connection after the shutdown work has stopped all concurrent
 * processing on the connection.
 */
void scoutfs_net_free_conn(struct super_block *sb,
			   struct scoutfs_net_connection *conn)
{
	if (conn) {
		scoutfs_net_shutdown(sb, conn);
		destroy_conn(conn);
	}
}

/*
 * Associate a bound socket with the caller's connection.  We call bind
 * and listen to assign the listening address and give it to the caller.
 *
 * If this returns success then the caller has to call either listen or
 * free_conn.
 */
int scoutfs_net_bind(struct super_block *sb,
		     struct scoutfs_net_connection *conn,
		     struct sockaddr_in *sin)
{
	struct socket *sock = NULL;
	int addrlen;
	int ret;

	/* caller state machine shouldn't let this happen */
	if (WARN_ON_ONCE(conn->sock))
		return -EINVAL;

	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret)
		goto out;

	addrlen = sizeof(struct sockaddr_in);
	ret = kernel_bind(sock, (struct sockaddr *)sin, addrlen);
	if (ret)
		goto out;

	ret = kernel_listen(sock, 255);
	if (ret)
		goto out;

	addrlen = sizeof(struct sockaddr_in);
	ret = kernel_getsockname(sock, (struct sockaddr *)&conn->sockname,
				 &addrlen);
	if (ret == 0 && addrlen != sizeof(struct sockaddr_in))
		ret = -EAFNOSUPPORT;
	if (ret)
		goto out;

	conn->sock = sock;
	*sin = conn->sockname;
	ret = 0;
out:
	if (ret < 0 && sock)
		sock_release(sock);
	return ret;
}

/*
 * Kick off blocking background work to accept connections from the
 * connection's listening socket that was created with a previous bind
 * call.
 *
 * The callback notify_down will be called once the listening socket is
 * shut down either by errors or the caller freeing the conn.
 */
void scoutfs_net_listen(struct super_block *sb,
			struct scoutfs_net_connection *conn)
{
	queue_work(conn->workq, &conn->listen_work);
}

/*
 * Start connecting to the given address.  notify_up may be called if
 * the connection completes.  notify_down will be called when either the
 * connection disconnects or times out.  Both could be called before
 * this function returns.  The caller must be careful not to call
 * connect again until notify_down has been called.
 */
void scoutfs_net_connect(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 struct sockaddr_in *sin, unsigned long timeout_ms)
{
	spin_lock(&conn->lock);
	conn->connect_sin = *sin;
	conn->connect_timeout_ms = timeout_ms;
	spin_unlock(&conn->lock);

	queue_work(conn->workq, &conn->connect_work);
}

/*
 * Submit a request down the connection.  It's up to the caller to
 * ensure that the conn is allocated.  Sends submitted when the
 * connection isn't established will be resent in order the next time
 * it's established.
 */
int scoutfs_net_submit_request(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, void *arg, u16 arg_len,
			       scoutfs_net_response_t resp_func,
			       void *resp_data, u64 *id_ret)
{
	return submit_send(sb, conn, SCOUTFS_NET_MSG_REQUEST, cmd, 0, 0,
			   arg, arg_len, resp_func, resp_data, id_ret);
}

/*
 * Send a response.  Responses don't get callbacks and use the request's
 * id so caller's don't need to get an id in return.
 *
 * The data payload is ignored if an error is sent so that callers have
 * simple processing exit paths.
 *
 * An error is returned if the response could not be sent.
 */
int scoutfs_net_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 u8 cmd, u64 id, int error, void *resp, u16 resp_len)
{
	if (error) {
		resp = NULL;
		resp_len = 0;
	}

	return submit_send(sb, conn, SCOUTFS_NET_MSG_RESPONSE,
			   cmd, id, net_err_from_host(sb, error),
			   resp, resp_len, NULL, NULL, NULL);
}

void scoutfs_net_cancel_request(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id)
{
	struct message_send *msend;

	spin_lock(&conn->lock);
	msend = find_send(conn, SCOUTFS_NET_MSG_REQUEST, cmd, id);
	if (msend)
		complete_send(conn, msend, NULL, 0, -ECANCELED);
	spin_unlock(&conn->lock);
}

struct sync_request_completion {
	struct completion comp;
	void *resp;
	unsigned int resp_len;
	int error;
};

static int sync_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 void *resp, unsigned int resp_len,
			 int error, void *data)
{
	struct sync_request_completion *sreq = data;

	if (error == 0 && resp_len != sreq->resp_len)
		error = -EMSGSIZE;

	if (error)
		sreq->error = error;
	else if (resp_len)
		memcpy(sreq->resp, resp, resp_len);

	complete(&sreq->comp);

	return 0;
}

/*
 * Send a request and wait for a response to be copied into the given
 * buffer.  Errors returned can come from the remote request processing
 * or local failure to send.
 *
 * The wait for the response is interruptible and can return
 * -ERESTARTSYS if it is interrupted.
 *
 * -EOVERFLOW is returned if the response message's data_length doesn't
 * match the caller's resp_len buffer.
 */
int scoutfs_net_sync_request(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     u8 cmd, void *arg, unsigned arg_len,
			     void *resp, size_t resp_len)
{
	struct sync_request_completion sreq;
	int ret;
	u64 id;

	init_completion(&sreq.comp);
	sreq.resp = resp;
	sreq.resp_len = resp_len;
	sreq.error = 0;

	ret = scoutfs_net_submit_request(sb, conn, cmd, arg, arg_len,
					 sync_response, &sreq, &id);

	ret = wait_for_completion_interruptible(&sreq.comp);
	if (ret == -ERESTARTSYS)
		scoutfs_net_cancel_request(sb, conn, cmd, id);
	else
		ret = sreq.error;

	return ret;
}

static void net_tseq_show_conn(struct seq_file *m,
			      struct scoutfs_tseq_entry *ent)
{
	struct scoutfs_net_connection *conn =
		container_of(ent, struct scoutfs_net_connection, tseq_entry);

	seq_printf(m, "name "SIN_FMT" peer "SIN_FMT" vg %u est %u sd %u cto_ms %lu nsi %llu lpi %llu\n",
		   SIN_ARG(&conn->sockname), SIN_ARG(&conn->peername),
		   conn->valid_greeting, conn->established,
		   conn->shutting_down, conn->connect_timeout_ms,
		   conn->next_send_id, conn->last_proc_id);
}

int scoutfs_net_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct net_info *ninf;
	int ret;

	/* fail the build if host errnos don't fit in the u8 mapping arrays */
#undef EXPAND_NET_ERRNO
#define EXPAND_NET_ERRNO(which) BUILD_BUG_ON(which >= U8_MAX);
	EXPAND_EACH_NET_ERRNO

	ninf = kzalloc(sizeof(struct net_info), GFP_KERNEL);
	if (!ninf) {
		ret = -ENOMEM;
		goto out;
	}
	sbi->net_info = ninf;

	scoutfs_tseq_tree_init(&ninf->conn_tseq_tree, net_tseq_show_conn);

	ninf->shutdown_workq = alloc_workqueue("scoutfs_net_shutdown",
					      WQ_UNBOUND, 0);
	if (!ninf->shutdown_workq) {
		ret = -ENOMEM;
		goto out;
	}

	ninf->conn_tseq_dentry = scoutfs_tseq_create("connections",
						     sbi->debug_root,
						     &ninf->conn_tseq_tree);
	if (!ninf->conn_tseq_dentry) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_net_destroy(sb);
	return ret;
}

void scoutfs_net_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;

	if (ninf) {
		if (ninf->shutdown_workq)
			destroy_workqueue(ninf->shutdown_workq);
		debugfs_remove(ninf->conn_tseq_dentry);
		kfree(ninf);
		sbi->net_info = NULL;
	}
}
