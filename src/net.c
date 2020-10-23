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
#include "scoutfs_trace.h"
#include "msg.h"
#include "net.h"
#include "endian_swap.h"
#include "tseq.h"

/*
 * scoutfs networking delivers requests and responses between nodes.
 *
 * Nodes decide to be either a connecting client or a listening server.
 * Both set up a connection and specify the set of request commands they
 * can process.
 *
 * Request and response messages are queued on a connection.  They're
 * resent down newly established sockets on a long lived connection.
 * Queued requests are removed as a response is processed or if the
 * request is canceled by the sender.  Queued responses are removed as
 * the receiver acknowledges their delivery.
 *
 * Request and response resending is asymmetrical because of the
 * client/server relationship.  If a client connects to a new server it
 * drops responses because the new server doesn't have any requests
 * pending.  If a server times out a client it drops everything because
 * that client is never coming back.
 *
 * Requests and responses are only processed once for a given client and
 * server pair.  Callers have to deal with the possibility that two
 * servers might both process the same client request, even though the
 * client may only see the most recent response.
 *
 * The functional core of this implementation is solid, but boy are the
 * interface boundaries getting fuzzy.  The core knows too much about
 * clients and servers and the communications across the net interface
 * boundary are questionable.  We probably want to pull more client and
 * server specific behaviour up into the client and server and turn the
 * "net" code into more passive shared framing helpers.
 *
 * XXX:
 *  - trace command and response data payloads
 *  - checksum message contents?
 *  - shutdown server if accept can't alloc resources for new conn?
 */

/* reasonable multiple of max client reconnect attempt interval */
#define CLIENT_RECONNECT_TIMEOUT_MS (20 * MSEC_PER_SEC)

/*
 * A connection's shutdown work executes in its own workqueue so that the
 * work can free the connection's workq.
 */
struct net_info {
	struct workqueue_struct *shutdown_workq;
	struct workqueue_struct *destroy_workq;
	struct dentry *conn_tseq_dentry;
	struct scoutfs_tseq_tree conn_tseq_tree;
	struct dentry *msg_tseq_dentry;
	struct scoutfs_tseq_tree msg_tseq_tree;
};

/* flags enum is in net.h */
#define test_conn_fl(conn, which) (!!((conn)->flags & CONN_FL_##which))
#define set_conn_fl(conn, which)				\
do {								\
	(conn)->flags |= CONN_FL_##which;			\
} while (0)
#define clear_conn_fl(conn, which)				\
do {								\
	(conn)->flags &= ~CONN_FL_##which;			\
} while (0)
#define assign_conn_fl(dst, src, which)				\
do {								\
	(dst)->flags |= ((conn)->flags & CONN_FL_##which);	\
} while (0)

/* listening and their accepting sockets have a fixed locking order */
enum {
	CONN_LOCK_LISTENER,
	CONN_LOCK_ACCEPTED,
};

/*
 * Messages to be sent are allocated and put on the send queue.
 *
 * Request messages are put on the resend queue until their response
 * messages is received and they can be freed.
 *
 * The send worker is the only context that references messages while
 * not holding the lock.  It does this while blocking sending the
 * message down the socket.  To free messages we mark them dead and have
 * the send worker free them while under the lock so that we don't have
 * to risk freeing messages from under the unlocked send worker.
 */
struct message_send {
	struct scoutfs_tseq_entry tseq_entry;
	unsigned long dead:1;
	struct list_head head;
	scoutfs_net_response_t resp_func;
	void *resp_data;
	struct scoutfs_net_header nh;
};

/*
 * Incoming received messages are processed in concurrent blocking work
 * contexts.
 */
struct message_recv {
	struct scoutfs_tseq_entry tseq_entry;
	struct work_struct proc_work;
	struct scoutfs_net_connection *conn;
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

static bool nh_is_response(struct scoutfs_net_header *nh)
{
	return !!(nh->flags & SCOUTFS_NET_FLAG_RESPONSE);
}

static bool nh_is_request(struct scoutfs_net_header *nh)
{
	return !nh_is_response(nh);
}

/*
 * We return dead requests so that the caller can stop searching other
 * lists for the dead request that we found.
 */
static struct message_send *search_list(struct scoutfs_net_connection *conn,
					struct list_head *list,
					u8 cmd, u64 id)
{
	struct message_send *msend;

	assert_spin_locked(&conn->lock);

	list_for_each_entry(msend, list, head) {
		if (nh_is_request(&msend->nh) && msend->nh.cmd == cmd &&
		    le64_to_cpu(msend->nh.id) == id)
			return msend;
	}

	return NULL;
}

/*
 * Find an active send request on the lists.  It's almost certainly
 * waiting on the resend queue but it could be actively being sent.
 */
static struct message_send *find_request(struct scoutfs_net_connection *conn,
					 u8 cmd, u64 id)
{
	struct message_send *msend;

	msend = search_list(conn, &conn->resend_queue, cmd, id) ?:
		search_list(conn, &conn->send_queue, cmd, id);
	if (msend && msend->dead)
		msend = NULL;
	return msend;
}

/*
 * Complete a send message by moving it to the send queue and marking it
 * to be freed.  It won't be visible to callers trying to find sends.
 */
static void complete_send(struct scoutfs_net_connection *conn,
			  struct message_send *msend)
{
	assert_spin_locked(&conn->lock);

	if (WARN_ON_ONCE(msend->dead) ||
	    WARN_ON_ONCE(list_empty(&msend->head)))
		return;

	msend->dead = 1;
	list_move(&msend->head, &conn->send_queue);
	queue_work(conn->workq, &conn->send_work);
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
			scoutfs_warn(sb, "host errno %d sent as EINVAL",
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

	if (!test_conn_fl(conn, shutting_down)) {
		clear_conn_fl(conn, established);
		set_conn_fl(conn, shutting_down);
		trace_scoutfs_conn_shutdown_queued(conn);
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
 *
 * If a non-zero rid is specified then the conn argument is a listening
 * connection and the connection to send the message down is found by
 * searching for the rid in its accepted connections.
 */
static int submit_send(struct super_block *sb,
		       struct scoutfs_net_connection *conn, u64 rid,
		       u8 cmd, u8 flags, u64 id, u8 net_err,
		       void *data, u16 data_len,
		       scoutfs_net_response_t resp_func, void *resp_data,
		       u64 *id_ret)
{
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *acc_conn;
	struct message_send *msend;
	u64 seq;

	if (WARN_ON_ONCE(cmd >= SCOUTFS_NET_CMD_UNKNOWN) ||
	    WARN_ON_ONCE(flags & SCOUTFS_NET_FLAGS_UNKNOWN) ||
	    WARN_ON_ONCE(net_err >= SCOUTFS_NET_ERR_UNKNOWN) ||
	    WARN_ON_ONCE(data_len > SCOUTFS_NET_MAX_DATA_LEN) ||
	    WARN_ON_ONCE(data_len && data == NULL) ||
	    WARN_ON_ONCE(net_err && (!(flags & SCOUTFS_NET_FLAG_RESPONSE))) ||
	    WARN_ON_ONCE(id == 0 && (flags & SCOUTFS_NET_FLAG_RESPONSE)))
		return -EINVAL;

	msend = kmalloc(offsetof(struct message_send,
				 nh.data[data_len]), GFP_NOFS);
	if (!msend)
		return -ENOMEM;

	spin_lock_nested(&conn->lock, CONN_LOCK_LISTENER);

	if (rid != 0) {
		list_for_each_entry(acc_conn, &conn->accepted_list,
				    accepted_head) {
			if (acc_conn->rid == rid) {
				spin_lock_nested(&acc_conn->lock,
						 CONN_LOCK_ACCEPTED);
				spin_unlock(&conn->lock);
				conn = acc_conn;
				rid = 0;
				break;
			}
		}
		if (rid != 0) {
			spin_unlock(&conn->lock);
			return -ENOTCONN;
		}
	}

	seq = conn->next_send_seq++;
	if (id == 0)
		id = conn->next_send_id++;

	msend->resp_func = resp_func;
	msend->resp_data = resp_data;
	msend->dead = 0;

	msend->nh.seq = cpu_to_le64(seq);
	msend->nh.recv_seq = 0;  /* set when sent, not when queued */
	msend->nh.id = cpu_to_le64(id);
	msend->nh.cmd = cmd;
	msend->nh.flags = flags;
	msend->nh.error = net_err;
	memset(msend->nh.__pad, 0, sizeof(msend->nh.__pad));
	msend->nh.data_len = cpu_to_le16(data_len);
	if (data_len)
		memcpy(msend->nh.data, data, data_len);

	if (test_conn_fl(conn, established) &&
	    (test_conn_fl(conn, valid_greeting) ||
	     cmd == SCOUTFS_NET_CMD_GREETING)) {
		list_add_tail(&msend->head, &conn->send_queue);
		queue_work(conn->workq, &conn->send_work);
	} else {
		list_add_tail(&msend->head, &conn->resend_queue);
	}

	if (id_ret)
		*id_ret = le64_to_cpu(msend->nh.id);

	scoutfs_tseq_add(&ninf->msg_tseq_tree, &msend->tseq_entry);

	spin_unlock(&conn->lock);

	return 0;
}

/*
 * Process an incoming request.  The greeting should ensure that the
 * sender won't send us unknown commands.  We return an error if we see
 * an unknown command because the greeting should agree on an understood
 * protocol.  The request function sends a response and returns an error
 * if they couldn't.
 */
static int process_request(struct scoutfs_net_connection *conn,
			   struct message_recv *mrecv)
{
	struct super_block *sb = conn->sb;
	scoutfs_net_request_t req_func;

	if (mrecv->nh.cmd < SCOUTFS_NET_CMD_UNKNOWN)
		req_func = conn->req_funcs[mrecv->nh.cmd];
	else
		req_func = NULL;

	if (req_func == NULL) {
		scoutfs_inc_counter(sb, net_unknown_request);
		return -EINVAL;
	}

	return req_func(sb, conn, mrecv->nh.cmd, le64_to_cpu(mrecv->nh.id),
			mrecv->nh.data, le16_to_cpu(mrecv->nh.data_len));
}

/*
 * An incoming response finds the queued request and calls its response
 * function.  The response function for a given request will only be
 * called once.  Requests can be canceled while a response is in flight.
 * It's not an error to receive a response to a request that no longer
 * exists.
 */
static int process_response(struct scoutfs_net_connection *conn,
			    struct message_recv *mrecv)
{
	struct super_block *sb = conn->sb;
	struct message_send *msend;
	scoutfs_net_response_t resp_func = NULL;
	void *resp_data;
	int ret = 0;

	spin_lock(&conn->lock);

	msend = find_request(conn, mrecv->nh.cmd, le64_to_cpu(mrecv->nh.id));
	if (msend) {
		resp_func = msend->resp_func;
		resp_data = msend->resp_data;
		complete_send(conn, msend);
	} else {
		scoutfs_inc_counter(sb, net_dropped_response);
	}

	spin_unlock(&conn->lock);

	if (resp_func)
		ret = resp_func(sb, conn, mrecv->nh.data,
				le16_to_cpu(mrecv->nh.data_len),
				net_err_to_host(mrecv->nh.error), resp_data);
	return ret;
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
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	int ret;

	trace_scoutfs_net_proc_work_enter(sb, 0, 0);

	if (nh_is_request(&mrecv->nh))
		ret = process_request(conn, mrecv);
	else
		ret = process_response(conn, mrecv);

	/* process_one_work explicitly allows freeing work in its func */
	scoutfs_tseq_del(&ninf->msg_tseq_tree, &mrecv->tseq_entry);
	kfree(mrecv);

	/* shut down the connection if processing returns fatal errors */
	if (ret)
		shutdown_conn(conn);

	trace_scoutfs_net_proc_work_exit(sb, 0, ret);
}

/*
 * Free live responses up to and including the seq by marking them dead
 * and moving them to the send queue to be freed.
 */
static int move_acked_responses(struct scoutfs_net_connection *conn,
				struct list_head *list, u64 seq)
{
	struct message_send *msend;
	struct message_send *tmp;
	int ret = 0;

	assert_spin_locked(&conn->lock);

	list_for_each_entry_safe(msend, tmp, list, head) {
		if (le64_to_cpu(msend->nh.seq) > seq)
			break;
		if (!nh_is_response(&msend->nh) || msend->dead)
			continue;

		msend->dead = 1;
		list_move(&msend->head, &conn->send_queue);
		ret = 1;
	}

	return ret;
}

/* acks are processed inline in the recv worker */
static void free_acked_responses(struct scoutfs_net_connection *conn, u64 seq)
{
	int moved;

	spin_lock(&conn->lock);

	moved = move_acked_responses(conn, &conn->send_queue, seq) +
		move_acked_responses(conn, &conn->resend_queue, seq);

	spin_unlock(&conn->lock);

	if (moved)
		queue_work(conn->workq, &conn->send_work);
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

static bool invalid_message(struct scoutfs_net_connection *conn,
			    struct scoutfs_net_header *nh)
{
	/* seq and id must be non-zero */
	if (nh->seq == 0 || nh->id == 0)
		return true;

	/* greeting should negotiate understood protocol */
	if (nh->cmd >= SCOUTFS_NET_CMD_UNKNOWN ||
	    (nh->flags & SCOUTFS_NET_FLAGS_UNKNOWN) ||
	    nh->error >= SCOUTFS_NET_ERR_UNKNOWN)
		return true;

	/* payloads have a limit */
	if (le16_to_cpu(nh->data_len) > SCOUTFS_NET_MAX_DATA_LEN)
		return true;

	/* only responses can carry errors */
	if (nh_is_request(nh) && nh->error != SCOUTFS_NET_ERR_NONE)
		return true;

	if (nh->cmd == SCOUTFS_NET_CMD_GREETING) {
		/* each endpoint can only receive one greeting per socket */
		if (test_conn_fl(conn, saw_greeting))
			return true;

		/* servers get greeting requests, clients get responses */
		if (!!conn->listening_conn != !!nh_is_request(nh))
			return true;
	}

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
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
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
		if (invalid_message(conn, &nh)) {
			scoutfs_inc_counter(sb, net_recv_invalid_message);
			ret = -EBADMSG;
			break;
		}

		trace_scoutfs_recv_clock_sync(nh.clock_sync_id);

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

		if (nh.cmd == SCOUTFS_NET_CMD_GREETING) {
			/* greetings are out of band, no seq mechanics */
			set_conn_fl(conn, saw_greeting);

		} else if (le64_to_cpu(nh.seq) <=
			   atomic64_read(&conn->recv_seq)) {
			/* drop any resent duplicated messages */
			scoutfs_inc_counter(sb, net_recv_dropped_duplicate);
			kfree(mrecv);
			continue;

		} else {
			/* record that we've received sender's seq */
			atomic64_set(&conn->recv_seq, le64_to_cpu(nh.seq));
			/* and free our responses that sender has received */
			free_acked_responses(conn, le64_to_cpu(nh.recv_seq));
		}

		scoutfs_tseq_add(&ninf->msg_tseq_tree, &mrecv->tseq_entry);

		/* synchronously process greeting before next recvmsg */
		if (nh.cmd == SCOUTFS_NET_CMD_GREETING)
			scoutfs_net_proc_worker(&mrecv->proc_work);
		else
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

static void free_msend(struct net_info *ninf, struct message_send *msend)
{
	list_del_init(&msend->head);
	scoutfs_tseq_del(&ninf->msg_tseq_tree, &msend->tseq_entry);
	kfree(msend);
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
 *
 * We set the current recv_seq on every outgoing frame as it represents
 * the current connection state, not the state back when each message
 * was first queued.
 */
static void scoutfs_net_send_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, send_work);
	struct super_block *sb = conn->sb;
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct message_send *msend;
	int ret = 0;
	int len;

	trace_scoutfs_net_send_work_enter(sb, 0, 0);

	spin_lock(&conn->lock);

	while ((msend = list_first_entry_or_null(&conn->send_queue,
						 struct message_send, head))) {

		if (msend->dead) {
			free_msend(ninf, msend);
			continue;
		}

		if ((msend->nh.cmd == SCOUTFS_NET_CMD_FAREWELL) &&
		    nh_is_response(&msend->nh)) {
			set_conn_fl(conn, saw_farewell);
		}

		msend->nh.recv_seq =
			cpu_to_le64(atomic64_read(&conn->recv_seq));

		spin_unlock(&conn->lock);

		len = nh_bytes(le16_to_cpu(msend->nh.data_len));

		scoutfs_inc_counter(sb, net_send_messages);
		scoutfs_add_counter(sb, net_send_bytes, len);
		trace_scoutfs_net_send_message(sb, &conn->sockname,
					       &conn->peername, &msend->nh);

		msend->nh.clock_sync_id = scoutfs_clock_sync_id();
		trace_scoutfs_send_clock_sync(msend->nh.clock_sync_id);

		ret = sendmsg_full(conn->sock, &msend->nh, len);

		spin_lock(&conn->lock);

		msend->nh.recv_seq = 0;

		if (ret)
			break;

		/* resend if it wasn't freed while we sent */
		if (!msend->dead)
			list_move_tail(&msend->head, &conn->resend_queue);
	}

	spin_unlock(&conn->lock);

	if (ret) {
		scoutfs_inc_counter(sb, net_send_error);
		shutdown_conn(conn);
	}

	trace_scoutfs_net_send_work_exit(sb, 0, ret);
}

/*
 * Listening conns try to destroy accepted conns.  Workqueues model
 * flushing work as acquiring a workqueue class lock so it thinks that
 * this is a deadlock because it doesn't know about our hierarchy of
 * workqueues.  The workqueue lockdep_map is private so we can't set a
 * subclass to differentiate between listening and accepted conn
 * workqueues.  Instead we queue final conn destruction off to a longer
 * lived specific workqueue that has a different class.
 */
static void scoutfs_net_destroy_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, destroy_work);
	struct super_block *sb = conn->sb;
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *listener;
	struct message_send *msend;
	struct message_send *tmp;

	trace_scoutfs_net_destroy_work_enter(sb, 0, 0);
	trace_scoutfs_conn_destroy_start(conn);

	WARN_ON_ONCE(conn->sock != NULL);
	WARN_ON_ONCE(!list_empty(&conn->accepted_list));

	/* tell callers that accepted connection finally done */
	if (conn->listening_conn && conn->notify_down)
		conn->notify_down(sb, conn, conn->info, conn->rid);

	/* free all messages, refactor and complete for forced unmount? */
	list_splice_init(&conn->resend_queue, &conn->send_queue);
	list_for_each_entry_safe(msend, tmp, &conn->send_queue, head) {
		free_msend(ninf, msend);
	}

	/* accepted sockets are removed from their listener's list */
	if (conn->listening_conn) {
		listener = conn->listening_conn;

		spin_lock(&listener->lock);
		list_del_init(&conn->accepted_head);
		if (list_empty(&listener->accepted_list))
			wake_up(&listener->waitq);
		spin_unlock(&listener->lock);
	}

	destroy_workqueue(conn->workq);
	scoutfs_tseq_del(&ninf->conn_tseq_tree, &conn->tseq_entry);
	kfree(conn->info);
	trace_scoutfs_conn_destroy_free(conn);
	kfree(conn);

	trace_scoutfs_net_destroy_work_exit(sb, 0, 0);
}

static void destroy_conn(struct scoutfs_net_connection *conn)
{
	struct net_info *ninf = SCOUTFS_SB(conn->sb)->net_info;

	queue_work(ninf->destroy_workq, &conn->destroy_work);
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
		acc_conn = scoutfs_net_alloc_conn(sb, conn->notify_up,
						  conn->notify_down,
						  conn->info_size,
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
		set_conn_fl(acc_conn, established);
		list_add_tail(&acc_conn->accepted_head, &conn->accepted_list);

		trace_scoutfs_conn_accept(acc_conn);

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

	trace_scoutfs_conn_connect_start(conn);

	ret = kernel_connect(sock, (struct sockaddr *)&conn->connect_sin,
			     sizeof(struct sockaddr_in), 0);
	if (ret)
		goto out;

	ret = sock_opts_and_names(conn, sock);
	if (ret)
		goto out;

	scoutfs_info(sb, "client connected "SIN_FMT" -> "SIN_FMT,
		     SIN_ARG(&conn->sockname),
		     SIN_ARG(&conn->peername));

	spin_lock(&conn->lock);

	/* clear greeting state for next negotiation */
	clear_conn_fl(conn, valid_greeting);
	set_conn_fl(conn, established);
	wake_up(&conn->waitq);

	trace_scoutfs_conn_connect_complete(conn);

	spin_unlock(&conn->lock);

	queue_work(conn->workq, &conn->recv_work);
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

/*
 * Safely shut down an active connection.  This can be triggered by
 * errors in workers or by an external call to free the connection.  The
 * shutting down flag ensures that this only executes once for each live
 * socket.
 */
static void scoutfs_net_shutdown_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, shutdown_work);
	struct super_block *sb = conn->sb;
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *listener;
	struct scoutfs_net_connection *acc_conn;
	struct message_send *msend;
	struct message_send *tmp;
	unsigned long delay;

	trace_scoutfs_net_shutdown_work_enter(sb, 0, 0);
	trace_scoutfs_conn_shutdown_start(conn);

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

	memset(&conn->peername, 0, sizeof(conn->peername));

	/* listening connections shut down all the connections they accepted */
	spin_lock_nested(&conn->lock, CONN_LOCK_LISTENER);
	list_for_each_entry(acc_conn, &conn->accepted_list, accepted_head) {
		spin_lock_nested(&acc_conn->lock, CONN_LOCK_ACCEPTED);
		shutdown_conn_locked(acc_conn);
		spin_unlock(&acc_conn->lock);
	}
	spin_unlock(&conn->lock);

	/* free any conns waiting for reconnection */
	cancel_delayed_work_sync(&conn->reconn_free_dwork);
	queue_delayed_work(conn->workq, &conn->reconn_free_dwork, 0);
	/* relies on delay 0 scheduling immediately so no timer to cancel */
	flush_delayed_work(&conn->reconn_free_dwork);

	/* and wait for accepted conn shutdown work to finish */
	wait_event(conn->waitq, empty_accepted_list(conn));

	spin_lock(&conn->lock);

	/* greetings aren't resent across sockets */
	list_splice_tail_init(&conn->send_queue, &conn->resend_queue);
	list_for_each_entry_safe(msend, tmp, &conn->resend_queue, head) {
		if (msend->nh.cmd == SCOUTFS_NET_CMD_GREETING)
			free_msend(ninf, msend);
	}

	clear_conn_fl(conn, saw_greeting);

	/* signal connect failure */
	memset(&conn->connect_sin, 0, sizeof(conn->connect_sin));
	wake_up(&conn->waitq);

	/* resolve racing with listener shutdown with locked shutting_down */
	if (conn->listening_conn &&
	    (test_conn_fl(conn->listening_conn, shutting_down) ||
	     test_conn_fl(conn, saw_farewell))) {

		/* free accepted sockets after farewell or listener shutdown */
		spin_unlock(&conn->lock);
		destroy_conn(conn);

	} else {

		if (conn->listening_conn) {
			/* server accepted sockets wait for reconnect */
			listener = conn->listening_conn;
			delay = msecs_to_jiffies(CLIENT_RECONNECT_TIMEOUT_MS);
			set_conn_fl(conn, reconn_wait);
			conn->reconn_deadline = jiffies + delay;
			queue_delayed_work(listener->workq,
					   &listener->reconn_free_dwork, delay);
		} else {
			/* clients and listeners can retry */
			clear_conn_fl(conn, shutting_down);
			if (conn->notify_down)
				conn->notify_down(sb, conn, conn->info,
						  conn->rid);
		}

		trace_scoutfs_conn_shutdown_complete(conn);
		spin_unlock(&conn->lock);
	}

	trace_scoutfs_net_shutdown_work_exit(sb, 0, 0);
}

/*
 * Free any connections that have been shutdown for too long without the
 * client reconnecting.  This runs in work on the listening connection.
 * It's racing with connection attempts searching for shutdown
 * connections to steal state from.  Shutdown cancels the work and waits
 * for it to finish.
 *
 * Connections are currently freed without the lock held so this walks
 * the entire list every time it frees a connection.  This is irritating
 * but timed out connections are rare and client counts are relatively
 * low given a cpu's ability to burn through the list.
 */
static void scoutfs_net_reconn_free_worker(struct work_struct *work)
{
	DEFINE_CONN_FROM_WORK(conn, work, reconn_free_dwork.work);
	struct super_block *sb = conn->sb;
	struct scoutfs_net_connection *acc;
	unsigned long now = jiffies;
	unsigned long deadline = 0;
	bool requeue = false;

	trace_scoutfs_net_reconn_free_work_enter(sb, 0, 0);

restart:
	spin_lock(&conn->lock);
	list_for_each_entry(acc, &conn->accepted_list, accepted_head) {

		if (test_conn_fl(acc, reconn_wait) &&
		    !test_conn_fl(acc, reconn_freeing) &&
		    (test_conn_fl(conn, shutting_down) ||
		     time_after_eq(now, acc->reconn_deadline))) {
			set_conn_fl(acc, reconn_freeing);
			spin_unlock(&conn->lock);
			if (!test_conn_fl(conn, shutting_down))
				scoutfs_info(sb, "client timed out "SIN_FMT" -> "SIN_FMT", can not reconnect",
					     SIN_ARG(&acc->sockname),
					     SIN_ARG(&acc->peername));
			destroy_conn(acc);
			goto restart;
		}

		/* calc delay of next work, can drift a bit */
		if (test_conn_fl(acc, reconn_wait) &&
		    !test_conn_fl(acc, reconn_freeing) &&
		    (!requeue || time_before(now, deadline))) {
			requeue = true;
			deadline = acc->reconn_deadline;
		}
	}
	spin_unlock(&conn->lock);

	if (requeue)
		queue_delayed_work(conn->workq, &conn->reconn_free_dwork,
				   deadline - now);

	trace_scoutfs_net_reconn_free_work_exit(sb, 0, 0);
}

/*
 * Accepted connections inherit the callbacks from their listening
 * connection.
 *
 * notify_up is called once a valid greeting is received.  rid is
 * non-zero on accepted sockets once they've seen a valid greeting.
 * Connected and listening connections have a rid of 0.
 *
 * notify_down is always called as connections are shut down.  It can be
 * called without notify_up ever being called.  The rid is only
 * non-zero for accepted connections.
 */
struct scoutfs_net_connection *
scoutfs_net_alloc_conn(struct super_block *sb,
		       scoutfs_net_notify_t notify_up,
		       scoutfs_net_notify_t notify_down, size_t info_size,
		       scoutfs_net_request_t *req_funcs, char *name_suffix)
{
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *conn;

	conn = kzalloc(sizeof(struct scoutfs_net_connection), GFP_NOFS);
	if (!conn)
		return NULL;

	conn->info = kzalloc(info_size, GFP_NOFS);
	if (!conn->info) {
		kfree(conn);
		return NULL;
	}

	conn->workq = alloc_workqueue("scoutfs_net_%s",
				      WQ_UNBOUND | WQ_NON_REENTRANT, 0,
				      name_suffix);
	if (!conn->workq) {
		kfree(conn->info);
		kfree(conn);
		return NULL;
	}

	conn->sb = sb;
	conn->notify_up = notify_up;
	conn->notify_down = notify_down;
	conn->info_size = info_size;
	conn->req_funcs = req_funcs;
	spin_lock_init(&conn->lock);
	init_waitqueue_head(&conn->waitq);
	conn->sockname.sin_family = AF_INET;
	conn->peername.sin_family = AF_INET;
	INIT_LIST_HEAD(&conn->accepted_head);
	INIT_LIST_HEAD(&conn->accepted_list);
	conn->next_send_seq = 1;
	conn->next_send_id = 1;
	atomic64_set(&conn->recv_seq, 0);
	INIT_LIST_HEAD(&conn->send_queue);
	INIT_LIST_HEAD(&conn->resend_queue);
	INIT_WORK(&conn->listen_work, scoutfs_net_listen_worker);
	INIT_WORK(&conn->connect_work, scoutfs_net_connect_worker);
	INIT_WORK(&conn->send_work, scoutfs_net_send_worker);
	INIT_WORK(&conn->recv_work, scoutfs_net_recv_worker);
	INIT_WORK(&conn->shutdown_work, scoutfs_net_shutdown_worker);
	INIT_WORK(&conn->destroy_work, scoutfs_net_destroy_worker);
	INIT_DELAYED_WORK(&conn->reconn_free_dwork,
			  scoutfs_net_reconn_free_worker);

	scoutfs_tseq_add(&ninf->conn_tseq_tree, &conn->tseq_entry);
	trace_scoutfs_conn_alloc(conn);

	return conn;
}

/*
 * Give the caller the client rid of the connection.  This used by rare
 * server processing callers who want to send async responses after
 * request processing has returned.  We didn't want the churn of
 * providing the requesting rid to all the request handlers, but we
 * probably should.
 */
u64 scoutfs_net_client_rid(struct scoutfs_net_connection *conn)
{
	return conn->rid;
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
	flush_work(&conn->destroy_work);
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
	int optval;
	int ret;

	/* caller state machine shouldn't let this happen */
	if (WARN_ON_ONCE(conn->sock))
		return -EINVAL;

	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret)
		goto out;

	optval = 1;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&optval, sizeof(optval));
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
 * Return once a connection attempt has completed either successfully
 * or in error.
 */
static bool connect_result(struct scoutfs_net_connection *conn, int *error)
{
	bool done = false;

	spin_lock(&conn->lock);
	if (test_conn_fl(conn, established)) {
		done = true;
		*error = 0;
	} else if (test_conn_fl(conn, shutting_down) ||
		   conn->connect_sin.sin_family == 0) {
		done = true;
		*error = -ESHUTDOWN;
	}
	trace_scoutfs_conn_connect_result(conn);
	spin_unlock(&conn->lock);

	return done;
}

/*
 * Connect to the given address.  An error is returned if the socket was
 * not connected before the given timeout.  The connection isn't fully
 * active until the connecting caller starts greeting negotiation by
 * sending the initial greeting request.
 *
 * The conn notify_down callback can be called as the connection is
 * shutdown before this returns.
 */
int scoutfs_net_connect(struct super_block *sb,
			struct scoutfs_net_connection *conn,
			struct sockaddr_in *sin, unsigned long timeout_ms)
{
	int error = 0;
	int ret;

	spin_lock(&conn->lock);
	conn->connect_sin = *sin;
	conn->connect_timeout_ms = timeout_ms;
	spin_unlock(&conn->lock);

	queue_work(conn->workq, &conn->connect_work);

	ret = wait_event_interruptible(conn->waitq,
				       connect_result(conn, &error));
	return ret ?: error;
}

static void set_valid_greeting(struct scoutfs_net_connection *conn)
{
	assert_spin_locked(&conn->lock);

	/* recv should have dropped invalid duplicate greeting messages */
	BUG_ON(test_conn_fl(conn, valid_greeting));

	set_conn_fl(conn, valid_greeting);
	list_splice_tail_init(&conn->resend_queue, &conn->send_queue);
	queue_work(conn->workq, &conn->send_work);
}

/*
 * The client has received a valid greeting from the server.  Send
 * can proceed and we might need to reset our recv state if we reconnected
 * to a new server.
 */
void scoutfs_net_client_greeting(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 bool new_server)
{
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct message_send *msend;
	struct message_send *tmp;

	/* only called on client connections :/ */
	BUG_ON(conn->listening_conn);

	spin_lock(&conn->lock);

	if (new_server) {
		atomic64_set(&conn->recv_seq, 0);
		list_for_each_entry_safe(msend, tmp, &conn->resend_queue, head){
			if (nh_is_response(&msend->nh))
				free_msend(ninf, msend);
		}
	}

	set_valid_greeting(conn);

	spin_unlock(&conn->lock);

	/* client up/down drives reconnect */
	if (conn->notify_up)
		conn->notify_up(sb, conn, conn->info, 0);
}

/*
 * The calling server has received a valid greeting from a client.  If
 * the client is reconnecting to us then we need to find its old
 * connection that held its state and transfer it to this connection
 * (connection and socket life cycles make this easier than migrating
 * the socket between the connections).
 *
 * The previous connection that holds the client's state might still be
 * in active use depending on network failure and work processing races.
 * We shut it down before migrating its message state.  We can be
 * processing greetings from multiple reconnecting sockets that are all
 * referring to the same original connection.  We use the increasing
 * greeting id to have the most recent connection attempt win.
 *
 * A node can be reconnecting to us for the first time.  It will notice
 * the new server term and take steps to recover.
 *
 * A client can be reconnecting to us after we've destroyed their state.
 * This is fatal for the client if they just took too long to reconnect.
 * But this can also happen if something disconnects the socket after
 * we've sent a farewell response before the client received it.  In
 * this case we let the client reconnect so we can resend the farewell
 * response and they can disconnect cleanly.
 *
 * At this point our connection is idle except for send submissions and
 * shutdown being queued.  Once we shut down a We completely own a We
 * have exclusive access to a previous conn once its shutdown and we set
 * _freeing.
 */
void scoutfs_net_server_greeting(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 u64 rid, u64 greeting_id,
				 bool reconnecting, bool first_contact,
				 bool farewell)
{
	struct scoutfs_net_connection *listener;
	struct scoutfs_net_connection *reconn;
	struct scoutfs_net_connection *acc;

	/* only called on accepted server connections :/ */
	BUG_ON(!conn->listening_conn);

	/* see if we have a previous conn for the client's sent rid */
	reconn = NULL;
	if (reconnecting) {
		listener = conn->listening_conn;
restart:
		spin_lock_nested(&listener->lock, CONN_LOCK_LISTENER);
		list_for_each_entry(acc, &listener->accepted_list,
				    accepted_head) {
			if (acc->rid != rid ||
			    acc->greeting_id >= greeting_id ||
			    test_conn_fl(acc, reconn_freeing))
				continue;

			if (!test_conn_fl(acc, reconn_wait)) {
				spin_lock_nested(&acc->lock,
						 CONN_LOCK_ACCEPTED);
				shutdown_conn_locked(acc);
				spin_unlock(&acc->lock);
				spin_unlock(&listener->lock);
				msleep(10); /* XXX might be freed :/ */
				goto restart;
			}

			reconn = acc;
			set_conn_fl(reconn, reconn_freeing);
			break;
		}
		spin_unlock(&listener->lock);
	}

	/* drop a connection if we can't find its necessary old conn */
	if (reconnecting && !reconn && !first_contact && !farewell) {
		shutdown_conn(conn);
		return;
	}

	/* migrate state from previous conn for this reconnecting rid */
	if (reconn) {
		spin_lock(&conn->lock);

		assign_conn_fl(conn, reconn, saw_farewell);
		conn->next_send_seq = reconn->next_send_seq;
		conn->next_send_id = reconn->next_send_id;
		atomic64_set(&conn->recv_seq, atomic64_read(&reconn->recv_seq));

		/* greeting response/ack will be on conn send queue */
		BUG_ON(!list_empty(&reconn->send_queue));
		BUG_ON(!list_empty(&conn->resend_queue));
		list_splice_init(&reconn->resend_queue, &conn->resend_queue);

		/* new conn info is unused, swap, old won't call down */
		swap(conn->info, reconn->info);
		reconn->notify_down = NULL;

		trace_scoutfs_conn_reconn_migrate(conn);
		spin_unlock(&conn->lock);

		/* we set _freeing */
		destroy_conn(reconn);
	}

	spin_lock(&conn->lock);

	conn->rid = rid;
	conn->greeting_id = greeting_id;
	set_valid_greeting(conn);

	spin_unlock(&conn->lock);

	/* only call notify_up the first time we see the rid */
	if (conn->notify_up && first_contact)
		conn->notify_up(sb, conn, conn->info, rid);
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
	return submit_send(sb, conn, 0, cmd, 0, 0, 0, arg, arg_len,
			   resp_func, resp_data, id_ret);
}

/*
 * Send a request to a specific rid that was accepted by this listening
 * connection.
 */
int scoutfs_net_submit_request_node(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    u64 rid, u8 cmd,
				    void *arg, u16 arg_len,
				    scoutfs_net_response_t resp_func,
				    void *resp_data, u64 *id_ret)
{
	return submit_send(sb, conn, rid, cmd, 0, 0, 0, arg, arg_len,
			   resp_func, resp_data, id_ret);
}

/*
 * Send a response.  Responses don't get callbacks and use the request's
 * id so caller's don't need to get an id in return.
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

	return submit_send(sb, conn, 0, cmd, SCOUTFS_NET_FLAG_RESPONSE, id,
			   net_err_from_host(sb, error), resp, resp_len,
			   NULL, NULL, NULL);
}

int scoutfs_net_response_node(struct super_block *sb,
			      struct scoutfs_net_connection *conn,
			      u64 rid, u8 cmd, u64 id, int error,
			      void *resp, u16 resp_len)
{
	if (error) {
		resp = NULL;
		resp_len = 0;
	}

	return submit_send(sb, conn, rid, cmd, SCOUTFS_NET_FLAG_RESPONSE,
			   id, net_err_from_host(sb, error), resp, resp_len,
			   NULL, NULL, NULL);
}

/*
 * The response function that was submitted with the request is not
 * called if the request is canceled here.
 */
void scoutfs_net_cancel_request(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id)
{
	struct message_send *msend;

	spin_lock(&conn->lock);
	msend = find_request(conn, cmd, id);
	if (msend)
		complete_send(conn, msend);
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

	seq_printf(m, "name "SIN_FMT" peer "SIN_FMT" rid %016llx greeting_id %llu vg %u est %u sd %u sg %u sf %u rw %u rf %u cto_ms rdl_j %lu %lu nss %llu rs %llu nsi %llu\n",
		   SIN_ARG(&conn->sockname), SIN_ARG(&conn->peername),
		   conn->rid, conn->greeting_id,
		   test_conn_fl(conn, valid_greeting),
		   test_conn_fl(conn, established),
		   test_conn_fl(conn, shutting_down),
		   test_conn_fl(conn, saw_greeting),
		   test_conn_fl(conn, saw_farewell),
		   test_conn_fl(conn, reconn_wait),
		   test_conn_fl(conn, reconn_freeing),
		   conn->connect_timeout_ms, conn->reconn_deadline,
		   conn->next_send_seq, (u64)atomic64_read(&conn->recv_seq),
		   conn->next_send_id);
}

/*
 * How's this for sneaky?!  We line up the structs so that the entries
 * and function pointers are at the same offsets.  recv's function
 * pointer value is known and can't be found in send's.
 */
static bool tseq_entry_is_recv(struct scoutfs_tseq_entry *ent)
{
	struct message_recv *mrecv =
		container_of(ent, struct message_recv, tseq_entry);

	BUILD_BUG_ON(offsetof(struct message_recv, tseq_entry) !=
		     offsetof(struct message_send, tseq_entry));
	BUILD_BUG_ON(offsetof(struct message_recv, proc_work.func) !=
		     offsetof(struct message_send, resp_func));

	return mrecv->proc_work.func == scoutfs_net_proc_worker;
}

static void net_tseq_show_msg(struct seq_file *m,
			      struct scoutfs_tseq_entry *ent)
{
	struct message_send *msend;
	struct message_recv *mrecv;

	if (tseq_entry_is_recv(ent)) {
		mrecv = container_of(ent, struct message_recv, tseq_entry);

		seq_printf(m, "recv "SNH_FMT"\n", SNH_ARG(&mrecv->nh));
	} else {
		msend = container_of(ent, struct message_send, tseq_entry);

		seq_printf(m, "send "SNH_FMT"\n", SNH_ARG(&msend->nh));
	}
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
	scoutfs_tseq_tree_init(&ninf->msg_tseq_tree, net_tseq_show_msg);

	ninf->shutdown_workq = alloc_workqueue("scoutfs_net_shutdown",
					       WQ_UNBOUND | WQ_NON_REENTRANT,
					       0);
	ninf->destroy_workq = alloc_workqueue("scoutfs_net_destroy",
					       WQ_UNBOUND | WQ_NON_REENTRANT,
					       0);
	if (!ninf->shutdown_workq || !ninf->destroy_workq) {
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

	ninf->msg_tseq_dentry = scoutfs_tseq_create("messages",
						    sbi->debug_root,
						    &ninf->msg_tseq_tree);
	if (!ninf->msg_tseq_dentry) {
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
		if (ninf->destroy_workq)
			destroy_workqueue(ninf->destroy_workq);
		debugfs_remove(ninf->conn_tseq_dentry);
		debugfs_remove(ninf->msg_tseq_dentry);
		kfree(ninf);
		sbi->net_info = NULL;
	}
}
