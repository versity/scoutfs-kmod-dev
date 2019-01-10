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
 * scoutfs networking delivers requests and responses between nodes.
 *
 * Nodes decide to be either a connecting client or a listening server.
 * Both set up a connection and specify the set of request commands they
 * can process.
 *
 * Requests are tracked on a connection and sent to its peer.  They're
 * resent down newly established sockets on a long lived connection.
 * Queued requests are removed as a response is processed or if the
 * request is canceled by the sender.
 *
 * Request processing sends a response down the socket that received a
 * connection.  Processing is stopped as a socket is shutdown so
 * responses are only send down sockets that received a request.
 *
 * Thus requests can be received multiple times as sockets are shutdown
 * and reconnected.  Responses are only processed once for a given
 * request.  It is up to request and response implementations to ensure
 * that duplicate requests are safely handled.
 *
 * It turns out that we have to deal with duplicate request processing
 * at the layer above networking anyway.  Request processing can make
 * persistent changes that are committed on the server before it
 * crashes.  The client then reconnects to before it crashes and the
 * client reconnects to a server who must detect that the persistent
 * work on behalf of the resent request has already been committed.  If
 * we have to deal with that duplicate processing we may as well
 * simplify networking by allowing it between reconnecting peers as
 * well.
 *
 * XXX:
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
	struct dentry *msg_tseq_dentry;
	struct scoutfs_tseq_tree msg_tseq_tree;
};

struct scoutfs_net_connection {
	struct super_block *sb;
	scoutfs_net_notify_t notify_up;
	scoutfs_net_notify_t notify_down;
	size_t info_size;
	scoutfs_net_request_t *req_funcs;

	spinlock_t lock;
	wait_queue_head_t waitq;

	unsigned long valid_greeting:1,	/* other commands can proceed */
		      established:1,	/* added sends queue send work */
		      shutting_down:1;	/* shutdown work has been queued */

	struct sockaddr_in connect_sin;
	unsigned long connect_timeout_ms;

	struct socket *sock;
	u64 node_id;			/* assigned during greeting */
	struct sockaddr_in sockname;
	struct sockaddr_in peername;

	struct list_head accepted_head;
	struct scoutfs_net_connection *listening_conn;
	struct list_head accepted_list;

	u64 next_send_id;
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

	u8 info[0] __aligned(sizeof(u64));
};

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
 *
 * If a non-zero node_id is specified then the conn argument is a listening
 * connection and the connection to send the message down is found by
 * searching for the node_id in its accepted connections.
 */
static int submit_send(struct super_block *sb,
		       struct scoutfs_net_connection *conn, u64 node_id,
		       u8 cmd, u8 flags, u64 id, u8 net_err,
		       void *data, u16 data_len,
		       scoutfs_net_response_t resp_func, void *resp_data,
		       u64 *id_ret)
{
	struct net_info *ninf = SCOUTFS_SB(sb)->net_info;
	struct scoutfs_net_connection *acc_conn;
	struct message_send *msend;

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

	if (node_id != 0) {
		list_for_each_entry(acc_conn, &conn->accepted_list,
				    accepted_head) {
			if (acc_conn->node_id == node_id) {
				spin_lock_nested(&acc_conn->lock,
						 CONN_LOCK_ACCEPTED);
				spin_unlock(&conn->lock);
				conn = acc_conn;
				node_id = 0;
				break;
			}
		}
		if (node_id != 0) {
			spin_unlock(&conn->lock);
			return -ENOTCONN;
		}
	}

	msend->resp_func = resp_func;
	msend->resp_data = resp_data;
	msend->dead = 0;

	if (id == 0)
		id = conn->next_send_id++;
	msend->nh.id = cpu_to_le64(id);
	msend->nh.cmd = cmd;
	msend->nh.flags = flags;
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

	scoutfs_tseq_add(&ninf->msg_tseq_tree, &msend->tseq_entry);

	spin_unlock(&conn->lock);

	return 0;
}

/*
 * Messages can flow once we receive and process a valid greeting from
 * our peer.
 *
 * At this point recv processing has queued the greeting response
 * message on the send queue.  Any request messages waiting to be resent
 * need to be added to the end of the send queue after the greeting
 * response.
 *
 * Update the conn's node_id so that servers can send to specific
 * clients.
 */
static void saw_valid_greeting(struct scoutfs_net_connection *conn, u64 node_id)
{
	struct super_block *sb = conn->sb;

	spin_lock(&conn->lock);

	conn->valid_greeting = 1;
	conn->node_id = node_id;
	list_splice_tail_init(&conn->resend_queue, &conn->send_queue);
	queue_work(conn->workq, &conn->send_work);

	spin_unlock(&conn->lock);

	if (conn->notify_up)
		conn->notify_up(sb, conn, conn->info, node_id);
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
	scoutfs_net_request_t req_func;
	struct scoutfs_net_greeting *gr;
	int ret;

	if (mrecv->nh.cmd < SCOUTFS_NET_CMD_UNKNOWN)
		req_func = conn->req_funcs[mrecv->nh.cmd];
	else
		req_func = NULL;

	if (req_func == NULL) {
		scoutfs_inc_counter(sb, net_unknown_request);
		return -EINVAL;
	}

	ret = req_func(sb, conn, mrecv->nh.cmd, le64_to_cpu(mrecv->nh.id),
		       mrecv->nh.data, le16_to_cpu(mrecv->nh.data_len));

	/*
	 * Greeting response updates our *request* node_id so that
	 * we can consume a new allocation without callbacks.  We're
	 * about to free the recv in the caller anyway.
	 */
	if (!conn->valid_greeting &&
	    mrecv->nh.cmd == SCOUTFS_NET_CMD_GREETING && ret == 0) {
		gr = (void *)mrecv->nh.data;
		saw_valid_greeting(conn, le64_to_cpu(gr->node_id));
	}

	return ret;
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

	if (!conn->valid_greeting &&
	    mrecv->nh.cmd == SCOUTFS_NET_CMD_GREETING && msend && ret == 0)
		saw_valid_greeting(conn, 0);

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

		scoutfs_tseq_add(&ninf->msg_tseq_tree, &mrecv->tseq_entry);
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

		/* active requests are resent, everything else is freed */
		if (nh_is_request(&msend->nh) && !msend->dead)
			list_move_tail(&msend->head, &conn->resend_queue);
		else
			msend->dead = 1;
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

	scoutfs_info(sb, "client connected "SIN_FMT" -> "SIN_FMT,
		     SIN_ARG(&conn->sockname),
		     SIN_ARG(&conn->peername));

	spin_lock(&conn->lock);

	/* clear greeting state for next negotiation */
	conn->valid_greeting = 0;
	conn->established = 1;
	wake_up(&conn->waitq);

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
	struct scoutfs_net_connection *acc_conn;
	struct message_send *msend;
	struct message_send *tmp;

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

	memset(&conn->peername, 0, sizeof(conn->peername));

	/* listening connections shut down all the connections they accepted */
	spin_lock_nested(&conn->lock, CONN_LOCK_LISTENER);
	list_for_each_entry(acc_conn, &conn->accepted_list, accepted_head) {
		spin_lock_nested(&acc_conn->lock, CONN_LOCK_ACCEPTED);
		shutdown_conn_locked(acc_conn);
		spin_unlock(&acc_conn->lock);
	}
	spin_unlock(&conn->lock);
	wait_event(conn->waitq, empty_accepted_list(conn));

	spin_lock(&conn->lock);

	/* resend any pending requests, drop responses or greetings */
	list_splice_tail_init(&conn->send_queue, &conn->resend_queue);
	list_for_each_entry_safe(msend, tmp, &conn->resend_queue, head) {
		if (nh_is_response(&msend->nh) ||
		    msend->nh.cmd == SCOUTFS_NET_CMD_GREETING)
			free_msend(ninf, msend);
	}

	/* signal connect failure */
	memset(&conn->connect_sin, 0, sizeof(conn->connect_sin));
	wake_up(&conn->waitq);
	spin_unlock(&conn->lock);

	/* tell the caller that the connection is down */
	if (conn->notify_down)
		conn->notify_down(sb, conn, conn->info, conn->node_id);

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

/*
 * Accepted connections inherit the callbacks from their listening
 * connection.
 *
 * notify_up is called once a valid greeting is received.  node_id is
 * non-zero on accepted sockets once they've seen a valid greeting.
 * Connected and listening connections have a node_id of 0.
 *
 * notify_down is always called as connections are shut down.  It can be
 * called without notify_up ever being called.  The node_id is only
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

	conn = kzalloc(offsetof(struct scoutfs_net_connection,
				info[info_size]), GFP_NOFS);
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
	conn->info_size = info_size;
	conn->req_funcs = req_funcs;
	spin_lock_init(&conn->lock);
	init_waitqueue_head(&conn->waitq);
	conn->sockname.sin_family = AF_INET;
	conn->peername.sin_family = AF_INET;
	INIT_LIST_HEAD(&conn->accepted_head);
	INIT_LIST_HEAD(&conn->accepted_list);
	conn->next_send_id = 1;
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
 * Give the caller the client node_id of the connection.  This used by
 * rare server processing callers who want to send async responses after
 * request processing has returned.  We didn't want to plumb the
 * requesting node_id into all the request handlers but that'd work too.
 */
u64 scoutfs_net_client_node_id(struct scoutfs_net_connection *conn)
{
	return conn->node_id;
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
 * Return once a connection attempt has completed either successfully
 * or in error.
 */
static bool connect_result(struct scoutfs_net_connection *conn, int *error)
{
	bool done = false;

	spin_lock(&conn->lock);
	if (conn->established) {
		done = true;
		*error = 0;
	} else if (conn->shutting_down || conn->connect_sin.sin_family == 0) {
		done = true;
		*error = -ESHUTDOWN;
	}
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
 * Send a request to a specific node_id that was accepted by this listening
 * connection.
 */
int scoutfs_net_submit_request_node(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    u64 node_id, u8 cmd,
				    void *arg, u16 arg_len,
				    scoutfs_net_response_t resp_func,
				    void *resp_data, u64 *id_ret)
{
	return submit_send(sb, conn, node_id, cmd, 0, 0, 0, arg, arg_len,
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
			      u64 node_id, u8 cmd, u64 id, int error,
			      void *resp, u16 resp_len)
{
	if (error) {
		resp = NULL;
		resp_len = 0;
	}

	return submit_send(sb, conn, node_id, cmd, SCOUTFS_NET_FLAG_RESPONSE,
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

	seq_printf(m, "name "SIN_FMT" peer "SIN_FMT" vg %u est %u sd %u cto_ms %lu nsi %llu\n",
		   SIN_ARG(&conn->sockname), SIN_ARG(&conn->peername),
		   conn->valid_greeting, conn->established,
		   conn->shutting_down, conn->connect_timeout_ms,
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
		debugfs_remove(ninf->conn_tseq_dentry);
		debugfs_remove(ninf->msg_tseq_dentry);
		kfree(ninf);
		sbi->net_info = NULL;
	}
}
