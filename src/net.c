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
#include <linux/sort.h>

#include "format.h"
#include "net.h"
#include "counters.h"
#include "inode.h"
#include "btree.h"
#include "manifest.h"
#include "bio.h"
#include "alloc.h"
#include "seg.h"
#include "compact.h"
#include "scoutfs_trace.h"
#include "msg.h"

/*
 * scoutfs mounts use a simple client-server model to send and process
 * requests to maintain consistency with lighter overhead than full
 * locking.
 *
 * All mounts try to establish themselves as a server.  They try to
 * acquire an exclusive lock that allows them to act as the server.
 * While they hold that lock they broadcast their listening address with
 * an address lock's lvb.  The server only accepts client connections,
 * processes requests, and sends replies.  It never sends requests to
 * clients.  The client is responsible for reliability and forward
 * progress.
 *
 * All mounts must connect to the server to function.  They sample the
 * address lock's lvb to find an address and try to connect to it.
 * Callers enqueue reqeust messages with a reply function.  The requests
 * are sent down each re-established connection to the server.  If the
 * client receives a reply it frees the request and calls the reply
 * function.
 *
 * All kernel socket calls are non-blocking and made from work functions
 * in a single threaded workqueue.  This makes it easy to stop all work
 * on the socket before shutting it down.
 *
 * XXX:
 *  - include mount id in the workqueue names?
 *  - set recv buf size to multiple of largest message size
 */

struct net_info {
	struct super_block *sb;

	/* protects lists and sock info pointers */
	struct mutex mutex;

	/* client connects and sends requests */
	struct delayed_work client_work;
	struct sock_info *connected_sinf;
	struct list_head to_send;
	u64 next_id;

	/* server listens and processes requests */
	struct delayed_work server_work;
	struct sock_info *listening_sinf;
	bool server_loaded;

	/* server commits metadata while processing requests */
	struct rw_semaphore commit_rwsem;
	struct llist_head commit_waiters;
	struct work_struct commit_work;

	/* server remembers the stable manifest root for clients */
	struct scoutfs_btree_root stable_manifest_root;

	/* level 0 segment addition waits for it to clear */ 
	wait_queue_head_t waitq;

	/* server tracks seq use */
	spinlock_t seq_lock;
	struct list_head pending_seqs;

	/* both track active sockets for destruction */
	struct list_head active_socks;

	/* non-blocking sock work is serialized, one at a time */
	struct workqueue_struct *sock_wq;
	/* processing is unlimited and concurrent but each is non-reentrant */
	struct workqueue_struct *proc_wq;
};

#define DECLARE_NET_INFO(sb, name) \
	struct net_info *name = SCOUTFS_SB(sb)->net_info

typedef int (*reply_func_t)(struct super_block *sb, void *recv, int bytes,
			    void *arg);

/*
 * Send buffers are allocated either by clients who send requests or by
 * the server who sends replies.  Request sends are freed when they get
 * a reply and reply sends are freed either after they're sent or when
 * their accepted client socket is shut down.
 */
struct send_buf {
	struct list_head head;
	reply_func_t func;
	void *arg;
	struct scoutfs_net_header nh[0];
};

/*
 * Receive bufs hold messages from the socket while they're being
 * processed.  They have embedded work so we can have easy concurrent
 * processing.  Their processing can block for IO.  Their sending socket
 * can be torn down during their processing in which case no reply is
 * sent.
 */
struct recv_buf {
	struct net_info *nti;
	struct sock_info *sinf;
	struct list_head head;
	struct work_struct proc_work;
	struct scoutfs_net_header nh[0];
};

struct sock_info {
	struct super_block *sb;
	struct list_head head;
	bool shutting_down;

	unsigned send_pos;
	struct list_head to_send;
	struct list_head have_sent;
	struct list_head active_rbufs;

	struct scoutfs_lock *listen_lck;
	struct scoutfs_inet_addr addr;

	struct work_struct listen_work;
	struct work_struct accept_work;
	struct work_struct connect_work;
	struct work_struct send_work;
	struct work_struct recv_work;
	struct work_struct shutdown_work;

	struct socket *sock;
};

/*
 * XXX instead of magic keys in the main fs resource we could have
 * another resource that contains the server locks.
 */
static u8 listen_type = SCOUTFS_NET_LISTEN_TYPE;
static struct scoutfs_key_buf listen_key;
static u8 addr_type = SCOUTFS_NET_ADDR_TYPE;
static struct scoutfs_key_buf addr_key;

static int send_msg(struct socket *sock, void *buf, unsigned len)
{
	struct kvec kvec = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = {
		.msg_iov = (struct iovec *)&kvec,
		.msg_iovlen = 1,
		.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT,
	};

	return kernel_sendmsg(sock, &msg, &kvec, 1, len);
}

static int recv_msg(struct socket *sock, void *buf, unsigned len, int flags)
{
	struct kvec kvec = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = {
		.msg_iov = (struct iovec *)&kvec,
		.msg_iovlen = 1,
		.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT | flags,
	};

	return kernel_recvmsg(sock, &msg, &kvec, 1, len, msg.msg_flags);
}

/*
 * Don't queue work on the socket if it's shutting down so that the
 * shutdown work knows it can free the socket without work pending.
 */
static void queue_sock_work(struct sock_info *sinf, struct work_struct *work)
{
	DECLARE_NET_INFO(sinf->sb, nti);

	if (!sinf->shutting_down)
		queue_work(nti->sock_wq, work);
}

/*
 * This non-blocking work consumes the send queue in the socket info as
 * messages are sent out.  If the messages have a reply function then
 * they're requests that are resent until we receive a reply.  If they
 * don't then they're one-off replies that we free once they're sent.
 */
static void scoutfs_net_send_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      send_work);
	DECLARE_NET_INFO(sinf->sb, nti);
	struct send_buf *sbuf;
	struct send_buf *pos;
	char *buf;
	int total;
	int len;
	int ret = 0;

	mutex_lock(&nti->mutex);

	list_for_each_entry_safe(sbuf, pos, &sinf->to_send, head) {
		total = sizeof(struct scoutfs_net_header) +
		        le16_to_cpu(sbuf->nh->data_len);

		buf = (char *)sbuf->nh + sinf->send_pos;
		len = total - sinf->send_pos;

		ret = send_msg(sinf->sock, buf, len);
		trace_printk("sinf %p sock %p send len %d ret %d\n",
			     sinf, sinf->sock, len, ret);
		if (ret < 0) {
			if (ret == -EAGAIN)
				ret = 0;
			break;
		}
		if (ret == 0 || ret > len) {
			ret = -EINVAL;
			break;
		}

		sinf->send_pos += ret;

		if (sinf->send_pos == total) {
			sinf->send_pos = 0;
			list_del_init(&sbuf->head);

			if (sbuf->func)
				list_add_tail(&sbuf->head, &sinf->have_sent);
			else
				kfree(sbuf);
		}
	}

	if (ret < 0) {
		trace_printk("ret %d\n", ret);
		queue_sock_work(sinf, &sinf->shutdown_work);
	}

	mutex_unlock(&nti->mutex);
}

struct commit_waiter {
	struct completion comp;
	struct llist_node node;
	int ret;
};

/*
 * This is called while still holding the rwsem that prevents commits so
 * that the caller can be sure to be woken by the next commit after they
 * queue and release the lock.
 *
 * This could queue delayed work but we're first trying to have batching
 * work by having concurrent modification line up behind a commit in
 * flight.  Once the commit finishes it'll unlock and hopefully everyone
 * will race to make their changes and they'll all be applied by the
 * next commit after that.
 */
static void queue_commit_work(struct net_info *nti, struct commit_waiter *cw)
{
	lockdep_assert_held(&nti->commit_rwsem);

	cw->ret = 0;
	init_completion(&cw->comp);
	llist_add(&cw->node, &nti->commit_waiters);
	queue_work(nti->proc_wq, &nti->commit_work);
}

static int wait_for_commit(struct commit_waiter *cw)
{
	wait_for_completion(&cw->comp);
	return cw->ret;
}

/*
 * A core function of request processing is to modify the manifest and
 * allocator.  Often the processing needs to make the modifications
 * persistent before replying.  We'd like to batch these commits as much
 * as is reasonable so that we don't degrade to a few IO round trips per
 * request.
 *
 * Getting that batching right is bound up in the concurrency of request
 * processing so a clear way to implement the batched commits is to
 * implement commits with work funcs like the processing.  This commit
 * work is queued on the non-reentrant proc_wq so there will only ever
 * be one commit executing at a time.
 *
 * Processing paths acquire the rwsem for reading while they're making
 * multiple dependent changes.  When they're done and want it persistent
 * they add themselves to the list of waiters and queue the commit work.
 * This work runs, acquires the lock to exclude other writers, and
 * performs the commit.  Readers can run concurrently with these
 * commits.
 */
static void scoutfs_net_commit_func(struct work_struct *work)
{
	struct net_info *nti = container_of(work, struct net_info, commit_work);
	struct super_block *sb = nti->sb;
	struct commit_waiter *cw;
	struct commit_waiter *pos;
	struct llist_node *node;
	int ret;

	down_write(&nti->commit_rwsem);

	if (scoutfs_btree_has_dirty(sb)) {
		ret = scoutfs_alloc_apply_pending(sb) ?:
		      scoutfs_btree_write_dirty(sb) ?:
		      scoutfs_write_dirty_super(sb);

		/* we'd need to loop or something */
		BUG_ON(ret);

		scoutfs_btree_write_complete(sb);

		nti->stable_manifest_root = SCOUTFS_SB(sb)->super.manifest.root;
		scoutfs_advance_dirty_super(sb);
	} else {
		ret = 0;
	}

	node = llist_del_all(&nti->commit_waiters);

	/* waiters always wait on completion, cw could be free after complete */
	llist_for_each_entry_safe(cw, pos, node, node) {
		cw->ret = ret;
		complete(&cw->comp);
	}

	up_write(&nti->commit_rwsem);
}

static struct send_buf *alloc_sbuf(unsigned data_len)
{
	unsigned len = offsetof(struct send_buf, nh[0].data[data_len]);
	struct send_buf *sbuf;

	sbuf = kmalloc(len, GFP_NOFS);
	if (sbuf) {
		INIT_LIST_HEAD(&sbuf->head);
		sbuf->nh->data_len = cpu_to_le16(data_len);
	}

	return sbuf;
}

static struct send_buf *process_bulk_alloc(struct super_block *sb,void *req,
					   int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_net_segnos *ns;
	struct commit_waiter cw;
	struct send_buf *sbuf;
	u64 segno;
	int ret;
	int i;

	if (req_len != 0)
		return ERR_PTR(-EINVAL);

	sbuf = alloc_sbuf(offsetof(struct scoutfs_net_segnos,
				   segnos[SCOUTFS_BULK_ALLOC_COUNT]));
	if (!sbuf)
		return ERR_PTR(-ENOMEM);

	ns = (void *)sbuf->nh->data;
	ns->nr = cpu_to_le16(SCOUTFS_BULK_ALLOC_COUNT);

	down_read(&nti->commit_rwsem);

	for (i = 0; i < SCOUTFS_BULK_ALLOC_COUNT; i++) {
		ret = scoutfs_alloc_segno(sb, &segno);
		if (ret) {
			while (i-- > 0)
				scoutfs_alloc_free(sb,
					le64_to_cpu(ns->segnos[i]));
			break;
		}

		ns->segnos[i] = cpu_to_le64(segno);
	}


	if (ret == 0)
		queue_commit_work(nti, &cw);
	up_read(&nti->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(&cw);

	if (ret)
		sbuf->nh->status = SCOUTFS_NET_STATUS_ERROR;
	else
		sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;

	return sbuf;
}

static void init_net_ment_keys(struct scoutfs_net_manifest_entry *net_ment,
			       struct scoutfs_key_buf *first,
			       struct scoutfs_key_buf *last)
{
	scoutfs_key_init(first, net_ment->keys,
			 le16_to_cpu(net_ment->first_key_len));
	scoutfs_key_init(last, net_ment->keys +
			 le16_to_cpu(net_ment->first_key_len),
			 le16_to_cpu(net_ment->last_key_len));
}

/*
 * Allocate a contiguous manifest entry for communication over the network.
 */
static struct scoutfs_net_manifest_entry *
alloc_net_ment(struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_net_manifest_entry *net_ment;
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	net_ment = kmalloc(offsetof(struct scoutfs_net_manifest_entry,
				    keys[ment->first.key_len +
					 ment->last.key_len]), GFP_NOFS);
	if (!net_ment)
		return NULL;

	net_ment->segno = cpu_to_le64(ment->segno);
	net_ment->seq = cpu_to_le64(ment->seq);
	net_ment->first_key_len = cpu_to_le16(ment->first.key_len);
	net_ment->last_key_len = cpu_to_le16(ment->last.key_len);
	net_ment->level = ment->level;

	init_net_ment_keys(net_ment, &first, &last);
	scoutfs_key_copy(&first, &ment->first);
	scoutfs_key_copy(&last, &ment->last);

	return net_ment;
}

/* point a native manifest entry at a contiguous net manifest */
static void init_ment_net_ment(struct scoutfs_manifest_entry *ment,
			       struct scoutfs_net_manifest_entry *net_ment)
{
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	init_net_ment_keys(net_ment, &first, &last);
	scoutfs_key_clone(&ment->first, &first);
	scoutfs_key_clone(&ment->last, &last);

	ment->segno = le64_to_cpu(net_ment->segno);
	ment->seq = le64_to_cpu(net_ment->seq);
	ment->level = net_ment->level;
}

static unsigned net_ment_bytes(struct scoutfs_net_manifest_entry *net_ment)
{
	return offsetof(struct scoutfs_net_manifest_entry,
			keys[le16_to_cpu(net_ment->first_key_len) +
			     le16_to_cpu(net_ment->last_key_len)]);
}

/*
 * This is new segments arriving.  It needs to wait for level 0 to be
 * free.  It has relatively little visibility into the manifest, though.
 * We don't want it to block holding commits because that'll stop
 * manifest updates from emptying level 0.
 *
 * Maybe the easiest way is to protect the level counts with a seqlock,
 * or whatever.
 */

/*
 * The sender has written their level 0 segment and has given us its
 * details.  We wait for there to be room in level 0 before adding it.
 */
static struct send_buf *process_record_segment(struct super_block *sb,
					       void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_manifest_entry ment;
	struct scoutfs_net_manifest_entry *net_ment;
	struct commit_waiter cw;
	struct send_buf *sbuf;
	int ret;

	if (req_len < sizeof(struct scoutfs_net_manifest_entry)) {
		sbuf = ERR_PTR(-EINVAL);
		goto out;
	}

	net_ment = req;

	if (req_len != net_ment_bytes(net_ment)) {
		sbuf = ERR_PTR(-EINVAL);
		goto out;
	}

retry:
	down_read(&nti->commit_rwsem);
	scoutfs_manifest_lock(sb);

	if (scoutfs_manifest_level0_full(sb)) {
		scoutfs_manifest_unlock(sb);
		up_read(&nti->commit_rwsem);
		/* XXX waits indefinitely?  io errors? */
		wait_event(nti->waitq, !scoutfs_manifest_level0_full(sb));
		goto retry;
	}

	init_ment_net_ment(&ment, net_ment);

	ret = scoutfs_manifest_add(sb, &ment);
	scoutfs_manifest_unlock(sb);

	if (ret == 0)
		queue_commit_work(nti, &cw);
	up_read(&nti->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(&cw);

	scoutfs_compact_kick(sb);

	sbuf = alloc_sbuf(0);
	if (!sbuf) {
		sbuf = ERR_PTR(-ENOMEM);
		goto out;
	}

	if (ret)
		sbuf->nh->status = SCOUTFS_NET_STATUS_ERROR;
	else
		sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;
out:
	return sbuf;
}

static struct send_buf *process_alloc_segno(struct super_block *sb,
					    void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	__le64 * __packed lesegno;
	struct commit_waiter cw;
	struct send_buf *sbuf;
	u64 segno;
	int ret;

	if (req_len != 0) {
		sbuf = ERR_PTR(-EINVAL);
		goto out;
	}

	down_read(&nti->commit_rwsem);

	ret = scoutfs_alloc_segno(sb, &segno);
	if (ret == 0)
		queue_commit_work(nti, &cw);

	up_read(&nti->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(&cw);

	sbuf = alloc_sbuf(sizeof(__le64));
	if (!sbuf) {
		sbuf = ERR_PTR(-ENOMEM);
		goto out;
	}

	if (ret) {
		sbuf->nh->status = SCOUTFS_NET_STATUS_ERROR;
	} else {
		lesegno = (void *)sbuf->nh->data;
		*lesegno = cpu_to_le64(segno);
		sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;
	}

out:
	return sbuf;
}

/*
 * XXX should this call into inodes?  not sure about the layering here.
 */
static struct send_buf *process_alloc_inodes(struct super_block *sb,
					     void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_inode_alloc *ial;
	struct commit_waiter cw;
	struct send_buf *sbuf;
	int ret;
	u64 ino;
	u64 nr;

	if (req_len != 0)
		return ERR_PTR(-EINVAL);

	sbuf = alloc_sbuf(sizeof(struct scoutfs_net_inode_alloc));
	if (!sbuf)
		return ERR_PTR(-ENOMEM);

	down_read(&nti->commit_rwsem);

	spin_lock(&sbi->next_ino_lock);
	ino = le64_to_cpu(super->next_ino);
	nr = min(100000ULL, ~0ULL - ino);
	le64_add_cpu(&super->next_ino, nr);
	spin_unlock(&sbi->next_ino_lock);

	queue_commit_work(nti, &cw);
	up_read(&nti->commit_rwsem);

	ret = wait_for_commit(&cw);

	ial = (void *)sbuf->nh->data;
	ial->ino = cpu_to_le64(ino);
	ial->nr = cpu_to_le64(nr);

	if (ret < 0)
		sbuf->nh->status = SCOUTFS_NET_STATUS_ERROR;
	else
		sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;

	return sbuf;
}

struct pending_seq {
	struct list_head head;
	u64 seq;
};

/*
 * Give the client the next seq for it to use in items in its
 * transaction.  They tell us the seq they just used so we can remove it
 * from pending tracking and possibly include it in get_last_seq
 * replies.
 *
 * The list walk is O(clients) and the message processing rate goes from
 * every committed segment to every sync deadline interval.
 *
 * XXX The pending seq tracking should be persistent so that it survives
 * server failover.
 */
static struct send_buf *process_advance_seq(struct super_block *sb,
					    void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *next_ps;
	struct pending_seq *ps;
	struct commit_waiter cw;
	__le64 * __packed prev;
	__le64 * __packed next;
	struct send_buf *sbuf;
	int ret;

	if (req_len != sizeof(__le64))
		return ERR_PTR(-EINVAL);

	prev = req;

	sbuf = alloc_sbuf(sizeof(__le64));
	if (!sbuf)
		return ERR_PTR(-ENOMEM);

	next = (void *)sbuf->nh->data;

	next_ps = kmalloc(sizeof(struct pending_seq), GFP_NOFS);
	if (!next_ps) {
		ret = -ENOMEM;
		goto out;
	}

	down_read(&nti->commit_rwsem);

	spin_lock(&nti->seq_lock);

	list_for_each_entry(ps, &nti->pending_seqs, head) {
		if (ps->seq == le64_to_cpu(*prev)) {
			list_del_init(&ps->head);
			kfree(ps);
			break;
		}
	}

	*next = super->next_seq;
	le64_add_cpu(&super->next_seq, 1);

	trace_printk("prev %llu next %llu, super next_seq %llu\n",
		     le64_to_cpup(prev), le64_to_cpup(next),
		     le64_to_cpu(super->next_seq));

	next_ps->seq = le64_to_cpup(next);
	list_add_tail(&next_ps->head, &nti->pending_seqs);

	spin_unlock(&nti->seq_lock);

	queue_commit_work(nti, &cw);
	up_read(&nti->commit_rwsem);

	ret = wait_for_commit(&cw);
out:
	if (ret < 0)
		sbuf->nh->status = SCOUTFS_NET_STATUS_ERROR;
	else
		sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;

	return sbuf;
}

/*
 * Give the client the last seq that is stable before the lowest seq
 * that is still dirty out at a client.
 */
static struct send_buf *process_get_last_seq(struct super_block *sb,
					     void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *ps;
	__le64 * __packed last;
	struct send_buf *sbuf;

	if (req_len != 0)
		return ERR_PTR(-EINVAL);

	sbuf = alloc_sbuf(sizeof(__le64));
	if (!sbuf)
		return ERR_PTR(-ENOMEM);

	last = (void *)sbuf->nh->data;

	spin_lock(&nti->seq_lock);
	ps = list_first_entry_or_null(&nti->pending_seqs,
				      struct pending_seq, head);
	if (ps) {
		*last = cpu_to_le64(ps->seq - 1);
	} else {
		*last = super->next_seq;
		le64_add_cpu(last, -1ULL);
	}
	spin_unlock(&nti->seq_lock);

	trace_printk("last %llu\n", le64_to_cpup(last));

	sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;

	return sbuf;
}

static struct send_buf *process_get_manifest_root(struct super_block *sb,
						  void *req, int req_len)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_btree_root *root;
	struct send_buf *sbuf;

	if (req_len != 0)
		return ERR_PTR(-EINVAL);

	sbuf = alloc_sbuf(sizeof(struct scoutfs_btree_root));
	if (!sbuf)
		return ERR_PTR(-ENOMEM);

	root = (void *)sbuf->nh->data;

	scoutfs_manifest_lock(sb);
	memcpy(root, &nti->stable_manifest_root,
	       sizeof(struct scoutfs_btree_root));
	scoutfs_manifest_unlock(sb);

	sbuf->nh->status = SCOUTFS_NET_STATUS_SUCCESS;

	return sbuf;
}

typedef struct send_buf *(*proc_func_t)(struct super_block *sb, void *req,
				        int req_len);

static proc_func_t type_proc_func(u8 type)
{
	static proc_func_t funcs[] = {
		[SCOUTFS_NET_ALLOC_INODES] = process_alloc_inodes,
		[SCOUTFS_NET_ALLOC_SEGNO] = process_alloc_segno,
		[SCOUTFS_NET_RECORD_SEGMENT] = process_record_segment,
		[SCOUTFS_NET_BULK_ALLOC] = process_bulk_alloc,
		[SCOUTFS_NET_ADVANCE_SEQ] = process_advance_seq,
		[SCOUTFS_NET_GET_LAST_SEQ] = process_get_last_seq,
		[SCOUTFS_NET_GET_MANIFEST_ROOT] = process_get_manifest_root,
	};

	return type < SCOUTFS_NET_UNKNOWN ? funcs[type] : NULL;
}

/*
 * Process an incoming request and queue its reply to send if the socket
 * is still open by the time we have the reply.
 */
static int process_request(struct net_info *nti, struct recv_buf *rbuf)
{
	struct super_block *sb = nti->sb;
	struct send_buf *sbuf;
	proc_func_t proc;
	unsigned data_len;

	data_len = le16_to_cpu(rbuf->nh->data_len);
	proc = type_proc_func(rbuf->nh->type);
	if (proc)
		sbuf = proc(sb, (void *)rbuf->nh->data, data_len);
	else
		sbuf = ERR_PTR(-EINVAL);
	if (IS_ERR(sbuf))
		return PTR_ERR(sbuf);

	/* processing sets data_len and status */
	sbuf->func = NULL;
	sbuf->nh->id = rbuf->nh->id;
	sbuf->nh->type = rbuf->nh->type;

	mutex_lock(&nti->mutex);
	if (rbuf->sinf) {
		list_add(&sbuf->head, &rbuf->sinf->to_send);
		queue_sock_work(rbuf->sinf, &rbuf->sinf->send_work);
		sbuf = NULL;
	}
	mutex_unlock(&nti->mutex);

	kfree(sbuf);

	return 0;
}

/*
 * The server only sends replies down the socket on which it receives
 * the request.  If we receive a reply we must have sent the request
 * down the socket and the send buf will be found on the have_sent list.
 */
static int process_reply(struct net_info *nti, struct recv_buf *rbuf)
{
	struct super_block *sb = nti->sb;
	reply_func_t func = NULL;
	struct send_buf *sbuf;
	void *arg;
	int ret;

	mutex_lock(&nti->mutex);

	if (rbuf->sinf) {
		list_for_each_entry(sbuf, &rbuf->sinf->have_sent, head) {
			if (sbuf->nh->id == rbuf->nh->id) {
				list_del_init(&sbuf->head);
				func = sbuf->func;
				arg = sbuf->arg;
				kfree(sbuf);
				sbuf = NULL;
				break;
			}
		}
	}

	mutex_unlock(&nti->mutex);

	if (func == NULL)
		return 0;

	if (rbuf->nh->status == SCOUTFS_NET_STATUS_SUCCESS)
		ret = le16_to_cpu(rbuf->nh->data_len);
	else
		ret = -EIO;

	return func(sb, rbuf->nh->data, ret, arg);
}

static void destroy_server_state(struct super_block *sb)
{
	DECLARE_NET_INFO(sb, nti);
	struct pending_seq *ps;
	struct pending_seq *tmp;

	scoutfs_compact_destroy(sb);
	scoutfs_alloc_destroy(sb);
	scoutfs_manifest_destroy(sb);
	scoutfs_btree_destroy(sb);

	/* XXX these should be persistent and reclaimed during recovery */
	list_for_each_entry_safe(ps, tmp, &nti->pending_seqs, head) {
		list_del_init(&ps->head);
		kfree(ps);
	}
}

/*
 * Process each received message in its own non-reentrant work so we get
 * concurrent request processing.
 */
static void scoutfs_net_proc_func(struct work_struct *work)
{
	struct recv_buf *rbuf = container_of(work, struct recv_buf, proc_work);
	struct net_info *nti = rbuf->nti;
	struct super_block *sb = nti->sb;
	int ret = 0;

	/*
	 * This is the first blocking context we have once all the
	 * server locking and networking is set up so we bring up the
	 * rest of the server state the first time we get here.
	 */
	while (!nti->server_loaded) {
		mutex_lock(&nti->mutex);
		if (!nti->server_loaded) {
			ret = scoutfs_read_supers(sb, &SCOUTFS_SB(sb)->super) ?:
			      scoutfs_btree_setup(sb) ?:
			      scoutfs_manifest_setup(sb) ?:
			      scoutfs_alloc_setup(sb) ?:
			      scoutfs_compact_setup(sb);
			if (ret == 0) {
				scoutfs_advance_dirty_super(sb);
				nti->server_loaded = true;
				nti->stable_manifest_root =
					SCOUTFS_SB(sb)->super.manifest.root;
			} else {
				destroy_server_state(sb);
			}
		}
		mutex_unlock(&nti->mutex);
		if (ret) {
			trace_printk("server setup failed %d\n", ret);
			queue_sock_work(rbuf->sinf, &rbuf->sinf->shutdown_work);
			return;
		}
	}

	if (rbuf->nh->status == SCOUTFS_NET_STATUS_REQUEST)
		ret = process_request(nti, rbuf);
	else
		ret = process_reply(nti, rbuf);

	if (ret)
		trace_printk("type %u id %llu status %u ret %d\n",
			     rbuf->nh->type, le64_to_cpu(rbuf->nh->id),
			     rbuf->nh->status, ret);

	mutex_lock(&nti->mutex);

	if (ret < 0 && rbuf->sinf)
		queue_sock_work(rbuf->sinf, &rbuf->sinf->shutdown_work);

	if (!list_empty(&rbuf->head))
		list_del_init(&rbuf->head);

	mutex_unlock(&nti->mutex);

	kfree(rbuf);
}

/*
 * only accepted (not listening or connected) sockets receive requests
 * and only connected sockets receive replies.  This is running in the
 * single threaded socket workqueue so it isn't racing with the shutdown
 * work that would null the sinf pointer if it matches this sinf.
 */
static bool inappropriate_message(struct net_info *nti, struct sock_info *sinf,
				  struct recv_buf *rbuf)
{
	if (rbuf->nh->status == SCOUTFS_NET_STATUS_REQUEST &&
	    (sinf == nti->listening_sinf || sinf == nti->connected_sinf))
		return true;

	if (rbuf->nh->status != SCOUTFS_NET_STATUS_REQUEST &&
	    sinf != nti->connected_sinf)
		return true;

	return false;
}

/*
 * Parse an incoming message on a socket.  We peek at the socket buffer
 * until it has the whole message.  Then we queue request or reply
 * processing work and shut down the socket if anything weird happens.
 */
static void scoutfs_net_recv_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      recv_work);
	DECLARE_NET_INFO(sinf->sb, nti);
	struct scoutfs_net_header nh;
	struct recv_buf *rbuf;
	int len;
	int inq;
	int ret;

	for (;;) {
		/* peek to see data_len in the header */
		ret = recv_msg(sinf->sock, &nh, sizeof(nh), MSG_PEEK);
		trace_printk("sinf %p sock %p peek ret %d\n",
			     sinf, sinf->sock, ret);
		if (ret != sizeof(nh)) {
			if (ret > 0 || ret == -EAGAIN)
				ret = 0;
			else if (ret == 0)
				ret = -EIO;
			break;
		}

		/* XXX verify data_len isn't insane */

		len = sizeof(struct scoutfs_net_header) +
		      le16_to_cpu(nh.data_len);

		/* XXX rx buf has to be > max packet len */
		ret = kernel_sock_ioctl(sinf->sock, SIOCINQ,
				        (unsigned long)&inq);
		trace_printk("sinf %p sock %p ioctl ret %d\n",
			     sinf, sinf->sock, ret);
		if (ret < 0 || inq < len)
			break;

		rbuf = kmalloc(sizeof(struct recv_buf) + len, GFP_NOFS);
		if (!rbuf) {
			ret = -ENOMEM;
			break;
		}

		ret = recv_msg(sinf->sock, rbuf->nh, len, 0);
		trace_printk("sinf %p sock %p recv len %d ret %d\n",
			     sinf, sinf->sock, len, ret);
		if (ret != len) {
			if (ret >= 0)
				ret = -EIO;
			break;
		}

		if (inappropriate_message(nti, sinf, rbuf)) {
			ret = -EINVAL;
			break;
		}

		rbuf->nti = nti;
		rbuf->sinf = sinf;
		INIT_LIST_HEAD(&rbuf->head);
		INIT_WORK(&rbuf->proc_work, scoutfs_net_proc_func);

		mutex_lock(&nti->mutex);
		list_add(&rbuf->head, &sinf->active_rbufs);
		mutex_unlock(&nti->mutex);
		queue_work(nti->proc_wq, &rbuf->proc_work);
		rbuf = NULL;
	}

	if (ret < 0) {
		kfree(rbuf);
		trace_printk("ret %d\n", ret);
		queue_sock_work(sinf, &sinf->shutdown_work);
	}
}


/*
 * Connecting sockets kick off send and recv work once the socket is
 * connected and all sockets shutdown when closed.
 */
static void scoutfs_net_state_change(struct sock *sk)
{
	struct sock_info *sinf = sk->sk_user_data;

	trace_printk("sk %p state %u sinf %p\n", sk, sk->sk_state, sinf);

	if (sinf && sinf->sock->sk == sk) {
		switch(sk->sk_state) {
			case TCP_ESTABLISHED:
				queue_sock_work(sinf, &sinf->send_work);
				queue_sock_work(sinf, &sinf->recv_work);
				break;
			case TCP_CLOSE:
				queue_sock_work(sinf, &sinf->shutdown_work);
				break;
		}
	}
}

/*
 * Listening sockets accept incoming sockets and accepted and connected
 * sockets recv data.
 */
static void scoutfs_net_data_ready(struct sock *sk, int bytes)
{
	struct sock_info *sinf = sk->sk_user_data;

	trace_printk("sk %p bytes %d sinf %p\n", sk, bytes, sinf);

	if (sinf && sinf->sock->sk == sk) {
		if (sk->sk_state == TCP_LISTEN)
			queue_sock_work(sinf, &sinf->accept_work);
		else
			queue_sock_work(sinf, &sinf->recv_work);
	}
}

/*
 * Connected and accepted sockets send once there's space again in the
 * tx buffer.
 */
static void scoutfs_net_write_space(struct sock *sk)
{
	struct sock_info *sinf = sk->sk_user_data;

	trace_printk("sk %p sinf %p\n", sk, sinf);

	if (sinf && sinf->sock->sk == sk) {
		if (sk_stream_is_writeable(sk))
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		queue_sock_work(sinf, &sinf->send_work);
	}
}

/*
 * Accepted sockets inherit the sk fields from the listening socket so
 * all the callbacks check that the sinf they're working on points to
 * the socket executing the callback.  This ensures that we'll only get
 * callbacks doing work once we've initialized sinf for the socket.
 */
static void set_sock_callbacks(struct sock_info *sinf)
{
	struct sock *sk = sinf->sock->sk;

	sk->sk_state_change = scoutfs_net_state_change;
	sk->sk_data_ready = scoutfs_net_data_ready;
	sk->sk_write_space = scoutfs_net_write_space;
	sk->sk_user_data = sinf;

}

static int write_server_addr(struct super_block *sb,
			     struct scoutfs_inet_addr *addr)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	super->server_addr.addr = addr->addr;
	super->server_addr.port = addr->port;

	return scoutfs_write_dirty_super(sb);
}

static int read_server_addr(struct super_block *sb,
			    struct scoutfs_inet_addr *addr)
{
	int ret;
	struct scoutfs_super_block stack;

	ret = scoutfs_read_supers(sb, &stack);
	if (ret == 0) {
		addr->addr = stack.server_addr.addr;
		addr->port = stack.server_addr.port;
	}
	return ret;
}

/*
 * The caller can provide an error to give to pending sends before
 * freeing them.
 */
static void free_sbuf_list(struct super_block *sb, struct list_head *list,
			   int ret)
{
	struct send_buf *sbuf;
	struct send_buf *pos;

	list_for_each_entry_safe(sbuf, pos, list, head) {
		list_del_init(&sbuf->head);
		if (ret && sbuf->func)
			sbuf->func(sb, NULL, ret, sbuf->arg);
		kfree(sbuf);
	}
}

/*
 * Remove the rbufs from the list and clear their sinf pointers so that
 * they can't reference a sinf that's being freed.
 */
static void empty_rbuf_list(struct list_head *list)
{
	struct recv_buf *rbuf;
	struct recv_buf *pos;

	list_for_each_entry_safe(rbuf, pos, list, head) {
		list_del_init(&rbuf->head);
		rbuf->sinf = NULL;
	}
}

/*
 * Shutdown and free a socket.  This can be queued from most all socket
 * work.  It executes in the single socket workqueue context so we know
 * that we're serialized with all other socket work.  Listening,
 * connecting, and accepting don't reference the socket once it's
 * possible for this work to execute.
 *
 * Other work won't be executing but could be queued when we get here.
 * We can't cancel other work from inside their workqueue (until later
 * kernels when cancel_work() comes back).  So we have a two phase
 * shutdown where we first prevent additional work from being queued and
 * then queue the work again.  By the time the work executes again we
 * know that none of our work will be pending.
 */
static void scoutfs_net_shutdown_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      shutdown_work);
	struct super_block *sb = sinf->sb;
	DECLARE_NET_INFO(sb, nti);
	struct socket *sock = sinf->sock;
	int ret;

	trace_printk("sinf %p sock %p shutting_down %d\n",
		     sinf, sock, sinf->shutting_down);

	if (!sinf->shutting_down) {
		sinf->shutting_down = true;
		queue_work(nti->sock_wq, &sinf->shutdown_work);
		return;
	}

	kernel_sock_shutdown(sock, SHUT_RDWR);

	mutex_lock(&nti->mutex);

	if (sinf == nti->listening_sinf) {
		nti->listening_sinf = NULL;

		/* shutdown the server, processing won't leave dirty metadata */
		destroy_server_state(sb);
		nti->server_loaded = false;

		/* clear addr, try to reacquire lock and listen */
		memset(&sinf->addr, 0, sizeof(sinf->addr));
		ret = write_server_addr(sb, &sinf->addr);
		if (ret)
			scoutfs_err(sb,
				    "Non-fatal error %d while writing server "
				    "address\n", ret);
		scoutfs_unlock_range(sb, sinf->listen_lck);
		queue_delayed_work(nti->proc_wq, &nti->server_work, 0);

	} if (sinf == nti->connected_sinf) {
		/* save reliable sends and try to reconnect */
		nti->connected_sinf = NULL;
		list_splice_init(&sinf->have_sent, &nti->to_send);
		list_splice_init(&sinf->to_send, &nti->to_send);
		queue_delayed_work(nti->proc_wq, &nti->client_work, 0);

	} else {
		/* free reply sends and stop rbuf socket refs */
		free_sbuf_list(sb, &sinf->to_send, 0);
		empty_rbuf_list(&sinf->active_rbufs);
	}

	list_del_init(&sinf->head);

	mutex_unlock(&nti->mutex);

	sock_release(sock);
	kfree(sinf);
}

static int add_send_buf(struct super_block *sb, int type, void *data,
			unsigned data_len, reply_func_t func, void *arg)
{
	DECLARE_NET_INFO(sb, nti);
	struct scoutfs_net_header *nh;
	struct sock_info *sinf;
	struct send_buf *sbuf;

	sbuf = alloc_sbuf(data_len);
	if (!sbuf)
		return -ENOMEM;

	sbuf->func = func;
	sbuf->arg = arg;
	sbuf->nh->status = SCOUTFS_NET_STATUS_REQUEST;

	nh = sbuf->nh;
	nh->type = type;
	if (data_len)
		memcpy(nh->data, data, data_len);

	mutex_lock(&nti->mutex);

	nh->id = cpu_to_le64(nti->next_id++);

	sinf = nti->connected_sinf;
	if (sinf) {
		list_add_tail(&sbuf->head, &sinf->to_send);
		queue_sock_work(sinf, &sinf->send_work);
	} else {
		list_add_tail(&sbuf->head, &nti->to_send);
	}

	mutex_unlock(&nti->mutex);

	return 0;
}

struct bulk_alloc_args {
	struct completion comp;
	u64 *segnos;
	int ret;
};

static int sort_cmp_u64s(const void *A, const void *B)
{
	const u64 *a = A;
	const u64 *b = B;

	return *a < *b ? -1  : *a > *b ? 1 : 0;
}

static void sort_swap_u64s(void *A, void *B, int size)
{
	u64 *a = A;
	u64 *b = B;

	swap(*a, *b);
}

static int bulk_alloc_reply(struct super_block *sb, void *reply, int ret,
			    void *arg)
{
	struct bulk_alloc_args *args = arg;
	struct scoutfs_net_segnos *ns = reply;
	u16 nr;
	int i;

	if (ret < sizeof(struct scoutfs_net_segnos) ||
	    ret != offsetof(struct scoutfs_net_segnos,
			    segnos[le16_to_cpu(ns->nr)])) {
		ret = -EINVAL;
		goto out;
	}

	nr = le16_to_cpu(ns->nr);

	args->segnos = kmalloc((nr + 1) * sizeof(args->segnos[0]), GFP_NOFS);
	if (args->segnos == NULL) {
		ret = -ENOMEM; /* XXX hmm. */
		goto out;
	}

	for (i = 0; i < nr; i++) {
		args->segnos[i] = le64_to_cpu(ns->segnos[i]);

		/* make sure they're all non-zero */
		if (args->segnos[i] == 0) {
			ret = -EINVAL;
			goto out;
		}
	}

	sort(args->segnos, nr, sizeof(args->segnos[0]),
	     sort_cmp_u64s, sort_swap_u64s);

	/* make sure they're all unique */
	for (i = 1; i < nr; i++) {
		if (args->segnos[i] == args->segnos[i - 1]) {
			ret = -EINVAL;
			goto out;
		}
	}

	args->segnos[nr] = 0;
	ret = 0;
out:
	if (ret && args->segnos) {
		kfree(args->segnos);
		args->segnos = NULL;
	}
	args->ret = ret;
	complete(&args->comp);
	return args->ret;
}

/*
 * Returns a 0-terminated allocated array of segnos, the caller is
 * responsible for freeing it.
 */
u64 *scoutfs_net_bulk_alloc(struct super_block *sb)
{
	struct bulk_alloc_args args;
	int ret;

	args.segnos = NULL;
	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_BULK_ALLOC, NULL, 0,
			   bulk_alloc_reply, &args);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		ret = args.ret;
		if (ret == 0 && (args.segnos == NULL || args.segnos[0] == 0))
			ret = -ENOSPC;
	}

	if (ret) {
		kfree(args.segnos);
		args.segnos = ERR_PTR(ret);
	}

	return args.segnos;
}

/*
 * Eventually we're going to have messages that control compaction.
 * Each client mount would have long-lived work that sends requests
 * which are stuck in processing until there's work to do.  They'd get
 * their entries, perform the compaction, and send a reply.  But we're
 * not there yet.
 *
 * This is a short circuit that's called directly by a work function
 * that's only queued on the server.  It makes compaction work inside
 * the commit consistency mechanics inside net message processing and
 * demonstrates the moving pieces that we'd need to cut up into a series
 * of messages and replies.
 *
 * The compaction work caller cleans up everything on errors.
 */
int scoutfs_net_get_compaction(struct super_block *sb, void *curs)
{
	DECLARE_NET_INFO(sb, nti);
	struct commit_waiter cw;
	u64 segno;
	int ret = 0;
	int nr;
	int i;

	down_read(&nti->commit_rwsem);

	nr = scoutfs_manifest_next_compact(sb, curs);
	if (nr <= 0) {
		up_read(&nti->commit_rwsem);
		return nr;
	}

	/* allow for expansion slop from sticky and alignment */
	for (i = 0; i < nr + SCOUTFS_COMPACTION_SLOP; i++) {
		ret = scoutfs_alloc_segno(sb, &segno);
		if (ret < 0)
			break;
		scoutfs_compact_add_segno(sb, curs, segno);
	}

	if (ret == 0)
		queue_commit_work(nti, &cw);
	up_read(&nti->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(&cw);

	return ret;
}

/*
 * This is a stub for recording the results of a compaction.  We just
 * call back into compaction to have it call the manifest and allocator
 * updates.
 *
 * In the future we'd encode the manifest and segnos in requests sent to
 * the server who'd update the manifest and allocator in request
 * processing.
 *
 * As we finish a compaction we wait level0 writers if it opened up
 * space in level 0.
 */
int scoutfs_net_finish_compaction(struct super_block *sb, void *curs,
				  void *list)
{
	DECLARE_NET_INFO(sb, nti);
	struct commit_waiter cw;
	bool level0_was_full;
	int ret;

	down_read(&nti->commit_rwsem);

	level0_was_full = scoutfs_manifest_level0_full(sb);

	ret = scoutfs_compact_commit(sb, curs, list);
	if (ret == 0) {
		queue_commit_work(nti, &cw);
		if (level0_was_full && !scoutfs_manifest_level0_full(sb))
			wake_up(&nti->waitq);
	}

	up_read(&nti->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(&cw);

	scoutfs_compact_kick(sb);

	return ret;
}

struct record_segment_args {
	struct completion comp;
	int ret;
};

static int record_segment_reply(struct super_block *sb, void *reply, int ret,
				void *arg)
{
	struct record_segment_args *args = arg;

	if (ret > 0)
		ret = -EINVAL;

	args->ret = ret;
	complete(&args->comp);
	return args->ret;
}

int scoutfs_net_record_segment(struct super_block *sb,
			       struct scoutfs_segment *seg, u8 level)
{
	struct scoutfs_net_manifest_entry *net_ment;
	struct record_segment_args args;
	struct scoutfs_manifest_entry ment;
	int ret;

	scoutfs_seg_init_ment(&ment, level, seg);
	net_ment = alloc_net_ment(&ment);
	if (!net_ment) {
		ret = -ENOMEM;
		goto out;
	}

	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_RECORD_SEGMENT, net_ment,
			   net_ment_bytes(net_ment),
			   record_segment_reply, &args);
	kfree(net_ment);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		ret = args.ret;
	}
out:
	return ret;
}

struct alloc_segno_args {
	u64 segno;
	struct completion comp;
	int ret;
};

static int alloc_segno_reply(struct super_block *sb, void *reply, int ret,
			     void *arg)
{
	struct alloc_segno_args *args = arg;
	__le64 * __packed segno = reply;

	if (ret == sizeof(__le64)) {
		args->segno = le64_to_cpup(segno);
		args->ret = 0;
	} else {
		args->ret = -EINVAL;
	}

	complete(&args->comp); /* args can be freed from this point */
	return args->ret;
}

int scoutfs_net_alloc_segno(struct super_block *sb, u64 *segno)
{
	struct alloc_segno_args args;
	int ret;

	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_ALLOC_SEGNO, NULL, 0,
			   alloc_segno_reply, &args);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		*segno = args.segno;
		ret = args.ret;
		if (ret == 0 && *segno == 0)
			ret = -ENOSPC;
	}
	return ret;
}

static int alloc_inodes_reply(struct super_block *sb, void *reply, int ret,
			      void *arg)
{
	struct scoutfs_net_inode_alloc *ial = reply;
	u64 ino;
	u64 nr;

	if (ret != sizeof(*ial)) {
		ret = -EINVAL;
		goto out;
	}

	ino = le64_to_cpu(ial->ino);
	nr = le64_to_cpu(ial->nr);

	/* catch wrapping */
	if (ino + nr < ino) {
		ret = -EINVAL;
		goto out;
	}

	/* XXX compare to greatest inode we've seen? */

	ret = 0;
out:
	if (ret < 0)
		scoutfs_inode_fill_pool(sb, 0, 0);
	else
		scoutfs_inode_fill_pool(sb, ino, nr);
	return ret;
}

int scoutfs_net_alloc_inodes(struct super_block *sb)
{
	return add_send_buf(sb, SCOUTFS_NET_ALLOC_INODES, NULL, 0,
			    alloc_inodes_reply, NULL);
}

struct advance_seq_args {
	u64 seq;
	struct completion comp;
	int ret;
};

static int advance_seq_reply(struct super_block *sb, void *reply, int ret,
				  void *arg)
{
	struct advance_seq_args *args = arg;
	__le64 * __packed seq = reply;

	if (ret == sizeof(__le64)) {
		args->seq = le64_to_cpup(seq);
		args->ret = 0;
	} else {
		args->ret = -EINVAL;
	}

	complete(&args->comp); /* args can be freed from this point */
	return args->ret;
}

int scoutfs_net_advance_seq(struct super_block *sb, u64 *seq)
{
	struct advance_seq_args args;
	__le64 leseq = cpu_to_le64p(seq);
	int ret;

	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_ADVANCE_SEQ, &leseq,
			   sizeof(leseq), advance_seq_reply, &args);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		*seq = args.seq;
		ret = args.ret;
	}
	return ret;
}

struct get_last_seq_args {
	u64 seq;
	struct completion comp;
	int ret;
};

static int get_last_seq_reply(struct super_block *sb, void *reply, int ret,
			     void *arg)
{
	struct get_last_seq_args *args = arg;
	__le64 * __packed seq = reply;

	if (ret == sizeof(__le64)) {
		args->seq = le64_to_cpup(seq);
		args->ret = 0;
	} else {
		args->ret = -EINVAL;
	}

	complete(&args->comp); /* args can be freed from this point */
	return args->ret;
}

int scoutfs_net_get_last_seq(struct super_block *sb, u64 *seq)
{
	struct get_last_seq_args args;
	int ret;

	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_GET_LAST_SEQ, NULL, 0,
			   get_last_seq_reply, &args);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		*seq = args.seq;
		ret = args.ret;
	}
	return ret;
}

struct get_manifest_root_args {
	struct scoutfs_btree_root *root;
	struct completion comp;
	int ret;
};

static int get_manifest_root_reply(struct super_block *sb, void *reply, int ret,
			     void *arg)
{
	struct get_manifest_root_args *args = arg;
	struct scoutfs_btree_root *root = reply;

	if (ret == sizeof(struct scoutfs_btree_root)) {
		memcpy(args->root, root, sizeof(struct scoutfs_btree_root));
		args->ret = 0;
	} else {
		args->ret = -EINVAL;
	}

	complete(&args->comp); /* args can be freed from this point */
	return args->ret;
}

int scoutfs_net_get_manifest_root(struct super_block *sb,
				  struct scoutfs_btree_root *root)
{
	struct get_manifest_root_args args;
	int ret;

	args.root = root;
	init_completion(&args.comp);

	ret = add_send_buf(sb, SCOUTFS_NET_GET_MANIFEST_ROOT, NULL, 0,
			   get_manifest_root_reply, &args);
	if (ret == 0) {
		wait_for_completion(&args.comp);
		ret = args.ret;
	}
	return ret;
}


static struct sock_info *alloc_sinf(struct super_block *sb)
{
	struct sock_info *sinf;

	sinf = kzalloc(sizeof(struct sock_info), GFP_NOFS);
	if (sinf) {
		sinf->sb = sb;
		INIT_LIST_HEAD(&sinf->head);
		INIT_LIST_HEAD(&sinf->to_send);
		INIT_LIST_HEAD(&sinf->have_sent);
		INIT_LIST_HEAD(&sinf->active_rbufs);

		/* callers set other role specific work as appropriate */
		INIT_WORK(&sinf->shutdown_work, scoutfs_net_shutdown_func);
	}

	return sinf;
}

static void scoutfs_net_accept_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      accept_work);
	struct super_block *sb = sinf->sb;
	DECLARE_NET_INFO(sb, nti);
	struct sock_info *new_sinf;
	struct socket *new_sock;
	int ret;

	for (;;) {
		ret = kernel_accept(sinf->sock, &new_sock, O_NONBLOCK);
		trace_printk("nti %p accept sock %p ret %d\n",
			     nti, new_sock, ret);
		if (ret < 0) {
			if (ret == -EAGAIN)
				ret = 0;
			break;
		}

		new_sinf = alloc_sinf(sb);
		if (!new_sinf) {
			ret = -ENOMEM;
			sock_release(new_sock);
			break;
		}

		trace_printk("accepted sinf %p sock %p sk %p\n",
			     new_sinf, new_sock, new_sock->sk);

		new_sinf->sock = new_sock;
		INIT_WORK(&new_sinf->send_work, scoutfs_net_send_func);
		INIT_WORK(&new_sinf->recv_work, scoutfs_net_recv_func);

		mutex_lock(&nti->mutex);
		list_add(&new_sinf->head, &nti->active_socks);
		queue_sock_work(new_sinf, &new_sinf->recv_work);
		mutex_unlock(&nti->mutex);

		set_sock_callbacks(new_sinf);
	}

	if (ret) {
		trace_printk("ret %d\n", ret);
		queue_sock_work(sinf, &sinf->shutdown_work);
	}
}

/*
 * Create a new TCP socket and set all the options that are used for
 * both connecting and listening sockets.
 */
static int create_sock_setopts(struct socket **sock_ret)
{
	struct socket *sock;
	int optval;
	int ret;

	*sock_ret = NULL;

	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret) {
		trace_printk("sock create ret %d\n", ret);
		return ret;
	}

	optval = 1;
	ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&optval,
				sizeof(optval));
	if (ret) {
		trace_printk("nodelay ret %d\n", ret);
		sock_release(sock);
		return ret;
	}

	*sock_ret = sock;

	return 0;
}

/*
 * The server work has acquired the listen lock.  We create a socket and
 * publish its bound address in the addr lock's lvb.
 *
 * This can block in the otherwise non-blocking socket workqueue while
 * acquiring the addr lock but it should be brief and doesn't matter
 * much given that we're bringing up a new server.  This should happen
 * rarely.
 */
static void scoutfs_net_listen_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      listen_work);
	struct super_block *sb = sinf->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_inet_addr addr;
	struct sockaddr_in sin;
	struct socket *sock;
	int addrlen;
	int optval;
	int ret;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = cpu_to_be32(le32_to_cpu(sbi->opts.listen_addr.addr));
	sin.sin_port = cpu_to_be16(le16_to_cpu(sbi->opts.listen_addr.port));

	trace_printk("binding to %pIS:%u\n",
		     &sin, be16_to_cpu(sin.sin_port));

	ret = create_sock_setopts(&sock);
	if (ret)
		goto out;

	trace_printk("listening sinf %p sock %p sk %p\n",
		     sinf, sock, sock->sk);

	optval = 1;
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,
				sizeof(optval));
	if (ret) {
		trace_printk("reuseaddr ret %d\n", ret);
		sock_release(sock);
		goto out;
	}

	sinf->sock = sock;
	INIT_WORK(&sinf->accept_work, scoutfs_net_accept_func);

	addrlen = sizeof(sin);
	ret = kernel_bind(sock, (struct sockaddr *)&sin, addrlen) ?:
	      kernel_getsockname(sock, (struct sockaddr *)&sin, &addrlen);
	if (ret)
		goto out;

	trace_printk("sock %p listening on %pIS:%u\n",
		     sock, &sin, be16_to_cpu(sin.sin_port));

	addr.addr = cpu_to_le32(be32_to_cpu(sin.sin_addr.s_addr));
	addr.port = cpu_to_le16(be16_to_cpu(sin.sin_port));

	set_sock_callbacks(sinf);

	ret = kernel_listen(sock, 255);
	if (ret)
		goto out;

	scoutfs_advance_dirty_super(sb);
	ret = write_server_addr(sb, &addr);
	if (ret)
		goto out;
	scoutfs_advance_dirty_super(sb);

	queue_sock_work(sinf, &sinf->accept_work);

out:
	if (ret) {
		trace_printk("ret %d\n", ret);
		queue_sock_work(sinf, &sinf->shutdown_work);
	}
}

/*
 * The client work has found an address to try and connect to.  Create a
 * connecting socket and wire up its callbacks.
 */
static void scoutfs_net_connect_func(struct work_struct *work)
{
	struct sock_info *sinf = container_of(work, struct sock_info,
					      connect_work);
	struct sockaddr_in sin;
	struct socket *sock;
	int addrlen;
	int ret;

	ret = create_sock_setopts(&sock);
	if (ret)
		goto out;

	trace_printk("connecting sinf %p sock %p sk %p\n",
		     sinf, sock, sock->sk);

	sinf->sock = sock;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = cpu_to_be32(le32_to_cpu(sinf->addr.addr));
	sin.sin_port = cpu_to_be16(le16_to_cpu(sinf->addr.port));

	trace_printk("connecting to %pIS:%u\n",
		     &sin, be16_to_cpu(sin.sin_port));

	/* callbacks can fire once inside connect that'll succeed */
	set_sock_callbacks(sinf);

	addrlen = sizeof(sin);
	ret = kernel_connect(sock, (struct sockaddr *)&sin, addrlen,
			     O_NONBLOCK);
	if (ret == -EINPROGRESS)
		ret = 0;
out:
	if (ret) {
		trace_printk("ret %d\n", ret);
		queue_sock_work(sinf, &sinf->shutdown_work);
	}
}

/*
 * This work executes whenever there isn't a socket on the client connected
 * to the server: on mount, after the connected socket is shut down, and
 * when we can't find an address in the addr lock's lvb.
 */
static void scoutfs_net_client_func(struct work_struct *work)
{
	struct net_info *nti = container_of(work, struct net_info,
					    client_work.work);
	struct super_block *sb = nti->sb;
	struct sock_info *sinf = NULL;
	int ret;

	BUG_ON(nti->connected_sinf);

	sinf = alloc_sinf(sb);
	if (!sinf) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_WORK(&sinf->connect_work, scoutfs_net_connect_func);
	INIT_WORK(&sinf->send_work, scoutfs_net_send_func);
	INIT_WORK(&sinf->recv_work, scoutfs_net_recv_func);

	ret = read_server_addr(sb, &sinf->addr);
	if (ret == 0 && sinf->addr.addr == cpu_to_le32(INADDR_ANY))
		ret = -ENOENT;
	if (ret < 0) {
		kfree(sinf);
		goto out;
	}

	mutex_lock(&nti->mutex);
	nti->connected_sinf = sinf;
	list_splice_init(&nti->to_send, &sinf->to_send);
	list_add(&sinf->head, &nti->active_socks);
	queue_sock_work(sinf, &sinf->connect_work);
	mutex_unlock(&nti->mutex);

out:
	if (ret < 0 && ret != -ESHUTDOWN) {
		trace_printk("ret %d\n", ret);
		queue_delayed_work(nti->proc_wq, &nti->client_work, HZ / 2);
	}
}

/*
 * This very long running blocking work just sits trying to acquire a
 * lock on the listening key which marks it as the active server.  When
 * it does that it queues off work to build up the listening socket.
 * The lock is associated with the listening socket and is unlocked when
 * the socket is shut down.
 *
 * This work is queued by mount, shutdown of the listening socket, and
 * errors.  It stops re-arming itself if it sees that locking has been
 * shut down.
 */
static void scoutfs_net_server_func(struct work_struct *work)
{
	struct net_info *nti = container_of(work, struct net_info,
					    server_work.work);
	struct super_block *sb = nti->sb;
	struct sock_info *sinf = NULL;
	int ret;

	BUG_ON(nti->listening_sinf);

	sinf = alloc_sinf(sb);
	if (!sinf) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_WORK(&sinf->listen_work, scoutfs_net_listen_func);
	INIT_WORK(&sinf->accept_work, scoutfs_net_accept_func);

	ret = scoutfs_lock_range(sb, DLM_LOCK_EX, &listen_key,
				 &listen_key, &sinf->listen_lck);
	if (ret) {
		kfree(sinf);
		goto out;
	}

	mutex_lock(&nti->mutex);
	nti->listening_sinf = sinf;
	list_add(&sinf->head, &nti->active_socks);
	queue_sock_work(sinf, &sinf->listen_work);
	mutex_unlock(&nti->mutex);

out:
	if (ret < 0 && ret != -ESHUTDOWN) {
		trace_printk("ret %d\n", ret);
		queue_delayed_work(nti->proc_wq, &nti->server_work, HZ / 2);
	}
}

static void free_nti(struct net_info *nti)
{
	if (nti) {
		if (nti->sock_wq)
			destroy_workqueue(nti->sock_wq);
		if (nti->proc_wq)
			destroy_workqueue(nti->proc_wq);
		kfree(nti);
	}
}

int scoutfs_net_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct net_info *nti;

	scoutfs_key_init(&listen_key, &listen_type, sizeof(listen_type));
	scoutfs_key_init(&addr_key, &addr_type, sizeof(addr_type));

	nti = kzalloc(sizeof(struct net_info), GFP_KERNEL);
	if (nti) {
		nti->sock_wq = alloc_workqueue("scoutfs_net_sock",
						WQ_UNBOUND, 1);
		nti->proc_wq = alloc_workqueue("scoutfs_net_proc",
						WQ_NON_REENTRANT, 0);
	}
	if (!nti || !nti->sock_wq || !nti->proc_wq) {
		free_nti(nti);
		return -ENOMEM;
	}

	nti->sb = sb;
	mutex_init(&nti->mutex);
	INIT_DELAYED_WORK(&nti->client_work, scoutfs_net_client_func);
	INIT_LIST_HEAD(&nti->to_send);
	nti->next_id = 1;
	INIT_DELAYED_WORK(&nti->server_work, scoutfs_net_server_func);
	init_rwsem(&nti->commit_rwsem);
	init_llist_head(&nti->commit_waiters);
	INIT_WORK(&nti->commit_work, scoutfs_net_commit_func);
	init_waitqueue_head(&nti->waitq);
	spin_lock_init(&nti->seq_lock);
	INIT_LIST_HEAD(&nti->pending_seqs);
	INIT_LIST_HEAD(&nti->active_socks);

	sbi->net_info = nti;

	queue_delayed_work(nti->proc_wq, &nti->server_work, 0);
	queue_delayed_work(nti->proc_wq, &nti->client_work, 0);

	return 0;
}

/*
 * Shutdown and destroy all our socket communications.
 *
 * This is called after locking has been shutdown.  Client and server
 * work that executes from this point on will fail with -ESHUTDOWN and
 * won't rearm itself.  That prevents new sockets from being created so
 * our job is to shutdown all the existing sockets.
 *
 * We'll have to be careful to shut down any non-vfs callers of ours
 * that might try to send requests during destruction.
 */
void scoutfs_net_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_NET_INFO(sb, nti);
	struct sock_info *sinf;
	struct sock_info *pos;

	if (nti) {
		/* let any currently executing client/server work finish */
		flush_workqueue(nti->proc_wq);

		/* stop any additional incoming accepted sockets */
		mutex_lock(&nti->mutex);
		sinf = nti->listening_sinf;
		if (sinf)
			queue_sock_work(sinf, &sinf->shutdown_work);
		mutex_unlock(&nti->mutex);
		drain_workqueue(nti->sock_wq);

		/* shutdown all the remaining sockets */
		mutex_lock(&nti->mutex);
		list_for_each_entry_safe(sinf, pos, &nti->active_socks, head)
			queue_sock_work(sinf, &sinf->shutdown_work);
		mutex_unlock(&nti->mutex);
		drain_workqueue(nti->sock_wq);

		/* wait for processing (and commits) to finish and free rbufs */
		drain_workqueue(nti->proc_wq);

		/* make sure client/server work isn't queued */
		cancel_delayed_work_sync(&nti->server_work);
		cancel_delayed_work_sync(&nti->client_work);

		/* call all pending replies with errors */
		list_for_each_entry_safe(sinf, pos, &nti->active_socks, head)

		/* and free all resources */
		free_sbuf_list(sb, &nti->to_send, -ESHUTDOWN);
		free_nti(nti);
		sbi->net_info = NULL;
	}
}
