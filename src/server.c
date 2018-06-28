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
#include "client.h"
#include "server.h"
#include "sock.h"
#include "endian_swap.h"

#define SIN_FMT		"%pIS:%u"
#define SIN_ARG(sin)	sin, be16_to_cpu((sin)->sin_port)

struct server_info {
	struct super_block *sb;

	struct workqueue_struct *wq;
	struct delayed_work dwork;

	struct mutex mutex;
	bool shutting_down;
	bool bind_warned;
	struct task_struct *listen_task;
	struct socket *listen_sock;

	/* request processing coordinates committing manifest and alloc */
	struct rw_semaphore commit_rwsem;
	struct llist_head commit_waiters;
	struct work_struct commit_work;


	/* adding new segments can have to wait for compaction */
	wait_queue_head_t compaction_waitq;

	/* server remembers the stable manifest root for clients */
	seqcount_t stable_seqcount;
	struct scoutfs_btree_root stable_manifest_root;

	/* server tracks seq use */
	spinlock_t seq_lock;
	struct list_head pending_seqs;

	/* server tracks pending frees to be applied during commit */
	struct rw_semaphore alloc_rwsem;
	struct list_head pending_frees;
};

struct server_request {
	struct server_connection *conn;
	struct work_struct work;

	struct scoutfs_net_header nh;
	/* data payload is allocated here, referenced as ->nh.data */
};

struct server_connection {
	struct server_info *server;
	struct sockaddr_in sockname;
	struct sockaddr_in peername;
	struct list_head head;
	struct socket *sock;
	struct work_struct recv_work;
	struct mutex send_mutex;
};

struct commit_waiter {
	struct completion comp;
	struct llist_node node;
	int ret;
};

static void init_extent_btree_key(struct scoutfs_extent_btree_key *ebk,
				  u8 type, u64 major, u64 minor)
{
	ebk->type = type;
	ebk->major = cpu_to_be64(major);
	ebk->minor = cpu_to_be64(minor);
}

static int init_extent_from_btree_key(struct scoutfs_extent *ext, u8 type,
				      struct scoutfs_extent_btree_key *ebk,
				      unsigned int key_bytes)
{
	u64 start;
	u64 len;

	/* btree _next doesn't have last key limit */
	if (ebk->type != type)
		return -ENOENT;

	if (key_bytes != sizeof(struct scoutfs_extent_btree_key) ||
	    (ebk->type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	     ebk->type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE))
		return -EIO; /* XXX corruption, bad key */

	start = be64_to_cpu(ebk->major);
	len = be64_to_cpu(ebk->minor);
	if (ebk->type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		swap(start, len);
	start -= len - 1;

	return scoutfs_extent_init(ext, ebk->type, 0, start, len, 0, 0);
}

/*
 * This is called by the extent core on behalf of the server who holds
 * the appropriate locks to protect the many btree items that can be
 * accessed on behalf of one extent operation.
 */
static int server_extent_io(struct super_block *sb, int op,
			    struct scoutfs_extent *ext, void *data)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_extent_btree_key ebk;
	SCOUTFS_BTREE_ITEM_REF(iref);
	bool mirror = false;
	u8 mirror_type;
	u8 mirror_op = 0;
	int ret;
	int err;

	trace_scoutfs_server_extent_io(sb, ext);

	if (WARN_ON_ONCE(ext->type != SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
			 ext->type != SCOUTFS_FREE_EXTENT_BLOCKS_TYPE))
		return -EINVAL;

	if (ext->type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE &&
	    (op == SEI_INSERT || op == SEI_DELETE)) {
		mirror = true;
		mirror_type = SCOUTFS_FREE_EXTENT_BLOCKS_TYPE;
		mirror_op = op == SEI_INSERT ? SEI_DELETE : SEI_INSERT;
	}

	init_extent_btree_key(&ebk, ext->type, ext->start + ext->len - 1,
			      ext->len);
	if (ext->type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		swap(ebk.major, ebk.minor);

	if (op == SEI_NEXT || op == SEI_PREV) {
		if (op == SEI_NEXT)
			ret = scoutfs_btree_next(sb, &super->alloc_root,
						 &ebk, sizeof(ebk), &iref);
		else
			ret = scoutfs_btree_prev(sb, &super->alloc_root,
						 &ebk, sizeof(ebk), &iref);
		if (ret == 0) {
			ret = init_extent_from_btree_key(ext, ext->type,
							 iref.key,
							 iref.key_len);
			scoutfs_btree_put_iref(&iref);
		}

	} else if (op == SEI_INSERT) {
		ret = scoutfs_btree_insert(sb, &super->alloc_root,
					   &ebk, sizeof(ebk), NULL, 0);

	} else if (op == SEI_DELETE) {
		ret = scoutfs_btree_delete(sb, &super->alloc_root,
					   &ebk, sizeof(ebk));

	} else {
		ret = WARN_ON_ONCE(-EINVAL);
	}

	if (ret == 0 && mirror) {
		swap(ext->type, mirror_type);
		ret = server_extent_io(sb, op, ext, data);
		swap(ext->type, mirror_type);
		if (ret < 0) {
			err = server_extent_io(sb, mirror_op, ext, data);
			if (err)
				scoutfs_corruption(sb,
						 SC_SERVER_EXTENT_CLEANUP,
						 corrupt_server_extent_cleanup,
						 "op %u ext "SE_FMT" ret %d",
						 op, SE_ARG(ext), err);
		}
	}

	return ret;
}

/*
 * Allocate an extent of the given length in the first smallest free
 * extent that contains it.  We allocate in multiples of segment blocks
 * and expose that to callers today.
 *
 * This doesn't have the cursor that segment allocation does.  It's
 * possible that a recently freed segment can merge to form a larger
 * free extent that can be very quickly allocated to a node.  The hope is
 * that doesn't happen very often.
 */
static int alloc_extent(struct super_block *sb, u64 blocks,
			u64 *start, u64 *len)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_extent ext;
	int ret;

	*start = 0;
	*len = 0;

	down_write(&server->alloc_rwsem);

	if (blocks & (SCOUTFS_SEGMENT_BLOCKS - 1)) {
		ret = -EINVAL;
		goto out;
	}

	scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLOCKS_TYPE, 0,
			    0, blocks, 0, 0);
	ret = scoutfs_extent_next(sb, server_extent_io, &ext, NULL);
	if (ret == -ENOENT)
		ret = scoutfs_extent_prev(sb, server_extent_io, &ext, NULL);
	if (ret) {
		if (ret == -ENOENT)
			ret = -ENOSPC;
		goto out;
	}

	trace_scoutfs_server_alloc_extent_next(sb, &ext);

	ext.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
	ext.len = min(blocks, ext.len);

	ret = scoutfs_extent_remove(sb, server_extent_io, &ext, NULL);
	if (ret)
		goto out;

	trace_scoutfs_server_alloc_extent_allocated(sb, &ext);
	le64_add_cpu(&super->free_blocks, -ext.len);

	*start = ext.start;
	*len = ext.len;
	ret = 0;

out:
	up_write(&server->alloc_rwsem);

	if (ret)
		scoutfs_inc_counter(sb, server_extent_alloc_error);
	else
		scoutfs_inc_counter(sb, server_extent_alloc);

	return ret;
}

struct pending_free_extent {
	struct list_head head;
	u64 start;
	u64 len;
};

/*
 * Now that the transaction's done we can apply all the pending frees.
 * The list entries are totally unsorted so this is the first time that
 * we can discover corruption from duplicated frees, etc.  This can also
 * fail on normal transient io or memory errors.
 *
 * We can't unwind if this fails.  The caller can freak out or keep
 * trying forever.
 */
static int apply_pending_frees(struct super_block *sb)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct pending_free_extent *pfe;
	struct pending_free_extent *tmp;
	struct scoutfs_extent ext;
	int ret;

	down_write(&server->alloc_rwsem);

	list_for_each_entry_safe(pfe, tmp, &server->pending_frees, head) {
		scoutfs_inc_counter(sb, server_free_pending_extent);
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE, 0,
				    pfe->start, pfe->len, 0, 0);
		trace_scoutfs_server_free_pending_extent(sb, &ext);
		ret = scoutfs_extent_add(sb, server_extent_io, &ext, NULL);
		if (ret) {
			scoutfs_inc_counter(sb, server_free_pending_error);
			break;
		}

		le64_add_cpu(&super->free_blocks, pfe->len);
		list_del_init(&pfe->head);
		kfree(pfe);
	}

	up_write(&server->alloc_rwsem);

	return 0;
}

/*
 * If there are still pending frees to destroy it means the server didn't
 * shut down cleanly and that's not well supported today so we want to
 * have it holler if this happens.  In the future we'd cleanly support
 * forced shutdown that had been told that it's OK to throw away dirty
 * state.
 */
static int destroy_pending_frees(struct super_block *sb)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct pending_free_extent *pfe;
	struct pending_free_extent *tmp;

	WARN_ON_ONCE(!list_empty(&server->pending_frees));

	down_write(&server->alloc_rwsem);

	list_for_each_entry_safe(pfe, tmp, &server->pending_frees, head) {
		list_del_init(&pfe->head);
		kfree(pfe);
	}

	up_write(&server->alloc_rwsem);

	return 0;
}

/*
 * We can't satisfy allocations with freed extents until the removed
 * references to the freed extents have been committed.  We add freed
 * extents to a list that is only applied to the persistent indexes as
 * the transaction is being committed and the current transaction won't
 * try to allocate any more extents.  If we didn't do this then we could
 * write to referenced data as part of the commit that frees it.  If the
 * commit was interrupted the stable data could have been overwritten.
 */
static int free_extent(struct super_block *sb, u64 start, u64 len)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct pending_free_extent *pfe;
	int ret;

	scoutfs_inc_counter(sb, server_free_extent);

	down_write(&server->alloc_rwsem);

	pfe = kmalloc(sizeof(struct pending_free_extent), GFP_NOFS);
	if (!pfe) {
		ret = -ENOMEM;
	} else {
		pfe->start = start;
		pfe->len = len;
		list_add_tail(&pfe->head, &server->pending_frees);
		ret = 0;
	}

	up_write(&server->alloc_rwsem);

	return ret;
}

/*
 * This is called by the compaction code which is running in the server.
 * The server caller has held all the locks, etc.
 */
int scoutfs_server_free_segno(struct super_block *sb, u64 segno)
{
	scoutfs_inc_counter(sb, server_free_segno);
	trace_scoutfs_free_segno(sb, segno);
	return free_extent(sb, segno << SCOUTFS_SEGMENT_BLOCK_SHIFT,
			   SCOUTFS_SEGMENT_BLOCKS);
}

/*
 * Allocate a segment on behalf of compaction or a node wanting to write
 * a level 0 segment.  It has to be aligned to the segment size because
 * we address segments with aligned segment numbers instead of block
 * offsets.
 *
 * We can use a simple cursor sweep of the index by start because all
 * server extents are multiples of the segment size.  Sweeping through
 * the volume tries to spread out new segment writes and make it more
 * rare to write to a recently freed segment which can cause a client to
 * have to re-read the manifest.
 */
static int alloc_segno(struct super_block *sb, u64 *segno)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_extent ext;
	u64 curs;
	int ret;

	down_write(&server->alloc_rwsem);

	curs = ALIGN(le64_to_cpu(super->alloc_cursor), SCOUTFS_SEGMENT_BLOCKS);
	*segno = 0;

	do {
		scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE, 0,
				    curs, 1, 0, 0);
		ret = scoutfs_extent_next(sb, server_extent_io, &ext, NULL);
	} while (ret == -ENOENT && curs && (curs = 0, 1));
	if (ret) {
		if (ret == -ENOENT)
			ret = -ENOSPC;
		goto out;
	}

	trace_scoutfs_server_alloc_segno_next(sb, &ext);

	/* use cursor if within extent, otherwise start of next extent */
	if (ext.start < curs)
		ext.start = curs;
	ext.len = SCOUTFS_SEGMENT_BLOCKS;

	ret = scoutfs_extent_remove(sb, server_extent_io, &ext, NULL);
	if (ret)
		goto out;

	super->alloc_cursor = cpu_to_le64(ext.start + ext.len);

	*segno = ext.start >> SCOUTFS_SEGMENT_BLOCK_SHIFT;

	trace_scoutfs_server_alloc_segno_allocated(sb, &ext);
	trace_scoutfs_alloc_segno(sb, *segno);
	scoutfs_inc_counter(sb, server_alloc_segno);

out:
	up_write(&server->alloc_rwsem);
	return ret;
}

/*
 * Trigger a server shutdown by shutting down the listening socket.  The
 * server thread will break out of accept and exit.
 */
static void shut_down_server(struct server_info *server)
{
	mutex_lock(&server->mutex);
	server->shutting_down = true;
	if (server->listen_sock)
		kernel_sock_shutdown(server->listen_sock, SHUT_RDWR);
	mutex_unlock(&server->mutex);
}

/*
 * This is called while still holding the rwsem that prevents commits so
 * that the caller can be sure to be woken by the next commit after they
 * queue and release the lock.
 *
 * It's important to realize that the caller's commit_waiter list node
 * might be serviced by a currently running commit work while queueing
 * another work run in the future.  This caller can return from
 * wait_for_commit() while the commit_work is still queued.
 *
 * This could queue delayed work but we're first trying to have batching
 * work by having concurrent modification line up behind a commit in
 * flight.  Once the commit finishes it'll unlock and hopefully everyone
 * will race to make their changes and they'll all be applied by the
 * next commit after that.
 */
static void queue_commit_work(struct server_info *server,
			      struct commit_waiter *cw)
{
	lockdep_assert_held(&server->commit_rwsem);

	cw->ret = 0;
	init_completion(&cw->comp);
	llist_add(&cw->node, &server->commit_waiters);
	queue_work(server->wq, &server->commit_work);
}

/*
 * Commit errors are fatal and shut down the server.  This is called
 * from request processing which shutdown will wait for.
 */
static int wait_for_commit(struct server_info *server,
			   struct commit_waiter *cw, u64 id, u8 type)
{
	struct super_block *sb = server->sb;

	wait_for_completion(&cw->comp);
	if (cw->ret < 0) {
		scoutfs_err(sb, "commit error %d processing req id %llu type %u",
				cw->ret, id, type);

		shut_down_server(server);
	}
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
 * implement commits with a single pending work func like the
 * processing.
 *
 * Processing paths acquire the rwsem for reading while they're making
 * multiple dependent changes.  When they're done and want it persistent
 * they add themselves to the list of waiters and queue the commit work.
 * This work runs, acquires the lock to exclude other writers, and
 * performs the commit.  Readers can run concurrently with these
 * commits.
 */
static void scoutfs_server_commit_func(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  commit_work);
	struct super_block *sb = server->sb;
	struct commit_waiter *cw;
	struct commit_waiter *pos;
	struct llist_node *node;
	int ret;

	trace_scoutfs_server_commit_work_enter(sb, 0, 0);

	down_write(&server->commit_rwsem);

	if (!scoutfs_btree_has_dirty(sb)) {
		ret = 0;
		goto out;
	}

	ret = apply_pending_frees(sb);
	if (ret) {
		scoutfs_err(sb, "server error freeing extents: %d", ret);
		goto out;
	}

	ret = scoutfs_btree_write_dirty(sb);
	if (ret) {
		scoutfs_err(sb, "server error writing btree blocks: %d", ret);
		goto out;
	}

	ret = scoutfs_write_dirty_super(sb);
	if (ret) {
		scoutfs_err(sb, "server error writing super block: %d", ret);
		goto out;
	}

	scoutfs_btree_write_complete(sb);

	write_seqcount_begin(&server->stable_seqcount);
	server->stable_manifest_root = SCOUTFS_SB(sb)->super.manifest.root;
	write_seqcount_end(&server->stable_seqcount);

	scoutfs_advance_dirty_super(sb);
	ret = 0;

out:
	node = llist_del_all(&server->commit_waiters);

	/* waiters always wait on completion, cw could be free after complete */
	llist_for_each_entry_safe(cw, pos, node, node) {
		cw->ret = ret;
		complete(&cw->comp);
	}

	up_write(&server->commit_rwsem);
	trace_scoutfs_server_commit_work_exit(sb, 0, ret);
}

/*
 * Request processing synchronously sends their reply from within their
 * processing work.  If this fails the socket is shutdown.
 */
static int send_reply(struct server_connection *conn, u64 id,
		      u8 type, int error, void *data, unsigned data_len)
{
	struct scoutfs_net_header nh;
	struct kvec kv[2];
	unsigned kv_len;
	u8 status;
	int ret;

	if (WARN_ON_ONCE(error > 0) || WARN_ON_ONCE(data && data_len == 0))
		return -EINVAL;

	kv[0].iov_base = &nh;
	kv[0].iov_len = sizeof(nh);
	kv_len = 1;

	/* maybe we can have better error communication to clients */
	if (error < 0) {
		status = SCOUTFS_NET_STATUS_ERROR;
		data = NULL;
		data_len = 0;
	} else {
		status = SCOUTFS_NET_STATUS_SUCCESS;
		if (data) {
			kv[1].iov_base = data;
			kv[1].iov_len = data_len;
			kv_len++;
		}
	}

	nh.id = cpu_to_le64(id);
	nh.data_len = cpu_to_le16(data_len);
	nh.type = type;
	nh.status = status;

	trace_scoutfs_server_send_reply(conn->server->sb, &conn->sockname,
					&conn->peername, &nh);

	mutex_lock(&conn->send_mutex);
	ret = scoutfs_sock_sendmsg(conn->sock, kv, kv_len);
	mutex_unlock(&conn->send_mutex);

	return ret;
}

void scoutfs_init_ment_to_net(struct scoutfs_net_manifest_entry *net_ment,
			      struct scoutfs_manifest_entry *ment)
{
	net_ment->segno = cpu_to_le64(ment->segno);
	net_ment->seq = cpu_to_le64(ment->seq);
	net_ment->first = ment->first;
	net_ment->last = ment->last;
	net_ment->level = ment->level;
}

void scoutfs_init_ment_from_net(struct scoutfs_manifest_entry *ment,
				struct scoutfs_net_manifest_entry *net_ment)
{
	ment->segno = le64_to_cpu(net_ment->segno);
	ment->seq = le64_to_cpu(net_ment->seq);
	ment->level = net_ment->level;
	ment->first = net_ment->first;
	ment->last = net_ment->last;
}

static int process_alloc_inodes(struct server_connection *conn,
				u64 id, u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_inode_alloc ial;
	struct commit_waiter cw;
	__le64 lecount;
	u64 ino;
	u64 nr;
	int ret;

	if (data_len != sizeof(lecount)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&lecount, data, data_len);

	down_read(&server->commit_rwsem);

	spin_lock(&sbi->next_ino_lock);
	ino = le64_to_cpu(super->next_ino);
	nr = min(le64_to_cpu(lecount), U64_MAX - ino);
	le64_add_cpu(&super->next_ino, nr);
	spin_unlock(&sbi->next_ino_lock);

	queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);

	ial.ino = cpu_to_le64(ino);
	ial.nr = cpu_to_le64(nr);

	ret = wait_for_commit(server, &cw, id, type);
out:
	return send_reply(conn, id, type, ret, &ial, sizeof(ial));
}

/*
 * Give the client an extent allocation of len blocks.  We leave the
 * details to the extent allocator.
 */
static int process_alloc_extent(struct server_connection *conn,
			       u64 id, u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct commit_waiter cw;
	struct scoutfs_net_extent nex;
	__le64 leblocks;
	u64 start;
	u64 len;
	int ret;

	if (data_len != sizeof(leblocks)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&leblocks, data, data_len);

	down_read(&server->commit_rwsem);
	ret = alloc_extent(sb, le64_to_cpu(leblocks), &start, &len);
	if (ret == -ENOSPC) {
		start = 0;
		len = 0;
		ret = 0;
	}
	if (ret == 0) {
		nex.start = cpu_to_le64(start);
		nex.len = cpu_to_le64(len);
		queue_commit_work(server, &cw);
	}
	up_read(&server->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(server, &cw, id, type);
out:
	return send_reply(conn, id, type, ret, &nex, sizeof(nex));
}

/*
 * We still special case segno allocation because it's aligned and we'd
 * like to keep that detail in the server.
 */
static int process_alloc_segno(struct server_connection *conn,
			       u64 id, u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct commit_waiter cw;
	__le64 lesegno = 0;
	u64 segno;
	int ret;

	if (data_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->commit_rwsem);
	ret = alloc_segno(sb, &segno);
	if (ret == 0) {
		lesegno = cpu_to_le64(segno);
		queue_commit_work(server, &cw);
	} else if (ret == -ENOSPC) {
		ret = 0;
	}
	up_read(&server->commit_rwsem);

	if (ret == 0 && lesegno != 0)
		ret = wait_for_commit(server, &cw, id, type);
out:
	return send_reply(conn, id, type, ret, &lesegno, sizeof(lesegno));
}

static int process_record_segment(struct server_connection *conn, u64 id,
				  u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_net_manifest_entry *net_ment;
	struct scoutfs_manifest_entry ment;
	struct commit_waiter cw;
	int ret;

	if (data_len < sizeof(struct scoutfs_net_manifest_entry)) {
		ret = -EINVAL;
		goto out;
	}

	net_ment = data;

	if (data_len != sizeof(*net_ment))  {
		ret = -EINVAL;
		goto out;
	}

retry:
	down_read(&server->commit_rwsem);
	scoutfs_manifest_lock(sb);

	if (scoutfs_manifest_level0_full(sb)) {
		scoutfs_manifest_unlock(sb);
		up_read(&server->commit_rwsem);
		/* XXX waits indefinitely?  io errors? */
		wait_event(server->compaction_waitq,
			   !scoutfs_manifest_level0_full(sb));
		goto retry;
	}

	scoutfs_init_ment_from_net(&ment, net_ment);

	ret = scoutfs_manifest_add(sb, &ment);
	scoutfs_manifest_unlock(sb);

	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);

	if (ret == 0) {
		ret = wait_for_commit(server, &cw, id, type);
		if (ret == 0)
			scoutfs_compact_kick(sb);
	}
out:
	return send_reply(conn, id, type, ret, NULL, 0);
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
static int process_advance_seq(struct server_connection *conn, u64 id, u8 type,
			       void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *next_ps;
	struct pending_seq *ps;
	struct commit_waiter cw;
	__le64 * __packed their_seq = data;
	__le64 next_seq;
	int ret;

	if (data_len != sizeof(__le64)) {
		ret = -EINVAL;
		goto out;
	}

	next_ps = kmalloc(sizeof(struct pending_seq), GFP_NOFS);
	if (!next_ps) {
		ret = -ENOMEM;
		goto out;
	}

	down_read(&server->commit_rwsem);
	spin_lock(&server->seq_lock);

	list_for_each_entry(ps, &server->pending_seqs, head) {
		if (ps->seq == le64_to_cpup(their_seq)) {
			list_del_init(&ps->head);
			kfree(ps);
			break;
		}
	}

	next_seq = super->next_seq;
	le64_add_cpu(&super->next_seq, 1);

	next_ps->seq = le64_to_cpu(next_seq);
	list_add_tail(&next_ps->head, &server->pending_seqs);

	spin_unlock(&server->seq_lock);
	queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	ret = wait_for_commit(server, &cw, id, type);

out:
	return send_reply(conn, id, type, ret, &next_seq, sizeof(next_seq));
}

static int process_get_last_seq(struct server_connection *conn, u64 id,
				u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *ps;
	__le64 last_seq;
	int ret;

	if (data_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	spin_lock(&server->seq_lock);
	ps = list_first_entry_or_null(&server->pending_seqs,
				      struct pending_seq, head);
	if (ps) {
		last_seq = cpu_to_le64(ps->seq - 1);
	} else {
		last_seq = super->next_seq;
		le64_add_cpu(&last_seq, -1ULL);
	}
	spin_unlock(&server->seq_lock);
	ret = 0;
out:
	return send_reply(conn, id, type, ret, &last_seq, sizeof(last_seq));
}

static int process_get_manifest_root(struct server_connection *conn, u64 id,
				     u8 type, void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct scoutfs_btree_root root;
	unsigned int start;
	int ret;

	if (data_len == 0) {
		do {
			start = read_seqcount_begin(&server->stable_seqcount);
			root = server->stable_manifest_root;
		} while (read_seqcount_retry(&server->stable_seqcount, start));
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return send_reply(conn, id, type, ret, &root, sizeof(root));
}

/*
 * Sample the super stats that the client wants for statfs by serializing
 * with each component.
 */
static int process_statfs(struct server_connection *conn, u64 id, u8 type,
			  void *data, unsigned data_len)
{
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_statfs nstatfs;
	int ret;

	if (data_len == 0) {
		/* uuid and total_segs are constant, so far */
		memcpy(nstatfs.uuid, super->uuid, sizeof(nstatfs.uuid));

		spin_lock(&sbi->next_ino_lock);
		nstatfs.next_ino = super->next_ino;
		spin_unlock(&sbi->next_ino_lock);

		down_read(&server->alloc_rwsem);
		nstatfs.total_blocks = super->total_blocks;
		nstatfs.bfree = super->free_blocks;
		up_read(&server->alloc_rwsem);
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return send_reply(conn, id, type, ret, &nstatfs, sizeof(nstatfs));
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
 * the commit consistency mechanics inside request processing and
 * demonstrates the moving pieces that we'd need to cut up into a series
 * of messages and replies.
 *
 * The compaction work caller cleans up everything on errors.
 */
int scoutfs_client_get_compaction(struct super_block *sb, void *curs)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct commit_waiter cw;
	u64 segno;
	int ret = 0;
	int nr;
	int i;

	down_read(&server->commit_rwsem);

	nr = scoutfs_manifest_next_compact(sb, curs);
	if (nr <= 0) {
		up_read(&server->commit_rwsem);
		return nr;
	}

	/* allow for expansion slop from sticky and alignment */
	for (i = 0; i < nr + SCOUTFS_COMPACTION_SLOP; i++) {
		ret = alloc_segno(sb, &segno);
		if (ret < 0)
			break;
		scoutfs_compact_add_segno(sb, curs, segno);
	}

	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(server, &cw, U64_MAX, 1);

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
int scoutfs_client_finish_compaction(struct super_block *sb, void *curs,
				     void *list)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct commit_waiter cw;
	bool level0_was_full;
	int ret;

	down_read(&server->commit_rwsem);

	level0_was_full = scoutfs_manifest_level0_full(sb);

	ret = scoutfs_compact_commit(sb, curs, list);
	if (ret == 0) {
		queue_commit_work(server, &cw);
		if (level0_was_full && !scoutfs_manifest_level0_full(sb))
			wake_up(&server->compaction_waitq);
	}

	up_read(&server->commit_rwsem);

	if (ret == 0)
		ret = wait_for_commit(server, &cw, U64_MAX, 2);

	scoutfs_compact_kick(sb);

	return ret;
}

typedef int (*process_func_t)(struct server_connection *conn, u64 id,
			      u8 type, void *data, unsigned data_len);

/*
 * Each request message gets its own concurrent blocking request processing
 * context.
 */
static void scoutfs_server_process_func(struct work_struct *work)
{
	struct server_request *req = container_of(work, struct server_request,
						  work);
	struct server_connection *conn = req->conn;
	static process_func_t process_funcs[] = {
		[SCOUTFS_NET_ALLOC_INODES]	= process_alloc_inodes,
		[SCOUTFS_NET_ALLOC_EXTENT]	= process_alloc_extent,
		[SCOUTFS_NET_ALLOC_SEGNO]	= process_alloc_segno,
		[SCOUTFS_NET_RECORD_SEGMENT]	= process_record_segment,
		[SCOUTFS_NET_ADVANCE_SEQ]	= process_advance_seq,
		[SCOUTFS_NET_GET_LAST_SEQ]	= process_get_last_seq,
		[SCOUTFS_NET_GET_MANIFEST_ROOT]	= process_get_manifest_root,
		[SCOUTFS_NET_STATFS]		= process_statfs,
	};
	struct scoutfs_net_header *nh = &req->nh;
	process_func_t func;
	int ret;

	if (nh->type < ARRAY_SIZE(process_funcs))
		func = process_funcs[nh->type];
	else
		func = NULL;

	if (func)
		ret = func(conn, le64_to_cpu(nh->id), nh->type, nh->data,
			   le16_to_cpu(nh->data_len));
	else
		ret = -EINVAL;

	if (ret)
		kernel_sock_shutdown(conn->sock, SHUT_RDWR);

	/* process_one_work explicitly allows freeing work in its func */
	kfree(req);
}

/*
 * Always block receiving from the socket.  This owns the socket.  If
 * receive fails this shuts down and frees the socket.
 */
static void scoutfs_server_recv_func(struct work_struct *work)
{
	struct server_connection *conn = container_of(work,
						      struct server_connection,
						      recv_work);
	struct server_info *server = conn->server;
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct socket *sock = conn->sock;
	struct workqueue_struct *req_wq;
	struct scoutfs_net_greeting greet;
	struct scoutfs_net_header nh;
	struct server_request *req;
	bool passed_greeting;
	unsigned data_len;
	struct kvec kv;
	int ret;

	trace_scoutfs_server_recv_work_enter(sb, 0, 0);

	req_wq = alloc_workqueue("scoutfs_server_requests",
				 WQ_NON_REENTRANT, 0);
	if (!req_wq) {
		ret = -ENOMEM;
		goto out;
	}

	/* first bounce the greeting */
	ret = scoutfs_sock_recvmsg(sock, &greet, sizeof(greet));
	if (ret)
		goto out;

	/* we'll close conn after failed greeting to let client see ours */
	passed_greeting = false;

	if (greet.fsid != super->id) {
		scoutfs_warn(sb, "client "SIN_FMT" has fsid 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(greet.fsid),
			     le64_to_cpu(super->id));
	} else if (greet.format_hash != super->format_hash) {
		scoutfs_warn(sb, "client "SIN_FMT" has format hash 0x%llx, expected 0x%llx",
			     SIN_ARG(&conn->peername),
			     le64_to_cpu(greet.format_hash),
			     le64_to_cpu(super->format_hash));
	} else {
		passed_greeting = true;
	}

	greet.fsid = super->id;
	greet.format_hash = super->format_hash;
	kv.iov_base = &greet;
	kv.iov_len = sizeof(greet);
	ret = scoutfs_sock_sendmsg(sock, &kv, 1);
	if (ret)
		goto out;

	for (;;) {
		/* receive the header */
		ret = scoutfs_sock_recvmsg(sock, &nh, sizeof(nh));
		if (ret)
			break;

		if (!passed_greeting)
			break;

		trace_scoutfs_server_recv_request(conn->server->sb,
						  &conn->sockname,
						  &conn->peername, &nh);

		/* XXX verify data_len isn't insane */
		/* XXX test for bad messages */
		data_len = le16_to_cpu(nh.data_len);

		req = kmalloc(sizeof(struct server_request) + data_len,
			      GFP_NOFS);
		if (!req) {
			ret = -ENOMEM;
			break;
		}

		ret = scoutfs_sock_recvmsg(sock, req->nh.data, data_len);
		if (ret)
			break;

		req->conn = conn;
		INIT_WORK(&req->work, scoutfs_server_process_func);
		req->nh = nh;

		queue_work(req_wq, &req->work);
		/* req is freed by its work func */
		req = NULL;
	}

out:
	scoutfs_info(sb, "server closing "SIN_FMT" -> "SIN_FMT,
		     SIN_ARG(&conn->peername), SIN_ARG(&conn->sockname));

	/* make sure reply sending returns */
	kernel_sock_shutdown(conn->sock, SHUT_RDWR);

	/* wait for processing work to drain */
	if (req_wq) {
		drain_workqueue(req_wq);
		destroy_workqueue(req_wq);
	}

	/* process_one_work explicitly allows freeing work in its func */
	mutex_lock(&server->mutex);
	sock_release(conn->sock);
	list_del_init(&conn->head);
	kfree(conn);
	smp_mb();
	wake_up_process(server->listen_task);
	mutex_unlock(&server->mutex);

	trace_scoutfs_server_recv_work_exit(sb, 0, ret);
}

/*
 * This relies on the caller having read the current super and advanced
 * its seq so that it's dirty.  This will go away when we communicate
 * the server address in a lock lvb.
 */
static int write_server_addr(struct super_block *sb, struct sockaddr_in *sin)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	super->server_addr.addr = be32_to_le32(sin->sin_addr.s_addr);
	super->server_addr.port = be16_to_le16(sin->sin_port);

	return scoutfs_write_dirty_super(sb);
}

static bool barrier_list_empty_careful(struct list_head *list)
{
	/* store caller's task state before loading wake condition */
	smp_mb();

	return list_empty_careful(list);
}

/*
 * This work is always running or has a delayed timer set while a super
 * is mounted.  It tries to grab the lock to become the server.  If it
 * succeeds it publishes its address and accepts connections.  If
 * anything goes wrong it releases the lock and sets a timer to try to
 * become the server all over again.
 */
static void scoutfs_server_func(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  dwork.work);
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	static struct sockaddr_in zeros = {0,};
	struct socket *new_sock;
	struct socket *sock = NULL;
	struct scoutfs_lock *lock = NULL;
	struct server_connection *conn;
	struct pending_seq *ps;
	struct pending_seq *ps_tmp;
	DECLARE_WAIT_QUEUE_HEAD(waitq);
	struct sockaddr_in sin;
	LIST_HEAD(conn_list);
	int addrlen;
	int optval;
	int ret;

	trace_scoutfs_server_work_enter(sb, 0, 0);

	init_waitqueue_head(&waitq);

	ret = scoutfs_lock_global(sb, DLM_LOCK_EX, 0,
				  SCOUTFS_LOCK_TYPE_GLOBAL_SERVER, &lock);
	if (ret)
		goto out;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = le32_to_be32(sbi->opts.listen_addr.addr);
	sin.sin_port = le16_to_be16(sbi->opts.listen_addr.port);

	optval = 1;
	ret = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) ?:
	      kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			        (char *)&optval, sizeof(optval)) ?:
	      kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			        (char *)&optval, sizeof(optval));
	if (ret)
		goto out;

	addrlen = sizeof(sin);
	ret = kernel_bind(sock, (struct sockaddr *)&sin, addrlen);
	if (ret) {
		if (!server->bind_warned) {
			scoutfs_err(sb, "server failed to bind to "SIN_FMT", errno %d%s.  Retrying indefinitely..",
				    SIN_ARG(&sin), ret,
				    ret == -EADDRNOTAVAIL ? " (Bad address?)"
							  : "");
			server->bind_warned = true;
		}
		goto out;
	}
	server->bind_warned = false;

	kernel_getsockname(sock, (struct sockaddr *)&sin, &addrlen);
	if (ret)
		goto out;

	ret = kernel_listen(sock, 255);
	if (ret)
		goto out;

	/* publish the address for clients to connect to */
	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	scoutfs_advance_dirty_super(sb);
	ret = write_server_addr(sb, &sin);
	if (ret)
		goto out;

	/* either see shutting down or they'll shutdown our sock */
	mutex_lock(&server->mutex);
	server->listen_task = current;
	server->listen_sock = sock;
	if (server->shutting_down)
		ret = -ESHUTDOWN;
	mutex_unlock(&server->mutex);
	if (ret)
		goto out;

	/* finally start up the server subsystems before accepting */
	ret = scoutfs_btree_setup(sb) ?:
	      scoutfs_manifest_setup(sb) ?:
	      scoutfs_compact_setup(sb);
	if (ret)
		goto shutdown;

	scoutfs_advance_dirty_super(sb);
	server->stable_manifest_root = super->manifest.root;

	scoutfs_info(sb, "server started on "SIN_FMT, SIN_ARG(&sin));

	for (;;) {
		ret = kernel_accept(sock, &new_sock, 0);
		if (ret < 0)
			break;

		conn = kmalloc(sizeof(struct server_connection), GFP_NOFS);
		if (!conn) {
			sock_release(new_sock);
			ret = -ENOMEM;
			continue;
		}

		addrlen = sizeof(struct sockaddr_in);
		ret = kernel_getsockname(new_sock,
					 (struct sockaddr *)&conn->sockname,
					 &addrlen) ?:
		      kernel_getpeername(new_sock,
					 (struct sockaddr *)&conn->peername,
					 &addrlen);
		if (ret) {
			sock_release(new_sock);
			continue;
		}

		/*
		 * XXX yeah, ok, killing the sock and accepting a new
		 * one is racey.  think about that in all the code.  Are
		 * we destroying a resource to shutdown that the thing
		 * we're canceling creates?
		 */

		conn->server = server;
		conn->sock = new_sock;
		mutex_init(&conn->send_mutex);

		scoutfs_info(sb, "server accepted "SIN_FMT" -> "SIN_FMT,
			     SIN_ARG(&conn->peername),
			     SIN_ARG(&conn->sockname));

		/* recv work owns the conn once its in the list */
		mutex_lock(&server->mutex);
		list_add(&conn->head, &conn_list);
		mutex_unlock(&server->mutex);

		INIT_WORK(&conn->recv_work, scoutfs_server_recv_func);
		queue_work(server->wq, &conn->recv_work);
	}

	/* shutdown send and recv on all accepted sockets */
	mutex_lock(&server->mutex);
	list_for_each_entry(conn, &conn_list, head)
		kernel_sock_shutdown(conn->sock, SHUT_RDWR);
	mutex_unlock(&server->mutex);

	/* wait for all recv work to finish and free connections */
	wait_event(waitq, barrier_list_empty_careful(&conn_list));

	scoutfs_info(sb, "server shutting down on "SIN_FMT, SIN_ARG(&sin));

shutdown:

	/* shut down all the server subsystems */
	scoutfs_compact_destroy(sb);
	destroy_pending_frees(sb);
	scoutfs_manifest_destroy(sb);
	scoutfs_btree_destroy(sb);

	/* XXX these should be persistent and reclaimed during recovery */
	list_for_each_entry_safe(ps, ps_tmp, &server->pending_seqs, head) {
		list_del_init(&ps->head);
		kfree(ps);
	}

	write_server_addr(sb, &zeros);

out:
	if (sock)
		sock_release(sock);

	scoutfs_unlock(sb, lock, DLM_LOCK_EX);

	/* always requeues, cancel_delayed_work_sync cancels on shutdown */
	queue_delayed_work(server->wq, &server->dwork, HZ / 2);

	trace_scoutfs_server_work_exit(sb, 0, ret);
}

int scoutfs_server_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server;

	server = kzalloc(sizeof(struct server_info), GFP_KERNEL);
	if (!server)
		return -ENOMEM;

	server->sb = sb;
	INIT_DELAYED_WORK(&server->dwork, scoutfs_server_func);
	mutex_init(&server->mutex);
	init_rwsem(&server->commit_rwsem);
	init_llist_head(&server->commit_waiters);
	INIT_WORK(&server->commit_work, scoutfs_server_commit_func);
	init_waitqueue_head(&server->compaction_waitq);
	seqcount_init(&server->stable_seqcount);
	spin_lock_init(&server->seq_lock);
	INIT_LIST_HEAD(&server->pending_seqs);
	init_rwsem(&server->alloc_rwsem);
	INIT_LIST_HEAD(&server->pending_frees);

	server->wq = alloc_workqueue("scoutfs_server", WQ_NON_REENTRANT, 0);
	if (!server->wq) {
		kfree(server);
		return -ENOMEM;
	}

	queue_delayed_work(server->wq, &server->dwork, 0);

	sbi->server_info = server;
	return 0;
}

void scoutfs_server_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server = sbi->server_info;

	if (server) {
		shut_down_server(server);

		/* wait for server work to wait for everything to shut down */
		cancel_delayed_work_sync(&server->dwork);
		/* recv work/compaction could have left commit_work queued */
		cancel_work_sync(&server->commit_work);

		trace_scoutfs_server_workqueue_destroy(sb, 0, 0);
		destroy_workqueue(server->wq);

		kfree(server);
		sbi->server_info = NULL;
	}
}
