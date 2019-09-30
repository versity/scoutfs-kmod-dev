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
#include <asm/unaligned.h>

#include "format.h"
#include "counters.h"
#include "inode.h"
#include "block.h"
#include "balloc.h"
#include "btree.h"
#include "manifest.h"
#include "seg.h"
#include "compact.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "server.h"
#include "net.h"
#include "lock_server.h"
#include "endian_swap.h"
#include "quorum.h"

/*
 * Every active mount can act as the server that listens on a net
 * connection and accepts connections from all the other mounts acting
 * as clients.
 *
 * The server is started by the mount that is elected leader by quorum.
 * If it sees errors it shuts down the server in the hopes that another
 * mount will become the leader and have less trouble.
 */

struct server_info {
	struct super_block *sb;
	spinlock_t lock;
	wait_queue_head_t waitq;

	struct workqueue_struct *wq;
	struct work_struct work;
	int err;
	bool shutting_down;
	struct completion start_comp;
	struct sockaddr_in listen_sin;
	u64 term;
	struct scoutfs_net_connection *conn;

	/* request processing coordinates committing manifest and alloc */
	struct rw_semaphore commit_rwsem;
	struct llist_head commit_waiters;
	struct work_struct commit_work;

	/* server remembers the stable manifest root for clients */
	seqcount_t stable_seqcount;
	struct scoutfs_btree_root stable_manifest_root;

	/* server tracks seq use */
	struct rw_semaphore seq_rwsem;

	/* server tracks pending frees to be applied during commit */
	struct rw_semaphore alloc_rwsem;
	struct list_head pending_frees;

	struct list_head clients;
	unsigned long nr_clients;

	/* track compaction in flight */
	unsigned long compacts_per_client;
	unsigned long nr_compacts;
	struct list_head compacts;
	struct work_struct compact_work;

	/* track clients waiting in unmmount for farewell response */
	struct mutex farewell_mutex;
	struct list_head farewell_requests;
	struct work_struct farewell_work;

	struct scoutfs_balloc_allocator alloc;
	struct scoutfs_block_writer wri;

	struct mutex logs_mutex;
};

#define DECLARE_SERVER_INFO(sb, name) \
	struct server_info *name = SCOUTFS_SB(sb)->server_info

/*
 * The server tracks each connected client.
 */
struct server_client_info {
	u64 rid;
	struct list_head head;
	unsigned long nr_compacts;
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
 *
 * The free_blocks count in the super tracks the number of blocks in
 * the primary extent index.  We update it here instead of expecting
 * callers to remember.
 */
static int server_extent_io(struct super_block *sb, int op,
			    struct scoutfs_extent *ext, void *data)
{
	DECLARE_SERVER_INFO(sb, server);
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
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->alloc_root,
					   &ebk, sizeof(ebk), NULL, 0);

	} else if (op == SEI_DELETE) {
		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->alloc_root,
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

	if (ret == 0 && ext->type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE) {
		if (op == SEI_INSERT)
			le64_add_cpu(&super->free_blocks, ext->len);
		else if (op == SEI_DELETE)
			le64_add_cpu(&super->free_blocks, -ext->len);
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
static int free_segno(struct super_block *sb, u64 segno)
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
 * "allocating" a segno removes an unknown segment from the allocator
 * and returns it, "removing" a segno removes a specific segno from the
 * allocator.
 */
static int remove_segno(struct super_block *sb, u64 segno)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_extent ext;
	int ret;

	trace_scoutfs_remove_segno(sb, segno);

	scoutfs_extent_init(&ext, SCOUTFS_FREE_EXTENT_BLKNO_TYPE, 0,
			    segno << SCOUTFS_SEGMENT_BLOCK_SHIFT,
			    SCOUTFS_SEGMENT_BLOCKS, 0, 0);

	down_write(&server->alloc_rwsem);
	ret = scoutfs_extent_remove(sb, server_extent_io, &ext, NULL);
	up_write(&server->alloc_rwsem);
	return ret;
}

static void stop_server(struct server_info *server)
{
	/* wait_event/wake_up provide barriers */
	server->shutting_down = true;
	wake_up(&server->waitq);
}

/*
 * Queue compaction work if clients have capacity for processing
 * requests and the manifest knows of levels with too many segments.
 */
static void try_queue_compact(struct server_info *server)
{
	struct super_block *sb = server->sb;
	bool can_request;

	spin_lock(&server->lock);
	can_request = server->nr_compacts <
		      (server->nr_clients * server->compacts_per_client);
	spin_unlock(&server->lock);
	if (can_request && scoutfs_manifest_should_compact(sb))
		queue_work(server->wq, &server->compact_work);
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
 * Wait for a commit during request processing and return its status.
 */
static inline int wait_for_commit(struct commit_waiter *cw)
{
	wait_for_completion(&cw->comp);
	return cw->ret;
}

/*
 * Add newly initialized free metadata block allocator items to the core
 * block allocator.  This is called as we commit transactions in the
 * server.  It adds many more free blocks than is ever consumed by a
 * transaction so this will stay ahead of the server's block allocation.
 * The intent is to have a low constant overhead to initializing block
 * allocators over time instead of requiring a large amount of IO during
 * mkfs.
 */
static int add_uninit_balloc_items(struct super_block *sb,
				   struct server_info *server,
				   struct scoutfs_super_block *super)
{
	u64 next = le64_to_cpu(super->next_uninit_free_block);
	u64 total = le64_to_cpu(super->total_blocks);
	u64 nr;
	int ret;

	/* next_uninit should always start a new item */
	if (WARN_ON_ONCE(next & SCOUTFS_BALLOC_ITEM_BIT_MASK))
		return -EIO;

	nr = min_t(u64, total - next,
		   round_up(512 * 1024 * 1024 / SCOUTFS_BLOCK_SIZE,
			    SCOUTFS_BALLOC_ITEM_BITS));

	ret = scoutfs_balloc_add_alloc_bulk(sb, &server->alloc, &server->wri,
					    next, nr);
	if (ret == 0)
		le64_add_cpu(&super->next_uninit_free_block, nr);

	return ret;
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
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct commit_waiter *cw;
	struct commit_waiter *pos;
	struct llist_node *node;
	int ret;

	trace_scoutfs_server_commit_work_enter(sb, 0, 0);

	down_write(&server->commit_rwsem);

	/* try to free first which can dirty the btrees */
	ret = apply_pending_frees(sb);
	if (ret) {
		scoutfs_err(sb, "server error freeing extents: %d", ret);
		goto out;
	}

	/* XXX not sure what to do about failure here */
	ret = add_uninit_balloc_items(sb, server, super);
	BUG_ON(ret);

	ret = scoutfs_block_writer_write(sb, &server->wri);
	if (ret) {
		scoutfs_err(sb, "server error writing btree blocks: %d", ret);
		goto out;
	}

	super->core_balloc_alloc = server->alloc.alloc_root;
	super->core_balloc_free = server->alloc.free_root;

	ret = scoutfs_write_super(sb, super);
	if (ret) {
		scoutfs_err(sb, "server error writing super block: %d", ret);
		goto out;
	}

	write_seqcount_begin(&server->stable_seqcount);
	server->stable_manifest_root = SCOUTFS_SB(sb)->super.manifest.root;
	write_seqcount_end(&server->stable_seqcount);

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

static int server_alloc_inodes(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_inode_alloc ial = { 0, };
	struct commit_waiter cw;
	__le64 lecount;
	u64 ino;
	u64 nr;
	int ret;

	if (arg_len != sizeof(lecount)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&lecount, arg, arg_len);

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

	ret = wait_for_commit(&cw);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &ial, sizeof(ial));
}

/*
 * Give the client an extent allocation of len blocks.  We leave the
 * details to the extent allocator.
 */
static int server_alloc_extent(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct commit_waiter cw;
	struct scoutfs_net_extent nex = {0,};
	__le64 leblocks;
	u64 start;
	u64 len;
	int ret;

	if (arg_len != sizeof(leblocks)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&leblocks, arg, arg_len);

	down_read(&server->commit_rwsem);
	ret = alloc_extent(sb, le64_to_cpu(leblocks), &start, &len);
	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);
	if (ret)
		goto out;

	nex.start = cpu_to_le64(start);
	nex.len = cpu_to_le64(len);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &nex, sizeof(nex));
}

static bool invalid_net_extent_list(struct scoutfs_net_extent_list *nexl,
				    unsigned data_len)
{
	return (data_len < sizeof(struct scoutfs_net_extent_list)) ||
	       (le64_to_cpu(nexl->nr) > SCOUTFS_NET_EXTENT_LIST_MAX_NR) ||
	       (data_len != offsetof(struct scoutfs_net_extent_list,
				    extents[le64_to_cpu(nexl->nr)]));
}

static int server_free_extents(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_net_extent_list *nexl;
	struct commit_waiter cw;
	int ret = 0;
	int err;
	u64 i;

	nexl = arg;
	if (invalid_net_extent_list(nexl, arg_len)) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->commit_rwsem);

	for (i = 0; i < le64_to_cpu(nexl->nr); i++) {
		ret = free_extent(sb, le64_to_cpu(nexl->extents[i].start),
				  le64_to_cpu(nexl->extents[i].len));
		if (ret)
			break;
	}

	if (i > 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);

	if (i > 0) {
		err = wait_for_commit(&cw);
		if (ret == 0)
			ret = err;
	}

out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/*
 * We still special case segno allocation because it's aligned and we'd
 * like to keep that detail in the server.
 */
static int server_alloc_segno(struct super_block *sb,
			      struct scoutfs_net_connection *conn,
			      u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct commit_waiter cw;
	__le64 lesegno = 0;
	u64 segno;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->commit_rwsem);
	ret = alloc_segno(sb, &segno);
	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);
	if (ret)
		goto out;

	lesegno = cpu_to_le64(segno);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &lesegno, sizeof(lesegno));
}

static int server_record_segment(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_net_manifest_entry *net_ment;
	struct scoutfs_manifest_entry ment;
	struct commit_waiter cw;
	int ret;

	if (arg_len != sizeof(struct scoutfs_net_manifest_entry)) {
		ret = -EINVAL;
		goto out;
	}

	net_ment = arg;

retry:
	down_read(&server->commit_rwsem);
	scoutfs_manifest_lock(sb);

	if (scoutfs_manifest_level0_full(sb)) {
		scoutfs_manifest_unlock(sb);
		up_read(&server->commit_rwsem);
		/* XXX waits indefinitely?  io errors? */
		wait_event(server->waitq, !scoutfs_manifest_level0_full(sb));
		goto retry;
	}

	scoutfs_init_ment_from_net(&ment, net_ment);

	ret = scoutfs_manifest_add(sb, &ment);
	scoutfs_manifest_unlock(sb);

	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);

	if (ret == 0) {
		ret = wait_for_commit(&cw);
		if (ret == 0)
			try_queue_compact(server);
	}

out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/*
 * Give the client references to stable persistent trees that they'll
 * use to write their next transaction.
 */
static int server_get_log_trees(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	u64 rid = scoutfs_net_client_rid(conn);
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees_key ltk;
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_log_trees lt;
	struct commit_waiter cw;
	u64 next_past;
	u64 at_least;
	u64 target;
	u64 from;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->commit_rwsem);

	mutex_lock(&server->logs_mutex);

	memset(&ltk, 0, sizeof(ltk));
	ltk.rid = cpu_to_be64(rid);
	ltk.nr = cpu_to_be64(U64_MAX);

	ret = scoutfs_btree_prev(sb, &super->logs_root,
				 &ltk, sizeof(ltk), &iref);
	if (ret < 0 && ret != -ENOENT)
		goto unlock;
	if (ret == 0) {
		if (iref.key_len == sizeof(struct scoutfs_log_trees_key) &&
		    iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			memcpy(&ltk, iref.key, iref.key_len);
			memcpy(&ltv, iref.val, iref.val_len);
			if (be64_to_cpu(ltk.rid) != rid)
				ret = -ENOENT;
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret == -EIO)
			goto unlock;
	}

	/* initialize new roots if we don't have any */
	if (ret == -ENOENT) {
		ltk.rid = cpu_to_be64(rid);
		ltk.nr = cpu_to_be64(1);
		memset(&ltv, 0, sizeof(ltv));
	}

	target = (64*1024*1024) / SCOUTFS_BLOCK_SIZE;

	/* XXX arbitrarily give client enough metadata for a transaction */
	while (le64_to_cpu(ltv.alloc_root.total_free) < target) {
		from = le64_to_cpu(super->core_balloc_cursor);
		at_least = target - le64_to_cpu(ltv.alloc_root.total_free);

		ret = scoutfs_balloc_move(sb, &server->alloc, &server->wri,
					  &ltv.alloc_root,
					  &server->alloc.alloc_root,
					  from, at_least, &next_past);
		if (ret == -ENOENT && from != 0) {
			super->core_balloc_cursor = 0;
			continue;
		}
		if (ret < 0)
			goto unlock;

		super->core_balloc_cursor = cpu_to_le64(next_past);

	}

	/* update client's log tree's item */
	ret = scoutfs_btree_force(sb, &server->alloc, &server->wri,
				  &super->logs_root, &ltk, sizeof(ltk),
				  &ltv, sizeof(ltv));
unlock:
	mutex_unlock(&server->logs_mutex);

	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);

	if (ret == 0) {
		lt.alloc_root = ltv.alloc_root;
		lt.free_root = ltv.free_root;
		lt.item_root = ltv.item_root;
		lt.bloom_ref = ltv.bloom_ref;
		lt.rid = be64_to_le64(ltk.rid);
		lt.nr = be64_to_le64(ltk.nr);
	}

out:
	WARN_ON_ONCE(ret < 0);
	return scoutfs_net_response(sb, conn, cmd, id, ret, &lt, sizeof(lt));
}

/*
 * The client is sending the roots of all the btree blocks that they
 * wrote to their free space for their transaction.  Make it persistent
 * by referencing the roots from their log item in the logs root and
 * committing.
 */
static int server_commit_log_trees(struct super_block *sb,
				   struct scoutfs_net_connection *conn,
				   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees_key ltk;
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_log_trees *lt;
	struct commit_waiter cw;
	int ret;

	if (arg_len != sizeof(struct scoutfs_log_trees)) {
		ret = -EINVAL;
		goto out;
	}
	lt = arg;

	down_read(&server->commit_rwsem);
	mutex_lock(&server->logs_mutex);

	/* find the client's existing item */
	memset(&ltk, 0, sizeof(ltk));
	ltk.rid = le64_to_be64(lt->rid);
	ltk.nr = le64_to_be64(lt->nr);
	ret = scoutfs_btree_lookup(sb, &super->logs_root,
				   &ltk, sizeof(ltk), &iref);
	if (ret < 0 && ret != -ENOENT)
		goto unlock;
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			memcpy(&ltv, iref.val, iref.val_len);
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto unlock;
	}

	ltv.alloc_root = lt->alloc_root;
	ltv.free_root = lt->free_root;
	ltv.item_root = lt->item_root;
	ltv.bloom_ref = lt->bloom_ref;

	ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				   &super->logs_root, &ltk, sizeof(ltk),
				   &ltv, sizeof(ltv));

unlock:
	mutex_unlock(&server->logs_mutex);

	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);
out:
	WARN_ON_ONCE(ret < 0);
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/*
 * Give the client the next sequence number for their transaction.  They
 * provide their previous transaction sequence number that they've
 * committed.
 *
 * We track the sequence numbers of transactions that clients have open.
 * This limits the transaction sequence numbers that can be returned in
 * the index of inodes by meta and data transaction numbers.  We
 * communicate the largest possible sequence number to clients via an
 * rpc.
 *
 * The transaction sequence tracking is stored in a btree so it is
 * shared across servers.  Final entries are removed when processing a
 * client's farewell or when it's removed.
 */
static int server_advance_seq(struct super_block *sb,
			      struct scoutfs_net_connection *conn,
			      u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct commit_waiter cw;
	__le64 their_seq;
	__le64 next_seq;
	struct scoutfs_trans_seq_btree_key tsk;
	u64 rid = scoutfs_net_client_rid(conn);
	int ret;

	if (arg_len != sizeof(__le64)) {
		ret = -EINVAL;
		goto out;
	}
	memcpy(&their_seq, arg, sizeof(their_seq));

	down_read(&server->commit_rwsem);
	down_write(&server->seq_rwsem);

	if (their_seq != 0) {
		tsk.trans_seq = le64_to_be64(their_seq);
		tsk.rid = cpu_to_be64(rid);

		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->trans_seqs,
					   &tsk, sizeof(tsk));
		if (ret < 0 && ret != -ENOENT)
			goto out;
	}

	next_seq = super->next_trans_seq;
	le64_add_cpu(&super->next_trans_seq, 1);

	trace_scoutfs_trans_seq_advance(sb, rid, le64_to_cpu(their_seq),
					le64_to_cpu(next_seq));

	tsk.trans_seq = le64_to_be64(next_seq);
	tsk.rid = cpu_to_be64(rid);

	ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				   &super->trans_seqs,
				   &tsk, sizeof(tsk), NULL, 0);
out:
	up_write(&server->seq_rwsem);
	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);

	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &next_seq, sizeof(next_seq));
}

/*
 * Remove any transaction sequences owned by the client.  They must have
 * committed any final transaction by the time they get here via sending
 * their farewell message.  This can be called multiple times as the
 * client's farewell is retransmitted so it's OK to not find any
 * entries.  This is called with the server commit rwsem held.
 */
static int remove_trans_seq(struct super_block *sb, u64 rid)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_trans_seq_btree_key tsk;
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret = 0;

	down_write(&server->seq_rwsem);

	tsk.trans_seq = 0;
	tsk.rid = 0;

	for (;;) {
		ret = scoutfs_btree_next(sb, &super->trans_seqs,
					 &tsk, sizeof(tsk), &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		memcpy(&tsk, iref.key, iref.key_len);
		scoutfs_btree_put_iref(&iref);

		if (be64_to_cpu(tsk.rid) == rid) {
			trace_scoutfs_trans_seq_farewell(sb, rid,
						be64_to_cpu(tsk.trans_seq));
			ret = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->trans_seqs,
						   &tsk, sizeof(tsk));
			break;
		}

		be64_add_cpu(&tsk.trans_seq, 1);
		tsk.rid = 0;
	}

	up_write(&server->seq_rwsem);

	return ret;
}

/*
 * Give the calling client the last valid trans_seq that it can return
 * in results from the indices of trans seqs to inodes.  These indices
 * promise to only advance so we can't return results past those that
 * are still outstanding and not yet visible in the indices.  If there
 * are no outstanding transactions (what?  how?) we give them the max
 * possible sequence.
 */
static int server_get_last_seq(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_trans_seq_btree_key tsk;
	SCOUTFS_BTREE_ITEM_REF(iref);
	u64 rid = scoutfs_net_client_rid(conn);
	__le64 last_seq = 0;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->seq_rwsem);

	tsk.trans_seq = 0;
	tsk.rid = 0;

	ret = scoutfs_btree_next(sb, &super->trans_seqs,
				 &tsk, sizeof(tsk), &iref);
	if (ret == 0) {
		if (iref.key_len != sizeof(tsk)) {
			ret = -EINVAL;
		} else {
			memcpy(&tsk, iref.key, iref.key_len);
			last_seq = cpu_to_le64(be64_to_cpu(tsk.trans_seq) - 1);
		}
		scoutfs_btree_put_iref(&iref);

	} else if (ret == -ENOENT) {
		last_seq = super->next_trans_seq;
		le64_add_cpu(&last_seq, -1ULL);
		ret = 0;
	}

	trace_scoutfs_trans_seq_last(sb, rid, le64_to_cpu(last_seq));

	up_read(&server->seq_rwsem);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &last_seq, sizeof(last_seq));
}

static int server_get_manifest_root(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_btree_root root;
	unsigned int start;
	int ret;

	if (arg_len == 0) {
		do {
			start = read_seqcount_begin(&server->stable_seqcount);
			root = server->stable_manifest_root;
		} while (read_seqcount_retry(&server->stable_seqcount, start));
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &root, sizeof(root));
}

/*
 * Sample the super stats that the client wants for statfs by serializing
 * with each component.
 */
static int server_statfs(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_statfs nstatfs;
	int ret;

	if (arg_len == 0) {
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

	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &nstatfs, sizeof(nstatfs));
}

static int server_lock(struct super_block *sb,
		       struct scoutfs_net_connection *conn,
		       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (arg_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_request(sb, rid, id, arg);
}

static int lock_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 void *resp, unsigned int resp_len,
			 int error, void *data)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (resp_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_response(sb, rid, resp);
}

int scoutfs_server_lock_request(struct super_block *sb, u64 rid,
				struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_submit_request_node(sb, server->conn, rid,
					      SCOUTFS_NET_CMD_LOCK,
					      nl, sizeof(*nl),
					      lock_response, NULL, NULL);
}

int scoutfs_server_lock_response(struct super_block *sb, u64 rid,
				 u64 id, struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_response_node(sb, server->conn, rid,
					 SCOUTFS_NET_CMD_LOCK, id, 0,
					 nl, sizeof(*nl));
}

static bool invalid_recover(struct scoutfs_net_lock_recover *nlr,
			    unsigned long bytes)
{
	return ((bytes < sizeof(*nlr)) ||
	        (bytes != offsetof(struct scoutfs_net_lock_recover,
			       locks[le16_to_cpu(nlr->nr)])));
}

static int lock_recover_response(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 void *resp, unsigned int resp_len,
				 int error, void *data)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (invalid_recover(resp, resp_len))
		return -EINVAL;

	return scoutfs_lock_server_recover_response(sb, rid, resp);
}

int scoutfs_server_lock_recover_request(struct super_block *sb, u64 rid,
					struct scoutfs_key *key)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_submit_request_node(sb, server->conn, rid,
					      SCOUTFS_NET_CMD_LOCK_RECOVER,
					      key, sizeof(*key),
					      lock_recover_response,
					      NULL, NULL);
}

static int insert_mounted_client(struct super_block *sb, u64 rid,
				 u64 gr_flags)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_mounted_client_btree_key mck;
	struct scoutfs_mounted_client_btree_val mcv;

	mck.rid = cpu_to_be64(rid);
	mcv.flags = 0;
	if (gr_flags & SCOUTFS_NET_GREETING_FLAG_VOTER)
		mcv.flags |= SCOUTFS_MOUNTED_CLIENT_VOTER;

	return scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				    &super->mounted_clients,
				    &mck, sizeof(mck), &mcv, sizeof(mcv));
}

/*
 * Remove the record of a mounted client.  The record can already be
 * removed if we're processing a farewell on behalf of a client that
 * already had a previous server process its farewell.
 *
 * When we remove the last mounted client that's voting we write a new
 * quorum block with the updated unmount_barrier.
 *
 * The caller has to serialize with farewell processing.
 */
static int delete_mounted_client(struct super_block *sb, u64 rid)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_mounted_client_btree_key mck;
	int ret;

	mck.rid = cpu_to_be64(rid);

	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->mounted_clients,
				   &mck, sizeof(mck));
	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

/*
 * Process an incoming greeting request in the server from the client.
 * We try to send responses to failed greetings so that the sender can
 * log some detail before shutting down.  A failure to send a greeting
 * response shuts down the connection.
 *
 * If a client reconnects they'll send their previously received
 * serer_term in their greeting request.
 *
 * XXX The logic of this has gotten convoluted.  The lock server can
 * send a recovery request so it needs to be called after the core net
 * greeting call enables messages.  But we want the greeting reply to be
 * sent first, so we currently queue it on the send queue before
 * enabling messages.  That means that a lot of errors that happen after
 * the reply can't be sent to the client.  They'll just see a disconnect
 * and won't know what's happened.  This all needs to be refactored.
 */
static int server_greeting(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_net_greeting *gr = arg;
	struct scoutfs_net_greeting greet;
	DECLARE_SERVER_INFO(sb, server);
	struct commit_waiter cw;
	__le64 umb = 0;
	bool reconnecting;
	bool first_contact;
	bool farewell;
	int ret = 0;
	int err;

	if (arg_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto send_err;
	}

	if (gr->fsid != super->hdr.fsid) {
		scoutfs_warn(sb, "client sent fsid 0x%llx, server has 0x%llx",
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->hdr.fsid));
		ret = -EINVAL;
		goto send_err;
	}

	if (gr->format_hash != super->format_hash) {
		scoutfs_warn(sb, "client sent format 0x%llx, server has 0x%llx",
			     le64_to_cpu(gr->format_hash),
			     le64_to_cpu(super->format_hash));
		ret = -EINVAL;
		goto send_err;
	}

	if (gr->server_term == 0) {
		down_read(&server->commit_rwsem);

		spin_lock(&server->lock);
		umb = super->unmount_barrier;
		spin_unlock(&server->lock);

		mutex_lock(&server->farewell_mutex);
		ret = insert_mounted_client(sb, le64_to_cpu(gr->rid),
					    le64_to_cpu(gr->flags));
		mutex_unlock(&server->farewell_mutex);

		if (ret == 0)
			queue_commit_work(server, &cw);
		up_read(&server->commit_rwsem);
		if (ret == 0) {
			ret = wait_for_commit(&cw);
			queue_work(server->wq, &server->farewell_work);
		}
	} else {
		umb = gr->unmount_barrier;
	}

send_err:
	err = ret;

	greet.fsid = super->hdr.fsid;
	greet.format_hash = super->format_hash;
	greet.server_term = cpu_to_le64(server->term);
	greet.unmount_barrier = umb;
	greet.rid = gr->rid;
	greet.flags = 0;

	/* queue greeting response to be sent first once messaging enabled */
	ret = scoutfs_net_response(sb, conn, cmd, id, err,
				   &greet, sizeof(greet));
	if (ret == 0 && err)
		ret = err;
	if (ret)
		goto out;

	/* have the net core enable messaging and resend */
	reconnecting = gr->server_term != 0;
	first_contact = le64_to_cpu(gr->server_term) != server->term;
	if (gr->flags & cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_FAREWELL))
		farewell = true;
	else
		farewell = false;

	scoutfs_net_server_greeting(sb, conn, le64_to_cpu(gr->rid), id,
				    reconnecting, first_contact, farewell);

	/* lock server might send recovery request */
	if (le64_to_cpu(gr->server_term) != server->term) {

		/* we're now doing two commits per greeting, not great */
		down_read(&server->commit_rwsem);

		ret = scoutfs_lock_server_greeting(sb, le64_to_cpu(gr->rid),
						   gr->server_term != 0);
		if (ret == 0)
			queue_commit_work(server, &cw);
		up_read(&server->commit_rwsem);
		if (ret == 0)
			ret = wait_for_commit(&cw);
		if (ret)
			goto out;
	}

out:
	return ret;
}

struct farewell_request {
	struct list_head entry;
	u64 net_id;
	u64 rid;
};

static bool invalid_mounted_client_item(struct scoutfs_btree_item_ref *iref)
{
	return (iref->key_len !=
			sizeof(struct scoutfs_mounted_client_btree_key)) ||
	       (iref->val_len !=
			sizeof(struct scoutfs_mounted_client_btree_val));
}

/*
 * This work processes farewell requests asynchronously.  Requests from
 * voting clients can be held until only the final quorum remains and
 * they've all sent farewell requests.
 *
 * When we remove the last mounted client record for the last voting
 * client then we increase the unmount_barrier and write it to the super
 * block.  If voting clients don't get their farewell response they'll
 * see the greater umount_barrier in the super and will know that their
 * farewell has been processed and that they can exit.
 *
 * Responses that are waiting for clients who aren't voting are
 * immediately sent.  Clients that don't have a mounted client record
 * have already had their farewell processed by another server and can
 * proceed.
 *
 * Farewell responses are unique in that sending them causes the server
 * to shutdown the connection to the client next time the socket
 * disconnects.  If the socket is destroyed before the client gets the
 * response they'll reconnect and we'll see them as a brand new client
 * who immediately sends a farewell.  It'll be processed and it all
 * works out.
 *
 * If this worker sees an error it assumes that this sever is done for
 * and that another had better take its place.
 */
static void farewell_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  farewell_work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_mounted_client_btree_key mck;
	struct scoutfs_mounted_client_btree_val *mcv;
	struct farewell_request *tmp;
	struct farewell_request *fw;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct commit_waiter cw;
	unsigned int nr_unmounting = 0;
	unsigned int nr_mounted = 0;
	LIST_HEAD(reqs);
	LIST_HEAD(send);
	bool deleted = false;
	bool voting;
	bool more_reqs;
	int ret;

	/* grab all the requests that are waiting */
	mutex_lock(&server->farewell_mutex);
	list_splice_init(&server->farewell_requests, &reqs);
	mutex_unlock(&server->farewell_mutex);

	/* count how many reqs requests are from voting clients */
	nr_unmounting = 0;
	list_for_each_entry_safe(fw, tmp, &reqs, entry) {
		mck.rid = cpu_to_be64(fw->rid);
		ret = scoutfs_btree_lookup(sb, &super->mounted_clients,
					   &mck, sizeof(mck), &iref);
		if (ret == 0 && invalid_mounted_client_item(&iref)) {
			scoutfs_btree_put_iref(&iref);
			ret = -EIO;
		}
		if (ret < 0) {
			if (ret == -ENOENT) {
				list_move_tail(&fw->entry, &send);
				continue;
			}
			goto out;
		}

		mcv = iref.val;
		voting = (mcv->flags & SCOUTFS_MOUNTED_CLIENT_VOTER) != 0;
		scoutfs_btree_put_iref(&iref);

		if (!voting) {
			list_move_tail(&fw->entry, &send);
			continue;
		}

		nr_unmounting++;
	}

	/* see how many mounted clients could vote for quorum */
	memset(&mck, 0, sizeof(mck));
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->mounted_clients,
					 &mck, sizeof(mck), &iref);
		if (ret == 0 && invalid_mounted_client_item(&iref)) {
			scoutfs_btree_put_iref(&iref);
			ret = -EIO;
		}
		if (ret != 0) {
			if (ret == -ENOENT)
				break;
			goto out;
		}

		memcpy(&mck, iref.key, sizeof(mck));
		mcv = iref.val;

		if (mcv->flags & SCOUTFS_MOUNTED_CLIENT_VOTER)
			nr_mounted++;

		scoutfs_btree_put_iref(&iref);
		be64_add_cpu(&mck.rid, 1);

	}

	/* send as many responses as we can to maintain quorum */
	while ((fw = list_first_entry_or_null(&reqs, struct farewell_request,
					      entry)) &&
	       (nr_mounted > super->quorum_count ||
		nr_unmounting >= nr_mounted)) {

		list_move_tail(&fw->entry, &send);
		nr_mounted--;
		nr_unmounting--;
		deleted = true;
	}

	/* process and send farewell responses */
	list_for_each_entry_safe(fw, tmp, &send, entry) {

		down_read(&server->commit_rwsem);

		ret = scoutfs_lock_server_farewell(sb, fw->rid) ?:
		      remove_trans_seq(sb, fw->rid) ?:
		      delete_mounted_client(sb, fw->rid);
		if (ret == 0)
			queue_commit_work(server, &cw);

		up_read(&server->commit_rwsem);
		if (ret == 0)
			ret = wait_for_commit(&cw);
		if (ret)
			goto out;
	}

	/* update the unmount barrier if we deleted all voting clients */
	if (deleted && nr_mounted == 0) {
		down_read(&server->commit_rwsem);
		le64_add_cpu(&super->unmount_barrier, 1);
		queue_commit_work(server, &cw);
		up_read(&server->commit_rwsem);
		ret = wait_for_commit(&cw);
		if (ret)
			goto out;
	}

	/* and finally send all the responses */
	list_for_each_entry_safe(fw, tmp, &send, entry) {

		ret = scoutfs_net_response_node(sb, server->conn, fw->rid,
						SCOUTFS_NET_CMD_FAREWELL,
						fw->net_id, 0, NULL, 0);
		if (ret)
			break;

		list_del_init(&fw->entry);
		kfree(fw);
	}

	ret = 0;
out:
	mutex_lock(&server->farewell_mutex);
	more_reqs = !list_empty(&server->farewell_requests);
	list_splice_init(&reqs, &server->farewell_requests);
	list_splice_init(&send, &server->farewell_requests);
	mutex_unlock(&server->farewell_mutex);

	if (ret < 0)
		stop_server(server);
	else if (more_reqs && !server->shutting_down)
		queue_work(server->wq, &server->farewell_work);
}

static void free_farewell_requests(struct super_block *sb, u64 rid)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct farewell_request *tmp;
	struct farewell_request *fw;

	mutex_lock(&server->farewell_mutex);
	list_for_each_entry_safe(fw, tmp, &server->farewell_requests, entry) {
		if (rid == 0 || fw->rid == rid) {
			list_del_init(&fw->entry);
			kfree(fw);
		}
	}
	mutex_unlock(&server->farewell_mutex);
}

/*
 * The server is receiving a farewell message from a client that is
 * unmounting.  It won't send any more requests and once it receives our
 * response it will not reconnect.
 *
 * XXX we should make sure that all our requests to the client have finished
 * before we respond.  Locking will have its own messaging for orderly
 * shutdown.  That leaves compaction which will be addressed as part of
 * the larger work of recovering compactions that were in flight when
 * a client crashed.
 */
static int server_farewell(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	u64 rid = scoutfs_net_client_rid(conn);
	struct farewell_request *fw;

	if (arg_len != 0)
		return -EINVAL;

	/* XXX tear down if we fence, or if we shut down */

	fw = kmalloc(sizeof(struct farewell_request), GFP_NOFS);
	if (fw == NULL)
		return -ENOMEM;

	fw->rid = rid;
	fw->net_id = id;

	mutex_lock(&server->farewell_mutex);
	list_add_tail(&fw->entry, &server->farewell_requests);
	mutex_unlock(&server->farewell_mutex);

	queue_work(server->wq, &server->farewell_work);

	/* response will be sent later */
	return 0;
}

/* requests sent to clients are tracked so we can free resources */
struct compact_request {
	struct list_head head;
	u64 rid;
	struct scoutfs_net_compact_request req;
};

/*
 * Find a node that can process our compaction request.  Return a
 * rid if we found a client and added the compaction to the client
 * and server counts.  Returns 0 if no suitable clients were found.
 */
static u64 compact_request_start(struct super_block *sb,
				 struct compact_request *cr)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct server_client_info *last;
	struct server_client_info *sci;
	u64 rid = 0;

	spin_lock(&server->lock);

	/* XXX no last_entry_or_null? :( */
	if (!list_empty(&server->clients))
		last = list_last_entry(&server->clients,
				       struct server_client_info, head);
	else
		last = NULL;

	while ((sci = list_first_entry_or_null(&server->clients,
					       struct server_client_info,
					       head)) != NULL) {
		list_move_tail(&sci->head, &server->clients);
		if (sci->nr_compacts < server->compacts_per_client) {
			list_add(&cr->head, &server->compacts);
			server->nr_compacts++;
			sci->nr_compacts++;
			rid = sci->rid;
			cr->rid = rid;
			break;
		}
		if (sci == last)
			break;
	}

	trace_scoutfs_server_compact_start(sb, le64_to_cpu(cr->req.id),
					   cr->req.ents[0].level, rid,
					   rid ? sci->nr_compacts : 0,
					   server->nr_compacts,
					   server->compacts_per_client);

	spin_unlock(&server->lock);

	return rid;
}

/*
 * Find a tracked compact request for the compaction id, remove it from
 * the server and client counts, and return it to the caller.
 */
static struct compact_request *compact_request_done(struct super_block *sb,
						    u64 id)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct compact_request *ret = NULL;
	struct server_client_info *sci;
	struct compact_request *cr;

	spin_lock(&server->lock);

	list_for_each_entry(cr, &server->compacts, head) {
		if (le64_to_cpu(cr->req.id) != id)
			continue;

		list_for_each_entry(sci, &server->clients, head) {
			if (sci->rid == cr->rid) {
				sci->nr_compacts--;
				break;
			}
		}

		server->nr_compacts--;
		list_del_init(&cr->head);
		ret = cr;
		break;
	}

	trace_scoutfs_server_compact_done(sb, id, ret ? ret->rid : 0,
					  server->nr_compacts);

	spin_unlock(&server->lock);

	return ret;
}

/*
 * When a client disconnects we forget the compactions that they had
 * in flight so that we have capacity to send compaction requests to the
 * remaining clients.
 *
 * XXX we do not free their allocated segnos because they could still be
 * running and writing to those blocks.  To do this safely we'd need
 * full recovery procedures with fencing to ensure that they're not able
 * to write to those blocks anymore.
 */
static void forget_client_compacts(struct super_block *sb,
				   struct server_client_info *sci)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct compact_request *cr;
	struct compact_request *pos;
	LIST_HEAD(forget);

	spin_lock(&server->lock);
	list_for_each_entry_safe(cr, pos, &server->compacts, head) {
		if (cr->rid == sci->rid) {
			sci->nr_compacts--;
			server->nr_compacts--;
			list_move(&cr->head, &forget);
		}
	}
	spin_unlock(&server->lock);

	list_for_each_entry_safe(cr, pos, &forget, head) {
		scoutfs_manifest_compact_done(sb, &cr->req);
		list_del_init(&cr->head);
		kfree(cr);
	}
}

static int segno_in_ents(u64 segno, struct scoutfs_net_manifest_entry *ents,
			 unsigned int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
			break;
		if (segno == le64_to_cpu(ents[i].segno))
			return 1;
	}

	return 0;
}

static int remove_segnos(struct super_block *sb, __le64 *segnos,
			 unsigned int nr,
			 struct scoutfs_net_manifest_entry *unless,
			 unsigned int nr_unless, bool cleanup);

/*
 * Free (unaligned) segnos if they're not found in the unless entries.
 * If this returns an error then we've cleaned up partial frees on
 * error.  This panics if it sees an error and can't cleanup on error.
 *
 * There are variants of this for lots of add/del, alloc/remove data
 * structurs.
 */
static int free_segnos(struct super_block *sb, __le64 *segnos,
		       unsigned int nr,
		       struct scoutfs_net_manifest_entry *unless,
		       unsigned int nr_unless, bool cleanup)

{
	u64 segno;
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		segno = le64_to_cpu(get_unaligned(&segnos[i]));
		if (segno == 0)
			break;
		if (segno_in_ents(segno, unless, nr_unless))
			continue;

		ret = free_segno(sb, segno);
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			remove_segnos(sb, segnos, i, unless, nr_unless, false);
			break;
		}
	}

	return ret;
}

/* the segno array can be unaligned */
static int alloc_segnos(struct super_block *sb, __le64 * segnos,
			unsigned int nr)

{
	u64 segno;
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		ret = alloc_segno(sb, &segno);
		if (ret < 0) {
			free_segnos(sb, segnos, i, NULL, 0, false);
			break;
		}
		put_unaligned(cpu_to_le64(segno), &segnos[i]);
	}

	return ret;
}

static int remove_segnos(struct super_block *sb, __le64 *segnos,
			 unsigned int nr,
			 struct scoutfs_net_manifest_entry *unless,
			 unsigned int nr_unless, bool cleanup)

{
	u64 segno;
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		segno = le64_to_cpu(get_unaligned(&segnos[i]));
		if (segno == 0)
			break;
		if (segno_in_ents(segno, unless, nr_unless))
			continue;

		ret = remove_segno(sb, segno);
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			free_segnos(sb, segnos, i, unless, nr_unless, false);
			break;
		}
	}

	return ret;
}


static int remove_entry_segnos(struct super_block *sb,
			       struct scoutfs_net_manifest_entry *ents,
			       unsigned int nr,
			       struct scoutfs_net_manifest_entry *unless,
			       unsigned int nr_unless, bool cleanup);

static int free_entry_segnos(struct super_block *sb,
			     struct scoutfs_net_manifest_entry *ents,
			     unsigned int nr,
			     struct scoutfs_net_manifest_entry *unless,
			     unsigned int nr_unless, bool cleanup)
{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
			break;
		if (segno_in_ents(le64_to_cpu(ents[i].segno),
				  unless, nr_unless))
			continue;

		ret = free_segno(sb, le64_to_cpu(ents[i].segno));
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			remove_entry_segnos(sb, ents, i, unless, nr_unless,
					    false);
			break;
		}
	}

	return ret;
}

static int remove_entry_segnos(struct super_block *sb,
			       struct scoutfs_net_manifest_entry *ents,
			       unsigned int nr,
			       struct scoutfs_net_manifest_entry *unless,
			       unsigned int nr_unless, bool cleanup)
{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
		       break;
		if (segno_in_ents(le64_to_cpu(ents[i].segno),
				  unless, nr_unless))
			continue;

		ret = remove_segno(sb, le64_to_cpu(ents[i].segno));
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			free_entry_segnos(sb, ents, i, unless, nr_unless,
					  false);
			break;
		}
	}

	return ret;
}

static int del_manifest_entries(struct super_block *sb,
				struct scoutfs_net_manifest_entry *ents,
				unsigned int nr, bool cleanup);

static int add_manifest_entries(struct super_block *sb,
				struct scoutfs_net_manifest_entry *ents,
				unsigned int nr, bool cleanup)
{
	struct scoutfs_manifest_entry ment;
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
			break;

		scoutfs_init_ment_from_net(&ment, &ents[i]);

		ret = scoutfs_manifest_add(sb, &ment);
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			del_manifest_entries(sb, ents, i, false);
			break;
		}
	}

	return ret;
}

static int del_manifest_entries(struct super_block *sb,
				struct scoutfs_net_manifest_entry *ents,
				unsigned int nr, bool cleanup)
{
	struct scoutfs_manifest_entry ment;
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
			break;

		scoutfs_init_ment_from_net(&ment, &ents[i]);

		ret = scoutfs_manifest_del(sb, &ment);
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			add_manifest_entries(sb, ents, i, false);
			break;
		}
	}

	return ret;
}

/*
 * Process a received compaction response.  This is called in concurrent
 * processing work context so it's racing with other compaction
 * responses and new compaction requests being built and sent.
 *
 * If the compaction failed then we only have to free the allocated
 * output segnos sent in the request.
 *
 * If the compaction succeeded then we need to delete the input manifest
 * entries, add any new output manifest entries, and free allocated
 * segnos and input manifest segnos that aren't found in output segnos.
 *
 * And finally we always remove the compaction from the runtime client
 * accounting
 *
 * As we finish a compaction we wake level0 writers if there's now space
 * in level 0 for a new segment.
 *
 * Errors in processing are taken as an indication that this server is
 * no longer able to do its job.  We return hard errors which shut down
 * the server in the hopes that another healthy server will start up.
 * We may want to revisit this.
 */
static int compact_response(struct super_block *sb,
			    struct scoutfs_net_connection *conn,
			    void *resp, unsigned int resp_len,
			    int error, void *data)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_net_compact_response *cresp = NULL;
	struct compact_request *cr = NULL;
	bool level0_was_full = false;
	bool add_ents = false;
	bool del_ents = false;
	bool rem_segnos = false;
	struct commit_waiter cw;
	__le64 id;
	int ret;

	if (error) {
		/* an error response without an id is fatal */
		if (resp_len != sizeof(__le64)) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&id, resp, resp_len);

	} else {
		if (resp_len != sizeof(struct scoutfs_net_compact_response)) {
			ret = -EINVAL;
			goto out;
		}

		cresp = resp;
		id = cresp->id;
	}

	trace_scoutfs_server_compact_response(sb, le64_to_cpu(id), error);

	/* XXX we only free tracked requests on responses, must still exist */
	cr = compact_request_done(sb, le64_to_cpu(id));
	if (WARN_ON_ONCE(cr == NULL)) {
		ret = -ENOENT;
		goto out;
	}

	down_read(&server->commit_rwsem);
	scoutfs_manifest_lock(sb);

	level0_was_full = scoutfs_manifest_level0_full(sb);

	if (error) {
		ret = 0;
		goto cleanup;
	}

	/* delete old manifest entries */
	ret = del_manifest_entries(sb, cr->req.ents, ARRAY_SIZE(cr->req.ents),
				   true);
	if (ret)
		goto cleanup;
	add_ents = true;

	/* add new manifest entries */
	ret = add_manifest_entries(sb, cresp->ents, ARRAY_SIZE(cresp->ents),
				   true);
	if (ret)
		goto cleanup;
	del_ents = true;

	/* free allocated segnos not found in new entries */
	ret = free_segnos(sb, cr->req.segnos, ARRAY_SIZE(cr->req.segnos),
			  cresp->ents, ARRAY_SIZE(cresp->ents), true);
	if (ret)
		goto cleanup;
	rem_segnos = true;

	/* free input segnos not found in new entries */
	ret = free_entry_segnos(sb, cr->req.ents, ARRAY_SIZE(cr->req.ents),
				cresp->ents, ARRAY_SIZE(cresp->ents), true);
cleanup:
	/* cleanup partial commits on errors */
	if (ret < 0 && rem_segnos)
		remove_segnos(sb, cr->req.segnos, ARRAY_SIZE(cr->req.segnos),
			      cresp->ents, ARRAY_SIZE(cresp->ents), false);
	if (ret < 0 && del_ents)
		del_manifest_entries(sb, cresp->ents, ARRAY_SIZE(cresp->ents),
				     false);
	if (ret < 0 && add_ents)
		add_manifest_entries(sb, cr->req.ents,
				     ARRAY_SIZE(cr->req.ents), false);

	/* free all the allocated output segnos if compaction failed */
	if ((error || ret < 0) && cr != NULL)
		free_segnos(sb, cr->req.segnos, ARRAY_SIZE(cr->req.segnos),
			    NULL, 0, false);

	if (ret == 0 && level0_was_full && !scoutfs_manifest_level0_full(sb))
		wake_up(&server->waitq);

	if (ret == 0)
		queue_commit_work(server, &cw);
	scoutfs_manifest_unlock(sb);
	up_read(&server->commit_rwsem);

	if (cr) {
		scoutfs_manifest_compact_done(sb, &cr->req);
		kfree(cr);
	}

	if (ret == 0) {
		ret = wait_for_commit(&cw);
		if (ret == 0)
			try_queue_compact(server);
	}

out:
	return ret;
}

/*
 * The compaction worker executes as the manifest is updated and we see
 * that a level has too many segments and clients aren't processing all
 * their max number of compaction requests.  Only one compaction worker
 * executes.
 *
 * We have the manifest build us a compaction request, find a client to
 * send it too, and record it for later completion processing.
 *
 * The manifest tracks pending compactions and won't use the same
 * segments as inputs to multiple compactions.  We track the number of
 * compactions in flight to each client to keep them balanced.
 */
static void scoutfs_server_compact_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  compact_work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_net_compact_request *req;
	struct compact_request *cr;
	struct commit_waiter cw;
	int nr_segnos = 0;
	u64 rid;
	__le64 id;
	int ret;

	trace_scoutfs_server_compact_work_enter(sb, 0, 0);

	cr = kzalloc(sizeof(struct compact_request), GFP_NOFS);
	if (!cr) {
		ret = -ENOMEM;
		goto out;
	}
	req = &cr->req;

	/* get the input manifest entries */
	ret = scoutfs_manifest_next_compact(sb, req);
	if (ret <= 0)
		goto out;

	nr_segnos = ret + SCOUTFS_COMPACTION_SEGNO_OVERHEAD;

	/* get the next id and allocate possible output segnos */
	down_read(&server->commit_rwsem);

	spin_lock(&server->lock);
	id = super->next_compact_id;
	le64_add_cpu(&super->next_compact_id, 1);
	spin_unlock(&server->lock);

	ret = alloc_segnos(sb, req->segnos, nr_segnos);
	if (ret == 0)
		queue_commit_work(server, &cw);
	up_read(&server->commit_rwsem);
	if (ret == 0)
		ret = wait_for_commit(&cw);
	if (ret)
		goto out;

	/* try to send to a node with capacity, they can disconnect */
retry:
	req->id = id;
	rid = compact_request_start(sb, cr);
	if (rid == 0) {
		ret = 0;
		goto out;
	}

	/* response processing can complete compaction before this returns */
	ret = scoutfs_net_submit_request_node(sb, server->conn, rid,
					      SCOUTFS_NET_CMD_COMPACT,
					      req, sizeof(*req),
					      compact_response, NULL, NULL);
	if (ret < 0) {
		cr = compact_request_done(sb, le64_to_cpu(id));
		BUG_ON(cr == NULL); /* must still be there, no node cleanup */
	}
	if (ret == -ENOTCONN)
		goto retry;
	if (ret < 0)
		goto out;

	/* cr is now owned by response processing */
	cr = NULL;
	ret = 1;

out:
	if (ret <= 0 && cr != NULL) {
		scoutfs_manifest_compact_done(sb, req);

		/* don't need to wait for commit when freeing in cleanup */
		down_read(&server->commit_rwsem);
		free_segnos(sb, req->segnos, nr_segnos, NULL, 0, false);
		up_read(&server->commit_rwsem);

		kfree(cr);
	}

	if (ret > 0)
		try_queue_compact(server);

	trace_scoutfs_server_compact_work_exit(sb, 0, ret);
}

static scoutfs_net_request_t server_req_funcs[] = {
	[SCOUTFS_NET_CMD_GREETING]		= server_greeting,
	[SCOUTFS_NET_CMD_ALLOC_INODES]		= server_alloc_inodes,
	[SCOUTFS_NET_CMD_ALLOC_EXTENT]		= server_alloc_extent,
	[SCOUTFS_NET_CMD_FREE_EXTENTS]		= server_free_extents,
	[SCOUTFS_NET_CMD_ALLOC_SEGNO]		= server_alloc_segno,
	[SCOUTFS_NET_CMD_RECORD_SEGMENT]	= server_record_segment,
	[SCOUTFS_NET_CMD_GET_LOG_TREES]		= server_get_log_trees,
	[SCOUTFS_NET_CMD_COMMIT_LOG_TREES]	= server_commit_log_trees,
	[SCOUTFS_NET_CMD_ADVANCE_SEQ]		= server_advance_seq,
	[SCOUTFS_NET_CMD_GET_LAST_SEQ]		= server_get_last_seq,
	[SCOUTFS_NET_CMD_GET_MANIFEST_ROOT]	= server_get_manifest_root,
	[SCOUTFS_NET_CMD_STATFS]		= server_statfs,
	[SCOUTFS_NET_CMD_LOCK]			= server_lock,
	[SCOUTFS_NET_CMD_FAREWELL]		= server_farewell,
};

static void server_notify_up(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     void *info, u64 rid)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (rid != 0) {
		sci->rid = rid;
		sci->nr_compacts = 0;
		spin_lock(&server->lock);
		list_add_tail(&sci->head, &server->clients);
		server->nr_clients++;
		trace_scoutfs_server_client_up(sb, rid, server->nr_clients);
		spin_unlock(&server->lock);

		try_queue_compact(server);
	}
}

static void server_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       void *info, u64 rid)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (rid != 0) {
		spin_lock(&server->lock);
		list_del_init(&sci->head);
		server->nr_clients--;
		trace_scoutfs_server_client_down(sb, rid,
						 server->nr_clients);
		spin_unlock(&server->lock);

		free_farewell_requests(sb, rid);

		forget_client_compacts(sb, sci);
		try_queue_compact(server);
	} else {
		stop_server(server);
	}
}

static void scoutfs_server_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  work);
	struct super_block *sb = server->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_connection *conn = NULL;
	DECLARE_WAIT_QUEUE_HEAD(waitq);
	struct sockaddr_in sin;
	LIST_HEAD(conn_list);
	int ret;
	int err;

	trace_scoutfs_server_work_enter(sb, 0, 0);

	sin = server->listen_sin;

	scoutfs_info(sb, "server setting up at "SIN_FMT, SIN_ARG(&sin));

	conn = scoutfs_net_alloc_conn(sb, server_notify_up, server_notify_down,
				      sizeof(struct server_client_info),
				      server_req_funcs, "server");
	if (!conn) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_net_bind(sb, conn, &sin);
	if (ret) {
		scoutfs_err(sb, "server failed to bind to "SIN_FMT", err %d%s",
			    SIN_ARG(&sin), ret,
			    ret == -EADDRNOTAVAIL ? " (Bad address?)"
						  : "");
		goto out;
	}

	if (ret)
		goto out;

	/* start up the server subsystems before accepting */
	ret = scoutfs_read_super(sb, super);
	if (ret < 0)
		goto shutdown;

	scoutfs_balloc_init(&server->alloc, &super->core_balloc_alloc,
			    &super->core_balloc_free);
	scoutfs_block_writer_init(sb, &server->wri);

	ret = scoutfs_manifest_setup(sb) ?:
	      scoutfs_lock_server_setup(sb, &server->alloc, &server->wri);
	if (ret)
		goto shutdown;

	/*
	 * Write our address in the super before it's possible for net
	 * processing to start writing the super as part of
	 * transactions.  In theory clients could be trying to connect
	 * to our address without having seen it in the super (maybe
	 * they saw it a long time ago).
	 */
	scoutfs_addr_from_sin(&super->server_addr, &sin);
	super->quorum_server_term = cpu_to_le64(server->term);
	ret = scoutfs_write_super(sb, super);
	if (ret < 0)
		goto shutdown;

	server->stable_manifest_root = super->manifest.root;

	/* start accepting connections and processing work */
	server->conn = conn;
	scoutfs_net_listen(sb, conn);

	scoutfs_info(sb, "server ready at "SIN_FMT, SIN_ARG(&sin));
	complete(&server->start_comp);

	/* wait_event/wake_up provide barriers */
	wait_event_interruptible(server->waitq, server->shutting_down);

shutdown:
	scoutfs_info(sb, "server shutting down at "SIN_FMT, SIN_ARG(&sin));
	/* wait for request processing */
	scoutfs_net_shutdown(sb, conn);
	/* drain compact work queued by responses */
	cancel_work_sync(&server->compact_work);
	/* wait for commit queued by request processing */
	flush_work(&server->commit_work);
	server->conn = NULL;

	destroy_pending_frees(sb);
	scoutfs_manifest_destroy(sb);
	scoutfs_lock_server_destroy(sb);

out:
	scoutfs_quorum_clear_leader(sb);
	scoutfs_net_free_conn(sb, conn);

	scoutfs_info(sb, "server stopped at "SIN_FMT, SIN_ARG(&sin));
	trace_scoutfs_server_work_exit(sb, 0, ret);

	/*
	 * Always try to clear our presence in the super so that we're
	 * not fenced.  We do this last because other mounts will try to
	 * reach quorum the moment they see zero here.  The later we do
	 * this the longer we have to finish shutdown while clients
	 * timeout.
	 */
	err = scoutfs_read_super(sb, super);
	if (err == 0) {
		super->quorum_fenced_term = cpu_to_le64(server->term);
		memset(&super->server_addr, 0, sizeof(super->server_addr));
		err = scoutfs_write_super(sb, super);
	}
	if (err < 0) {
		scoutfs_err(sb, "failed to clear election term %llu at "SIN_FMT", this mount could be fenced",
			    server->term, SIN_ARG(&sin));
	}

	server->err = ret;
	complete(&server->start_comp);
}

/*
 * Wait for the server to successfully start.  If this returns error then
 * the super block's fence_term has been set to the new server's term so
 * that it won't be fenced.
 */
int scoutfs_server_start(struct super_block *sb, struct sockaddr_in *sin,
			 u64 term)
{
	DECLARE_SERVER_INFO(sb, server);

	server->err = 0;
	server->shutting_down = false;
	server->listen_sin = *sin;
	server->term = term;
	init_completion(&server->start_comp);

	queue_work(server->wq, &server->work);

	wait_for_completion(&server->start_comp);
	return server->err;
}

/*
 * Start shutdown on the server but don't want for it to finish.
 */
void scoutfs_server_abort(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	stop_server(server);
}

/*
 * Once the server is stopped we give the caller our election info
 * which might have been modified while we were running.
 */
void scoutfs_server_stop(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	stop_server(server);
	/* XXX not sure both are needed */
	cancel_work_sync(&server->work);
	cancel_work_sync(&server->commit_work);
}

int scoutfs_server_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server;

	server = kzalloc(sizeof(struct server_info), GFP_KERNEL);
	if (!server)
		return -ENOMEM;

	server->sb = sb;
	spin_lock_init(&server->lock);
	init_waitqueue_head(&server->waitq);
	INIT_WORK(&server->work, scoutfs_server_worker);
	init_rwsem(&server->commit_rwsem);
	init_llist_head(&server->commit_waiters);
	INIT_WORK(&server->commit_work, scoutfs_server_commit_func);
	seqcount_init(&server->stable_seqcount);
	init_rwsem(&server->seq_rwsem);
	init_rwsem(&server->alloc_rwsem);
	INIT_LIST_HEAD(&server->pending_frees);
	INIT_LIST_HEAD(&server->clients);
	server->compacts_per_client = 2;
	INIT_LIST_HEAD(&server->compacts);
	INIT_WORK(&server->compact_work, scoutfs_server_compact_worker);
	mutex_init(&server->farewell_mutex);
	INIT_LIST_HEAD(&server->farewell_requests);
	INIT_WORK(&server->farewell_work, farewell_worker);
	mutex_init(&server->logs_mutex);

	server->wq = alloc_workqueue("scoutfs_server",
				     WQ_UNBOUND | WQ_NON_REENTRANT, 0);
	if (!server->wq) {
		kfree(server);
		return -ENOMEM;
	}

	sbi->server_info = server;
	return 0;
}

/*
 * The caller should have already stopped but we do the same just in
 * case.
 */
void scoutfs_server_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server = sbi->server_info;

	if (server) {
		stop_server(server);

		/* wait for server work to wait for everything to shut down */
		cancel_work_sync(&server->work);
		/* recv work/compaction could have left commit_work queued */
		cancel_work_sync(&server->commit_work);

		/* pending farewell requests are another server's problem */
		cancel_work_sync(&server->farewell_work);
		free_farewell_requests(sb, 0);

		trace_scoutfs_server_workqueue_destroy(sb, 0, 0);
		destroy_workqueue(server->wq);

		kfree(server);
		sbi->server_info = NULL;
	}
}
