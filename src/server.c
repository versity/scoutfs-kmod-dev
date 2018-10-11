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
#include "server.h"
#include "net.h"
#include "lock_server.h"
#include "endian_swap.h"

/*
 * Every active mount can act as the server that listens on a net
 * connection and accepts connections from all the other mounts acting
 * as clients.
 *
 * The server is started when raft elects the mount as the leader.  If
 * it sees errors it shuts down the server in the hopes that another
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
	struct scoutfs_net_connection *conn;

	/* request processing coordinates committing manifest and alloc */
	struct rw_semaphore commit_rwsem;
	struct llist_head commit_waiters;
	struct work_struct commit_work;

	/* server remembers the stable manifest root for clients */
	seqcount_t stable_seqcount;
	struct scoutfs_btree_root stable_manifest_root;

	/* server tracks seq use */
	spinlock_t seq_lock;
	struct list_head pending_seqs;

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
};

#define DECLARE_SERVER_INFO(sb, name) \
	struct server_info *name = SCOUTFS_SB(sb)->server_info

/*
 * The server tracks each connected client.
 */
struct server_client_info {
	u64 node_id;
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

	/* try to free first which can dirty the btrees */
	ret = apply_pending_frees(sb);
	if (ret) {
		scoutfs_err(sb, "server error freeing extents: %d", ret);
		goto out;
	}

	if (!scoutfs_btree_has_dirty(sb)) {
		ret = 0;
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
static int server_advance_seq(struct super_block *sb,
			      struct scoutfs_net_connection *conn,
			      u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *next_ps;
	struct pending_seq *ps;
	struct commit_waiter cw;
	__le64 * __packed their_seq = arg;
	__le64 next_seq;
	int ret;

	if (arg_len != sizeof(__le64)) {
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
	ret = wait_for_commit(&cw);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &next_seq, sizeof(next_seq));
}

static int server_get_last_seq(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct pending_seq *ps;
	__le64 last_seq;
	int ret;

	if (arg_len != 0) {
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
	u64 node_id = scoutfs_net_client_node_id(conn);

	if (arg_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_request(sb, node_id, id, arg);
}

static int lock_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 void *resp, unsigned int resp_len,
			 int error, void *data)
{
	u64 node_id = scoutfs_net_client_node_id(conn);

	if (resp_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_response(sb, node_id, resp);
}

int scoutfs_server_lock_request(struct super_block *sb, u64 node_id,
				struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_submit_request_node(sb, server->conn, node_id,
					      SCOUTFS_NET_CMD_LOCK,
					      nl, sizeof(*nl),
					      lock_response, NULL, NULL);
}

int scoutfs_server_lock_response(struct super_block *sb, u64 node_id,
				 u64 id, struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_response_node(sb, server->conn, node_id,
					 SCOUTFS_NET_CMD_LOCK, id, 0,
					 nl, sizeof(*nl));
}

/*
 * Process an incoming greeting request in the server from the client.
 * We try to send responses to failed greetings so that the sender can
 * log some detail before shutting down.  A failure to send a greeting
 * response shuts down the connection.
 *
 * We allocate a new node_id for the first connect attempt from a
 * client.  We update the request node_id for the calling net layer to
 * consume.
 *
 * If a client reconnects they'll send their initially assigned node_id
 * in their greeting request.
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
	__le64 node_id = 0;
	int ret = 0;

	if (arg_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto out;
	}

	if (gr->fsid != super->id) {
		scoutfs_warn(sb, "client sent fsid 0x%llx, server has 0x%llx",
			     le64_to_cpu(gr->fsid),
			     le64_to_cpu(super->id));
		ret = -EINVAL;
		goto out;
	}

	if (gr->format_hash != super->format_hash) {
		scoutfs_warn(sb, "client sent format 0x%llx, server has 0x%llx",
			     le64_to_cpu(gr->format_hash),
			     le64_to_cpu(super->format_hash));
		ret = -EINVAL;
		goto out;
	}

	if (gr->node_id == 0) {
		down_read(&server->commit_rwsem);

		spin_lock(&server->lock);
		node_id = super->next_node_id;
		le64_add_cpu(&super->next_node_id, 1);
		spin_unlock(&server->lock);

		queue_commit_work(server, &cw);
		up_read(&server->commit_rwsem);
		ret = wait_for_commit(&cw);
		if (ret)
			goto out;
	} else {
		node_id = gr->node_id;
	}

	greet.fsid = super->id;
	greet.format_hash = super->format_hash;
	greet.node_id = node_id;
out:
	ret = scoutfs_net_response(sb, conn, cmd, id, ret,
				   &greet, sizeof(greet));
	/* give net caller client's new node_id :/ */
	if (ret == 0 && node_id != 0)
		gr->node_id = node_id;
	return ret;
}

/* requests sent to clients are tracked so we can free resources */
struct compact_request {
	struct list_head head;
	u64 node_id;
	struct scoutfs_net_compact_request req;
};

/*
 * Find a node that can process our compaction request.  Return a
 * node_id if we found a client and added the compaction to the client
 * and server counts.  Returns 0 if no suitable clients were found.
 */
static u64 compact_request_start(struct super_block *sb,
				 struct compact_request *cr)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct server_client_info *last;
	struct server_client_info *sci;
	u64 node_id = 0;

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
			node_id = sci->node_id;
			cr->node_id = node_id;
			break;
		}
		if (sci == last)
			break;
	}

	trace_scoutfs_server_compact_start(sb, le64_to_cpu(cr->req.id),
					   cr->req.ents[0].level, node_id,
					   node_id ? sci->nr_compacts : 0,
					   server->nr_compacts,
					   server->compacts_per_client);

	spin_unlock(&server->lock);

	return node_id;
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
			if (sci->node_id == cr->node_id) {
				sci->nr_compacts--;
				break;
			}
		}

		server->nr_compacts--;
		list_del_init(&cr->head);
		ret = cr;
		break;
	}

	trace_scoutfs_server_compact_done(sb, id, ret ? ret->node_id : 0,
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
		if (cr->node_id == sci->node_id) {
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

static int segno_in_ents(__le64 segno, struct scoutfs_net_manifest_entry *ents,
			 unsigned int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (ents[i].segno == 0)
			break;
		if (segno == ents[i].segno)
			return 1;
	}

	return 0;
}

static int remove_segnos(struct super_block *sb, __le64 * __packed segnos,
			 unsigned int nr,
			 struct scoutfs_net_manifest_entry *unless,
			 unsigned int nr_unless, bool cleanup);

/*
 * Free segnos if they're not found in the unless entries.  If this
 * returns an error then we've cleaned up partial frees on error.  This
 * panics if it sees an error and can't cleanup on error.
 *
 * There are variants of this for lots of add/del, alloc/remove data
 * structurs.
 */
static int free_segnos(struct super_block *sb, __le64 * __packed segnos,
		       unsigned int nr,
		       struct scoutfs_net_manifest_entry *unless,
		       unsigned int nr_unless, bool cleanup)

{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (segnos[i] == 0)
			break;
		if (segno_in_ents(segnos[i], unless, nr_unless))
			continue;

		ret = free_segno(sb, le64_to_cpu(segnos[i]));
		BUG_ON(ret < 0 && !cleanup);
		if (ret < 0) {
			remove_segnos(sb, segnos, i, unless, nr_unless, false);
			break;
		}
	}

	return ret;
}

static int alloc_segnos(struct super_block *sb, __le64 * __packed segnos,
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
		segnos[i] = cpu_to_le64(segno);
	}

	return ret;
}

static int remove_segnos(struct super_block *sb, __le64 * __packed segnos,
			 unsigned int nr,
			 struct scoutfs_net_manifest_entry *unless,
			 unsigned int nr_unless, bool cleanup)

{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (segnos[i] == 0)
			break;
		if (segno_in_ents(segnos[i], unless, nr_unless))
			continue;

		ret = remove_segno(sb, le64_to_cpu(segnos[i]));
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
		if (segno_in_ents(ents[i].segno, unless, nr_unless))
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
		if (segno_in_ents(ents[i].segno, unless, nr_unless))
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
	u64 node_id;
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
	node_id = compact_request_start(sb, cr);
	if (node_id == 0) {
		ret = 0;
		goto out;
	}

	/* response processing can complete compaction before this returns */
	ret = scoutfs_net_submit_request_node(sb, server->conn, node_id,
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
	[SCOUTFS_NET_CMD_ADVANCE_SEQ]		= server_advance_seq,
	[SCOUTFS_NET_CMD_GET_LAST_SEQ]		= server_get_last_seq,
	[SCOUTFS_NET_CMD_GET_MANIFEST_ROOT]	= server_get_manifest_root,
	[SCOUTFS_NET_CMD_STATFS]		= server_statfs,
	[SCOUTFS_NET_CMD_LOCK]			= server_lock,
};

static void server_notify_up(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     void *info, u64 node_id)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (node_id != 0) {
		sci->node_id = node_id;
		sci->nr_compacts = 0;
		spin_lock(&server->lock);
		list_add_tail(&sci->head, &server->clients);
		server->nr_clients++;
		trace_scoutfs_server_client_up(sb, node_id, server->nr_clients);
		spin_unlock(&server->lock);

		try_queue_compact(server);
	}
}

static void server_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       void *info, u64 node_id)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (node_id != 0) {
		spin_lock(&server->lock);
		list_del_init(&sci->head);
		server->nr_clients--;
		trace_scoutfs_server_client_down(sb, node_id,
						 server->nr_clients);
		spin_unlock(&server->lock);

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
	struct pending_seq *ps;
	struct pending_seq *ps_tmp;
	DECLARE_WAIT_QUEUE_HEAD(waitq);
	struct sockaddr_in sin;
	LIST_HEAD(conn_list);
	int ret;

	trace_scoutfs_server_work_enter(sb, 0, 0);

	conn = scoutfs_net_alloc_conn(sb, server_notify_up, server_notify_down,
				      sizeof(struct server_client_info),
				      server_req_funcs, "server");
	if (!conn) {
		ret = -ENOMEM;
		goto out;
	}

	sin = server->listen_sin;

	ret = scoutfs_net_bind(sb, conn, &sin);
	if (ret) {
		scoutfs_err(sb, "server failed to bind to "SIN_FMT", err %d%s",
			    SIN_ARG(&sin), ret,
			    ret == -EADDRNOTAVAIL ? " (Bad address?)"
						  : "");
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	/* start up the server subsystems before accepting */
	ret = scoutfs_btree_setup(sb) ?:
	      scoutfs_manifest_setup(sb) ?:
	      scoutfs_lock_server_setup(sb);
	if (ret)
		goto shutdown;

	complete(&server->start_comp);

	scoutfs_advance_dirty_super(sb);
	server->stable_manifest_root = super->manifest.root;

	scoutfs_info(sb, "server started on "SIN_FMT, SIN_ARG(&sin));

	/* start accepting connections and processing work */
	server->conn = conn;
	scoutfs_net_listen(sb, conn);

	/* wait_event/wake_up provide barriers */
	wait_event_interruptible(server->waitq, server->shutting_down);

	scoutfs_info(sb, "server shutting down on "SIN_FMT, SIN_ARG(&sin));

shutdown:
	/* wait for request processing */
	scoutfs_net_shutdown(sb, conn);
	/* drain compact work queued by responses */
	cancel_work_sync(&server->compact_work);
	/* wait for commit queued by request processing */
	flush_work(&server->commit_work);
	server->conn = NULL;

	destroy_pending_frees(sb);
	scoutfs_manifest_destroy(sb);
	scoutfs_btree_destroy(sb);
	scoutfs_lock_server_destroy(sb);

	/* XXX these should be persistent and reclaimed during recovery */
	list_for_each_entry_safe(ps, ps_tmp, &server->pending_seqs, head) {
		list_del_init(&ps->head);
		kfree(ps);
	}

out:
	scoutfs_net_free_conn(sb, conn);

	trace_scoutfs_server_work_exit(sb, 0, ret);

	server->err = ret;
	complete(&server->start_comp);
}

/* XXX can we call start multiple times? */
int scoutfs_server_start(struct super_block *sb, struct sockaddr_in *sin)
{
	DECLARE_SERVER_INFO(sb, server);

	server->err = 0;
	server->shutting_down = false;
	server->listen_sin = *sin;
	init_completion(&server->start_comp);

	queue_work(server->wq, &server->work);

	wait_for_completion(&server->start_comp);
	return server->err;
}

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
	spin_lock_init(&server->seq_lock);
	INIT_LIST_HEAD(&server->pending_seqs);
	init_rwsem(&server->alloc_rwsem);
	INIT_LIST_HEAD(&server->pending_frees);
	INIT_LIST_HEAD(&server->clients);
	server->compacts_per_client = 2;
	INIT_LIST_HEAD(&server->compacts);
	INIT_WORK(&server->compact_work, scoutfs_server_compact_worker);

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

		trace_scoutfs_server_workqueue_destroy(sb, 0, 0);
		destroy_workqueue(server->wq);

		kfree(server);
		sbi->server_info = NULL;
	}
}
