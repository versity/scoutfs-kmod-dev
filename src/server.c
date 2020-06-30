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
#include "radix.h"
#include "btree.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "server.h"
#include "net.h"
#include "lock_server.h"
#include "endian_swap.h"
#include "quorum.h"
#include "trans.h"

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

	/* request processing coordinates shared commits */
	struct rw_semaphore commit_rwsem;
	struct llist_head commit_waiters;
	struct work_struct commit_work;
	bool prepared_commit;

	/* server tracks seq use */
	struct rw_semaphore seq_rwsem;

	struct rw_semaphore alloc_rwsem;

	struct list_head clients;
	unsigned long nr_clients;

	/* track clients waiting in unmmount for farewell response */
	struct mutex farewell_mutex;
	struct list_head farewell_requests;
	struct work_struct farewell_work;

	struct scoutfs_radix_allocator alloc;
	struct scoutfs_block_writer wri;

	struct mutex logs_mutex;

	/* stable versions stored from commits, given in locks and rpcs */
	seqcount_t roots_seqcount;
	struct scoutfs_net_roots roots;
};

#define DECLARE_SERVER_INFO(sb, name) \
	struct server_info *name = SCOUTFS_SB(sb)->server_info

/*
 * The server tracks each connected client.
 */
struct server_client_info {
	u64 rid;
	struct list_head head;
};

struct commit_waiter {
	struct completion comp;
	struct llist_node node;
	int ret;
};

static void stop_server(struct server_info *server)
{
	/* wait_event/wake_up provide barriers */
	server->shutting_down = true;
	wake_up(&server->waitq);
}

/*
 * Hold the shared rwsem that lets multiple holders modify blocks in the
 * current commit and prevents the commit worker from acquiring the
 * exclusive write lock to write the commit.  This can fail for the
 * first holder failing to prepare a new commit.
 *
 * We reclaim the server's stable meta_freed blocks.  This is run before
 * anything has modified allocators in the server.  We know that the
 * stable meta_freed tree in the super contains all the stable free
 * blocks which can be merged back into avail.  We reference the stable
 * freed tree in the super because the server allocator's freed tree is
 * going to be added to as blocks are freed during the merge.
 *
 * This is exported for server components isolated in their own files
 * (lock_server) and which are not called directly by the server core
 * (async timeout work).
 */
int scoutfs_server_hold_commit(struct super_block *sb)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_SERVER_INFO(sb, server);
	u64 tot;
	int ret = 0;

	scoutfs_inc_counter(sb, server_commit_hold);

	down_read(&server->commit_rwsem);

	while (!server->prepared_commit) {
		up_read(&server->commit_rwsem);
		down_write(&server->commit_rwsem);

		if (!server->prepared_commit) {
			scoutfs_inc_counter(sb, server_commit_prepare);
			BUG_ON(scoutfs_block_writer_dirty_bytes(sb,
								&server->wri));
			tot = le64_to_cpu(super->core_meta_freed.ref.sm_total);

			ret = scoutfs_radix_merge(sb, &server->alloc,
						  &server->wri,
						  &server->alloc.avail,
						  &server->alloc.freed,
						  &super->core_meta_freed,
						  true, tot);
			if (ret == 0)
				server->prepared_commit = true;
		}

		up_write(&server->commit_rwsem);
		if (ret < 0)
			break;

		down_read(&server->commit_rwsem);
	}

	return ret;
}

/*
 * This is called while holding the commit and returns once the commit
 * is successfully written.  Many holders can all wait for all holders
 * to drain before their shared commit is applied and they're all woken.
 *
 * It's important to realize that our commit_waiter list node might be
 * serviced by a currently executing commit work that is blocked waiting
 * for the holders to release the commit_rwsem.  This caller can return
 * from wait_for_commit() while another future commit_work is still
 * queued.
 *
 * This could queue delayed work but we're first trying to have batching
 * work by having concurrent modification line up behind a commit in
 * flight.  Once the commit finishes it'll unlock and hopefully everyone
 * will race to make their changes and they'll all be applied by the
 * next commit after that.
 */
int scoutfs_server_apply_commit(struct super_block *sb, int err)
{
	DECLARE_SERVER_INFO(sb, server);
	struct commit_waiter cw;

	if (err == 0) {
		cw.ret = 0;
		init_completion(&cw.comp);
		llist_add(&cw.node, &server->commit_waiters);
		scoutfs_inc_counter(sb, server_commit_queue);
		queue_work(server->wq, &server->commit_work);
	}

	up_read(&server->commit_rwsem);

	if (err == 0) {
		wait_for_completion(&cw.comp);
		err = cw.ret;
	}

	return err;
}

/*
 * The caller is about to overwrite a ref to an alloc tree.  As we do
 * so we update the given super free block counter with the difference
 * between the old and new allocator roots.
 */
static void update_free_blocks(__le64 *blocks, struct scoutfs_radix_root *prev,
			       struct scoutfs_radix_root *next)
{
	le64_add_cpu(blocks, le64_to_cpu(next->ref.sm_total) -
			     le64_to_cpu(prev->ref.sm_total));
}

void scoutfs_server_get_roots(struct super_block *sb,
			      struct scoutfs_net_roots *roots)
{
	DECLARE_SERVER_INFO(sb, server);
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&server->roots_seqcount);
		*roots = server->roots;
	} while (read_seqcount_retry(&server->roots_seqcount, seq));
}

static void set_roots(struct server_info *server,
		      struct scoutfs_btree_root *fs_root,
		      struct scoutfs_btree_root *logs_root)
{
	preempt_disable();
	write_seqcount_begin(&server->roots_seqcount);
	server->roots.fs_root = *fs_root;
	server->roots.logs_root = *logs_root;
	write_seqcount_end(&server->roots_seqcount);
	preempt_enable();
}

/*
 * Concurrent request processing dirties blocks in a commit and makes
 * the modifications persistent before replying.  We'd like to batch
 * these commits as much as is reasonable so that we don't degrade to a
 * few IO round trips per request.
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
	scoutfs_inc_counter(sb, server_commit_worker);

	down_write(&server->commit_rwsem);


	ret = scoutfs_block_writer_write(sb, &server->wri);
	if (ret) {
		scoutfs_err(sb, "server error writing btree blocks: %d", ret);
		goto out;
	}

	update_free_blocks(&super->free_meta_blocks, &super->core_meta_avail,
			   &server->alloc.avail);
	update_free_blocks(&super->free_meta_blocks, &super->core_meta_freed,
			   &server->alloc.freed);

	super->core_meta_avail = server->alloc.avail;
	super->core_meta_freed = server->alloc.freed;

	ret = scoutfs_write_super(sb, super);
	if (ret) {
		scoutfs_err(sb, "server error writing super block: %d", ret);
		goto out;
	}

	server->prepared_commit = false;
	set_roots(server, &super->fs_root, &super->logs_root);
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

static int server_alloc_inodes(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_net_inode_alloc ial = { 0, };
	__le64 lecount;
	u64 ino;
	u64 nr;
	int ret;

	if (arg_len != sizeof(lecount)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&lecount, arg, arg_len);

	ret = scoutfs_server_hold_commit(sb);
	if (ret)
		goto out;

	spin_lock(&sbi->next_ino_lock);
	ino = le64_to_cpu(super->next_ino);
	nr = min(le64_to_cpu(lecount), U64_MAX - ino);
	le64_add_cpu(&super->next_ino, nr);
	spin_unlock(&sbi->next_ino_lock);

	ret = scoutfs_server_apply_commit(sb, ret);
	if (ret == 0) {
		ial.ino = cpu_to_le64(ino);
		ial.nr = cpu_to_le64(nr);
	}
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &ial, sizeof(ial));
}

/*
 * Give the client roots to all the trees that they'll use to build
 * their transaction.
 *
 * We make sure that their alloc trees have sufficient blocks to
 * allocate metadata and data for the transaction.  We merge their freed
 * trees back into the core allocators.  They're were committed with the
 * previous transaction so they're stable and can now be reused, even by
 * the server in this commit.
 */
static int server_get_log_trees(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	u64 rid = scoutfs_net_client_rid(conn);
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_log_trees lt;
	struct scoutfs_key key;
	u64 count;
	u64 target;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = scoutfs_server_hold_commit(sb);
	if (ret)
		goto out;

	mutex_lock(&server->logs_mutex);

	scoutfs_key_init_log_trees(&key, rid, U64_MAX);

	ret = scoutfs_btree_prev(sb, &super->logs_root, &key, &iref);
	if (ret < 0 && ret != -ENOENT)
		goto unlock;
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			key = *iref.key;
			memcpy(&ltv, iref.val, iref.val_len);
			if (le64_to_cpu(key.sklt_rid) != rid)
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
		key.sklt_rid = cpu_to_le64(rid);
		key.sklt_nr = cpu_to_le64(1);
		memset(&ltv, 0, sizeof(ltv));
		scoutfs_radix_root_init(sb, &ltv.meta_avail, true);
		scoutfs_radix_root_init(sb, &ltv.meta_freed, true);
		scoutfs_radix_root_init(sb, &ltv.data_avail, false);
		scoutfs_radix_root_init(sb, &ltv.data_freed, false);
	}

	ret = scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &server->alloc.avail,
				  &ltv.meta_freed, &ltv.meta_freed, true,
				  le64_to_cpu(ltv.meta_freed.ref.sm_total)) ?:
	      scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &super->core_data_avail,
				  &ltv.data_freed, &ltv.data_freed, false,
				  le64_to_cpu(ltv.data_freed.ref.sm_total));
	if (ret < 0)
		goto unlock;

	/* ensure client has enough free metadata blocks for a transaction */
	target = (64*1024*1024) / SCOUTFS_BLOCK_LG_SIZE;
	if (le64_to_cpu(ltv.meta_avail.ref.sm_total) < target) {
		count = target - le64_to_cpu(ltv.meta_avail.ref.sm_total);

		ret = scoutfs_radix_merge(sb, &server->alloc, &server->wri,
					  &ltv.meta_avail,
					  &server->alloc.avail,
					  &server->alloc.avail, true, count);
		if (ret < 0)
			goto unlock;
	}

	/* ensure client has enough free data blocks for a transaction */
	target = SCOUTFS_TRANS_DATA_ALLOC_HWM / SCOUTFS_BLOCK_SM_SIZE;
	if (le64_to_cpu(ltv.data_avail.ref.sm_total) < target) {
		count = target - le64_to_cpu(ltv.data_avail.ref.sm_total);

		ret = scoutfs_radix_merge(sb, &server->alloc, &server->wri,
					  &ltv.data_avail,
					  &super->core_data_avail,
					  &super->core_data_avail, false,
					  count);
		if (ret < 0)
			goto unlock;
	}

	/* update client's log tree's item */
	ret = scoutfs_btree_force(sb, &server->alloc, &server->wri,
				  &super->logs_root, &key, &ltv, sizeof(ltv));
unlock:
	mutex_unlock(&server->logs_mutex);

	ret = scoutfs_server_apply_commit(sb, ret);
	if (ret == 0) {
		lt.meta_avail = ltv.meta_avail;
		lt.meta_freed = ltv.meta_freed;
		lt.item_root = ltv.item_root;
		lt.bloom_ref = ltv.bloom_ref;
		lt.data_avail = ltv.data_avail;
		lt.data_freed = ltv.data_freed;
		lt.rid = key.sklt_rid;
		lt.nr = key.sklt_nr;
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
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_log_trees *lt;
	struct scoutfs_key key;
	int ret;

	if (arg_len != sizeof(struct scoutfs_log_trees)) {
		ret = -EINVAL;
		goto out;
	}
	lt = arg;

	ret = scoutfs_server_hold_commit(sb);
	if (ret < 0) {
		scoutfs_err(sb, "server error preparing commit: %d", ret);
		goto out;
	}

	mutex_lock(&server->logs_mutex);

	/* find the client's existing item */
	scoutfs_key_init_log_trees(&key, le64_to_cpu(lt->rid),
				   le64_to_cpu(lt->nr));
	ret = scoutfs_btree_lookup(sb, &super->logs_root, &key, &iref);
	if (ret < 0 && ret != -ENOENT) {
		scoutfs_err(sb, "server error finding client logs: %d", ret);
		goto unlock;
	}
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			memcpy(&ltv, iref.val, iref.val_len);
		} else {
			ret = -EIO;
			scoutfs_err(sb, "server error, invalid log item: %d",
				    ret);
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto unlock;
	}

	update_free_blocks(&super->free_meta_blocks, &ltv.meta_avail,
			   &lt->meta_avail);
	update_free_blocks(&super->free_meta_blocks, &ltv.meta_freed,
			   &lt->meta_freed);
	update_free_blocks(&super->free_data_blocks, &ltv.data_avail,
			   &lt->data_avail);
	update_free_blocks(&super->free_data_blocks, &ltv.data_freed,
			   &lt->data_freed);

	ltv.meta_avail = lt->meta_avail;
	ltv.meta_freed = lt->meta_freed;
	ltv.item_root = lt->item_root;
	ltv.bloom_ref = lt->bloom_ref;
	ltv.data_avail = lt->data_avail;
	ltv.data_freed = lt->data_freed;

	ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				   &super->logs_root, &key, &ltv, sizeof(ltv));
	if (ret < 0)
		scoutfs_err(sb, "server error updating client logs: %d", ret);

unlock:
	mutex_unlock(&server->logs_mutex);

	ret = scoutfs_server_apply_commit(sb, ret);
	if (ret < 0)
		scoutfs_err(sb, "server error commiting client logs: %d", ret);
out:
	WARN_ON_ONCE(ret < 0);
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/*
 * Give the client the most recent version of the fs btrees that are
 * visible in persistent storage.  We don't want to accidentally give
 * them our in-memory dirty version.  This can be racing with commits.
 */
static int server_get_roots(struct super_block *sb,
			    struct scoutfs_net_connection *conn,
			    u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_net_roots roots;
	int ret;

	if (arg_len != 0) {
		memset(&roots, 0, sizeof(roots));
		ret = -EINVAL;
	}  else {
		scoutfs_server_get_roots(sb, &roots);
		ret = 0;
	}

	return scoutfs_net_response(sb, conn, cmd, id, 0,
				    &roots, sizeof(roots));
}

/*
 * A client is being evicted so we want to reclaim resources from their
 * log tree items.  The item trees and bloom refs stay around to be read
 * and eventually merged and we reclaim all the allocator items.
 *
 * The caller holds the commit rwsem which means we do all this work in
 * one server commit.  We'll need to keep the total amount of blocks in
 * trees in check.
 *
 * By the time we're evicting a client they've either synced their data
 * or have been forcefully removed.  The free blocks in the allocator
 * roots are stable and can be merged back into allocator items for use
 * without risking overwriting stable data.
 *
 * We can return an error without fully reclaiming all the log item's
 * referenced data.
 */
static int reclaim_log_trees(struct super_block *sb, u64 rid)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_key key;
	int ret;
	int err;

	mutex_lock(&server->logs_mutex);
	down_write(&server->alloc_rwsem);

	/* find the client's existing item */
	scoutfs_key_init_log_trees(&key, rid, 0);
	ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			key = *iref.key;
			memcpy(&ltv, iref.val, iref.val_len);
			if (le64_to_cpu(key.sklt_rid) != rid)
				ret = -ENOENT;
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	/*
	 * All of these can return errors after having modified the
	 * radix trees.  We have to try and update the roots in the
	 * log item.
	 */
	ret = scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &server->alloc.avail,
				  &ltv.meta_avail, &ltv.meta_avail, true,
				  le64_to_cpu(ltv.meta_avail.ref.sm_total)) ?:
	      scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &server->alloc.avail,
				  &ltv.meta_freed, &ltv.meta_freed, true,
				  le64_to_cpu(ltv.meta_freed.ref.sm_total)) ?:
	      scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &super->core_data_avail,
				  &ltv.data_avail, &ltv.data_avail, false,
				  le64_to_cpu(ltv.data_avail.ref.sm_total)) ?:
	      scoutfs_radix_merge(sb, &server->alloc, &server->wri,
				  &super->core_data_avail,
				  &ltv.data_freed, &ltv.data_freed, false,
				  le64_to_cpu(ltv.data_freed.ref.sm_total));

	err = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				  &super->logs_root, &key, &ltv, sizeof(ltv));
	BUG_ON(err != 0); /* alloc and log item roots out of sync */

out:
	up_write(&server->alloc_rwsem);
	mutex_unlock(&server->logs_mutex);

	return ret;
}

static void init_trans_seq_key(struct scoutfs_key *key, u64 seq, u64 rid)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_TRANS_SEQ_ZONE,
		.skts_trans_seq = cpu_to_le64(seq),
		.skts_rid = cpu_to_le64(rid),
	};
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
	__le64 their_seq;
	__le64 next_seq;
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_key key;
	int ret;

	if (arg_len != sizeof(__le64)) {
		ret = -EINVAL;
		goto out;
	}
	memcpy(&their_seq, arg, sizeof(their_seq));

	ret = scoutfs_server_hold_commit(sb);
	if (ret)
		goto out;

	down_write(&server->seq_rwsem);

	if (their_seq != 0) {
		init_trans_seq_key(&key, le64_to_cpu(their_seq), rid);
		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->trans_seqs, &key);
		if (ret < 0 && ret != -ENOENT)
			goto out;
	}

	next_seq = super->next_trans_seq;
	le64_add_cpu(&super->next_trans_seq, 1);

	trace_scoutfs_trans_seq_advance(sb, rid, le64_to_cpu(their_seq),
					le64_to_cpu(next_seq));

	init_trans_seq_key(&key, le64_to_cpu(next_seq), rid);
	ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				   &super->trans_seqs, &key, NULL, 0);
out:
	up_write(&server->seq_rwsem);
	ret = scoutfs_server_apply_commit(sb, ret);

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
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret = 0;

	down_write(&server->seq_rwsem);

	init_trans_seq_key(&key, 0, 0);

	for (;;) {
		ret = scoutfs_btree_next(sb, &super->trans_seqs, &key, &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		key = *iref.key;
		scoutfs_btree_put_iref(&iref);

		if (le64_to_cpu(key.skts_rid) == rid) {
			trace_scoutfs_trans_seq_farewell(sb, rid,
					le64_to_cpu(key.skts_trans_seq));
			ret = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->trans_seqs, &key);
			break;
		}

		scoutfs_key_inc(&key);
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
	SCOUTFS_BTREE_ITEM_REF(iref);
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_key key;
	__le64 last_seq = 0;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	down_read(&server->seq_rwsem);

	init_trans_seq_key(&key, 0, 0);
	ret = scoutfs_btree_next(sb, &super->trans_seqs, &key, &iref);
	if (ret == 0) {
		key = *iref.key;
		scoutfs_btree_put_iref(&iref);
		last_seq = key.skts_trans_seq;

	} else if (ret == -ENOENT) {
		last_seq = super->next_trans_seq;
		ret = 0;
	}

	le64_add_cpu(&last_seq, -1ULL);
	trace_scoutfs_trans_seq_last(sb, rid, le64_to_cpu(last_seq));

	up_read(&server->seq_rwsem);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &last_seq, sizeof(last_seq));
}

static inline __le64 le64_lg_to_sm(__le64 lg)
{
	return cpu_to_le64(le64_to_cpu(lg) << SCOUTFS_BLOCK_SM_LG_SHIFT);
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
		nstatfs.total_blocks = le64_lg_to_sm(super->total_meta_blocks);
		le64_add_cpu(&nstatfs.total_blocks,
			     le64_to_cpu(super->total_data_blocks));
		nstatfs.bfree = le64_lg_to_sm(super->free_meta_blocks);
		le64_add_cpu(&nstatfs.bfree,
			     le64_to_cpu(super->free_data_blocks));
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

int scoutfs_server_lock_response(struct super_block *sb, u64 rid, u64 id,
				 struct scoutfs_net_lock_grant_response *gr)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_response_node(sb, server->conn, rid,
					 SCOUTFS_NET_CMD_LOCK, id, 0,
					 gr, sizeof(*gr));
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

static void init_mounted_client_key(struct scoutfs_key *key, u64 rid)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_MOUNTED_CLIENT_ZONE,
		.skmc_rid = cpu_to_le64(rid),
	};
}

static int insert_mounted_client(struct super_block *sb, u64 rid,
				 u64 gr_flags)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_mounted_client_btree_val mcv;
	struct scoutfs_key key;

	init_mounted_client_key(&key, rid);
	mcv.flags = 0;
	if (gr_flags & SCOUTFS_NET_GREETING_FLAG_VOTER)
		mcv.flags |= SCOUTFS_MOUNTED_CLIENT_VOTER;

	return scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				    &super->mounted_clients, &key, &mcv,
				    sizeof(mcv));
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
	struct scoutfs_key key;
	int ret;

	init_mounted_client_key(&key, rid);

	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->mounted_clients, &key);
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
		ret = scoutfs_server_hold_commit(sb);
		if (ret < 0)
			goto send_err;

		spin_lock(&server->lock);
		umb = super->unmount_barrier;
		spin_unlock(&server->lock);

		mutex_lock(&server->farewell_mutex);
		ret = insert_mounted_client(sb, le64_to_cpu(gr->rid),
					    le64_to_cpu(gr->flags));
		mutex_unlock(&server->farewell_mutex);

		ret = scoutfs_server_apply_commit(sb, ret);
		queue_work(server->wq, &server->farewell_work);
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
		ret = scoutfs_server_hold_commit(sb);
		if (ret)
			goto out;

		ret = scoutfs_lock_server_greeting(sb, le64_to_cpu(gr->rid),
						   gr->server_term != 0);
		ret = scoutfs_server_apply_commit(sb, ret);
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
	return (iref->val_len !=
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
	struct scoutfs_mounted_client_btree_val *mcv;
	struct farewell_request *tmp;
	struct farewell_request *fw;
	SCOUTFS_BTREE_ITEM_REF(iref);
	unsigned int nr_unmounting = 0;
	unsigned int nr_mounted = 0;
	struct scoutfs_key key;
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
		init_mounted_client_key(&key, fw->rid);
		ret = scoutfs_btree_lookup(sb, &super->mounted_clients, &key,
					   &iref);
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
	init_mounted_client_key(&key, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->mounted_clients, &key,
					 &iref);
		if (ret == 0 && invalid_mounted_client_item(&iref)) {
			scoutfs_btree_put_iref(&iref);
			ret = -EIO;
		}
		if (ret != 0) {
			if (ret == -ENOENT)
				break;
			goto out;
		}

		key = *iref.key;
		mcv = iref.val;

		if (mcv->flags & SCOUTFS_MOUNTED_CLIENT_VOTER)
			nr_mounted++;

		scoutfs_btree_put_iref(&iref);
		scoutfs_key_inc(&key);
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
		ret = scoutfs_server_hold_commit(sb);
		if (ret)
			goto out;

		ret = scoutfs_lock_server_farewell(sb, fw->rid) ?:
		      remove_trans_seq(sb, fw->rid) ?:
		      reclaim_log_trees(sb, fw->rid) ?:
		      delete_mounted_client(sb, fw->rid);

		ret = scoutfs_server_apply_commit(sb, ret);
		if (ret)
			goto out;
	}

	/* update the unmount barrier if we deleted all voting clients */
	if (deleted && nr_mounted == 0) {
		ret = scoutfs_server_hold_commit(sb);
		if (ret)
			goto out;

		le64_add_cpu(&super->unmount_barrier, 1);

		ret = scoutfs_server_apply_commit(sb, ret);
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

static scoutfs_net_request_t server_req_funcs[] = {
	[SCOUTFS_NET_CMD_GREETING]		= server_greeting,
	[SCOUTFS_NET_CMD_ALLOC_INODES]		= server_alloc_inodes,
	[SCOUTFS_NET_CMD_GET_LOG_TREES]		= server_get_log_trees,
	[SCOUTFS_NET_CMD_COMMIT_LOG_TREES]	= server_commit_log_trees,
	[SCOUTFS_NET_CMD_GET_ROOTS]		= server_get_roots,
	[SCOUTFS_NET_CMD_ADVANCE_SEQ]		= server_advance_seq,
	[SCOUTFS_NET_CMD_GET_LAST_SEQ]		= server_get_last_seq,
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
		spin_lock(&server->lock);
		list_add_tail(&sci->head, &server->clients);
		server->nr_clients++;
		trace_scoutfs_server_client_up(sb, rid, server->nr_clients);
		spin_unlock(&server->lock);
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

	set_roots(server, &super->fs_root, &super->logs_root);
	scoutfs_radix_init_alloc(&server->alloc, &super->core_meta_avail,
				 &super->core_meta_freed);
	scoutfs_block_writer_init(sb, &server->wri);

	ret = scoutfs_lock_server_setup(sb, &server->alloc, &server->wri);
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
	/* wait for commit queued by request processing */
	flush_work(&server->commit_work);
	server->conn = NULL;

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
	init_rwsem(&server->seq_rwsem);
	init_rwsem(&server->alloc_rwsem);
	INIT_LIST_HEAD(&server->clients);
	mutex_init(&server->farewell_mutex);
	INIT_LIST_HEAD(&server->farewell_requests);
	INIT_WORK(&server->farewell_work, farewell_worker);
	mutex_init(&server->logs_mutex);
	seqcount_init(&server->roots_seqcount);

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
