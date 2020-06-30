/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
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

#include "format.h"
#include "counters.h"
#include "net.h"
#include "tseq.h"
#include "spbm.h"
#include "block.h"
#include "radix.h"
#include "btree.h"
#include "msg.h"
#include "scoutfs_trace.h"
#include "lock_server.h"

/*
 * The scoutfs server implements a simple lock service.  Client mounts
 * request access to locks identified by a key.  The server ensures that
 * access mode exclusion is properly enforced.
 *
 * The server processing paths are implemented in network message
 * receive processing callbacks.  We're receiving either a grant request
 * or an invalidation response.  These processing callbacks are fully
 * concurrent.  Our grant responses and invalidation requests are sent
 * from these contexts.
 *
 * We separate the locking of the global index of tracked locks from the
 * locking of a lock's state.  This allows concurrent work on unrelated
 * locks and lets processing block sending responses to unresponsive
 * clients without affecting other locks.
 *
 * Correctness of the protocol relies on the client and server each only
 * sending one request at a time for a given lock.  The server won't
 * process a request from a client until its outstanding invalidation
 * requests for the lock to other clients have been completed.  The
 * server specifies both the old mode and new mode when sending messages
 * to the client.  This lets the client resolve possible reordering when
 * processing incoming grant responses and invalidation requests.  The
 * server doesn't use the modes specified by the clients but they're
 * provided to add context.
 *
 * The server relies on the client's static rid and on reliable
 * messaging.  Each client has a rid that is unique for its life time.
 * Message requests and responses are reliably delivered in order across
 * reconnection.
 *
 * The server maintains a persistent record of connected clients.  A new
 * server instance discovers these and waits for previously connected
 * clients to reconnect and recover their state before proceeding.  If
 * clients don't reconnect they are forcefully prevented from unsafely
 * accessing the shared persistent storage.  (fenced, according to the
 * rules of the platform.. could range from being powered off to having
 * their switch port disabled to having their local block device set
 * read-only.)
 *
 * The lock server doesn't respond to memory pressure.  The only way
 * locks are freed is if they are invalidated to null on behalf of a
 * conflicting request, clients specifically request a null mode, or the
 * server shuts down.
 */

#define LOCK_SERVER_RECOVERY_MS	(10 * MSEC_PER_SEC)

struct lock_server_info {
	struct super_block *sb;

	spinlock_t lock;
	struct mutex mutex;
	struct rb_root locks_root;

	struct scoutfs_spbm recovery_pending;
	struct delayed_work recovery_dwork;

	struct scoutfs_tseq_tree tseq_tree;
	struct dentry *tseq_dentry;

	struct scoutfs_radix_allocator *alloc;
	struct scoutfs_block_writer *wri;
};

#define DECLARE_LOCK_SERVER_INFO(sb, name) \
	struct lock_server_info *name = SCOUTFS_SB(sb)->lock_server_info

/*
 * The state of a lock on the server is a function of the state of the
 * locks on all clients.
 *
 * @granted:
 * granted or trigger invalidation of previously granted.
 * The state of a lock on the server is a function of messages that have
 * been sent and received from clients on behalf of a given lock.
 *
 * While the invalidated list has entries, which means invalidation
 * messages are still in flight, no more requests will be processed.
 */
struct server_lock_node {
	atomic_t refcount;
	struct mutex mutex;
	struct rb_node node;
	struct scoutfs_key key;

	struct list_head granted;
	struct list_head requested;
	struct list_head invalidated;
};

enum {
	CLE_GRANTED,
	CLE_REQUESTED,
	CLE_INVALIDATED,
};

/*
 * Interactions with the client are tracked with these little mode
 * wrappers.
 *
 * @entry: The client mode's entry on one of the server lock lists indicating
 * that the mode is actively granted, a pending request from the client,
 * or a pending invalidation sent to the client.
 *
 * @rid: The client's rid used to send messages and tear down
 * state as client's exit.
 *
 * @net_id: The id of a client's request used to send grant responses.  The
 * id of invalidation requests sent to clients that could be used to cancel
 * the message.
 *
 * @mode: the mode that is granted to the client, that the client
 * requested, or that the server is asserting with a pending
 * invalidation request message.
 */
struct client_lock_entry {
	struct list_head head;
	u64 rid;
	u64 net_id;
	u8 mode;

	struct server_lock_node *snode;
	struct scoutfs_tseq_entry tseq_entry;
	u8 on_list;
};

enum {
	OL_GRANTED = 0,
	OL_REQUESTED,
	OL_INVALIDATED,
};

/*
 * Put an entry on a server lock's list while being careful to move or
 * add the list head and while maintaining debugging info.
 */
static void add_client_entry(struct server_lock_node *snode,
			     struct list_head *list,
			     struct client_lock_entry *clent)
{
	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	if (list_empty(&clent->head))
		list_add_tail(&clent->head, list);
	else
		list_move_tail(&clent->head, list);

	clent->on_list = list == &snode->granted ? OL_GRANTED :
			 list == &snode->requested ? OL_REQUESTED :
			 OL_INVALIDATED;
}

static void free_client_entry(struct lock_server_info *inf,
			      struct server_lock_node *snode,
			      struct client_lock_entry *clent)
{
	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	if (!list_empty(&clent->head))
		list_del_init(&clent->head);
	scoutfs_tseq_del(&inf->tseq_tree, &clent->tseq_entry);
	kfree(clent);
}

static bool invalid_mode(u8 mode)
{
	return mode >= SCOUTFS_LOCK_INVALID;
}

/*
 * Return the mode that we should invalidate a granted lock down to
 * given an incompatible requested mode.  Usually we completely
 * invalidate the items because incompatible requests have to be writers
 * and our cache will then be stale, but the single exception is
 * invalidating down to a read lock having held a write lock because the
 * cache is still valid for reads after being written out.
 */
static u8 invalidation_mode(u8 granted, u8 requested)
{
	if (granted == SCOUTFS_LOCK_WRITE && requested == SCOUTFS_LOCK_READ)
		return SCOUTFS_LOCK_READ;

	return SCOUTFS_LOCK_NULL;
}

/*
 * Return true of the client lock instances described by the entries can
 * be granted at the same time.  Typically this only means they're both
 * modes that are compatible between nodes. In addition there's the
 * special case where a read lock on a client is compatible with a write
 * lock on the same client because the client's cache covered by the
 * read lock is still valid if they get a write lock.
 */
static bool client_entries_compatible(struct client_lock_entry *granted,
				      struct client_lock_entry *requested)
{
	return (granted->mode == requested->mode &&
		(granted->mode == SCOUTFS_LOCK_READ ||
		 granted->mode == SCOUTFS_LOCK_WRITE_ONLY)) ||
	       (granted->rid == requested->rid &&
		granted->mode == SCOUTFS_LOCK_READ &&
		requested->mode == SCOUTFS_LOCK_WRITE);
}

/*
 * Get a locked server lock, possibly inserting the caller's allocated
 * lock if we don't find one for the given key.  The server lock's mutex
 * is held on return and the caller must put the lock when they're done.
 */
static struct server_lock_node *get_server_lock(struct lock_server_info *inf,
						struct scoutfs_key *key,
						struct server_lock_node *ins,
						bool or_next)
{
	struct rb_root *root = &inf->locks_root;
	struct server_lock_node *ret = NULL;
	struct server_lock_node *next = NULL;
	struct server_lock_node *snode;
	struct rb_node *parent = NULL;
	struct rb_node **node;
	int cmp;

	spin_lock(&inf->lock);

	node = &root->rb_node;
	while (*node) {
		parent = *node;
		snode = container_of(*node, struct server_lock_node, node);

		cmp = scoutfs_key_compare(key, &snode->key);
		if (cmp < 0) {
			if (or_next)
				next = snode;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			ret = snode;
			break;
		}
	}

	if (ret == NULL && ins) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
		ret = ins;
	}

	if (ret == NULL && or_next && next)
		ret = next;

	if (ret)
		atomic_inc(&ret->refcount);

	spin_unlock(&inf->lock);

	if (ret)
		mutex_lock(&ret->mutex);

	return ret;
}

/* Get a server lock node, allocating if one doesn't exist.  Caller must put. */
static struct server_lock_node *alloc_server_lock(struct lock_server_info *inf,
						  struct scoutfs_key *key)
{
	struct server_lock_node *snode;
	struct server_lock_node *ins;

	snode = get_server_lock(inf, key, NULL, false);
	if (snode == NULL) {
		ins = kzalloc(sizeof(struct server_lock_node), GFP_NOFS);
		if (ins) {
			atomic_set(&ins->refcount, 0);
			mutex_init(&ins->mutex);
			ins->key = *key;
			INIT_LIST_HEAD(&ins->granted);
			INIT_LIST_HEAD(&ins->requested);
			INIT_LIST_HEAD(&ins->invalidated);

			snode = get_server_lock(inf, key, ins, false);
			if (snode != ins)
				kfree(ins);
		}
	}

	return snode;
}

/*
 * Finish with a server lock which has the mutex held, freeing it if
 * it's empty and unused.
 */
static void put_server_lock(struct lock_server_info *inf,
			    struct server_lock_node *snode)
{
	bool should_free = false;

	BUG_ON(!mutex_is_locked(&snode->mutex));

	if (atomic_dec_and_test(&snode->refcount) &&
	    list_empty(&snode->granted) &&
	    list_empty(&snode->requested) &&
	    list_empty(&snode->invalidated)) {
		spin_lock(&inf->lock);
		rb_erase(&snode->node, &inf->locks_root);
		spin_unlock(&inf->lock);
		should_free = true;
	}

	mutex_unlock(&snode->mutex);

	if (should_free)
		kfree(snode);
}

static struct client_lock_entry *find_entry(struct server_lock_node *snode,
					    struct list_head *list,
					    u64 rid)
{
	struct client_lock_entry *clent;

	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	list_for_each_entry(clent, list, head) {
		if (clent->rid == rid)
			return clent;
	}

	return NULL;
}

static int process_waiting_requests(struct super_block *sb,
				    struct server_lock_node *snode);

/*
 * The server is receiving an incoming request from a client.  We queue
 * it on the lock and process it.
 *
 * XXX shut down if we get enomem?
 */
int scoutfs_lock_server_request(struct super_block *sb, u64 rid,
				u64 net_id, struct scoutfs_net_lock *nl)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *clent;
	struct server_lock_node *snode;
	int ret;

	trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_GRANT, SLT_REQUEST,
				   rid, net_id, nl);

	if (invalid_mode(nl->old_mode) || invalid_mode(nl->new_mode)) {
		ret = -EINVAL;
		goto out;
	}

	clent = kzalloc(sizeof(struct client_lock_entry), GFP_NOFS);
	if (!clent) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&clent->head);
	clent->rid = rid;
	clent->net_id = net_id;
	clent->mode = nl->new_mode;

	snode = alloc_server_lock(inf, &nl->key);
	if (snode == NULL) {
		kfree(clent);
		ret = -ENOMEM;
		goto out;
	}

	clent->snode = snode;
	add_client_entry(snode, &snode->requested, clent);
	scoutfs_tseq_add(&inf->tseq_tree, &clent->tseq_entry);

	ret = process_waiting_requests(sb, snode);
out:
	return ret;
}

/*
 * The server is receiving an invalidation response from the client.
 * Find the client's entry on the server lock's invalidation list and
 * free it so that request processing might be able to make forward
 * progress.
 *
 * XXX what to do with errors?  kick the client?
 */
int scoutfs_lock_server_response(struct super_block *sb, u64 rid,
				 struct scoutfs_net_lock *nl)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *clent;
	struct server_lock_node *snode;
	int ret;

	trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_INVALIDATE, SLT_RESPONSE,
				   rid, 0, nl);

	if (invalid_mode(nl->old_mode) || invalid_mode(nl->new_mode)) {
		ret = -EINVAL;
		goto out;
	}

	/* XXX should always have a server lock here?  recovery? */
	snode = get_server_lock(inf, &nl->key, NULL, false);
	if (!snode) {
		ret = -EINVAL;
		goto out;
	}

	clent = find_entry(snode, &snode->invalidated, rid);
	if (!clent) {
		put_server_lock(inf, snode);
		ret = -EINVAL;
		goto out;
	}

	if (nl->new_mode == SCOUTFS_LOCK_NULL) {
		free_client_entry(inf, snode, clent);
	} else {
		clent->mode = nl->new_mode;
		add_client_entry(snode, &snode->granted, clent);
	}

	ret = process_waiting_requests(sb, snode);
out:
	return ret;
}

/*
 * Make forward progress on a lock by checking each waiting request in
 * the order that they were received.  If the next request is compatible
 * with all the clients' grants then the request is granted and a
 * response is sent.
 *
 * Invalidation requests are sent for every client grant that is
 * incompatible with the next request.  We won't process the next
 * request again until we receive all the invalidation responses.  Once
 * they're all received then the request can be processed and will be
 * compatible with the remaining grants.
 *
 * This is called with the snode mutex held.  This can free the snode if
 * it's empty.  The caller can't reference the snode once this returns
 * so we unlock the snode mutex.
 *
 * All progress must wait for all clients to finish with recovery
 * because we don't know which locks they'll hold.  The unlocked
 * recovery_pending test here is OK.  It's filled by setup before
 * anything runs.  It's emptied by recovery completion.  We can get a
 * false nonempty result if we race with recovery completion, but that's
 * OK because recovery completion processes all the locks that have
 * requests after emptying, including the unlikely loser of that race.
 */
static int process_waiting_requests(struct super_block *sb,
				    struct server_lock_node *snode)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct scoutfs_net_lock_grant_response gres;
	struct scoutfs_net_lock nl;
	struct client_lock_entry *req;
	struct client_lock_entry *req_tmp;
	struct client_lock_entry *gr;
	struct client_lock_entry *gr_tmp;
	static atomic64_t write_version = ATOMIC64_INIT(0);
	u64 wv;
	int ret;

	BUG_ON(!mutex_is_locked(&snode->mutex));

	/* processing waits for all invalidation responses or recovery */
	if (!list_empty(&snode->invalidated) ||
	    !scoutfs_spbm_empty(&inf->recovery_pending)) {
		ret = 0;
		goto out;
	}

	/* walk through pending requests in order received */
	list_for_each_entry_safe(req, req_tmp, &snode->requested, head) {

		/* send invalidation to any incompatible grants */
		list_for_each_entry_safe(gr, gr_tmp, &snode->granted, head) {
			if (client_entries_compatible(gr, req))
				continue;

			nl.key = snode->key;
			nl.old_mode = gr->mode;
			nl.new_mode = invalidation_mode(gr->mode, req->mode);

			ret = scoutfs_server_lock_request(sb, gr->rid, &nl);
			if (ret)
				goto out;

			trace_scoutfs_lock_message(sb, SLT_SERVER,
						   SLT_INVALIDATE, SLT_REQUEST,
						   gr->rid, 0, &nl);

			add_client_entry(snode, &snode->invalidated, gr);
		}

		/* wait for any newly sent invalidations */
		if (!list_empty(&snode->invalidated))
			break;

		nl.key = snode->key;
		nl.new_mode = req->mode;

		/* see if there's an existing compatible grant to replace */
		gr = find_entry(snode, &snode->granted, req->rid);
		if (gr) {
			nl.old_mode = gr->mode;
			free_client_entry(inf, snode, gr);
		} else {
			nl.old_mode = SCOUTFS_LOCK_NULL;
		}

		if (nl.new_mode == SCOUTFS_LOCK_WRITE ||
		    nl.new_mode == SCOUTFS_LOCK_WRITE_ONLY) {
			wv = atomic64_inc_return(&write_version);
			nl.write_version = cpu_to_le64(wv);
		}

		gres.nl = nl;
		scoutfs_server_get_roots(sb, &gres.roots);

		ret = scoutfs_server_lock_response(sb, req->rid,
						   req->net_id, &gres);
		if (ret)
			goto out;

		trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_GRANT,
					   SLT_RESPONSE, req->rid,
					   req->net_id, &nl);

		/* don't track null client locks, track all else */ 
		if (req->mode == SCOUTFS_LOCK_NULL)
			free_client_entry(inf, snode, req);
		else
			add_client_entry(snode, &snode->granted, req);
	}

	ret = 0;
out:
	put_server_lock(inf, snode);

	return ret;
}

static void init_lock_clients_key(struct scoutfs_key *key, u64 rid)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_LOCK_CLIENTS_ZONE,
		.sklc_rid = cpu_to_le64(rid),
	};
}

/*
 * The server received a greeting from a client for the first time.  If
 * the client had already talked to the server then we must find an
 * existing record for it and should begin recovery.  If it doesn't have
 * a record then its timed out and we can't allow it to reconnect.  If
 * its connecting for the first time then we insert a new record.  If
 *
 * This is running in concurrent client greeting processing contexts.
 */
int scoutfs_lock_server_greeting(struct super_block *sb, u64 rid,
				 bool should_exist)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	init_lock_clients_key(&key, rid);

	mutex_lock(&inf->mutex);
	if (should_exist) {
		ret = scoutfs_btree_lookup(sb, &super->lock_clients, &key,
					   &iref);
		if (ret == 0)
			scoutfs_btree_put_iref(&iref);
	} else {
		ret = scoutfs_btree_insert(sb, inf->alloc, inf->wri,
					   &super->lock_clients,
					   &key, NULL, 0);
	}
	mutex_unlock(&inf->mutex);

	if (should_exist && ret == 0) {
		scoutfs_key_set_zeros(&key);
		ret = scoutfs_server_lock_recover_request(sb, rid, &key);
		if (ret)
			goto out;
	}

out:
	return ret;
}

/*
 * A client sent their last recovery response and can exit recovery.  If
 * they were the last client in recovery then we can process all the
 * server locks that had requests.
 */
static int finished_recovery(struct super_block *sb, u64 rid, bool cancel)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct server_lock_node *snode;
	struct scoutfs_key key;
	bool still_pending;
	int ret = 0;

	spin_lock(&inf->lock);
	scoutfs_spbm_clear(&inf->recovery_pending, rid);
	still_pending = !scoutfs_spbm_empty(&inf->recovery_pending);
	spin_unlock(&inf->lock);
	if (still_pending)
		return 0;

	if (cancel)
		cancel_delayed_work_sync(&inf->recovery_dwork);

	scoutfs_key_set_zeros(&key);

	scoutfs_info(sb, "all lock clients recovered");

	while ((snode = get_server_lock(inf, &key, NULL, true))) {

		key = snode->key;
		scoutfs_key_inc(&key);

		if (!list_empty(&snode->requested)) {
			ret = process_waiting_requests(sb, snode);
			if (ret)
				break;
		} else {
			put_server_lock(inf, snode);
		}
	}

	return ret;
}

/*
 * We sent a lock recover request to the client when we received its
 * greeting while in recovery.  Here we instantiate all the locks it
 * gave us in response and send another request from the next key.
 * We're done once we receive an empty response.
 */
int scoutfs_lock_server_recover_response(struct super_block *sb, u64 rid,
					 struct scoutfs_net_lock_recover *nlr)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *existing;
	struct client_lock_entry *clent;
	struct server_lock_node *snode;
	struct scoutfs_key key;
	int ret = 0;
	int i;

	/* client must be in recovery */
	spin_lock(&inf->lock);
	if (!scoutfs_spbm_test(&inf->recovery_pending, rid))
		ret = -EINVAL;
	spin_unlock(&inf->lock);
	if (ret)
		goto out;

	/* client has sent us all their locks */
	if (nlr->nr == 0) {
		ret = finished_recovery(sb, rid, true);
		goto out;
	}

	for (i = 0; i < le16_to_cpu(nlr->nr); i++) {
		clent = kzalloc(sizeof(struct client_lock_entry), GFP_NOFS);
		if (!clent) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(&clent->head);
		clent->rid = rid;
		clent->net_id = 0;
		clent->mode = nlr->locks[i].new_mode;

		snode = alloc_server_lock(inf, &nlr->locks[i].key);
		if (snode == NULL) {
			kfree(clent);
			ret = -ENOMEM;
			goto out;
		}

		existing = find_entry(snode, &snode->granted, rid);
		if (existing) {
			kfree(clent);
			put_server_lock(inf, snode);
			ret = -EEXIST;
			goto out;
		}

		clent->snode = snode;
		add_client_entry(snode, &snode->granted, clent);
		scoutfs_tseq_add(&inf->tseq_tree, &clent->tseq_entry);

		put_server_lock(inf, snode);
	}

	/* send request for next batch of keys */
	key = nlr->locks[le16_to_cpu(nlr->nr) - 1].key;
	scoutfs_key_inc(&key);

	ret = scoutfs_server_lock_recover_request(sb, rid, &key);
out:
	return ret;
}

static int get_rid_and_put_ref(struct scoutfs_btree_item_ref *iref, u64 *rid)
{
	int ret;

	if (iref->val_len == 0) {
		*rid = le64_to_cpu(iref->key->sklc_rid);
		ret = 0;
	} else {
		ret = -EIO;
	}
	scoutfs_btree_put_iref(iref);
	return ret;
}

/*
 * This work executes if enough time passes without all of the clients
 * finishing with recovery and canceling the work.  We walk through the
 * client records and find any that still have their recovery pending.
 */
static void scoutfs_lock_server_recovery_timeout(struct work_struct *work)
{
	struct lock_server_info *inf = container_of(work,
						    struct lock_server_info,
						    recovery_dwork.work);
	struct super_block *sb = inf->sb;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	bool timed_out;
	u64 rid;
	int ret;

	ret = scoutfs_server_hold_commit(sb);
	if (ret)
		goto out;

	/* we enter recovery if there are any client records */
	for (rid = 0; ; rid++) {
		init_lock_clients_key(&key, rid);
		ret = scoutfs_btree_next(sb, &super->lock_clients, &key, &iref);
		if (ret == -ENOENT) {
			ret = 0;
			break;
		}
		if (ret == 0)
			ret = get_rid_and_put_ref(&iref, &rid);
		if (ret < 0)
			break;

		spin_lock(&inf->lock);
		if (scoutfs_spbm_test(&inf->recovery_pending, rid)) {
			scoutfs_spbm_clear(&inf->recovery_pending, rid);
			timed_out = true;
		} else {
			timed_out = false;
		}
		spin_unlock(&inf->lock);

		if (!timed_out)
			continue;

		scoutfs_err(sb, "client rid %016llx lock recovery timed out",
			    rid);

		init_lock_clients_key(&key, rid);
		ret = scoutfs_btree_delete(sb, inf->alloc, inf->wri,
					   &super->lock_clients, &key);
		if (ret)
			break;
	}

	ret = scoutfs_server_apply_commit(sb, ret);
out:
	/* force processing all pending lock requests */
	if (ret == 0)
		ret = finished_recovery(sb, 0, false);

	if (ret < 0) {
		scoutfs_err(sb, "lock server saw err %d while timing out clients, shutting down", ret);
		scoutfs_server_abort(sb);
	}
}

/*
 * A client is leaving the lock service.  They aren't using locks and
 * won't send any more requests.  We tear down all the state we had for
 * them.  This can be called multiple times for a given client as their
 * farewell is resent to new servers.  It's OK to not find any state.
 * If we fail to delete a persistent entry then we have to shut down and
 * hope that the next server has more luck.
 */
int scoutfs_lock_server_farewell(struct super_block *sb, u64 rid)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct client_lock_entry *clent;
	struct client_lock_entry *tmp;
	struct server_lock_node *snode;
	struct scoutfs_key key;
	struct list_head *list;
	bool freed;
	int ret = 0;

	mutex_lock(&inf->mutex);
	init_lock_clients_key(&key, rid);
	ret = scoutfs_btree_delete(sb, inf->alloc, inf->wri,
				   &super->lock_clients, &key);
	mutex_unlock(&inf->mutex);
	if (ret == -ENOENT) {
		ret = 0;
		goto out;
	}
	if (ret < 0)
		goto out;

	scoutfs_key_set_zeros(&key);

	while ((snode = get_server_lock(inf, &key, NULL, true))) {

		freed = false;
		for (list = &snode->granted; list != NULL;
		     list = (list == &snode->granted) ? &snode->requested :
			    (list == &snode->requested) ? &snode->invalidated :
			    NULL) {

			list_for_each_entry_safe(clent, tmp, list, head) {
				if (clent->rid == rid) {
					free_client_entry(inf, snode, clent);
					freed = true;
				}
			}
		}

		key = snode->key;
		scoutfs_key_inc(&key);

		if (freed) {
			ret = process_waiting_requests(sb, snode);
			if (ret)
				goto out;
		} else {
			put_server_lock(inf, snode);
		}
	}
	ret = 0;

out:
	if (ret < 0) {
		scoutfs_err(sb, "lock server err %d during client rid %016llx farewell, shutting down",
			    ret, rid);
		scoutfs_server_abort(sb);
	}

	return ret;
}

static char *lock_mode_string(u8 mode)
{
	static char *mode_strings[] = {
		[SCOUTFS_LOCK_NULL] = "null",
		[SCOUTFS_LOCK_READ] = "read",
		[SCOUTFS_LOCK_WRITE] = "write",
		[SCOUTFS_LOCK_WRITE_ONLY] = "write_only",
	};

	if (mode < ARRAY_SIZE(mode_strings) && mode_strings[mode])
		return mode_strings[mode];

	return "unknown";
}

static char *lock_on_list_string(u8 on_list)
{
	static char *on_list_strings[] = {
		[OL_GRANTED] = "granted",
		[OL_REQUESTED] = "requested",
		[OL_INVALIDATED] = "invalidated",
	};

	if (on_list < ARRAY_SIZE(on_list_strings) && on_list_strings[on_list])
		return on_list_strings[on_list];

	return "unknown";
}

static void lock_server_tseq_show(struct seq_file *m,
				  struct scoutfs_tseq_entry *ent)
{
	struct client_lock_entry *clent = container_of(ent,
						       struct client_lock_entry,
						       tseq_entry);
	struct server_lock_node *snode = clent->snode;

	seq_printf(m, SK_FMT" %s %s rid %016llx net_id %llu\n",
		   SK_ARG(&snode->key), lock_mode_string(clent->mode),
		   lock_on_list_string(clent->on_list), clent->rid,
		   clent->net_id);
}

/*
 * Setup the lock server.  This is called before networking can deliver
 * requests.  If we find existing client records then we enter recovery.
 * Lock request processing is deferred until recovery is resolved for
 * all the existing clients, either they reconnect and replay locks or
 * we time them out.
 */
int scoutfs_lock_server_setup(struct super_block *sb,
			      struct scoutfs_radix_allocator *alloc,
			      struct scoutfs_block_writer *wri)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct lock_server_info *inf;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	unsigned int nr;
	u64 rid;
	int ret;

	inf = kzalloc(sizeof(struct lock_server_info), GFP_KERNEL);
	if (!inf)
		return -ENOMEM;

	inf->sb = sb;
	spin_lock_init(&inf->lock);
	mutex_init(&inf->mutex);
	inf->locks_root = RB_ROOT;
	scoutfs_spbm_init(&inf->recovery_pending);
	INIT_DELAYED_WORK(&inf->recovery_dwork,
			  scoutfs_lock_server_recovery_timeout);
	scoutfs_tseq_tree_init(&inf->tseq_tree, lock_server_tseq_show);
	inf->alloc = alloc;
	inf->wri = wri;

	inf->tseq_dentry = scoutfs_tseq_create("server_locks", sbi->debug_root,
					       &inf->tseq_tree);
	if (!inf->tseq_dentry) {
		kfree(inf);
		return -ENOMEM;
	}

	sbi->lock_server_info = inf;

	/* we enter recovery if there are any client records */
	nr = 0;
	for (rid = 0; ; rid++) {
		init_lock_clients_key(&key, rid);
		ret = scoutfs_btree_next(sb, &super->lock_clients, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0)
			ret = get_rid_and_put_ref(&iref, &rid);
		if (ret < 0)
			goto out;

		ret = scoutfs_spbm_set(&inf->recovery_pending, rid);
		if (ret)
			goto out;
		nr++;

		if (rid == U64_MAX)
			break;
	}
	ret = 0;

	if (nr) {
		schedule_delayed_work(&inf->recovery_dwork,
				msecs_to_jiffies(LOCK_SERVER_RECOVERY_MS));
		scoutfs_info(sb, "waiting for %u lock clients to recover", nr);
	}

out:
	return ret;
}

/*
 * The server will have shut down networking before stopping us so we
 * don't have to worry about message processing calls while we free.
 */
void scoutfs_lock_server_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct server_lock_node *snode;
	struct server_lock_node *stmp;
	struct client_lock_entry *clent;
	struct client_lock_entry *ctmp;
	LIST_HEAD(list);

	if (inf) {
		cancel_delayed_work_sync(&inf->recovery_dwork);

		debugfs_remove(inf->tseq_dentry);

		rbtree_postorder_for_each_entry_safe(snode, stmp,
						     &inf->locks_root, node) {

			list_splice_init(&snode->granted, &list);
			list_splice_init(&snode->requested, &list);
			list_splice_init(&snode->invalidated, &list);

			mutex_lock(&snode->mutex);
			list_for_each_entry_safe(clent, ctmp, &list, head) {
				free_client_entry(inf, snode, clent);
			}
			mutex_unlock(&snode->mutex);

			kfree(snode);
		}

		scoutfs_spbm_destroy(&inf->recovery_pending);

		kfree(inf);
		sbi->lock_server_info = NULL;
	}
}
