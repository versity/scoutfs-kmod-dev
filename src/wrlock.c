/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/random.h>
#include <linux/sched.h>

#include "super.h"
#include "wire.h"
#include "wrlock.h"
#include "trans.h"
#include "roster.h"
#include "trace.h"

/*
 * The persistent structures in each shard in a scoutfs volume can only
 * have one writer at a time.  Mounts send messages around to request
 * and grant locks on each shard.  (Reads are fully unlocked and have
 * enough metadata to detect and retry reads that raced and were
 * inconsistent.)
 *
 * When a local task needs to lock some shards it sends a request to all
 * the other mounts listing all the shards.  If the receiving mounts
 * don't have any of the shards locked they send a grant reply.
 *
 * Each mount has a granted lock and a tree of blocked lock entries for
 * every shard.  Local lock attempts and remote requests are always
 * inserted into the tree.  The first entry in the tree can be unblocked
 * if the granted lock in the shard doesn't block it.  When local
 * entries are granted the locking task is allowed to start modifying
 * the shard.  While they're modifying the shard their granted locks
 * block remote locks from being sent replies.  Once the writers under
 * the lock are done the grant can be removed and the remote entry is
 * sent a reply and freed.
 *
 * Processes can try to lock multiple shards so entries can be present
 * in the blocking tree and granted pointer on multiple shards.  They're
 * only unblocked when they're the first entry in all their shards'
 * blocking trees.
 *
 * The entries have to be very carefully ordered in the trees on all the
 * mounts to avoid locking cycle deadlocks.  We can't have two mounts
 * race to lock the same shard and both have their local ungranted entry
 * blocking the remote's request entry.  To address this entries aren't
 * sorted in the tree by time.  They're sorted by an id.  This ensures
 * that all of the entries will have the same blocking tree on all the
 * mounts and so will always be processed in the same order.
 *
 * Entries are created on a mount when a task tries to lock some shards.
 * The id is constructed from a counter, a random number, and the
 * mount's unique id.  The counter is one greater than the greatest
 * counter ever seen in received lock requests.  This ensures that lock
 * attempts that don't race are granted in order.  But attempts can race
 * so entries can have the same counter.  Next they're sorted by a
 * random number to ensure a kind of fairness.  Then if the mounts are
 * unlucky enough to chose the same number we fall back to sorting by
 * the unique mount id.
 *
 * The roster determines the set of mounts that are participating in the
 * locking protocol.  We have to carefully manage the entries as mounts
 * join and leave the cluster.  When mounts join we send them all our
 * blocking locks and if they leave we remove their entries and resend
 * all our blocked entries to everyone because we don't track which
 * mounts had send grants to which local blocked entries, or not.
 *
 * XXX
 *  - sync if we revoke a local grant before we send a reply
 */

/*
 * Every mount tracks their write locking state for all the shards in
 * the volume.
 */
struct wrlock_context {
	struct super_block *sb;
	wait_queue_head_t waitq;
	spinlock_t lock;

	struct rb_root id_root;
	struct list_head mark_list;
	struct list_head send_list;
	struct workqueue_struct *send_workq;
	struct work_struct send_work;

	/* private copies of roster state used under the lock */
	long grants_needed;
	u64 last_peer_id;

	u64 next_id_counter;

	/* XXX redundant in the super?  only one for now ;) */
	u32 nr_shards;
	struct wrlock_context_shard {
		struct list_head mark_head;
		struct rb_root blocked_root;
		struct wrlock_entry *granted;
	} shards[0];
};

/* a native version of the wire wrlock_id that includes the roster id */
struct wrlock_id {
	u64 counter;
	u32 jitter;
	u64 roster_id;
};

/*
 * Entries represent an attempt to lock multiple shards.
 *
 * Local entries exist on the context that initiated the request.  They
 * count the number of grant replies and then count the number of
 * writers actively modifying the shards under the lock.
 *
 * Remote entries only exist while other entries are before them in the
 * blocked trees in any of their shards.  Once they're first in all the
 * blocked trees a grant message is sent and they're freed.
 */
struct wrlock_entry {
	struct rb_node id_node;
	struct list_head send_head;

	/* local lock tasks wait for the entry to be granted */
	struct task_struct *waiter;
	struct scoutfs_wrlock_held *held;
	long grants;
	long writers;

	/* tells roster broadcast who to send to */
	u64 last_peer_id;
	struct wrlock_id id;

	u8 nr_shards;
	struct wrlock_entry_shard {
		struct rb_node blocked_node;
		u32 shd;
		u8 index;
	} shards[SCOUTFS_WRLOCK_MAX_SHARDS];
};

#define ENTF "ent id %llu.%llu.%llu"
#define ENTA(ent) ent->id.counter, ent->id.jitter, ent->id.roster_id

static struct wrlock_entry *ent_from_blocked_node(struct rb_node *node)
{
	struct wrlock_entry_shard *shard;

	shard = container_of(node, struct wrlock_entry_shard,
			     blocked_node);
	return container_of(shard, struct wrlock_entry,
			    shards[shard->index]);
}

/* Return the first blocked entry */
static struct wrlock_entry *blocked_ent(struct wrlock_context_shard *shard)
{
	struct rb_node *node = rb_first(&shard->blocked_root);

	return node ? ent_from_blocked_node(node) : NULL;
}

static int cmp_u64s(u64 a, u64 b)
{
	return a < b ? -1 : a > b ? 1 : 0;
}

static int cmp_u32s(u32 a, u32 b)
{
	return a < b ? -1 : a > b ? 1 : 0;
}

static int cmp_ids(struct wrlock_id *a, struct wrlock_id *b)
{
	return cmp_u64s(a->counter, b->counter) ?:
	       cmp_u32s(a->jitter, b->jitter) ?:
	       cmp_u64s(a->roster_id, b->roster_id);
}

static void insert_ent_shard(struct rb_root *root, struct wrlock_entry *ins,
			     struct rb_node *ins_node)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct wrlock_entry *ent;

	while (*node) {
		parent = *node;
		ent = ent_from_blocked_node(*node);

		if (cmp_ids(&ins->id, &ent->id) < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(ins_node, parent, node);
	rb_insert_color(ins_node, root);
}

/* Insert the entry into the blocked tree for each of its shards. */
/*
 * Insert an entry in to all of its trees.  All entries have to be on
 * the blocked tree for all of its shards.
 *
 * But the id tree is a little lazy.  It's only used to look up local
 * entries when grants are received.  It could be a hash table instead of
 * a tree and remote entries don't need to be in it.  But this re-use
 * of the tree code is easy and isn't that expensive compared to all
 * the rest of the processing.
 */
static void insert_ent(struct wrlock_context *ctx, struct wrlock_entry *ins)
{
	int i;

	insert_ent_shard(&ctx->id_root, ins, &ins->id_node);

	for (i = 0; i < ins->nr_shards; i++)
		insert_ent_shard(&ctx->shards[ins->shards[i].shd].blocked_root,
				 ins, &ins->shards[i].blocked_node);

	scoutfs_trace(ctx->sb, "inserted "ENTF, ENTA(ins));
}

static struct wrlock_entry *lookup_ent(struct wrlock_context *ctx,
				       struct wrlock_id *id)
{
	struct rb_node *node = ctx->id_root.rb_node;
	struct wrlock_entry *ent;
	int cmp;

	while (node) {
		ent = ent_from_blocked_node(node);

		cmp = cmp_ids(id, &ent->id);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return ent;
	}

	return NULL;
}

static void erase_and_clear(struct rb_node *node, struct rb_root *root)
{
	if (!RB_EMPTY_NODE(node)) {
		rb_erase(node, root);
		RB_CLEAR_NODE(node);
	}
}

/* remove all of the entry's rb nodes from the context's trees */
static void erase_ent(struct wrlock_context *ctx, struct wrlock_entry *ent)
{
	int i;

	erase_and_clear(&ent->id_node, &ctx->id_root);

	for (i = 0; i < ent->nr_shards; i++)
		erase_and_clear(&ent->shards[i].blocked_node,
				&ctx->shards[ent->shards[i].shd].blocked_root);

	scoutfs_trace(ctx->sb, "erased "ENTF, ENTA(ent));
}

static struct wrlock_entry *alloc_ent(void)
{
	struct wrlock_entry *ent;
	int i;

	ent = kzalloc(sizeof(*ent), GFP_NOFS);
	if (!ent)
		return ERR_PTR(-ENOMEM);

	RB_CLEAR_NODE(&ent->id_node);
	INIT_LIST_HEAD(&ent->send_head);

	/* for container_of to find the ent while walking shard nodes */
	for (i = 0; i < ARRAY_SIZE(ent->shards); i++) {
		RB_CLEAR_NODE(&ent->shards[i].blocked_node);
		ent->shards[i].index = i;
	}

	return ent;
}

/*
 * Callers try to free the ent every time they remove a reference to it
 * from the context and are done with it.  We only free it if there are
 * no more references to it in the context.
 */
static void try_free_ent(struct wrlock_context *ctx, struct wrlock_entry *ent)
{
	int i;

	if (!RB_EMPTY_NODE(&ent->id_node) || !list_empty(&ent->send_head))
		return;

	for (i = 0; i < ent->nr_shards; i++) {
		if (!RB_EMPTY_NODE(&ent->shards[i].blocked_node) ||
		    ctx->shards[ent->shards[i].shd].granted == ent)
			return;
	}

	WARN_ON_ONCE(ent->writers);
	scoutfs_trace(ctx->sb, "freed "ENTF, ENTA(ent));

	kfree(ent);
}

static bool is_local(struct wrlock_context *ctx, struct wrlock_entry *ent)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(ctx->sb);

	return ent->id.roster_id == sbi->roster_id;
}

/*
 * An entry in the blocked tree can be blocked for a few reasons:
 *
 * - a local entry hasn't received its grant replies yet
 * - there are blocked entries before it on any of its shards
 * - a remote entry is waiting for local writers to drain
 *
 * Note in particular that a local entry isn't blocked by granted writers
 * because it'll join them and that remote entries aren't blocked by local
 * grants with no writers because it revokes them to send a grant reply.
 */
static bool is_blocked(struct wrlock_context *ctx, struct wrlock_entry *ent)
{
	struct wrlock_context_shard *shard;
	int i;

	if (is_local(ctx, ent) && ent->grants < ctx->grants_needed)
		return true;

	for (i = 0; i < ent->nr_shards; i++) {
		if (rb_prev(&ent->shards[i].blocked_node))
			return true;

		if (!is_local(ctx, ent)) {
			shard = &ctx->shards[ent->shards[i].shd];
			if (shard->granted && shard->granted->writers)
				return true;
		}
	}

	return false;
}

/* mark a given shard for later processing to see if entries aren't blocked */
static void mark_context_shard(struct wrlock_context *ctx, u32 shard)
{
	struct list_head *head = &ctx->shards[shard].mark_head;

	if (list_empty(head))
		list_add_tail(head, &ctx->mark_list);
}

static void mark_ent_shards(struct wrlock_context *ctx,
			    struct wrlock_entry *ent)
{
	int i;

	for (i = 0; i < ent->nr_shards; i++)
		mark_context_shard(ctx, ent->shards[i].shd);
}

static void queue_send(struct wrlock_context *ctx, struct wrlock_entry *ent)
{
	if (list_empty(&ent->send_head)) {
		list_add_tail(&ent->send_head, &ctx->send_list);
		queue_work(ctx->send_workq, &ctx->send_work);
		scoutfs_trace(ctx->sb, "queued "ENTF, ENTA(ent));
	}
}

/*
 * Try to unblock entries in the shard.  We're done when the first entry
 * in the shard is still blocked.
 *
 * If we unblock a remote entry then we have to send its grant message.
 * If there is a granted local entry but it has no writers then we
 * remove it so that future writers will have to request a new lock from
 * the remote peer whose request we granted.
 *
 * If we unblock a local entry then we move it to the granted pointers
 * for each of its shards.  There are two tricky cases here.
 *
 * The first is a local entry being granted which covers more shards
 * than the current granted entry on some of its shards.  We don't want
 * the larger unblocked entry to wait for the smaller granted entry's
 * writers to drain.  Instead we set the granted pointers to the new
 * unblocked large entry after giving it the smaller granted entry's
 * writer counters.  Unlocking will drop the write counters on whatever
 * entry is currently granted on its shards.
 *
 * The second is making sure that a waiting locking task gets a chance
 * to work with a newly granted local entry before the next blocking
 * remote entry revokes it.  We increment the writers count the moment a
 * local entry is granted.  It will stay that way until the task drops
 * the writer count.  We just have to be careful to address all the
 * races with the task sleeping, waking, and interrupting.
 */
static void unblock_shard(struct wrlock_context *ctx,
			  struct wrlock_context_shard *shard)
{
	struct wrlock_entry *ent;
	int i;

	ent = blocked_ent(shard);
	if (!ent)
		return;

	if (is_blocked(ctx, ent)) {
		/* send initial requests for local blocked entries */
		if (ent->last_peer_id < ctx->last_peer_id)
			queue_send(ctx, ent);
		return;
	}

	scoutfs_trace(ctx->sb, "unblocked "ENTF, ENTA(ent));

	erase_ent(ctx, ent);
	mark_ent_shards(ctx, ent);

	/* unblocked remote entries remove local grants and send replies */
	if (!is_local(ctx, ent)) {
		for (i = 0; i < ent->nr_shards; i++) {
			shard = &ctx->shards[ent->shards[i].shd];
			if (shard->granted) {
				WARN_ON_ONCE(shard->granted->writers);
				try_free_ent(ctx, shard->granted);
				shard->granted = NULL;
			}
		}

		queue_send(ctx, ent);
		return;
	}

	/* grant the entry on all its shards */
	for (i = 0; i < ent->nr_shards; i++) {
		shard = &ctx->shards[ent->shards[i].shd];

		/* the ent couldn't have been granted if it was blocked */
		WARN_ON_ONCE(shard->granted == ent);

		if (shard->granted) {
			ent->writers += shard->granted->writers;
			try_free_ent(ctx, shard->granted);
		}

		shard->granted = ent;
		if (ent->waiter)
			ent->writers++;

		scoutfs_trace(ctx->sb, "granted ctx 0x%llx shd %llu wr %llu",
			      ctx, ent->shards[i].shd, ent->writers);
	}

	if (ent->waiter) {
		/* the task is responsible for the writer count if nr is set */
		ent->held->nr_shards = ent->nr_shards;
		smp_mb(); /* wait_event condition isn't locked */
		wake_up_process(ent->waiter);
		ent->waiter = NULL;
		ent->held = NULL;
	}
}

/*
 * Walk all the shards that have been marked and see if their blocked
 * entry is still blocked.  As we unblock entries we mark all their
 * shards and keep going until the blocked entries in the shards
 * stabilize.
 */
static void unblock_marked_shards(struct wrlock_context *ctx)
{
	struct wrlock_context_shard *shard;

	while ((shard = list_first_entry_or_null(&ctx->mark_list,
						 struct wrlock_context_shard,
						 mark_head))) {
		list_del_init(&shard->mark_head);
		unblock_shard(ctx, shard);
	}
}

/*
 * Statically round robin every 1M inodes to each shard.
 *
 * XXX this will almost certainly need to be more clever.  We'll want
 * to size the batching more carefully and we'll need to cope with growing
 * and shrinking the number of shards.
 */
static u32 ino_shd(struct wrlock_context *ctx, u64 ino)
{
	return (u32)(ino >> SCOUTFS_INO_BATCH_SHIFT) % ctx->nr_shards;
}

/*
 * Shards in entries are sorted and unique to make receive verification
 * easier.  Entries will only have a small handful of shards.
 */
static void add_ent_shd(struct wrlock_entry *ent, u32 shd)
{
	int i;

	for (i = 0; i < ent->nr_shards; i++) {
		if (shd < ent->shards[i].shd)
			swap(shd, ent->shards[i].shd);
		else if (shd == ent->shards[i].shd)
			return;
	}

	ent->shards[i].shd = shd;
	ent->nr_shards++;
}

/*
 * Get write locks on the shards that contain the given inodes.
 *
 * We always insert a new entry so that local attempts are inserted in
 * the blocking tree after blocked remote entries.  This way local lock
 * matching doesn't stave remote lock attempts.
 *
 * In the fast path the inserted entry will be first and all its shards
 * will be granted so we'll increase entry writer counts and return.  In
 * the slow path we send lock requests and sleep until we get grant
 * replies.
 *
 * The writer counts are set when our entry is granted while we're still
 * waiting for it so that we're guaranteed to get to work with our
 * granted lock before a remote request has a chance to revoke it.
 */
int scoutfs_wrlock_lock(struct super_block *sb,
			struct scoutfs_wrlock_held *held, int nr_inos, ...)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct wrlock_entry *ent;
	va_list args;
	int ret;
	int i;

	if (WARN_ON_ONCE(nr_inos <= 0 || nr_inos > SCOUTFS_WRLOCK_MAX_SHARDS) ||
	    WARN_ON_ONCE(held->nr_shards))
		return -EINVAL;

	ent = alloc_ent();
	if (!ent)
		return -ENOMEM;

        va_start(args, nr_inos);
	while (nr_inos--) {
		/* XXX verify inodes? */
		add_ent_shd(ent, ino_shd(ctx, va_arg(args, u64)));
	}
        va_end(args);

	/* held's nr_shards is set when the ent is granted and writers inced */
	for (i = 0; i < ent->nr_shards; i++)
		held->shards[i] = ent->shards[i].shd;

	ent->waiter = current;
	ent->held = held;
	ent->id.jitter = get_random_int();  /* XXX how expensive? */
	ent->id.roster_id = sbi->roster_id;

	/* the context owns and can free the entry after we unlock */
	spin_lock(&ctx->lock);

	ent->id.counter = ctx->next_id_counter++;

	insert_ent(ctx, ent);
	mark_ent_shards(ctx, ent);
	unblock_marked_shards(ctx);

	spin_unlock(&ctx->lock);

	ret = wait_event_interruptible(ctx->waitq, held->nr_shards);
	if (ret == 0)
		ret = scoutfs_hold_trans(sb);

	scoutfs_trace(sb, "lock nr %llu ret %lld", held->nr_shards, ret);

	/* unlock on error locks the context before using held.nr_shards */
	if (ret)
		scoutfs_wrlock_unlock(sb, held);

	return ret;
}

/*
 * The held shards must have had granted entries for us to increment the
 * write counts.  The increased write counts should have pinned entries
 * to the shards so they must still be around for us to decrease the
 * counts.
 *
 * If we're the last writer of an entry then we'll check to see if any
 * of its shards have blocked remote entries that can now make progress.
 *
 * XXX we'd need to sync dirty blocks before sending the grant.
 */
void scoutfs_wrlock_unlock(struct super_block *sb,
			   struct scoutfs_wrlock_held *held)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct wrlock_context_shard *shard;
	u32 shd;
	int i;

	scoutfs_release_trans(sb);

	spin_lock(&ctx->lock);

	for (i = 0; i < held->nr_shards; i++) {
		shd = held->shards[i];
		shard = &ctx->shards[shd];

		/* XXX this would imply unlocked writing, very bad indeed */
		if (WARN_ON_ONCE(!shard->granted) ||
		    WARN_ON_ONCE(shard->granted->writers <= 0))
			continue;

		shard->granted->writers--;

		scoutfs_trace(sb, "unlock ctx 0x%llx shd %llu wr %llu",
			      ctx, shd, shard->granted->writers);

		if (shard->granted->writers == 0)
			mark_context_shard(ctx, shd);
	}

	unblock_marked_shards(ctx);

	spin_unlock(&ctx->lock);

}

/*
 * Process an incoming request message.  We allocate and insert an entry
 * for the request.  When it's not blocked by previous entries or a
 * granted entry on all its shards then we send a reply and free the
 * entry.
 *
 * Shard numbers in the incoming request must be unique and sorted.
 */
int scoutfs_wrlock_process_request(struct super_block *sb, u64 peer_id,
				   struct scoutfs_wrlock_request *req)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct wrlock_entry *ent;
	int ret = 0;
	u32 shd;
	u32 prev;
	int i;

	ent = alloc_ent();
	if (!ent)
		return -ENOMEM;

	if (req->nr_shards > SCOUTFS_WRLOCK_MAX_SHARDS) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0, prev = 0; i < req->nr_shards; prev = shd, i++) {
		shd = le32_to_cpu(req->shards[i]);

		if (shd >= ctx->nr_shards || (prev && shd <= prev)) {
			ret = -EINVAL;
			goto out;
		}

		add_ent_shd(ent, shd);
	}

	ent->id.counter = le64_to_cpu(req->wid.counter);
	ent->id.jitter = le32_to_cpu(req->wid.jitter);
	ent->id.roster_id = peer_id;

	spin_lock(&ctx->lock);

	ctx->next_id_counter = max(ent->id.counter + 1, ctx->next_id_counter);

	insert_ent(ctx, ent);
	mark_ent_shards(ctx, ent);
	unblock_marked_shards(ctx);

	spin_unlock(&ctx->lock);

out:
	if (ret)
		kfree(ent);
	return ret;
}

/*
 * Process an incoming grant message.  The sending peer is telling us
 * that they don't have any entries blocking our lock.  We increment its
 * count and wake the locker on the last grant.
 *
 * An entry won't be found at the id if the process attempting the lock
 * exited and removed the entry before all the grants arrived.
 *
 * XXX freak out if grants is greater than grants_needed?  That'd imply
 * that we could have prematurely given a locker access to its shards.
 */
void scoutfs_wrlock_process_grant(struct super_block *sb,
				  struct scoutfs_wrlock_grant *grant)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct wrlock_entry *ent;
	struct wrlock_id id = {
		.counter = le64_to_cpu(grant->wid.counter),
		.jitter = le32_to_cpu(grant->wid.jitter),
		.roster_id = sbi->roster_id,
	};

	spin_lock(&ctx->lock);

	ent = lookup_ent(ctx, &id);
	if (ent) {
		ent->grants++;

		scoutfs_trace(sb, "grant rx "ENTF" grants %llu needed %llu",
			      ENTA(ent), ent->grants, ctx->grants_needed);

		if (ent->grants == ctx->grants_needed) {
			mark_ent_shards(ctx, ent);
			unblock_marked_shards(ctx);
		}
	}

	spin_unlock(&ctx->lock);
}

/*
 * Send wrlock messages to peers.  Entries are put on the send queue
 * when we need to either broadcast requests to new peers or send a
 * grant reply to a specific requesting peer.
 *
 * XXX As currently imagined any send failures trigger reconnection and
 * recovery.  We need a bit more clarity on what the roster
 * implementation before worrying too much about the details of recovery
 * in here.
 */
static void send_work_func(struct work_struct *work)
{
	struct wrlock_context *ctx = container_of(work, struct wrlock_context,
						  send_work);
	struct super_block *sb = ctx->sb;
	struct scoutfs_message msg;
	struct wrlock_entry *ent;
	struct wrlock_entry *tmp;
	u64 peer_id;
	int i;

	spin_lock(&ctx->lock);

	list_for_each_entry_safe(ent, tmp, &ctx->send_list, send_head) {

		if (is_local(ctx, ent)) {
			msg.cmd = SCOUTFS_MSG_WRLOCK_REQUEST;
			msg.request.wid.counter = cpu_to_le64(ent->id.counter);
			msg.request.wid.jitter = cpu_to_le32(ent->id.jitter);
			msg.request.nr_shards = ent->nr_shards;
			for (i = 0; i < ent->nr_shards; i++) {
				msg.request.shards[i] =
					cpu_to_le32(ent->shards[i].shd);
			}

			msg.len = offsetof(struct scoutfs_wrlock_request,
					 shards[ent->nr_shards]);
			peer_id = ent->last_peer_id;
			ent->last_peer_id = ctx->last_peer_id;
		} else {
			msg.cmd = SCOUTFS_MSG_WRLOCK_GRANT;
			msg.grant.wid.counter = cpu_to_le64(ent->id.counter);
			msg.grant.wid.jitter = cpu_to_le32(ent->id.jitter);

			msg.len = sizeof(msg.grant);
			peer_id = ent->id.roster_id;
		}

		scoutfs_trace(sb, "send "ENTF" cmd %llu", ENTA(ent), msg.cmd);

		list_del_init(&ent->send_head);
		try_free_ent(ctx, ent);

		spin_unlock(&ctx->lock);

		if (msg.cmd == SCOUTFS_MSG_WRLOCK_GRANT)
			scoutfs_roster_send(sb, peer_id, &msg);
		else
			scoutfs_roster_broadcast(sb, peer_id, &msg);

		spin_lock(&ctx->lock);
	}

	spin_unlock(&ctx->lock);
}

/*
 * The roster tells us when mounts join or leave the cluster.
 *
 * Our job is easy if a peer is joining because they don't have any
 * entries yet.  They could start sending requests immediately and their
 * entries could be inserted behind our blocked local entries.  We send
 * them all our blocked entries so that they can grant them and make
 * forward progress in that case.
 *
 * If a peer is leaving then we have two problems.
 *
 * First they might have already granted some entries but we can't tell
 * which.  We don't track grant replies per peer.  We can't adjust the
 * entry grant counts to match a smaller number of needed grants.  So we
 * reset all the blocked local entries and resend them to everyone.  We
 * reset the id so that we're not confused by grants in flight.  It's
 * not great but it's simple and rare.
 *
 * XXX Worse, they might have held locks.  We'd need to wait a grace
 * period or fence them so that we're sure that they are no longer
 * writing to shards.
 */
void scoutfs_wrlock_roster_update(struct super_block *sb, u64 peer_id,
				  bool join)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct rb_node *node;
	struct wrlock_entry *ent;
	LIST_HEAD(list);
	int i;

	spin_lock(&ctx->lock);

	/* take the peer change into account before walking entries */
	if (join) {
		ctx->grants_needed++;
		ctx->last_peer_id = peer_id;
	} else {
		ctx->grants_needed--;
	}

	scoutfs_trace(sb, "update ctx 0x%llx peer_id %llu join %llu gr %llu",
		      ctx, peer_id, join, ctx->grants_needed);

	/*
	 * Walk all the blocked entries on all the shards.  Entries can
	 * be on multiple shards so we're careful to only modify them on
	 * the first visit.
	 */
	for (i = 0; i < ctx->nr_shards; i++) {
		node = rb_first(&ctx->shards[i].blocked_root);
		while (node) {
			ent = ent_from_blocked_node(node);
			node = rb_next(node);

			/* drop remote blocked entries from a leaving peer */
			if (!join && ent->id.roster_id == peer_id) {
				erase_ent(ctx, ent);
				mark_ent_shards(ctx, ent);
				try_free_ent(ctx, ent);
			}

			/* send blocked local locks just to the new peer */
			if (join && is_local(ctx, ent))
				queue_send(ctx, ent);

			/* reset and resend local entries when leaving */
			if (!join && is_local(ctx, ent) && ent->last_peer_id) {
				ent->grants = 0;
				ent->last_peer_id = 0;
				ent->id.counter = ctx->next_id_counter++;
				ent->id.jitter = get_random_int();

				erase_ent(ctx, ent);
				insert_ent(ctx, ent);
				mark_ent_shards(ctx, ent);
				queue_send(ctx, ent);
			}
		}
	}

	unblock_marked_shards(ctx);

	spin_unlock(&ctx->lock);
}

int scoutfs_wrlock_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx;
	u32 nr = 1; /* XXX */
	int i;

	ctx = vmalloc(offsetof(struct wrlock_context, shards[nr]));
	if (!ctx)
		return -ENOMEM;

	/* XXX need some kind of mount id */
	ctx->send_workq = alloc_ordered_workqueue("scoutfs-%s-%u:%u-send", 0,
						  sb->s_id,
						  MAJOR(sb->s_bdev->bd_dev),
						  MINOR(sb->s_bdev->bd_dev));
	if (!ctx->send_workq) {
		vfree(ctx);
		return -ENOMEM;
	}

	ctx->sb = sb;
	init_waitqueue_head(&ctx->waitq);
	spin_lock_init(&ctx->lock);
	ctx->id_root = RB_ROOT;
	INIT_LIST_HEAD(&ctx->mark_list);
	INIT_LIST_HEAD(&ctx->send_list);
	INIT_WORK(&ctx->send_work, send_work_func);
	ctx->nr_shards = nr;

	for (i = 0; i < nr; i++) {
		INIT_LIST_HEAD(&ctx->shards[i].mark_head);
		ctx->shards[i].blocked_root = RB_ROOT;
	}

	sbi->wrlock_context = ctx;

	scoutfs_trace(sb, "setup ctx 0x%llx", ctx);

	return 0;
}

/*
 * Destroy the messaging work and free the wrlock entries.  There should
 * be no more active lockers at this point.
 */
void scoutfs_wrlock_teardown(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wrlock_context *ctx = sbi->wrlock_context;
	struct wrlock_context_shard *shard;
	struct wrlock_entry *ent;
	struct wrlock_entry *tmp;
	int i;

	if (!ctx)
		return;

	scoutfs_trace(sb, "teardown ctx 0x%llx", ctx);

	destroy_workqueue(ctx->send_workq);

	for (i = 0; i < ctx->nr_shards; i++) {
		shard = &ctx->shards[i];

		try_free_ent(ctx, shard->granted);
		shard->granted = NULL;

		list_for_each_entry_safe(ent, tmp, &ctx->send_list, send_head) {
			list_del_init(&ent->send_head);
			try_free_ent(ctx, ent);
		}

		while ((ent = blocked_ent(shard))) {
			erase_ent(ctx, ent);
			try_free_ent(ctx, ent);
		}
	}

	vfree(ctx);
}
