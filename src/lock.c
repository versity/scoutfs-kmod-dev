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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dlm.h>
#include <linux/mm.h>
#include <linux/sort.h>

#include "super.h"
#include "lock.h"
#include "item.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "cmp.h"
#include "dlmglue.h"
#include "inode.h"
#include "trans.h"
#include "counters.h"
#include "endian_swap.h"

#define LN_FMT "%u.%u.%u.%llu.%llu"
#define LN_ARG(name) \
	(name)->scope, (name)->zone, (name)->type, le64_to_cpu((name)->first),\
	le64_to_cpu((name)->second)

typedef struct ocfs2_super dlmglue_ctxt;

/*
 * allocated per-super, freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	dlmglue_ctxt dlmglue;
	bool dlmglue_online;
	char ls_name[DLM_LOCKSPACE_LEN];

	spinlock_t lock;
	unsigned int seq_cnt;
	struct rb_root lock_tree;
	struct rb_root lock_range_tree;
	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long long lru_nr;
	struct workqueue_struct *lock_reclaim_wq;
};

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

static void scoutfs_lock_reclaim(struct work_struct *work);

struct task_ref {
	struct task_struct *task;
	struct rb_node node;
	int count;
	int mode;/* for debugging */
};

static struct task_ref *find_task_ref(struct scoutfs_lock *lock,
				     struct task_struct *task)
{
	struct rb_node *n;
	struct task_ref *tmp;

	spin_lock(&lock->task_refs_lock);
	n = lock->task_refs.rb_node;
	while (n) {
		tmp = rb_entry(n, struct task_ref, node);

		if (tmp->task < task)
			n = n->rb_left;
		else if (tmp->task > task)
			n = n->rb_right;
		else {
			spin_unlock(&lock->task_refs_lock);
			return tmp;
		}
	}
	spin_unlock(&lock->task_refs_lock);

	return NULL;
}

static struct task_ref *alloc_task_ref(struct task_struct *task, int mode)
{
	struct task_ref *ref = kzalloc(sizeof(*ref), GFP_NOFS);
	if (ref) {
		ref->task = task;
		ref->count = 1;
		ref->mode = mode;
		RB_CLEAR_NODE(&ref->node);
	}
	return ref;
}

static void insert_task_ref(struct scoutfs_lock *lock, struct task_ref *ref)
{
	struct task_ref *tmp;
	struct rb_node *parent = NULL;
	struct rb_node **p;

	spin_lock(&lock->task_refs_lock);
	p = &lock->task_refs.rb_node;
	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct task_ref, node);

		if (tmp->task < ref->task)
			p = &(*p)->rb_left;
		else if (tmp->task > ref->task)
			p = &(*p)->rb_right;
		else
			BUG(); /* We should never find a duplicate */
	}

	rb_link_node(&ref->node, parent, p);
	rb_insert_color(&ref->node, &lock->task_refs);
	spin_unlock(&lock->task_refs_lock);
}

static void get_task_ref(struct task_ref *ref)
{
	ref->count++;
}

static struct task_ref *new_task_ref(struct scoutfs_lock *lock,
				     struct task_struct *task, int mode)
{
	struct task_ref *ref = alloc_task_ref(task, mode);
	if (ref)
		insert_task_ref(lock, ref);

	return ref;
}

static int put_task_ref(struct scoutfs_lock *lock, struct task_ref *ref)
{
	if (!ref)
		return 0;

	ref->count--;
	if (ref->count == 0) {
		spin_lock(&lock->task_refs_lock);
		rb_erase(&ref->node, &lock->task_refs);
		spin_unlock(&lock->task_refs_lock);

		kfree(ref);
		return 0;
	}
	return 1;
}

/*
 * invalidate cached data associated with an inode whose lock is going
 * away.
 *
 * Our inode granular locks mean that we have to invalidate all the
 * child dentries of a dir so that they can't satisfy lookup after we
 * re-acquire the lock.  We're invalidating the lock so there can't be
 * active users that could modify the entries in the dcache (lookup,
 * create, rename, unlink).  We have to make it through all the child
 * entries and remove them from the hash so that lookup can't find them.
 */
static void invalidate_inode(struct super_block *sb, u64 ino)
{
	struct inode *inode;
	struct dentry *parent;
	struct dentry *child;

	inode = scoutfs_ilookup(sb, ino);
	if (!inode)
		return;

	if (S_ISREG(inode->i_mode))
		truncate_inode_pages(inode->i_mapping, 0);

	if (S_ISDIR(inode->i_mode) && (parent = d_find_alias(inode))) {

		spin_lock(&parent->d_lock);
		list_for_each_entry(child, &parent->d_subdirs, d_u.d_child){
			spin_lock_nested(&child->d_lock, DENTRY_D_LOCK_NESTED);
			__d_drop(child);
			spin_unlock(&child->d_lock);
		}
		spin_unlock(&parent->d_lock);

		dput(parent);
	}

	iput(inode);
}

/*
 * Invalidate caches on this because another node wants a lock
 * with the a lock with the given mode and range. We always have to
 * write out dirty overlapping items.  If they're writing then we need
 * to also invalidate all cached overlapping structures.
 */
static int invalidate_caches(struct super_block *sb, int mode,
			     struct scoutfs_lock *lock)
{
	struct scoutfs_key_buf *start = lock->start;
	struct scoutfs_key_buf *end = lock->end;
	u64 ino, last;
	int ret;

	trace_scoutfs_lock_invalidate(sb, lock);

	ret = scoutfs_item_writeback(sb, start, end);
	if (ret)
		return ret;


	if (mode == DLM_LOCK_EX ||
	    (mode == DLM_LOCK_PR && lock->lockres.l_level == DLM_LOCK_CW)) {
		if (lock->lock_name.zone == SCOUTFS_FS_ZONE) {
			ino = le64_to_cpu(lock->lock_name.first);
			last = ino + SCOUTFS_LOCK_INODE_GROUP_NR - 1;
			while (ino <= last) {
				invalidate_inode(sb, ino);
				ino++;
			}
		}

		ret = scoutfs_item_invalidate(sb, start, end);
	}

	return ret;
}

static void free_scoutfs_lock(struct scoutfs_lock *lock)
{
	struct lock_info *linfo;

	if (lock) {
		linfo = SCOUTFS_SB(lock->sb)->lock_info;

		scoutfs_inc_counter(lock->sb, lock_free);
		ocfs2_lock_res_free(&lock->lockres);
		scoutfs_key_free(lock->sb, lock->start);
		scoutfs_key_free(lock->sb, lock->end);
		BUG_ON(!RB_EMPTY_NODE(&lock->node));
		BUG_ON(!RB_EMPTY_NODE(&lock->range_node));
		kfree(lock);
	}
}

static void put_scoutfs_lock(struct super_block *sb, struct scoutfs_lock *lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	unsigned int refs;

	if (lock) {
		spin_lock(&linfo->lock);
		BUG_ON(!lock->refcnt);
		refs = --lock->refcnt;
		if (!refs) {
			trace_scoutfs_lock_free(sb, lock);
			rb_erase(&lock->node, &linfo->lock_tree);
			RB_CLEAR_NODE(&lock->node);
			if(!RB_EMPTY_NODE(&lock->range_node)) {
				rb_erase(&lock->range_node,
					 &linfo->lock_range_tree);
				RB_CLEAR_NODE(&lock->range_node);
			}
			list_del(&lock->lru_entry);
			spin_unlock(&linfo->lock);
			ocfs2_simple_drop_lockres(&linfo->dlmglue,
						  &lock->lockres);
			free_scoutfs_lock(lock);
			return;
		}
		spin_unlock(&linfo->lock);
	}
}

static void dec_lock_users(struct scoutfs_lock *lock)
{
	DECLARE_LOCK_INFO(lock->sb, linfo);

	spin_lock(&linfo->lock);
	lock->users--;
	if (list_empty(&lock->lru_entry) && lock->users == 0) {
		list_add_tail(&lock->lru_entry, &linfo->lru_list);
		linfo->lru_nr++;
	}
	spin_unlock(&linfo->lock);
}

static struct ocfs2_super *get_ino_lock_osb(struct ocfs2_lock_res *lockres)
{
	struct scoutfs_lock *lock = lockres->l_priv;
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);

	return &linfo->dlmglue;
}

static int ino_lock_downconvert(struct ocfs2_lock_res *lockres, int blocking)
{
	struct scoutfs_lock *lock = lockres->l_priv;
	struct super_block *sb = lock->sb;

	invalidate_caches(sb, blocking, lock);

	return UNBLOCK_CONTINUE;
}

static void lock_name_string(struct ocfs2_lock_res *lockres, char *buf,
			     unsigned int len)
{
	struct scoutfs_lock *lock = lockres->l_priv;

	snprintf(buf, len, LN_FMT, LN_ARG(&lock->lock_name));
}

static struct ocfs2_lock_res_ops scoufs_ino_lops = {
	.get_osb 		= get_ino_lock_osb,
	.downconvert_worker 	= ino_lock_downconvert,
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.print			= lock_name_string,
	.flags			= LOCK_TYPE_REQUIRES_REFRESH,
};

static struct ocfs2_lock_res_ops scoufs_ino_index_lops = {
	.get_osb 		= get_ino_lock_osb,
	.downconvert_worker 	= ino_lock_downconvert,
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.print			= lock_name_string,
};

static struct ocfs2_lock_res_ops scoutfs_global_lops = {
	.get_osb 		= get_ino_lock_osb,
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.print			= lock_name_string,
	.flags			= 0,
};

static struct ocfs2_lock_res_ops scoutfs_node_id_lops = {
	.get_osb		= get_ino_lock_osb,
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.downconvert_worker 	= ino_lock_downconvert,
	.print			= lock_name_string,
	.flags			= 0,
};

static struct scoutfs_lock *alloc_scoutfs_lock(struct super_block *sb,
					       struct scoutfs_lock_name *lock_name,
					       struct ocfs2_lock_res_ops *type,
					       struct scoutfs_key_buf *start,
					       struct scoutfs_key_buf *end)

{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;

	if (WARN_ON_ONCE(!!start != !!end))
		return NULL;

	lock = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (lock == NULL)
		return NULL;

	RB_CLEAR_NODE(&lock->node);
	RB_CLEAR_NODE(&lock->range_node);

	if (start) {
		lock->start = scoutfs_key_dup(sb, start);
		lock->end = scoutfs_key_dup(sb, end);
		if (!lock->start || !lock->end) {
			free_scoutfs_lock(lock);
			return NULL;
		}
	}

	spin_lock_init(&lock->task_refs_lock);
	lock->task_refs = RB_ROOT;
	RB_CLEAR_NODE(&lock->node);
	lock->sb = sb;
	lock->lock_name = *lock_name;
	INIT_LIST_HEAD(&lock->lru_entry);
	ocfs2_lock_res_init_once(&lock->lockres);
	BUG_ON(sizeof(struct scoutfs_lock_name) >= OCFS2_LOCK_ID_MAX_LEN);
	/* kzalloc above ensures that l_name is NULL terminated */
	memcpy(&lock->lockres.l_name[0], &lock->lock_name,
	       sizeof(struct scoutfs_lock_name));
	ocfs2_lock_res_init_common(&linfo->dlmglue, &lock->lockres, type, lock);
	INIT_WORK(&lock->reclaim_work, scoutfs_lock_reclaim);
	init_waitqueue_head(&lock->waitq);

	return lock;
}

static int cmp_lock_names(struct scoutfs_lock_name *a,
			  struct scoutfs_lock_name *b)
{
	return ((int)a->scope - (int)b->scope) ?:
	       ((int)a->zone - (int)b->zone) ?:
	       ((int)a->type - (int)b->type) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->first), le64_to_cpu(b->first)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->second), le64_to_cpu(b->second));
}

static int insert_range_node(struct super_block *sb, struct scoutfs_lock *ins)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct rb_root *root = &linfo->lock_range_tree;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_lock *lock;
	int cmp;

	if (!ins->start)
		return 0;

	while (*node) {
		parent = *node;
		lock = container_of(*node, struct scoutfs_lock, range_node);

		cmp = scoutfs_key_compare_ranges(ins->start, ins->end,
						 lock->start, lock->end);
		if (WARN_ON_ONCE(cmp == 0)) {
			scoutfs_warn_sk(sb, "inserting lock %p name "LN_FMT" start "SK_FMT" end "SK_FMT" overlaps with existing lock %p name "LN_FMT" start "SK_FMT" end "SK_FMT"\n",
					ins, LN_ARG(&ins->lock_name),
					SK_ARG(ins->start), SK_ARG(ins->end),
					lock, LN_ARG(&lock->lock_name),
					SK_ARG(lock->start), SK_ARG(lock->end));
			return -EINVAL;
		}

		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}


	rb_link_node(&ins->range_node, parent, node);
	rb_insert_color(&ins->range_node, root);

	return 0;
}

static struct scoutfs_lock *find_alloc_scoutfs_lock(struct super_block *sb,
					struct scoutfs_lock_name *lock_name,
					struct ocfs2_lock_res_ops *type,
					struct scoutfs_key_buf *start,
					struct scoutfs_key_buf *end)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *new = NULL;
	struct scoutfs_lock *found;
	struct scoutfs_lock *lock;
	struct rb_node *parent;
	struct rb_node **node;
	int cmp;
	int ret;

search:
	spin_lock(&linfo->lock);
	node = &linfo->lock_tree.rb_node;
	parent = NULL;
	found = NULL;
	while (*node) {
		parent = *node;
		lock = container_of(*node, struct scoutfs_lock, node);

		cmp = cmp_lock_names(lock_name, &lock->lock_name);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			found = lock;
			break;
		}
		lock = NULL;
	}

	if (!found) {
		if (!new) {
			spin_unlock(&linfo->lock);
			new = alloc_scoutfs_lock(sb, lock_name, type, start,
						 end);
			if (!new)
				return NULL;

			goto search;
		}
		found = new;
		new = NULL;
		found->refcnt = 1; /* Freed by shrinker or on umount */
		found->sequence = ++linfo->seq_cnt;

		ret = insert_range_node(sb, found);
		if (ret < 0) {
			spin_unlock(&linfo->lock);
			free_scoutfs_lock(found);
			return NULL;
		}

		trace_scoutfs_lock_rb_insert(sb, found);
		rb_link_node(&found->node, parent, node);
		rb_insert_color(&found->node, &linfo->lock_tree);
		scoutfs_inc_counter(sb, lock_alloc);
	}
	found->refcnt++;
	if (test_bit(SCOUTFS_LOCK_RECLAIM, &found->flags)) {
		spin_unlock(&linfo->lock);
		wait_event(found->waitq,
			   test_bit(SCOUTFS_LOCK_DROPPED, &found->flags));
		put_scoutfs_lock(sb, found);
		goto search;
	}

	if (!list_empty(&found->lru_entry)) {
		list_del_init(&found->lru_entry);
		linfo->lru_nr--;
	}
	found->users++;
	spin_unlock(&linfo->lock);

	free_scoutfs_lock(new);
	return found;
}

static void scoutfs_lock_reclaim(struct work_struct *work)
{
	struct scoutfs_lock *lock = container_of(work, struct scoutfs_lock,
						 reclaim_work);
	struct lock_info *linfo = SCOUTFS_SB(lock->sb)->lock_info;

	trace_scoutfs_lock_reclaim(lock->sb, lock);

	/*
	 * Drop the last ref on our lock here, allowing us to clean up
	 * the dlm lock. We might race with another process in
	 * find_alloc_scoutfs_lock(), hence the dropped flag telling
	 * those processes to go ahead and drop the lock ref as well.
	 */
	BUG_ON(lock->users);

	set_bit(SCOUTFS_LOCK_DROPPED, &lock->flags);
	wake_up(&lock->waitq);

	put_scoutfs_lock(linfo->sb, lock);
}

static int shrink_lock_tree(struct shrinker *shrink, struct shrink_control *sc)
{
	struct lock_info *linfo = container_of(shrink, struct lock_info,
					       shrinker);
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	unsigned long flags;
	unsigned long nr;
	int ret;

	nr = sc->nr_to_scan;
	if (!nr)
		goto out;

	spin_lock_irqsave(&linfo->lock, flags);
	list_for_each_entry_safe(lock, tmp, &linfo->lru_list, lru_entry) {
		if (nr-- == 0)
			break;

		trace_shrink_lock_tree(linfo->sb, lock);

		WARN_ON(lock->users);

		set_bit(SCOUTFS_LOCK_RECLAIM, &lock->flags);
		list_del_init(&lock->lru_entry);
		linfo->lru_nr--;

		queue_work(linfo->lock_reclaim_wq, &lock->reclaim_work);
	}
	spin_unlock_irqrestore(&linfo->lock, flags);

out:
	ret = min_t(unsigned long, linfo->lru_nr, INT_MAX);
	trace_scoutfs_lock_shrink_exit(linfo->sb, sc->nr_to_scan, ret);
	return ret;
}

static void free_lock_tree(struct super_block *sb)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct rb_node *node = rb_first(&linfo->lock_tree);

	while (node) {
		struct scoutfs_lock *lock;

		lock = rb_entry(node, struct scoutfs_lock, node);
		node = rb_next(node);
		put_scoutfs_lock(sb, lock);
	}
}

/*
 * Acquire a coherent lock on the given range of keys.  While the lock
 * is held other lockers are serialized.  Cache coherency is maintained
 * by the locking infrastructure.  Lock acquisition causes writeout from
 * or invalidation of other caches.
 *
 * The caller provides the opaque lock structure used for storage and
 * their start and end pointers will be accessed while the lock is held.
 */
static int lock_name_keys(struct super_block *sb, int mode, int flags,
			 struct scoutfs_lock_name *lock_name,
			 struct ocfs2_lock_res_ops *type,
			 struct scoutfs_key_buf *start,
			 struct scoutfs_key_buf *end,
			 struct scoutfs_lock **ret_lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	struct task_ref *ref = NULL;
	int lkm_flags;
	int ret;

	*ret_lock = NULL;

	if (WARN_ON_ONCE(!(flags & SCOUTFS_LKF_TRYLOCK) &&
			 scoutfs_trans_held()))
		return -EINVAL;

	lock = find_alloc_scoutfs_lock(sb, lock_name, type, start, end);
	if (!lock)
		return -ENOMEM;

	trace_scoutfs_lock_resource(sb, lock);

	if (!(flags & SCOUTFS_LKF_NO_TASK_REF)) {
		ref = find_task_ref(lock, current);
		if (ref) {
			/*
			 * We found a ref, which means we have already locked
			 * this resource. Check that the calling task isn't
			 * trying to switch modes in the middle of a recursive
			 * lock request.
			 */
			BUG_ON(!ocfs2_levels_compat(&lock->lockres, mode));
			get_task_ref(ref);
			ret = 0;
			goto out;
		}

		ref = new_task_ref(lock, current, mode);
		if (!ref) {
			ret = -ENOMEM;
			goto out;
		}
	}

	lkm_flags = DLM_LKF_NOORDER;
	if (flags & SCOUTFS_LKF_TRYLOCK)
		lkm_flags |= DLM_LKF_NOQUEUE; /* maybe also NONBLOCK? */

	ret = ocfs2_cluster_lock(&linfo->dlmglue, &lock->lockres, mode,
				 lkm_flags, 0);
out:
	if (ret) {
		put_task_ref(lock, ref);
		dec_lock_users(lock);
		put_scoutfs_lock(sb, lock);
	} else {
		trace_scoutfs_lock(sb, lock);
		*ret_lock = lock;
	}

	return ret;
}

u64 scoutfs_lock_refresh_gen(struct scoutfs_lock *lock)
{
	return ocfs2_lock_refresh_gen(&lock->lockres);
}

int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_lock_name lock_name;
	struct scoutfs_inode_key start_ikey;
	struct scoutfs_inode_key end_ikey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	ino &= ~(u64)SCOUTFS_LOCK_INODE_GROUP_MASK;

	lock_name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	lock_name.zone = SCOUTFS_FS_ZONE;
	lock_name.type = SCOUTFS_INODE_TYPE;
	lock_name.first = cpu_to_le64(ino);
	lock_name.second = 0;

	start_ikey.zone = SCOUTFS_FS_ZONE;
	start_ikey.ino = cpu_to_be64(ino);
	start_ikey.type = 0;
	scoutfs_key_init(&start, &start_ikey, sizeof(start_ikey));

	end_ikey.zone = SCOUTFS_FS_ZONE;
	end_ikey.ino = cpu_to_be64(ino + SCOUTFS_LOCK_INODE_GROUP_NR - 1);
	end_ikey.type = ~0;
	scoutfs_key_init(&end, &end_ikey, sizeof(end_ikey));

	return lock_name_keys(sb, mode, flags, &lock_name, &scoufs_ino_lops,
			      &start, &end, ret_lock);
}

/*
 * Acquire a lock on an inode.
 *
 * _REFRESH_INODE indicates that the caller needs to have the vfs inode
 * fields current with respect to lock coverage.  dlmglue increases the
 * lock's refresh_gen once every time its mode is changed from a mode
 * that couldn't have the inode cached to one that could.
 */
int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **lock)
{
	int ret;

	ret = scoutfs_lock_ino(sb, mode, flags, scoutfs_ino(inode), lock);
	if (ret < 0)
		goto out;

	if (flags & SCOUTFS_LKF_REFRESH_INODE) {
		ret = scoutfs_inode_refresh(inode, *lock, flags);
		if (ret < 0) {
			scoutfs_unlock(sb, *lock, mode);
			*lock = NULL;
		}
	}

out:
	return ret;
}

struct lock_inodes_arg {
	struct inode *inode;
	struct scoutfs_lock **lockp;
};

/*
 * All args with inodes go to the front of the array and are then sorted
 * by their inode number.
 */
static int cmp_arg(const void *A, const void *B)
{
	const struct lock_inodes_arg *a = A;
	const struct lock_inodes_arg *b = B;

	if (a->inode && b->inode)
		return scoutfs_cmp_u64s(scoutfs_ino(a->inode),
					scoutfs_ino(b->inode));

	return a->inode ? -1 : b->inode ? 1 : 0;
}

static void swap_arg(void *A, void *B, int size)
{
	struct lock_inodes_arg *a = A;
	struct lock_inodes_arg *b = B;

	swap(*a, *b);
}

/*
 * Lock all the inodes in inode number order.  The inode arguments can
 * be in any order and can be duplicated or null.  This relies on core
 * lock matching to efficiently handle duplicate lock attempts of the
 * same group.  Callers can try to use the lock range keys for all the
 * locks they attempt to acquire without knowing that they map to the
 * same groups.
 *
 * On error no locks are held and all pointers are set to null.  Lock
 * pointers for null inodes are always set to null.
 *
 * (pretty great collision with d_lock() here)
 */
int scoutfs_lock_inodes(struct super_block *sb, int mode, int flags,
			struct inode *a, struct scoutfs_lock **a_lock,
			struct inode *b, struct scoutfs_lock **b_lock,
			struct inode *c, struct scoutfs_lock **c_lock,
			struct inode *d, struct scoutfs_lock **D_lock)
{
	struct lock_inodes_arg args[] = {
		{a, a_lock}, {b, b_lock}, {c, c_lock}, {d, D_lock},
	};
	int ret;
	int i;

	/* set all lock pointers to null and validating input */
	ret = 0;
	for (i = 0; i < ARRAY_SIZE(args); i++) {
		if (WARN_ON_ONCE(args[i].inode && !args[i].lockp))
			ret = -EINVAL;
		if (args[i].lockp)
			*args[i].lockp = NULL;
	}
	if (ret)
		return ret;

	/* sort by having an inode then inode number */
	sort(args, ARRAY_SIZE(args), sizeof(args[0]), cmp_arg, swap_arg);

	/* lock unique inodes */
	for (i = 0; i < ARRAY_SIZE(args) && args[i].inode; i++) {
		ret = scoutfs_lock_inode(sb, mode, flags, args[i].inode,
					 args[i].lockp);
		if (ret)
			break;
	}

	/* unlock on error */
	for (i = ARRAY_SIZE(args) - 1; ret < 0 && i >= 0; i--) {
		if (args[i].lockp && *args[i].lockp) {
			scoutfs_unlock(sb, *args[i].lockp, mode);
			*args[i].lockp = NULL;
		}
	}

	return ret;
}

/*
 * Acquire a cluster lock with a global scope in the lock space.
 */
int scoutfs_lock_global(struct super_block *sb, int mode, int flags, int type,
			struct scoutfs_lock **lock)
{
	struct scoutfs_lock_name lock_name;

	memset(&lock_name, 0, sizeof(lock_name));
	lock_name.scope = SCOUTFS_LOCK_SCOPE_GLOBAL;
	lock_name.type = type;

	return lock_name_keys(sb, mode, flags, &lock_name, &scoutfs_global_lops,
			      NULL, NULL, lock);
}

/*
 * Set the caller's keys to the range of index item keys that are
 * covered by the lock which covers the given index item.
 *
 * We're trying to strike a balance between minimizing lock
 * communication by locking a large number of items and minimizing
 * contention and hold times by locking a small number of items.
 *
 * The seq indexes have natural batching and limits on the number of
 * keys per major value.
 *
 * The file size index is very different.  We don't control the
 * distribution of sizes amongst inodes.  We map ranges of sizes to a
 * small set of locks by rounding the size down to groups of sizes
 * identified by their highest set bit and two next significant bits.
 * This results in ranges that increase by quarters of powers of two.
 * (small sizes don't have enough bits for this scheme, they're all
 * mapped to a range from 0 to 15.) two (0 and 1 are mapped to 0).  Each
 * lock then covers all the sizes in their range and all the inodes with
 * those sizes.
 *
 * This can also be used to find items that are covered by the same lock
 * because their starting keys are the same.
 */
void scoutfs_lock_get_index_item_range(u8 type, u64 major, u64 ino,
				       struct scoutfs_inode_index_key *start,
				       struct scoutfs_inode_index_key *end)
{
	u64 start_major;
	u64 end_major;
	int bit;

	switch(type) {
	case SCOUTFS_INODE_INDEX_SIZE_TYPE:
		bit = major ? fls64(major) : 0;
		if (bit < 5) {
			/* sizes [ 0 .. 15 ] are in their own lock */
			start_major = 0;
			end_major = 15;
		} else {
			/* last bit, 2 lesser bits, mask */
			start_major = major & (7ULL << (bit - 3));
			end_major = start_major + (1ULL << (bit - 3)) - 1;
		}
		break;

	case SCOUTFS_INODE_INDEX_META_SEQ_TYPE:
	case SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE:
		start_major = major & ~SCOUTFS_LOCK_SEQ_GROUP_MASK;
		end_major = major | SCOUTFS_LOCK_SEQ_GROUP_MASK;
		break;
	default:
		BUG();
	}

	if (start) {
		start->zone = SCOUTFS_INODE_INDEX_ZONE;
		start->type = type;
		start->major = cpu_to_be64(start_major);
		start->minor = 0;
		start->ino = 0;
	}

	if (end) {
		end->zone = SCOUTFS_INODE_INDEX_ZONE;
		end->type = type;
		end->major = cpu_to_be64(end_major);
		end->minor = 0;
		end->ino = cpu_to_be64(~0ULL);
	}
}

/*
 * Lock the given index item.  We use the index masks to name a reasonable
 * batch of logical items to lock and calculate the start and end
 * key values that are covered by the lock.
 *
 */
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock)
{
	struct scoutfs_lock_name lock_name;
	struct scoutfs_inode_index_key start_ikey;
	struct scoutfs_inode_index_key end_ikey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	scoutfs_lock_get_index_item_range(type, major, ino,
					  &start_ikey, &end_ikey);

	lock_name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	lock_name.zone = start_ikey.zone;
	lock_name.type = start_ikey.type;
	lock_name.first = be64_to_le64(start_ikey.major);
	lock_name.second = be64_to_le64(start_ikey.ino);

	scoutfs_key_init(&start, &start_ikey, sizeof(start_ikey));
	scoutfs_key_init(&end, &end_ikey, sizeof(end_ikey));

	return lock_name_keys(sb, mode, 0, &lock_name,
			      &scoufs_ino_index_lops, &start, &end, ret_lock);
}

/*
 * The node_id lock protects a mount's private persistent items in the
 * node_id zone.  It's held for the duration of the mount.  It lets the
 * mount modify the node_id items at will and signals to other mounts
 * that we're still alive and our node_id items shouldn't be reclaimed.
 *
 * Being held for the entire mount prevents other nodes from reclaiming
 * our items, like free blocks, when it would make sense for them to be
 * able to.  Maybe we have a bunch free and they're trying to allocate
 * and are getting ENOSPC.
 */
int scoutfs_lock_node_id(struct super_block *sb, int mode, int flags,
			 u64 node_id, struct scoutfs_lock **lock)
{
	struct scoutfs_lock_name lock_name;
	struct scoutfs_orphan_key start_okey;
	struct scoutfs_orphan_key end_okey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	lock_name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	lock_name.zone = SCOUTFS_NODE_ZONE;
	lock_name.type = 0;
	lock_name.first = cpu_to_le64(node_id);
	lock_name.second = 0;

	start_okey.zone = SCOUTFS_NODE_ZONE;
	start_okey.node_id = cpu_to_be64(node_id);
	start_okey.type = 0;
	start_okey.ino = 0;
	scoutfs_key_init(&start, &start_okey, sizeof(start_okey));

	end_okey.zone = SCOUTFS_NODE_ZONE;
	end_okey.node_id = cpu_to_be64(node_id);
	end_okey.type = ~0;
	end_okey.ino = cpu_to_be64(~0ULL);
	scoutfs_key_init(&end, &end_okey, sizeof(end_okey));

	return lock_name_keys(sb, mode, flags, &lock_name,
			      &scoutfs_node_id_lops, &start, &end, lock);
}

void scoutfs_unlock_flags(struct super_block *sb, struct scoutfs_lock *lock,
			  int level, int flags)
{
	struct task_ref *ref;
	DECLARE_LOCK_INFO(sb, linfo);

	if (!lock)
		return;

	trace_scoutfs_unlock(sb, lock);

	if (!(flags & SCOUTFS_LKF_NO_TASK_REF)) {
		ref = find_task_ref(lock, current);
		BUG_ON(!ref);
		if (put_task_ref(lock, ref))
			return;
	}

	ocfs2_cluster_unlock(&linfo->dlmglue, &lock->lockres, level);

	dec_lock_users(lock);

	put_scoutfs_lock(sb, lock);
}

void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    int level)
{
	scoutfs_unlock_flags(sb, lock, level, 0);
}

/*
 * The moment this is done we can have other mounts start asking
 * us to write back and invalidate, so do this very very late.
 */
static int init_lock_info(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct lock_info *linfo;
	int ret;

	linfo = kzalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linfo)
		return -ENOMEM;

	ret = ocfs2_init_super(&linfo->dlmglue, 0);
	if (ret)
		goto out;

	spin_lock_init(&linfo->lock);
	INIT_LIST_HEAD(&linfo->lru_list);
	linfo->shrinker.shrink = shrink_lock_tree;
	linfo->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&linfo->shrinker);
	linfo->sb = sb;
	linfo->lock_tree = RB_ROOT;
	linfo->lock_range_tree = RB_ROOT;

	snprintf(linfo->ls_name, DLM_LOCKSPACE_LEN, "%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	sbi->lock_info = linfo;

	trace_init_lock_info(sb, linfo);
out:
	if (ret)
		kfree(linfo);

	return 0;
}

void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);

	if (linfo) {
		unregister_shrinker(&linfo->shrinker);
		if (linfo->lock_reclaim_wq)
			destroy_workqueue(linfo->lock_reclaim_wq);
		/*
		 * Do this before uninitializing the dlm and after
		 * draining the reclaim workqueue.
		 */
		free_lock_tree(sb);

		if (linfo->dlmglue_online) {
			/*
			 * fs/dlm has a harmless but unannotated
			 * inversion between their connection and socket
			 * locking that triggers during shutdown and
			 * disables lockdep.
			 */
			lockdep_off();
			ocfs2_dlm_shutdown(&linfo->dlmglue, 0);
			lockdep_on();
		}

		sbi->lock_info = NULL;

		trace_scoutfs_lock_destroy(sb, linfo);

		kfree(linfo);
	}
}

int scoutfs_lock_setup(struct super_block *sb)
{
	struct lock_info *linfo;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	ret = init_lock_info(sb);
	if (ret)
		return ret;
	linfo = sbi->lock_info;

	linfo->lock_reclaim_wq = alloc_workqueue("scoutfs_reclaim",
						 WQ_UNBOUND|WQ_HIGHPRI, 0);
	if (!linfo->lock_reclaim_wq) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ocfs2_dlm_init(&linfo->dlmglue, "null", sbi->opts.cluster_name,
			     linfo->ls_name, sbi->debug_root);
	if (ret)
		goto out;
	linfo->dlmglue_online = true;

out:
	if (ret)
		scoutfs_lock_destroy(sb);

	return ret;
}
