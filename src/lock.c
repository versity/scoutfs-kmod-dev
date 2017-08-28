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
	bool shutdown;
	struct list_head id_head;

	spinlock_t lock;
	unsigned int seq_cnt;
	wait_queue_head_t waitq;
	struct rb_root lock_tree;
	struct workqueue_struct *downconvert_wq;
	struct shrinker shrinker;
	struct list_head lru_list;
	unsigned long long lru_nr;
};

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

static void scoutfs_downconvert_func(struct work_struct *work);

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
	struct inode *inode;
	u64 ino, last;
	int ret;

	trace_scoutfs_lock_invalidate_sb(sb, mode, start, end);

	ret = scoutfs_item_writeback(sb, start, end);
	if (ret)
		return ret;

	if (mode == DLM_LOCK_EX) {
		if (lock->lock_name.zone == SCOUTFS_FS_ZONE) {
			ino = le64_to_cpu(lock->lock_name.first);
			last = ino + SCOUTFS_LOCK_INODE_GROUP_NR - 1;
			while (ino <= last) {
				inode = scoutfs_ilookup(lock->sb, ino);
				if (inode && S_ISREG(inode->i_mode))
					truncate_inode_pages(inode->i_mapping,
							     0);

				iput(inode);
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

		ocfs2_simple_drop_lockres(&linfo->dlmglue, &lock->lockres);
		scoutfs_key_free(lock->sb, lock->start);
		scoutfs_key_free(lock->sb, lock->end);
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
			BUG_ON(lock->holders);
			/* can't be (even racy) busy without refs */
			BUG_ON(work_busy(&lock->dc_work));
			rb_erase(&lock->node, &linfo->lock_tree);
			list_del(&lock->lru_entry);
			spin_unlock(&linfo->lock);
			free_scoutfs_lock(lock);
			return;
		}
		spin_unlock(&linfo->lock);
	}
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

static struct ocfs2_lock_res_ops scoufs_ino_lops = {
	.get_osb 		= get_ino_lock_osb,
	.downconvert_worker 	= ino_lock_downconvert,
	/* XXX: .post_unlock for lru */
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.flags			= LOCK_TYPE_REQUIRES_REFRESH,
};

static struct ocfs2_lock_res_ops scoufs_ino_index_lops = {
	.get_osb 		= get_ino_lock_osb,
	.downconvert_worker 	= ino_lock_downconvert,
	/* XXX: .post_unlock for lru */
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.flags			= 0,
};

static struct ocfs2_lock_res_ops scoutfs_global_lops = {
	.get_osb 		= get_ino_lock_osb,
	/* XXX: .post_unlock for lru */
	/* XXX: .check_downconvert that queries the item cache for dirty items */
	.flags			= 0,
};

static struct scoutfs_lock *alloc_scoutfs_lock(struct super_block *sb,
					       struct scoutfs_lock_name *lock_name,
					       struct ocfs2_lock_res_ops *type,
					       struct scoutfs_key_buf *start,
					       struct scoutfs_key_buf *end)

{
	DECLARE_LOCK_INFO(sb, linfo);
//	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_lock *lock;

	if (WARN_ON_ONCE(!!start != !!end))
		return NULL;

	lock = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (lock == NULL)
		return NULL;

	if (start) {
		lock->start = scoutfs_key_dup(sb, start);
		lock->end = scoutfs_key_dup(sb, end);
		if (!lock->start || !lock->end) {
			free_scoutfs_lock(lock);
			return NULL;
		}
	}

	RB_CLEAR_NODE(&lock->node);
	lock->sb = sb;
	lock->lock_name = *lock_name;
	lock->mode = DLM_LOCK_IV;
	INIT_WORK(&lock->dc_work, scoutfs_downconvert_func);
	INIT_LIST_HEAD(&lock->lru_entry);
	ocfs2_lock_res_init_once(&lock->lockres);
	BUG_ON(sizeof(struct scoutfs_lock_name) >= OCFS2_LOCK_ID_MAX_LEN);
	/* kzalloc above ensures that l_name is NULL terminated */
	memcpy(&lock->lockres.l_name[0], &lock->lock_name,
	       sizeof(struct scoutfs_lock_name));
	ocfs2_lock_res_init_common(&linfo->dlmglue, &lock->lockres, type, lock);

	return lock;
}

static int cmp_lock_names(struct scoutfs_lock_name *a,
			  struct scoutfs_lock_name *b)
{
	return (int)a->scope - (int)b->scope ?:
	       (int)a->zone - (int)b->zone ?:
	       (int)a->type - (int)b->type ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->first), le64_to_cpu(b->first)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(b->second), le64_to_cpu(b->second));
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
		rb_link_node(&found->node, parent, node);
		rb_insert_color(&found->node, &linfo->lock_tree);
	}
	found->refcnt++;
	if (!list_empty(&found->lru_entry)) {
		list_del_init(&found->lru_entry);
		linfo->lru_nr--;
	}
	spin_unlock(&linfo->lock);

	kfree(new);
	return found;
}

static int shrink_lock_tree(struct shrinker *shrink, struct shrink_control *sc)
{
	struct lock_info *linfo = container_of(shrink, struct lock_info,
					       shrinker);
	struct scoutfs_lock *lock;
	struct scoutfs_lock *tmp;
	unsigned long flags;
	unsigned long nr;
	LIST_HEAD(list);

	nr = sc->nr_to_scan;
	if (!nr)
		goto out;

	spin_lock_irqsave(&linfo->lock, flags);
	list_for_each_entry_safe(lock, tmp, &linfo->lru_list, lru_entry) {
		if (nr-- == 0)
			break;

		WARN_ON(lock->holders);
		WARN_ON(lock->refcnt != 1);
		WARN_ON(lock->flags & SCOUTFS_LOCK_QUEUED);

		rb_erase(&lock->node, &linfo->lock_tree);
		list_del(&lock->lru_entry);
		list_add_tail(&lock->lru_entry, &list);
		linfo->lru_nr--;
	}
	spin_unlock_irqrestore(&linfo->lock, flags);

	list_for_each_entry_safe(lock, tmp, &list, lru_entry) {
		trace_shrink_lock_tree(linfo->sb, lock);
		list_del(&lock->lru_entry);
		free_scoutfs_lock(lock);
	}
out:
	return min_t(unsigned long, linfo->lru_nr, INT_MAX);
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

static int lock_granted(struct lock_info *linfo, struct scoutfs_lock *lock,
			int mode)
{
	int ret;

	spin_lock(&linfo->lock);
	ret = !!(mode == lock->mode);
	spin_unlock(&linfo->lock);

	return ret;
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
	int lkm_flags;
	int ret;

	lock = find_alloc_scoutfs_lock(sb, lock_name, type, start, end);
	if (!lock)
		return -ENOMEM;

	trace_scoutfs_lock_resource(sb, lock);

	lkm_flags = DLM_LKF_NOORDER;
	if (flags & SCOUTFS_LKF_TRYLOCK)
		lkm_flags |= DLM_LKF_NOQUEUE; /* maybe also NONBLOCK? */

	ret = ocfs2_cluster_lock(&linfo->dlmglue, &lock->lockres, mode,
				 lkm_flags, 0);
	if (ret)
		return ret;

	*ret_lock = lock;
	return 0;
#if 0
check_lock_state:
	spin_lock(&linfo->lock);
	if (linfo->shutdown) {
		spin_unlock(&linfo->lock);
		put_scoutfs_lock(sb, lock);
		return -ESHUTDOWN;
	}

	if (lock->flags & SCOUTFS_LOCK_BLOCKING) {
		spin_unlock(&linfo->lock);
		wait_event(linfo->waitq, !lock_blocking(linfo, lock));
		goto check_lock_state;
	}

	if (lock->mode > DLM_LOCK_IV) {
		if (lock->mode < mode) {
			/*
			 * We already have the lock but at a mode which is not
			 * compatible with what the caller wants. Set the lock
			 * blocking to let the downconvert thread do it's work
			 * so we can reacquire at the correct mode.
			 */
			set_lock_blocking(linfo, lock);
			spin_unlock(&linfo->lock);
			goto check_lock_state;
		}
		lock->holders++;
		spin_unlock(&linfo->lock);
		goto out;
	}

	lock->rqmode = mode;
	lock->holders++;
	spin_unlock(&linfo->lock);

	ret = dlm_lock(linfo->dlmglue.cconn->cc_lockspace, mode, &lock->lksb,
		       DLM_LKF_NOORDER, &lock->lock_name,
		       sizeof(struct scoutfs_lock_name),
		       0, scoutfs_ast, lock, scoutfs_bast);
	if (ret) {
		scoutfs_err(sb, "Error %d locking "LN_FMT, ret,
			    LN_ARG(&lock->lock_name));
		put_scoutfs_lock(sb, lock);
		return ret;
	}

	wait_event(linfo->waitq, lock_granted(linfo, lock, mode));
out:
	*ret_lock = lock;
	return 0;
#endif
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
 * map inode index items to locks.  The idea is to not have to
 * constantly get locks over a reasonable distribution of items, but
 * also not have an insane amount of items covered by locks.  time and
 * seq indexes have natural batching and limits on the number of keys
 * per major value.  Size keys are very different.  For them we use a
 * mix of a sort of linear-log distribution (top 4 bits of size), and
 * then also a lot of inodes per size.
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
	u64 major_mask;
	u64 ino_mask;
	int bit;

	switch(type) {
	case SCOUTFS_INODE_INDEX_SIZE_TYPE:
		major_mask = 0;
		if (major) {
			bit = fls64(major);
			if (bit > 4)
				major_mask = (1 << (bit - 4)) - 1;
		}
		ino_mask = (1 << 12) - 1;
		break;

	case SCOUTFS_INODE_INDEX_META_SEQ_TYPE:
	case SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE:
		major_mask = (1 << 10) - 1;
		ino_mask = ~0ULL;
		break;
	default:
		BUG();
	}

	lock_name.scope = SCOUTFS_LOCK_SCOPE_FS_ITEMS;
	lock_name.zone = SCOUTFS_INODE_INDEX_ZONE;
	lock_name.type = type;
	lock_name.first = cpu_to_le64(major & ~major_mask);
	lock_name.second = cpu_to_le64(ino & ~ino_mask);

	start_ikey.zone = SCOUTFS_INODE_INDEX_ZONE;
	start_ikey.type = type;
	start_ikey.major = cpu_to_be64(major & ~major_mask);
	start_ikey.minor = cpu_to_be32(0);
	start_ikey.ino = cpu_to_be64(ino & ~ino_mask);
	scoutfs_key_init(&start, &start_ikey, sizeof(start_ikey));

	end_ikey.zone = SCOUTFS_INODE_INDEX_ZONE;
	end_ikey.type = type;
	end_ikey.major = cpu_to_be64(major | major_mask);
	end_ikey.minor = cpu_to_be32(U32_MAX);
	end_ikey.ino = cpu_to_be64(ino | ino_mask);
	scoutfs_key_init(&end, &end_ikey, sizeof(end_ikey));

	return lock_name_keys(sb, mode, 0, &lock_name,
			      &scoufs_ino_index_lops, &start, &end, ret_lock);
}

void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    int level)
{
	DECLARE_LOCK_INFO(sb, linfo);

	if (!lock)
		return;

	trace_scoutfs_unlock(sb, lock);

	ocfs2_cluster_unlock(&linfo->dlmglue, &lock->lockres, level);

#if 0
	spin_lock(&linfo->lock);
	lock->holders--;
	if (lock->holders == 0 && (lock->flags & SCOUTFS_LOCK_BLOCKING))
		queue_blocking_work(linfo, lock);
	spin_unlock(&linfo->lock);
#endif
	put_scoutfs_lock(sb, lock);
}

static void unlock_range(struct super_block *sb, struct scoutfs_lock *lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	int ret;

	trace_scoutfs_unlock(sb, lock);

	BUG_ON(!lock->sequence);

	spin_lock(&linfo->lock);
	lock->rqmode = DLM_LOCK_IV;
	spin_unlock(&linfo->lock);
	ret = dlm_unlock(linfo->dlmglue.cconn->cc_lockspace, lock->lksb.sb_lkid,
			 0, &lock->lksb, lock);
	if (ret) {
		scoutfs_err(sb, "Error %d unlocking "LN_FMT, ret,
			    LN_ARG(&lock->lock_name));
		goto out;
	}

	wait_event(linfo->waitq, lock_granted(linfo, lock, DLM_LOCK_IV));
out:
	/* lock was removed from tree, wake up umount process */
	wake_up(&linfo->waitq);
}

static void scoutfs_downconvert_func(struct work_struct *work)
{
	struct scoutfs_lock *lock = container_of(work, struct scoutfs_lock,
						 dc_work);
	struct super_block *sb = lock->sb;
	DECLARE_LOCK_INFO(sb, linfo);

	trace_scoutfs_downconvert_func(sb, lock);

	spin_lock(&linfo->lock);
	lock->flags &= ~SCOUTFS_LOCK_QUEUED;
	if (lock->holders)
		goto out; /* scoutfs_unlock_range will requeue for us */

	spin_unlock(&linfo->lock);

	WARN_ON_ONCE(lock->holders);
	WARN_ON_ONCE(lock->refcnt == 0);
	/*
	 * Use write mode to invalidate all since we are completely
	 * dropping the lock. Once we are dowconverting, we can
	 * invalidate based on what level we're downconverting to (PR,
	 * NL).
	 */
	invalidate_caches(sb, DLM_LOCK_EX, lock);
	unlock_range(sb, lock);

	spin_lock(&linfo->lock);
	/* Check whether we can add the lock to the LRU list:
	 *
	 * First, check mode to be sure that the lock wasn't reacquired
	 * while we slept in unlock_range().
	 *
	 * Next, check refs. refcnt == 1 means the only holder is the
	 * lock tree so in particular we have nobody in
	 * scoutfs_lock_range concurrently trying to acquire a lock.
	 */
	if (lock->mode == DLM_LOCK_IV && lock->refcnt == 1 &&
	    list_empty(&lock->lru_entry)) {
		list_add_tail(&lock->lru_entry, &linfo->lru_list);
		linfo->lru_nr++;
	}
out:
	spin_unlock(&linfo->lock);
	put_scoutfs_lock(sb, lock);
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
	init_waitqueue_head(&linfo->waitq);
	INIT_LIST_HEAD(&linfo->lru_list);
	linfo->shrinker.shrink = shrink_lock_tree;
	linfo->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&linfo->shrinker);
	linfo->sb = sb;
	linfo->shutdown = false;
	INIT_LIST_HEAD(&linfo->id_head);

	snprintf(linfo->ls_name, DLM_LOCKSPACE_LEN, "%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	sbi->lock_info = linfo;

	trace_printk("sb %p id %016llx allocated linfo %p held %p\n",
		     sb, le64_to_cpu(sbi->super.id), linfo, linfo);
out:
	if (ret)
		kfree(linfo);

	return 0;
}

/*
 * Cause all lock attempts from our super to fail, waking anyone who is
 * currently blocked attempting to lock.  Now that locks can't block we
 * can easily tear down subsystems that use locking before freeing lock
 * infrastructure.
 */
void scoutfs_lock_shutdown(struct super_block *sb)
{
	DECLARE_LOCK_INFO(sb, linfo);

	if (linfo) {
		spin_lock(&linfo->lock);
		linfo->shutdown = true;
		spin_unlock(&linfo->lock);

		wake_up(&linfo->waitq);
	}
}

void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linfo);

	if (linfo) {
		free_lock_tree(sb); /* Do this before uninitializing the dlm. */

		if (linfo->downconvert_wq)
			destroy_workqueue(linfo->downconvert_wq);
		unregister_shrinker(&linfo->shrinker);
		if (linfo->dlmglue_online) {
			ocfs2_dlm_shutdown(&linfo->dlmglue, 0);
			ocfs2_uninit_super(&linfo->dlmglue);
		}

		sbi->lock_info = NULL;

		trace_printk("sb %p id %016llx freeing linfo %p linfo %p\n",
			     sb, le64_to_cpu(sbi->super.id), linfo, linfo);

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

	linfo->downconvert_wq = alloc_workqueue("scoutfs_dc",
					       WQ_UNBOUND|WQ_HIGHPRI, 0);
	if (!linfo->downconvert_wq) {
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
