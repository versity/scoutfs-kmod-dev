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

#include "super.h"
#include "lock.h"
#include "item.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "cmp.h"

#define LN_FMT "%u.%u.%llu.%llu"
#define LN_ARG(name) \
	(name)->zone, (name)->type, le64_to_cpu((name)->first), \
	le64_to_cpu((name)->second)

/*
 * allocated per-super, freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	dlm_lockspace_t *ls;
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
			     struct scoutfs_key_buf *start,
			     struct scoutfs_key_buf *end)
{
	int ret;

	trace_scoutfs_lock_invalidate_sb(sb, mode, start, end);

	ret = scoutfs_item_writeback(sb, start, end);
	if (ret)
		return ret;

	if (mode == DLM_LOCK_EX)
		ret = scoutfs_item_invalidate(sb, start, end);

	return ret;
}

static void free_scoutfs_lock(struct scoutfs_lock *lock)
{
	if (lock) {
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

static struct scoutfs_lock *alloc_scoutfs_lock(struct super_block *sb,
					       struct scoutfs_lock_name *lock_name,
					       struct scoutfs_key_buf *start,
					       struct scoutfs_key_buf *end)

{
	struct scoutfs_lock *lock;

	lock = kzalloc(sizeof(struct scoutfs_lock), GFP_NOFS);
	if (lock) {
		lock->start = scoutfs_key_dup(sb, start);
		lock->end = scoutfs_key_dup(sb, end);
		if (!lock->start || !lock->end) {
			free_scoutfs_lock(lock);
			lock = NULL;
		} else {
			RB_CLEAR_NODE(&lock->node);
			lock->sb = sb;
			lock->lock_name = *lock_name;
			lock->mode = DLM_LOCK_IV;
			INIT_WORK(&lock->dc_work, scoutfs_downconvert_func);
			INIT_LIST_HEAD(&lock->lru_entry);
		}
	}

	return lock;
}

static int cmp_lock_names(struct scoutfs_lock_name *a,
			  struct scoutfs_lock_name *b)
{
	return (int)a->zone - (int)b->zone ?:
	       (int)a->type - (int)b->type ?:
	       scoutfs_cmp_u64s(le64_to_cpu(a->first), le64_to_cpu(b->first)) ?:
	       scoutfs_cmp_u64s(le64_to_cpu(b->second), le64_to_cpu(b->second));
}

static struct scoutfs_lock *find_alloc_scoutfs_lock(struct super_block *sb,
					struct scoutfs_lock_name *lock_name,
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
			new = alloc_scoutfs_lock(sb, lock_name, start, end);
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

static void scoutfs_ast(void *astarg)
{
	struct scoutfs_lock *lock = astarg;
	DECLARE_LOCK_INFO(lock->sb, linfo);

	trace_scoutfs_ast(lock->sb, lock);

	spin_lock(&linfo->lock);
	lock->mode = lock->rqmode;
	/* Clear blocking flag when we are granted an unlock request */
	if (lock->rqmode == DLM_LOCK_IV)
		lock->flags &= ~SCOUTFS_LOCK_BLOCKING;
	lock->rqmode = DLM_LOCK_IV;
	spin_unlock(&linfo->lock);

	wake_up(&linfo->waitq);
}

static void queue_blocking_work(struct lock_info *linfo,
				struct scoutfs_lock *lock)
{
	assert_spin_locked(&linfo->lock);
	if (!(lock->flags & SCOUTFS_LOCK_QUEUED)) {
		/* Take a ref for the workqueue */
		lock->flags |= SCOUTFS_LOCK_QUEUED;
		lock->refcnt++;
		queue_work(linfo->downconvert_wq, &lock->dc_work);
	}
}

static void set_lock_blocking(struct lock_info *linfo,
			      struct scoutfs_lock *lock)
{
	assert_spin_locked(&linfo->lock);
	lock->flags |= SCOUTFS_LOCK_BLOCKING;
	if (lock->holders == 0)
		queue_blocking_work(linfo, lock);
}

static void scoutfs_bast(void *astarg, int mode)
{
	struct scoutfs_lock *lock = astarg;
	struct lock_info *linfo = SCOUTFS_SB(lock->sb)->lock_info;

	trace_scoutfs_bast(lock->sb, lock);

	spin_lock(&linfo->lock);
	set_lock_blocking(linfo, lock);
	spin_unlock(&linfo->lock);
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

static int lock_blocking(struct lock_info *linfo, struct scoutfs_lock *lock)
{
	int ret;

	spin_lock(&linfo->lock);
	ret = !!(lock->flags & SCOUTFS_LOCK_BLOCKING);
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
static int lock_name_keys(struct super_block *sb, int mode,
			 struct scoutfs_lock_name *lock_name,
			 struct scoutfs_key_buf *start,
			 struct scoutfs_key_buf *end,
			 struct scoutfs_lock **ret_lock)
{
	DECLARE_LOCK_INFO(sb, linfo);
	struct scoutfs_lock *lock;
	int ret;

	lock = find_alloc_scoutfs_lock(sb, lock_name, start, end);
	if (!lock)
		return -ENOMEM;

	trace_scoutfs_lock_resource(sb, lock);

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

	ret = dlm_lock(linfo->ls, mode, &lock->lksb, DLM_LKF_NOORDER,
		       &lock->lock_name, sizeof(struct scoutfs_lock_name),
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
}

int scoutfs_lock_ino_group(struct super_block *sb, int mode, u64 ino,
			   struct scoutfs_lock **ret_lock)
{
	struct scoutfs_lock_name lock_name;
	struct scoutfs_inode_key start_ikey;
	struct scoutfs_inode_key end_ikey;
	struct scoutfs_key_buf start;
	struct scoutfs_key_buf end;

	ino &= ~(u64)SCOUTFS_LOCK_INODE_GROUP_MASK;

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

	return lock_name_keys(sb, mode, &lock_name, &start, &end, ret_lock);
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
	case SCOUTFS_INODE_INDEX_CTIME_TYPE:
		major_mask = (1 << 5) - 1;
		ino_mask = ~0ULL;
		break;

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

	return lock_name_keys(sb, mode, &lock_name, &start, &end, ret_lock);
}

void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock)
{
	DECLARE_LOCK_INFO(sb, linfo);

	if (!lock)
		return;

	trace_scoutfs_unlock(sb, lock);

	spin_lock(&linfo->lock);
	lock->holders--;
	if (lock->holders == 0 && (lock->flags & SCOUTFS_LOCK_BLOCKING))
		queue_blocking_work(linfo, lock);
	spin_unlock(&linfo->lock);

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
	ret = dlm_unlock(linfo->ls, lock->lksb.sb_lkid, 0, &lock->lksb, lock);
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
	invalidate_caches(sb, DLM_LOCK_EX, lock->start, lock->end);
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

	linfo = kzalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linfo)
		return -ENOMEM;

	spin_lock_init(&linfo->lock);
	init_waitqueue_head(&linfo->waitq);
	INIT_LIST_HEAD(&linfo->lru_list);
	linfo->shrinker.shrink = shrink_lock_tree;
	linfo->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&linfo->shrinker);
	linfo->sb = sb;
	linfo->shutdown = false;
	INIT_LIST_HEAD(&linfo->id_head);
	linfo->ls = NULL;

	snprintf(linfo->ls_name, DLM_LOCKSPACE_LEN, "%llx",
		 le64_to_cpu(sbi->super.hdr.fsid));

	sbi->lock_info = linfo;

	trace_printk("sb %p id %016llx allocated linfo %p held %p\n",
		     sb, le64_to_cpu(sbi->super.id), linfo, linfo);

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
	int ret;

	if (linfo) {
		if (linfo->downconvert_wq)
			destroy_workqueue(linfo->downconvert_wq);
		unregister_shrinker(&linfo->shrinker);
		if (linfo->ls) {
			ret = dlm_release_lockspace(linfo->ls, 2);
			if (ret)
				scoutfs_info(sb, "Error %d releasing lockspace %s\n",
					     ret, linfo->ls_name);
		}

		free_lock_tree(sb);

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
		kfree(linfo);
		return -ENOMEM;
	}

	/*
	 * Open coded '64' here is for lvb_len. We never use the LVB
	 * flag so this doesn't matter, but the dlm needs a non-zero
	 * multiple of 8
	 */
	ret = dlm_new_lockspace(linfo->ls_name, sbi->opts.cluster_name,
				DLM_LSFL_FS|DLM_LSFL_NEWEXCL, 64, NULL,
				NULL, NULL, &linfo->ls);
	if (ret)
		scoutfs_lock_destroy(sb);

	return ret;
}
