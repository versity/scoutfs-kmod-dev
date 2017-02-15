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

#include "super.h"
#include "lock.h"
#include "item.h"
#include "scoutfs_trace.h"

/*
 * This is meant to be simple and correct, not performant.
 */

static DECLARE_RWSEM(global_rwsem);
static LIST_HEAD(global_super_list);

/*
 * Allocated once and pointed to by the lock info of all the supers with
 * the same fsid.  Freed as the last super unmounts.
 */
struct held_locks {
	spinlock_t lock;
	struct list_head list;
	wait_queue_head_t waitq;
};


/*
 * allocated per-super.  Stored in the global list for finding supers
 * with fsids and stored in a list with others with the same fsid for
 * invalidation.  Freed on unmount.
 */
struct lock_info {
	struct super_block *sb;
	struct held_locks *held;
	struct list_head id_head;
	struct list_head global_head;
};

#define DECLARE_LOCK_INFO(sb, name) \
	struct lock_info *name = SCOUTFS_SB(sb)->lock_info

/*
 * locks are compatible if they're from the same super, or are both reads,
 * or don't overlap.
 */
static bool compatible_locks(struct scoutfs_lock *a, struct scoutfs_lock *b)
{
	return a->sb == b->sb ||
	       (a->mode == SCOUTFS_LOCK_MODE_READ &&
	        b->mode == SCOUTFS_LOCK_MODE_READ) ||
	       scoutfs_key_compare_ranges(a->start, a->end, b->start, b->end);
}

static bool lock_added(struct held_locks *held, struct scoutfs_lock *add)
{
	struct scoutfs_lock *lck;
	bool added = true;

	spin_lock(&held->lock);

	list_for_each_entry(lck, &held->list, head) {
		if (!compatible_locks(lck, add)) {
			added = false;
			break;
		}
	}

	if (added)
		list_add(&add->head, &held->list);

	spin_unlock(&held->lock);

	return added;
}

/*
 * Invalidate caches on this super because another super has acquired
 * a lock with the given mode and range.  We always have to write out
 * dirty overlapping items.  If they're writing then we need to also
 * invalidate all cached overlapping structures.
 */
static int invalidate_caches(struct super_block *sb, int mode,
			     struct scoutfs_key_buf *start,
			     struct scoutfs_key_buf *end)
{
	int ret;

	ret = scoutfs_item_writeback(sb, start, end);
	if (ret)
		return ret;

	if (mode == SCOUTFS_LOCK_MODE_WRITE) {
		scoutfs_item_invalidate(sb, start, end);
#if 0
		scoutfs_dir_invalidate(sb, start, end) ?:
		scoutfs_inode_invalidate(sb, start, end) ?:
		scoutfs_data_invalidate(sb, start, end);
#endif
	}

	return 0;
}

#define for_each_other_linf(linf, from_linf)				  \
	for (linf = list_entry(from_linf->id_head.next, struct lock_info, \
			       id_head);				  \
	     linf != from_linf;						  \
	     linf = list_entry(linf->id_head.next, struct lock_info,	  \
			       id_head))

static int invalidate_others(struct super_block *from, int mode,
			     struct scoutfs_key_buf *start,
			     struct scoutfs_key_buf *end)
{
	DECLARE_LOCK_INFO(from, from_linf);
	struct lock_info *linf;
	int ret;

	down_read(&global_rwsem);

	for_each_other_linf(linf, from_linf) {
		ret = invalidate_caches(linf->sb, mode, start, end);
		if (ret)
			break;
	}

	up_read(&global_rwsem);

	return ret;
}

static void unlock(struct held_locks *held, struct scoutfs_lock *lck)
{
	spin_lock(&held->lock);
	list_del_init(&lck->head);
	spin_unlock(&held->lock);

	wake_up(&held->waitq);
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
int scoutfs_lock_range(struct super_block *sb, int mode,
		       struct scoutfs_key_buf *start,
		       struct scoutfs_key_buf *end,
		       struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linf);
	struct held_locks *held = linf->held;
	int ret;

	INIT_LIST_HEAD(&lck->head);
	lck->sb = sb;
	lck->start = start;
	lck->end = end;
	lck->mode = mode;

	ret = wait_event_interruptible(held->waitq, lock_added(held, lck));
	if (ret == 0) {
		ret = invalidate_others(sb, mode, start, end);
		if (ret)
			unlock(held, lck);
	}

	return ret;
}

void scoutfs_unlock_range(struct super_block *sb, struct scoutfs_lock *lck)
{
	DECLARE_LOCK_INFO(sb, linf);
	struct held_locks *held = linf->held;

	unlock(held, lck);
}

/*
 * The moment this is done we can have other mounts start asking
 * us to write back and invalidate, so do this very very late.
 */
int scoutfs_lock_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_sb_info *other_sbi;
	struct lock_info *other_linf;
	struct held_locks *held;
	struct lock_info *linf;

	linf = kmalloc(sizeof(struct lock_info), GFP_KERNEL);
	if (!linf)
		return -ENOMEM;

	held = kmalloc(sizeof(struct held_locks), GFP_KERNEL);
	if (!held) {
		kfree(linf);
		return -ENOMEM;
	}

	spin_lock_init(&held->lock);
	INIT_LIST_HEAD(&held->list);
	init_waitqueue_head(&held->waitq);

	linf->sb = sb;
	linf->held = held;
	INIT_LIST_HEAD(&linf->id_head);
	INIT_LIST_HEAD(&linf->global_head);

	sbi->lock_info = linf;

	trace_printk("sb %p id %016llx allocated linf %p held %p\n",
		     sb, le64_to_cpu(sbi->super.id), linf, held);

	down_write(&global_rwsem);

	list_for_each_entry(other_linf, &global_super_list, global_head) {
		other_sbi = SCOUTFS_SB(other_linf->sb);
		if (other_sbi->super.id == sbi->super.id) {
			list_add(&linf->id_head, &other_linf->id_head);
			linf->held = other_linf->held;
			trace_printk("sharing held %p\n", linf->held);
			break;
		}
	}

	/* add to global list after walking so we don't see ourselves */
	list_add(&linf->global_head, &global_super_list);

	up_write(&global_rwsem);

	if (linf->held != held)
		kfree(held);

	return 0;
}

void scoutfs_lock_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_INFO(sb, linf);
	struct held_locks *held;

	if (linf) {
		down_write(&global_rwsem);

		list_del_init(&linf->global_head);

		if (!list_empty(&linf->id_head)) {
			list_del_init(&linf->id_head);
			held = NULL;
		} else {
			held = linf->held;
		}

		up_write(&global_rwsem);

		trace_printk("sb %p id %016llx freeing linf %p held %p\n",
			     sb, le64_to_cpu(sbi->super.id), linf, held);

		kfree(held);
		kfree(linf);
	}
}
