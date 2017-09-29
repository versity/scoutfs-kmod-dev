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
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "per_task.h"

/*
 * There are times when we'd like to pass data from a caller to its
 * callee but we're bouncing through functions and callbacks that don't
 * provide per-task storage.  We add a trivial little locked list that
 * lets a caller store a pointer for callees.  The lists are put in the
 * scope of the sharing so the contention is rare and limited to real
 * concurrency -- imagine, for example, concurrent file reading on an
 * inode.
 */

/*
 * Return the pointer that our caller added for us on the given list.
 * The expected promise is that the pointer is valid until we return to
 * the caller who will remove it from the list.
 */
void *scoutfs_per_task_get(struct scoutfs_per_task *pt)
{
	const struct task_struct *task = current;
	struct scoutfs_per_task_entry *ent;
	void *ret = NULL;

	spin_lock(&pt->lock);

	list_for_each_entry(ent, &pt->list, head) {
		if (ent->task == task){
			ret = ent->ptr;
			break;
		}
	}

	spin_unlock(&pt->lock);

	return ret;
}

void scoutfs_per_task_add(struct scoutfs_per_task *pt,
			  struct scoutfs_per_task_entry *ent, void *ptr)
{
	ent->task = current;
	ent->ptr = ptr;

	spin_lock(&pt->lock);
	list_add(&ent->head, &pt->list);
	spin_unlock(&pt->lock);
}

void scoutfs_per_task_del(struct scoutfs_per_task *pt,
			  struct scoutfs_per_task_entry *ent)
{
	BUG_ON(!list_empty(&ent->head) && ent->task != current);

	if (!list_empty(&ent->head)) {
		spin_lock(&pt->lock);
		list_del_init(&ent->head);
		spin_unlock(&pt->lock);
	}
}

void scoutfs_per_task_init(struct scoutfs_per_task *pt)
{
	spin_lock_init(&pt->lock);
	INIT_LIST_HEAD(&pt->list);
}
