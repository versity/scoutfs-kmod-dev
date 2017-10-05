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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/aio.h>

#include "format.h"
#include "super.h"
#include "data.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "lock.h"
#include "file.h"
#include "inode.h"
#include "per_task.h"

/* TODO: Direct I/O, AIO */
ssize_t scoutfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	int ret;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret == 0) {
		scoutfs_per_task_add(&si->pt_data_lock, &pt_ent, inode_lock);
		ret = generic_file_aio_read(iocb, iov, nr_segs, pos);
		scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
		scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);
	}

	return ret;
}

ssize_t scoutfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	int ret;

	if (iocb->ki_left == 0) /* Does this even happen? */
		return 0;

	mutex_lock(&inode->i_mutex);
	ret = scoutfs_lock_inode(sb, DLM_LOCK_EX, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret)
		goto out;

	ret = scoutfs_complete_truncate(inode, inode_lock);
	if (ret)
		goto out;

	scoutfs_per_task_add(&si->pt_data_lock, &pt_ent, inode_lock);

	/* XXX: remove SUID bit */

	ret = __generic_file_aio_write(iocb, iov, nr_segs, &iocb->ki_pos);
out:
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
	scoutfs_unlock(sb, inode_lock, DLM_LOCK_EX);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0 || ret == -EIOCBQUEUED) {
		ssize_t err;

		err = generic_write_sync(file, pos, ret);
		if (err < 0 && ret > 0)
			ret = err;
	}

	return ret;
}

int scoutfs_permission(struct inode *inode, int mask)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	ret = scoutfs_lock_inode(sb, DLM_LOCK_PR, SCOUTFS_LKF_REFRESH_INODE,
				 inode, &inode_lock);
	if (ret)
		return ret;

	ret = generic_permission(inode, mask);

	scoutfs_unlock(sb, inode_lock, DLM_LOCK_PR);

	return ret;
}

loff_t scoutfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	int ret = 0;

	switch (whence) {
	case SEEK_END:
	case SEEK_DATA:
	case SEEK_HOLE:
		/*
		 * These require a lock and inode refresh as they
		 * reference i_size.
		 *
		 * XXX: SEEK_DATA/SEEK_HOLE can search our extent
		 * items instead of relying on generic_file_llseek()
		 * trickery.
		 */
		ret = scoutfs_lock_inode(sb, DLM_LOCK_PR,
					 SCOUTFS_LKF_REFRESH_INODE, inode,
					 &lock);
	case SEEK_SET:
	case SEEK_CUR:
		/* No lock required, fall through to the generic helper */
		break;
	default:
		ret = -EINVAL;
	}

	if (ret == 0)
		offset = generic_file_llseek(file, offset, whence);

	scoutfs_unlock(sb, lock, DLM_LOCK_PR);

	return ret ? ret : offset;
}
