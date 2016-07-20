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
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <linux/uio.h>

#include "format.h"
#include "btree.h"
#include "key.h"
#include "ioctl.h"

/*
 * Find all the inodes in the given inode range that have changed since
 * the given tree update sequence number.
 *
 * The inodes are returned in inode order, not sequence order.
 */
static long scoutfs_ioc_inodes_since(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_inodes_since __user *uargs = (void __user *)arg;
	struct scoutfs_ioctl_inodes_since args;
	struct scoutfs_ioctl_ino_seq __user *uiseq;
	struct scoutfs_ioctl_ino_seq iseq;
	struct scoutfs_key first;
	struct scoutfs_key last;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	long bytes;
	int ret;

	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	uiseq = (void __user *)(unsigned long)args.buf_ptr;
	if (args.buf_len < sizeof(iseq) || args.buf_len > INT_MAX)
		return -EINVAL;

	scoutfs_set_key(&first, args.first_ino, SCOUTFS_INODE_KEY, 0);
	scoutfs_set_key(&last, args.last_ino, SCOUTFS_INODE_KEY, 0);

	bytes = 0;
	while ((ret = scoutfs_btree_since(sb, &first, &last,
					  args.seq, &curs)) > 0) {

		iseq.ino = scoutfs_key_inode(curs.key);
		iseq.seq = curs.seq;

		/*
		 * We can't copy to userspace with our locks held
		 * because faults could try to use tree blocks that we
		 * have locked.  If a non-faulting copy fails we release
		 * the cursor and try a blocking copy and pick up where
		 * we left off.
		 */
		pagefault_disable();
		ret = __copy_to_user_inatomic(uiseq, &iseq, sizeof(iseq));
		pagefault_enable();
		if (ret) {
			first = *curs.key;
			scoutfs_inc_key(&first);
			scoutfs_btree_release(&curs);
			if (copy_to_user(uiseq, &iseq, sizeof(iseq))) {
				ret = -EFAULT;
				break;
			}
		}

		uiseq++;
		bytes += sizeof(iseq);
		if (bytes + sizeof(iseq) > args.buf_len) {
			ret = 0;
			break;
		}
	}

	scoutfs_btree_release(&curs);

	if (bytes)
		ret = bytes;

	return ret;
}

long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SCOUTFS_IOC_INODES_SINCE:
		return scoutfs_ioc_inodes_since(file, arg);
	}

	return -ENOTTY;
}
