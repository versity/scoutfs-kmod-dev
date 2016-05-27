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

#include "ioctl.h"
#include "trace.h"

int scoutfs_copy_ibuf(struct iovec *iov, unsigned long arg)
{
	struct scoutfs_ioctl_buf __user *user_ibuf = (void __user *)arg;
	struct scoutfs_ioctl_buf ibuf;

	if (copy_from_user(&ibuf, user_ibuf, sizeof(ibuf)))
		return -EFAULT;

	/* limit lengths to an int for some helpers that take int len args */
	if (ibuf.len < 0)
		return -EINVAL;

	iov->iov_base = (void __user *)(long)ibuf.ptr;
	iov->iov_len = ibuf.len;

	/*
	 * This is not meant to protect the rest of the code from
	 * faults, it can't.  It's meant to return early for iovecs that
	 * are completely garbage.
	 */
	if (!access_ok(VERIFY_READ, iov->iov_base, iov->iov_len))
		return -EFAULT;

	return 0;
}
