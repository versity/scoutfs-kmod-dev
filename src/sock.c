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
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "sock.h"

/*
 * Some quick socket helper wrappers.
 */

static struct kvec *kvec_advance(struct kvec *kv, unsigned *kv_len,
				 unsigned bytes)
{
	while (*kv_len && bytes) {
		if (kv->iov_len <= bytes) {
			bytes -= kv->iov_len;
			kv++;
			(*kv_len)--;
		} else {
			kv->iov_base += bytes;
			kv->iov_len -= bytes;
			bytes = 0;
		}
	}

	return kv;
}

/*
 * This can modify the kvec as it modifies the vec to continue after
 * partial sends.
 */
int scoutfs_sock_sendmsg(struct socket *sock, struct kvec *kv, unsigned kv_len)
{
	struct msghdr msg;
	int ret;

	while (kv_len) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = (struct iovec *)kv;
		msg.msg_iovlen = kv_len;
		msg.msg_flags = MSG_NOSIGNAL;

		ret = kernel_sendmsg(sock, &msg, kv, kv_len,
				     iov_length((struct iovec *)kv, kv_len));
		if (ret <= 0)
			return -ECONNABORTED;

		kv = kvec_advance(kv, &kv_len, ret);
	}

	return 0;
}

int scoutfs_sock_recvmsg(struct socket *sock, void *buf, unsigned len)
{
	struct msghdr msg;
	struct kvec kv;
	int ret;

	while (len) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = (struct iovec *)&kv;
		msg.msg_iovlen = 1;
		msg.msg_flags = MSG_NOSIGNAL;
		kv.iov_base = buf;
		kv.iov_len = len;

		ret = kernel_recvmsg(sock, &msg, &kv, 1, len, msg.msg_flags);
		if (ret <= 0)
			return -ECONNABORTED;

		len -= ret;
		buf += ret;
	}

	return 0;
}
