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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/random.h>
#include <linux/statfs.h>

#include "super.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "xattr.h"
#include "msg.h"
#include "block.h"
#include "counters.h"
#include "trans.h"
#include "buddy.h"
#include "kvec.h"
#include "scoutfs_trace.h"

/*
 * Return the result of memcmp between the min of the two total lengths.
 * If their shorter lengths are equal than the shorter length is considered
 * smaller than the longer.
 */
int scoutfs_kvec_memcmp(struct kvec *a, struct kvec *b)
{
	int b_off = 0;
	int a_off = 0;
	int len;
	int ret;

	while (a->iov_base && b->iov_base) {
		len = min(a->iov_len - a_off, b->iov_len - b_off);
		ret = memcmp(a->iov_base + a_off, b->iov_base + b_off, len);
		if (ret)
			return ret;

		b_off += len;
		if (b_off == b->iov_len)
			b++;
		a_off += len;
		if (a_off == a->iov_len)
			a++;
	}

	return a->iov_base ? 1 : b->iov_base ? -1 : 0;
}

/*
 * Returns 0 if [a,b] overlaps with [c,d].  Returns -1 if a < c and
 * 1 if b > d.
 */
int scoutfs_kvec_cmp_overlap(struct kvec *a, struct kvec *b,
			     struct kvec *c, struct kvec *d)
{
	return scoutfs_kvec_memcmp(a, c) < 0 ? -1 :
	       scoutfs_kvec_memcmp(b, d) > 0 ? 1 : 0;
}

/*
 * Set just the pointers and length fields in the dst vector to point to
 * the source vector.
 */
void scoutfs_kvec_clone(struct kvec *dst, struct kvec *src)
{
	int i;

	for (i = 0; i < SCOUTFS_KVEC_NR; i++)
		*(dst++) = *(src++);
}

/*
 * Copy as much of src as fits in dst.  Null base pointers termintae the
 * copy.  The number of bytes copied is returned.  Only the buffers
 * pointed to by dst are changed, the kvec elements are not changed.
 */
int scoutfs_kvec_memcpy(struct kvec *dst, struct kvec *src)
{
	int src_off = 0;
	int dst_off = 0;
	int copied = 0;
	int len;

	while (dst->iov_base && src->iov_base) {
		len = min(dst->iov_len - dst_off, src->iov_len - src_off);
		memcpy(dst->iov_base + dst_off, src->iov_base + src_off, len);

		copied += len;

		src_off += len;
		if (src_off == src->iov_len)
			src++;
		dst_off += len;
		if (dst_off == dst->iov_len)
			dst++;
	}

	return copied;
}

/*
 * Copy the src key vector into one new allocation in the dst.  The existing
 * dst is clobbered.  The source isn't changed.
 */
int scoutfs_kvec_dup_flatten(struct kvec *dst, struct kvec *src)
{
	void *ptr;
	size_t len = scoutfs_kvec_length(src);

	ptr = kmalloc(len, GFP_NOFS);
	if (!ptr)
		return -ENOMEM;

	scoutfs_kvec_init(dst, ptr, len);
	scoutfs_kvec_memcpy(dst, src);
	return 0;
}

/*
 * Free all the set pointers in the kvec.  The pointer values aren't modified
 * if they're freed.
 */
void scoutfs_kvec_kfree(struct kvec *kvec)
{
	while (kvec->iov_base)
		kfree((kvec++)->iov_base);
}
