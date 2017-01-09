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
#include <linux/ctype.h>

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

struct iter {
	struct kvec *kvec;
	size_t count;
	size_t off;
	size_t i;
};

static void iter_advance(struct iter *iter, size_t len)
{
	iter->off += len;
	iter->count -= len;

	while (iter->i < SCOUTFS_KVEC_NR && iter->off >= iter->kvec->iov_len) {
		iter->off -= iter->kvec->iov_len;
		iter->kvec++;
		iter->i++;
	}
}

static void iter_init(struct iter *iter, struct kvec *kvec)
{
	iter->kvec = kvec;
	iter->i = 0;
	iter->off = 0;
	iter->count = scoutfs_kvec_length(kvec);

	iter_advance(iter, 0);
}

static void *iter_ptr(struct iter *iter)
{
	if (iter->i < SCOUTFS_KVEC_NR)
		return iter->kvec->iov_base + iter->off;
	else
		return NULL;
}

/* count of contiguous bytes available at the next vector */
static size_t iter_contig(struct iter *iter)
{
	if (iter->i < SCOUTFS_KVEC_NR)
		return iter->kvec->iov_len - iter->off;
	else
		return 0;
}

/* count of bytes remaining in the iteration */
static size_t iter_count(struct iter *iter)
{
	return iter->count;
}

/*
 * Return the result of memcmp between the min of the two total lengths.
 * If their shorter lengths are equal than the shorter length is considered
 * smaller than the longer.
 */
int scoutfs_kvec_memcmp(struct kvec *a, struct kvec *b)
{
	struct iter a_iter;
	struct iter b_iter;
	size_t len;
	int ret;

	iter_init(&a_iter, a);
	iter_init(&b_iter, b);

	while ((len = min(iter_contig(&a_iter), iter_contig(&b_iter)))) {
		ret = memcmp(iter_ptr(&a_iter), iter_ptr(&b_iter), len);
		if (ret)
			return ret;

		iter_advance(&a_iter, len);
		iter_advance(&b_iter, len);
	}

	return iter_contig(&a_iter) ? 1 : iter_contig(&b_iter) ? -1 : 0;
}

/*
 * Return -1 if [a,b] doesn't overlap with and is to the left of [c,d],
 * 1 if it doesn't overlap and is to the right of, and 0 if they
 * overlap.
 */
int scoutfs_kvec_cmp_overlap(struct kvec *a, struct kvec *b,
			     struct kvec *c, struct kvec *d)
{
	return scoutfs_kvec_memcmp(b, c) < 0 ? -1 :
	       scoutfs_kvec_memcmp(a, d) > 0 ? 1 : 0;
}

/*
 * Set just the pointers and length fields in the dst vector to point to
 * the source vector.
 */
void scoutfs_kvec_clone(struct kvec *dst, struct kvec *src)
{
	int i;

	for (i = 0; i < SCOUTFS_KVEC_NR; i++)
		dst[i] = src[i];
}

/*
 * Copy as much of src as fits in dst.  Null base pointers termintae the
 * copy.  The number of bytes copied is returned.  Only the buffers
 * pointed to by dst are changed, the kvec elements are not changed.
 */
int scoutfs_kvec_memcpy(struct kvec *dst, struct kvec *src)
{
	struct iter dst_iter;
	struct iter src_iter;
	size_t copied = 0;
	size_t len;

	iter_init(&dst_iter, dst);
	iter_init(&src_iter, src);

	while ((len = min(iter_contig(&dst_iter), iter_contig(&src_iter)))) {
		memcpy(iter_ptr(&dst_iter), iter_ptr(&src_iter), len);

		copied += len;
		iter_advance(&dst_iter, len);
		iter_advance(&src_iter, len);
	}

	return copied;
}

/*
 * Copy bytes in src into dst, stopping if dst is full.  The number of copied
 * bytes is returned and the lengths of dst are updated if the size changes.
 * The pointers in dst are not changed.
 */
int scoutfs_kvec_memcpy_truncate(struct kvec *dst, struct kvec *src)
{
	int copied = scoutfs_kvec_memcpy(dst, src);
	size_t bytes;
	int i;

	if (copied < scoutfs_kvec_length(dst)) {
		bytes = copied;
		for (i = 0; i < SCOUTFS_KVEC_NR; i++) {
			dst[i].iov_len = min(dst[i].iov_len, bytes);
			bytes -= dst[i].iov_len;
		}
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
	if (!ptr) {
		scoutfs_kvec_init_null(dst);
		return -ENOMEM;
	}

	scoutfs_kvec_init(dst, ptr, len);
	scoutfs_kvec_memcpy(dst, src);
	return 0;
}

/*
 * Free all the set pointers in the kvec.
 */
void scoutfs_kvec_kfree(struct kvec *kvec)
{
	int i;

	for (i = 0; i < SCOUTFS_KVEC_NR; i++) {
		kfree(kvec[i].iov_base);
		kvec[i].iov_base = NULL;
	}
}

void scoutfs_kvec_init_null(struct kvec *kvec)
{
	memset(kvec, 0, SCOUTFS_KVEC_BYTES);
}

void scoutfs_kvec_swap(struct kvec *a, struct kvec *b)
{
	SCOUTFS_DECLARE_KVEC(tmp);

	memcpy(tmp, a, SCOUTFS_KVEC_BYTES);
	memcpy(a, b, SCOUTFS_KVEC_BYTES);
	memcpy(b, tmp, SCOUTFS_KVEC_BYTES);
}

int scoutfs_kvec_alloc_key(struct kvec *kvec)
{
	const size_t len = SCOUTFS_MAX_KEY_SIZE;
	void *ptr;

	ptr = kzalloc(len, GFP_NOFS);
	if (!ptr) {
		scoutfs_kvec_init_null(kvec);
		return -ENOMEM;
	}

	scoutfs_kvec_init(kvec, ptr, len);
	return 0;
}

void scoutfs_kvec_init_key(struct kvec *kvec)
{
	scoutfs_kvec_init(kvec, kvec[0].iov_base, SCOUTFS_MAX_KEY_SIZE);
}

void scoutfs_kvec_set_max_key(struct kvec *kvec)
{
	__u8 *type = kvec[0].iov_base;

	*type = SCOUTFS_MAX_UNUSED_KEY;
	scoutfs_kvec_init(kvec, type, 1);
}

/*
 * Increase the kvec as though it is a big endian value.  Carry
 * increments of the least significant byte as long as it wraps.
 */
void scoutfs_kvec_be_inc(struct kvec *kvec)
{
	int i;
	int b;

	for (i = SCOUTFS_KVEC_NR - 1; i >= 0; i--) {
		for (b = (int)kvec[i].iov_len - 1; b >= 0; b--) {
			if (++((u8 *)kvec[i].iov_base)[b])
				return;
		}
	}
}

void scoutfs_kvec_be_dec(struct kvec *kvec)
{
	int i;
	int b;

	for (i = SCOUTFS_KVEC_NR - 1; i >= 0; i--) {
		for (b = (int)kvec[i].iov_len - 1; b >= 0; b--) {
			if (--((u8 *)kvec[i].iov_base)[b] != 0xff)
				return;
		}
	}
}

/*
 * Clone the source kvec into the dst if the dst is empty or if
 * the src kvec is less than the dst.
 */
void scoutfs_kvec_clone_less(struct kvec *dst, struct kvec *src)
{
	if (scoutfs_kvec_length(dst) == 0 ||
            scoutfs_kvec_memcmp(src, dst) < 0)
		scoutfs_kvec_clone(dst, src);
}

/*
 * Copy bytes from the kvec iterator into the dest buffer, zeroing the
 * remainder of the buffer if there aren't enough bytes available in
 * the iterator.  If the tail bool is set then the kvec data is copied
 * into the tail of the buffer and the head is zeroed.
 */
static bool iter_memcpy_zero(void *dst, struct iter *src, size_t len, bool tail)
{
	size_t ctg;
	size_t diff;

	if (len == 0 || iter_count(src) == 0)
		return false;

	if (iter_count(src) < len) {
		diff = len - iter_count(src);
		if (tail) {
			memset(dst, 0, diff);
			dst += diff;
		} else {
			memset(dst + len - diff, 0, diff);
		}
		len = iter_count(src);
	}

	while ((ctg = min(len, iter_contig(src)))) {
		memcpy(dst, iter_ptr(src), ctg);
		iter_advance(src, ctg);
		dst += ctg;
		len -= ctg;
	}

	return true;
}

static int iter_puts_printable(char *dst, struct iter *src)
{
	int len = iter_count(src);
	size_t ctg;
	int i;

	while ((ctg = iter_contig(src))) {
		memcpy(dst, iter_ptr(src), ctg);
		iter_advance(src, ctg);

		for (i = 0; i < ctg; i++) {
			if (!isprint(dst[i]))
				dst[i] = '_';
		}

		dst += ctg;
	}

	return len;
}

#define EMPTY_STR "''"
#define U64_U_BYTES 20
#define U64_D_BYTES 21
#define U64_X_BYTES 16

/*
 * XXX figure out what to do about corrupt keys.
 */

unsigned scoutfs_kvec_key_strlen(struct kvec *key)
{
	struct iter iter;
	unsigned len = 0;
	u8 type;

	iter_init(&iter, key);

	if (iter_count(&iter) == 0) {
		len = sizeof(EMPTY_STR) - 1;
		goto out;
	}

	iter_memcpy_zero(&type, &iter, sizeof(type), false);

	len = 4;  /* "typ." */

	switch(type) {
	case SCOUTFS_INODE_KEY:
		len += U64_U_BYTES;
		break;
	case SCOUTFS_DIRENT_KEY:
		len += U64_U_BYTES + (iter_count(&iter) - 8);
		break;
	case SCOUTFS_MAX_UNUSED_KEY:
		break;
	default:
		/* hex of everything after the type */
		len += (scoutfs_kvec_length(key) - 1) * 2;
		break;
	}

out:
	return len + 1; /* null term */
}

void scoutfs_kvec_key_sprintf(char *buf, struct kvec *key)
{
	struct iter iter;
	__be64 be;
	u8 type;

	iter_init(&iter, key);

	if (iter_contig(&iter) == 0) {
		buf += sprintf(buf, EMPTY_STR);
		goto done;
	}

	iter_memcpy_zero(&type, &iter, sizeof(type), false);

	switch(type) {
	case SCOUTFS_INODE_KEY:
		buf += sprintf(buf, "ino.");
		iter_memcpy_zero(&be, &iter, sizeof(be), false);
		buf += sprintf(buf, "%llu", be64_to_cpu(be));
		break;
	case SCOUTFS_DIRENT_KEY:
		buf += sprintf(buf, "den.");
		iter_memcpy_zero(&be, &iter, sizeof(be), false);
		buf += sprintf(buf, "%llu.", be64_to_cpu(be));
		buf += iter_puts_printable(buf, &iter);
		break;
	case SCOUTFS_MAX_UNUSED_KEY:
		buf += sprintf(buf, "max");
		break;
	default:
		buf += sprintf(buf, "unk.");
		while (iter_memcpy_zero(&be, &iter, sizeof(be), true))
			buf += sprintf(buf, "%llx", be64_to_cpu(be));
		break;
	}

done:
	*buf = '\0';
}
