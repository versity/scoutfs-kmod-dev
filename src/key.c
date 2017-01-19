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

#include "key.h"

struct scoutfs_key_buf *scoutfs_key_alloc(struct super_block *sb, u16 len)
{
	struct scoutfs_key_buf *key;

	if (WARN_ON_ONCE(len > SCOUTFS_MAX_KEY_SIZE))
		return NULL;

	key = kmalloc(sizeof(struct scoutfs_key_buf) + len, GFP_NOFS);
	if (key) {
		key->data = key + 1;
		key->key_len = len;
		key->buf_len = len;
	}

	return key;
}

struct scoutfs_key_buf *scoutfs_key_dup(struct super_block *sb,
					struct scoutfs_key_buf *key)
{
	struct scoutfs_key_buf *dup;

	dup = scoutfs_key_alloc(sb, key->key_len);
	if (dup)
		memcpy(dup->data, key->data, dup->key_len);
	return dup;
}

void scoutfs_key_free(struct super_block *sb, struct scoutfs_key_buf *key)
{
	kfree(key);
}

/*
 * Keys are large multi-byte big-endian values.  To correctly increase
 * or decrease keys we need to start by extending the key to the full
 * precision using the max key size, setting the least significant bytes
 * to 0.
 */
static void extend_zeros(struct scoutfs_key_buf *key)
{
	if (key->key_len < SCOUTFS_MAX_KEY_SIZE &&
	    !WARN_ON_ONCE(key->buf_len != SCOUTFS_MAX_KEY_SIZE)) {
		memset(key->data + key->key_len, 0,
		       key->buf_len - key->key_len);
		key->key_len = key->buf_len;
	}
}

void scoutfs_key_inc(struct scoutfs_key_buf *key)
{
	u8 *bytes = key->data;
	int i;

	extend_zeros(key);

	for (i = key->key_len - 1; i >= 0; i--) {
		if (++bytes[i] != 0)
			break;
	}
}

void scoutfs_key_dec(struct scoutfs_key_buf *key)
{
	u8 *bytes = key->data;
	int i;

	extend_zeros(key);

	for (i = key->key_len - 1; i >= 0; i--) {
		if (--bytes[i] != 255)
			break;
	}
}
