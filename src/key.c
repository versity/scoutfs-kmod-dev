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

/*
 * There are callers that work with a range of keys of a uniform length
 * who know that it's safe to increment their keys that aren't full
 * precision.  These are exceptional so a specific function variant
 * marks them.
 */
void scoutfs_key_inc_cur_len(struct scoutfs_key_buf *key)
{
	u8 *bytes = key->data;
	int i;

	for (i = key->key_len - 1; i >= 0; i--) {
		if (++bytes[i] != 0)
			break;
	}
}

void scoutfs_key_inc(struct scoutfs_key_buf *key)
{
	extend_zeros(key);
	scoutfs_key_inc_cur_len(key);
}

void scoutfs_key_dec_cur_len(struct scoutfs_key_buf *key)
{
	u8 *bytes = key->data;
	int i;

	for (i = key->key_len - 1; i >= 0; i--) {
		if (--bytes[i] != 255)
			break;
	}
}

void scoutfs_key_dec(struct scoutfs_key_buf *key)
{
	extend_zeros(key);
	scoutfs_key_dec_cur_len(key);
}

/* return the bytes of the string including the null term */
#define snprintf_null(buf, size, fmt, args...) \
	(snprintf((buf), (size), fmt, ##args) + 1)

/*
 * Write the null-terminated string that describes the key to the
 * buffer.  The bytes copied (including the null) is returned.  A null
 * buffer can be used to find the string size without writing anything.
 *
 * XXX nonprintable characters in the trace?
 */
int scoutfs_key_str_size(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_inode_key *ikey;
	u8 zone = 0;
	u8 type = 0;
	int len;

	if (key == NULL || key->data == NULL)
		return snprintf_null(buf, size, "[NULL]");

	if (key->key_len == 0)
		return snprintf_null(buf, size, "[0 len]");

	zone = *(u8 *)key->data;

	/* handle smaller and unknown zones, fall through to fs types */
	switch(zone) {
	case SCOUTFS_INODE_INDEX_ZONE: {
		struct scoutfs_inode_index_key *ikey = key->data;
		static char *type_strings[] = {
			[SCOUTFS_INODE_INDEX_SIZE_TYPE]		= "siz",
			[SCOUTFS_INODE_INDEX_META_SEQ_TYPE]	= "msq",
			[SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE]	= "dsq",
		};

		if (key->key_len < sizeof(struct scoutfs_inode_index_key))
			break;

		if (type_strings[ikey->type])
			return snprintf_null(buf, size, "iin.%s.%llu.%u.%llu",
					     type_strings[ikey->type],
					     be64_to_cpu(ikey->major),
					     be32_to_cpu(ikey->minor),
					     be64_to_cpu(ikey->ino));
		else
			return snprintf_null(buf, size, "[iin type %u?]",
					     ikey->type);
	}

	/* node zone keys start with zone, node, type */
	case SCOUTFS_NODE_ZONE: {
		struct scoutfs_free_extent_blkno_key *fkey = key->data;

		static char *type_strings[] = {
			[SCOUTFS_FREE_EXTENT_BLKNO_TYPE]	= "fno",
			[SCOUTFS_FREE_EXTENT_BLOCKS_TYPE]	= "fks",
		};

		switch(fkey->type) {
		case SCOUTFS_ORPHAN_TYPE: {
			struct scoutfs_orphan_key *okey = key->data;

			if (key->key_len < sizeof(struct scoutfs_orphan_key))
				break;
			return snprintf_null(buf, size, "nod.%llu.orp.%llu",
					     be64_to_cpu(okey->node_id),
					     be64_to_cpu(okey->ino));
		}

		case SCOUTFS_FREE_EXTENT_BLKNO_TYPE:
		case SCOUTFS_FREE_EXTENT_BLOCKS_TYPE:
			return snprintf_null(buf, size, "nod.%llu.%s.%llu.%llu",
					     be64_to_cpu(fkey->node_id),
					     type_strings[fkey->type],
					     be64_to_cpu(fkey->last_blkno),
					     be64_to_cpu(fkey->blocks));
		default:
			return snprintf_null(buf, size, "[nod type %u?]",
					     fkey->type);
		}
	}

	case SCOUTFS_FS_ZONE:
		break;

	default:
		return snprintf_null(buf, size, "[zone %u?]", zone);
	}

	/* everything in the fs tree starts with zone, ino, type */
	ikey = key->data;
	switch(ikey->type) {
	case SCOUTFS_INODE_TYPE: {
		struct scoutfs_inode_key *ikey = key->data;

		if (key->key_len < sizeof(struct scoutfs_inode_key))
			break;

		return snprintf_null(buf, size, "fs.%llu.ino",
				     be64_to_cpu(ikey->ino));
	}

	case SCOUTFS_XATTR_TYPE: {
		struct scoutfs_xattr_key *xkey = key->data;

		len = (int)key->key_len - offsetof(struct scoutfs_xattr_key,
						   name[1]);
		if (len <= 0)
			break;

		return snprintf_null(buf, size, "fs.%llu.xat.%.*s",
				     be64_to_cpu(xkey->ino), len, xkey->name);
	}

	case SCOUTFS_DIRENT_TYPE: {
		struct scoutfs_dirent_key *dkey = key->data;

		len = (int)key->key_len - sizeof(struct scoutfs_dirent_key);
		if (len <= 0)
			break;

		return snprintf_null(buf, size, "fs.%llu.dnt.%.*s",
				     be64_to_cpu(dkey->ino), len, dkey->name);
	}

	case SCOUTFS_READDIR_TYPE: {
		struct scoutfs_readdir_key *rkey = key->data;

		return snprintf_null(buf, size, "fs.%llu.rdr.%llu",
				     be64_to_cpu(rkey->ino),
				     be64_to_cpu(rkey->pos));
	}

	case SCOUTFS_LINK_BACKREF_TYPE: {
		struct scoutfs_link_backref_key *lkey = key->data;

		len = (int)key->key_len - sizeof(*lkey);
		if (len <= 0)
			break;

		return snprintf_null(buf, size, "fs.%llu.lbr.%llu.%.*s",
				     be64_to_cpu(lkey->ino),
				     be64_to_cpu(lkey->dir_ino), len,
				     lkey->name);
	}

	case SCOUTFS_SYMLINK_TYPE: {
		struct scoutfs_symlink_key *skey = key->data;

		return snprintf_null(buf, size, "fs.%llu.sym",
				     be64_to_cpu(skey->ino));
	}

	case SCOUTFS_FILE_EXTENT_TYPE: {
		struct scoutfs_file_extent_key *ekey = key->data;

		return snprintf_null(buf, size, "fs.%llu.ext.%llu.%llu.%llu.%x",
				     be64_to_cpu(ekey->ino),
				     be64_to_cpu(ekey->last_blk_off),
				     be64_to_cpu(ekey->last_blkno),
				     be64_to_cpu(ekey->blocks),
				     ekey->flags);
	}

	default:
		return snprintf_null(buf, size, "[fs type %u?]", type);
	}

	return snprintf_null(buf, size, "[fs type %u trunc len %u]",
			     type, key->key_len);
}

/*
 * A null buf can be set to find the length of the formatted string.
 */
int scoutfs_key_str(char *buf, struct scoutfs_key_buf *key)
{
	return scoutfs_key_str_size(buf, key, buf ? INT_MAX : 0);
}

#define MAX_STR_COUNT 10

struct key_strings {
	bool started;
	int next_str;
	char strings[MAX_STR_COUNT][SK_STR_BYTES];
};

static DEFINE_PER_CPU(struct key_strings, percpu_key_strings);

void scoutfs_key_start_percpu(void)
{
	struct key_strings *ks = this_cpu_ptr(&percpu_key_strings);

	BUG_ON(ks->started);
	ks->started = true;
	get_cpu();
}

char *scoutfs_key_percpu_string(void)
{
	struct key_strings *ks = this_cpu_ptr(&percpu_key_strings);
	char *str;

	BUG_ON(!ks->started);

	str = ks->strings[ks->next_str++];
	BUG_ON(ks->next_str >= MAX_STR_COUNT);

	return str;
}

void scoutfs_key_finish_percpu(void)
{
	struct key_strings *ks = this_cpu_ptr(&percpu_key_strings);

	BUG_ON(!ks->started);

	ks->next_str = 0;
	ks->started = false;

	put_cpu();
}
