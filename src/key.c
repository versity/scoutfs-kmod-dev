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
 * Store a formatted string representing the key in the buffer.  The key
 * must be at least min_len to store the data needed by the format at
 * all.  fmt_len is the length of data that's used by the format.  These
 * are different because we have badly designed keys with variable
 * length data that isn't described by the key.  It's assumed from the
 * length of the key.  Take dirents -- they need to at least have a
 * dirent struct, but the name length is the rest of the key.
 *
 * (XXX And this goes horribly wrong when we pad out dirent keys to max
 * len to increment at high precision.  We'll never see these items used
 * by real fs code, but temporary keys and range endpoints can be full
 * precision and we can try and print them and get very confused.  We
 * need to rev the format to include explicit lengths.)
 *
 * If the format doesn't cover the entire key then we append more
 * formatting to represent the trailing bytes: runs of zeros compresesd
 * to _ and then hex output of non-zero bytes.
 */
static int __printf(6, 7) snprintf_key(char *buf, size_t size,
				       struct scoutfs_key_buf *key,
				       unsigned min_len, unsigned fmt_len,
				       const char *fmt, ...)

{
	va_list args;
	char *data;
	char *end;
	int left;
	int part;
	int ret;
	int nr;

	if (key->key_len < min_len)
		return snprintf_null(buf, size, "[trunc len %u < min %u]",
				     key->key_len, min_len);

	if (fmt_len == 0)
		fmt_len = min_len;

	va_start(args, fmt);
	ret = vsnprintf(buf, size, fmt, args);
	va_end(args);
	/* next formatting overwrites null */
	if (buf) {
		buf += ret;
		size -= min_t(int, size, ret);
	}

	data = key->data + fmt_len;
	left = key->key_len - fmt_len;

	while (left && (!buf || size > 1)) {
		/* compress runs of zero bytes to _ */
		end = memchr_inv(data, 0, left);
		nr = end ? end - data : left;
		if (nr) {
			if (buf) {
				*(buf++) = '_';
				size--;
			}
			ret++;
			data += nr;
			left -= nr;
			continue;
		}

		/*
		 * hex print non-zero bytes.  %ph is limited to 64 bytes
		 * and is buggy in that it still tries to print to buf
		 * past size.  (so buf = null, size = 0 crashes instead
		 * of printing the length of the formatted string.)
		 */
		end = memchr(data, 0, left);
		nr = end ? end - data : left;
		nr = min(nr, 64);

		if (buf)
			part = snprintf(buf, size, "%*phN", nr, data);
		else
			part = nr * 2;
		if (buf) {
			buf += part;
			size -= min_t(int, size, part);
		}
		ret += part;

		data += nr;
		left -= nr;
	}

	/* always store and include null */
	if (buf)
		*buf = '\0';
	return ret + 1;
}

typedef int (*key_printer_t)(char *buf, struct scoutfs_key_buf *key,
			     size_t size);

static int pr_ino_idx(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	static char *type_strings[] = {
		[SCOUTFS_INODE_INDEX_META_SEQ_TYPE]	= "msq",
		[SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE]	= "dsq",
	};
	struct scoutfs_inode_index_key *ikey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_inode_index_key), 0,
			    "iin.%s.%llu.%u.%llu",
			    type_strings[ikey->type], be64_to_cpu(ikey->major),
			    be32_to_cpu(ikey->minor), be64_to_cpu(ikey->ino));
}

static int pr_free_bits(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	static char *type_strings[] = {
		[SCOUTFS_FREE_BITS_SEGNO_TYPE]		= "fsg",
		[SCOUTFS_FREE_BITS_BLKNO_TYPE]		= "fbk",
	};
	struct scoutfs_free_bits_key *frk = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_block_mapping_key), 0,
			    "nod.%llu.%s.%llu",
			    be64_to_cpu(frk->node_id),
			    type_strings[frk->type],
			    be64_to_cpu(frk->base));
}

static int pr_orphan(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_orphan_key *okey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_orphan_key), 0,
			    "nod.%llu.orp.%llu",
			    be64_to_cpu(okey->node_id),
			    be64_to_cpu(okey->ino));
}

static int pr_inode(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_inode_key *ikey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_inode_key), 0,
			    "fs.%llu.ino",
			    be64_to_cpu(ikey->ino));
}

static int pr_xattr(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_xattr_key *xkey = key->data;
	int len = (int)key->key_len -
		  offsetof(struct scoutfs_xattr_key, name[1]);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_xattr_key), key->key_len,
			    "fs.%llu.xat.%.*s",
			    be64_to_cpu(xkey->ino), len, xkey->name);
}

static int pr_dirent(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_dirent_key *dkey = key->data;
	int len = (int)key->key_len - sizeof(struct scoutfs_dirent_key);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_dirent_key), key->key_len,
			    "fs.%llu.dnt.%.*s",
			    be64_to_cpu(dkey->ino), len, dkey->name);
}

static int pr_readdir(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_readdir_key *rkey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_readdir_key), 0,
			    "fs.%llu.rdr.%llu",
			    be64_to_cpu(rkey->ino), be64_to_cpu(rkey->pos));
}

static int pr_link_backref(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_link_backref_key *lkey = key->data;
	int len = (int)key->key_len - sizeof(*lkey);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_link_backref_key),
			    key->key_len,
			    "fs.%llu.lbr.%llu.%.*s",
			    be64_to_cpu(lkey->ino), be64_to_cpu(lkey->dir_ino),
			    len, lkey->name);
}

static int pr_symlink(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_symlink_key *skey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_symlink_key), 0,
			    "fs.%llu.sym",
			    be64_to_cpu(skey->ino));
}

static int pr_block_mapping(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_block_mapping_key *bmk = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_block_mapping_key), 0,
			    "fs.%llu.bmp.%llu",
			    be64_to_cpu(bmk->ino),
			    be64_to_cpu(bmk->base));
}

const static key_printer_t key_printers[SCOUTFS_MAX_ZONE][SCOUTFS_MAX_TYPE] = {
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_META_SEQ_TYPE] =
		pr_ino_idx,
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE] =
		pr_ino_idx,
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_BITS_SEGNO_TYPE] = pr_free_bits,
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_BITS_BLKNO_TYPE] = pr_free_bits,
	[SCOUTFS_NODE_ZONE][SCOUTFS_ORPHAN_TYPE] = pr_orphan,
	[SCOUTFS_FS_ZONE][SCOUTFS_INODE_TYPE] = pr_inode,
	[SCOUTFS_FS_ZONE][SCOUTFS_XATTR_TYPE] = pr_xattr,
	[SCOUTFS_FS_ZONE][SCOUTFS_DIRENT_TYPE] = pr_dirent,
	[SCOUTFS_FS_ZONE][SCOUTFS_READDIR_TYPE] = pr_readdir,
	[SCOUTFS_FS_ZONE][SCOUTFS_LINK_BACKREF_TYPE] = pr_link_backref,
	[SCOUTFS_FS_ZONE][SCOUTFS_SYMLINK_TYPE] = pr_symlink,
	[SCOUTFS_FS_ZONE][SCOUTFS_BLOCK_MAPPING_TYPE] = pr_block_mapping,
};

/*
 * Write the null-terminated string that describes the key to the
 * buffer.  The bytes copied (including the null) is returned.  A null
 * buffer can be used to find the string size without writing anything.
 *
 * XXX nonprintable characters in the trace?
 */
int scoutfs_key_str_size(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	u8 zone;
	u8 type;

	if (key == NULL || key->data == NULL)
		return snprintf_null(buf, size, "[NULL]");

	/* always at least zone, some id, and type */
	if (key->key_len < (1 + 8 + 1))
		return snprintf_null(buf, size, "[trunc len %u]", key->key_len);

	zone = *(u8 *)key->data;

	/*
	 * each zone's keys always start with the same fields that let
	 * us deref any key to get the type.  We chose a few representative
	 * keys from each zone to get the type.
	 */
	if (zone == SCOUTFS_INODE_INDEX_ZONE) {
		struct scoutfs_inode_index_key *ikey = key->data;
		type = ikey->type;
	} else if (zone == SCOUTFS_NODE_ZONE) {
		struct scoutfs_free_bits_key *fkey = key->data;
		type = fkey->type;
	} else if (zone == SCOUTFS_FS_ZONE) {
		struct scoutfs_inode_key *ikey = key->data;
		type = ikey->type;
	} else {
		type = 255;
	}

	if (zone > SCOUTFS_MAX_ZONE || type > SCOUTFS_MAX_TYPE ||
	    key_printers[zone][type] == NULL) {
		return snprintf_null(buf, size, "[unk zone %u type %u]",
				     zone, type);
	}

	return key_printers[zone][type](buf, key, size);
}

/*
 * Callers never have a pre-existing buffer whose size they need to be
 * careful for.  For a given static string they're first calling with a
 * null buf to find out the formatted length without storing anything.
 * Then they're called again with a buffer of that allocation size.  As
 * long as the formatting is consistent this pattern won't overflow.
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
