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
/*
 * This has a crazy name because it's in an external module build at
 * the moment.  When it's merged upstream it'll move to
 * include/trace/events/scoutfs.h
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM scoutfs

#if !defined(_TRACE_SCOUTFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCOUTFS_H

#include <linux/tracepoint.h>
#include <linux/unaligned/access_ok.h>

#include "key.h"
#include "format.h"

struct scoutfs_sb_info;

#define show_key_type(type)						       \
	__print_symbolic(type,						       \
		{ SCOUTFS_INODE_KEY,		"INODE" },		       \
		{ SCOUTFS_XATTR_KEY,		"XATTR" },		       \
		{ SCOUTFS_XATTR_NAME_HASH_KEY,	"XATTR_NAME_HASH"},	       \
		{ SCOUTFS_XATTR_VAL_HASH_KEY,	"XATTR_VAL_HASH" },	       \
		{ SCOUTFS_DIRENT_KEY,		"DIRENT" },		       \
		{ SCOUTFS_LINK_BACKREF_KEY,	"LINK_BACKREF"},	       \
		{ SCOUTFS_SYMLINK_KEY,		"SYMLINK" },		       \
		{ SCOUTFS_BMAP_KEY,		"BMAP" })

#define	TRACE_KEYF	"%llu.%s.%llu"

TRACE_EVENT(scoutfs_write_begin,
	TP_PROTO(u64 ino, loff_t pos, unsigned len),

	TP_ARGS(ino, pos, len),

	TP_STRUCT__entry(
		__field(__u64, inode)
		__field(__u64, pos)
		__field(__u32, len)
	),

	TP_fast_assign(
		__entry->inode = ino;
		__entry->pos = pos;
		__entry->len = len;
	),

	TP_printk("ino %llu pos %llu len %u",
		  __entry->inode, __entry->pos, __entry->len)
);

TRACE_EVENT(scoutfs_write_end,
	TP_PROTO(u64 ino, loff_t pos, unsigned len, unsigned copied),

	TP_ARGS(ino, pos, len, copied),

	TP_STRUCT__entry(
		__field(__u64, inode)
		__field(__u64, pos)
		__field(__u32, len)
		__field(__u32, copied)
	),

	TP_fast_assign(
		__entry->inode = ino;
		__entry->pos = pos;
		__entry->len = len;
		__entry->copied = copied;
	),

	TP_printk("ino %llu pos %llu len %u",
		  __entry->inode, __entry->pos, __entry->len)
);

TRACE_EVENT(scoutfs_dirty_inode,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(__u64, ino)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->ino = scoutfs_ino(inode);
		__entry->size = inode->i_size;
	),

	TP_printk("ino %llu size %llu",
		__entry->ino, __entry->size)
);

TRACE_EVENT(scoutfs_update_inode,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(__u64, ino)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->ino = scoutfs_ino(inode);
		__entry->size = inode->i_size;
	),

	TP_printk("ino %llu size %llu",
		__entry->ino, __entry->size)
);

TRACE_EVENT(scoutfs_buddy_alloc,
	TP_PROTO(u64 blkno, int order, int region, int ret),

	TP_ARGS(blkno, order, region, ret),

	TP_STRUCT__entry(
		__field(u64, blkno)
		__field(int, order)
		__field(int, region)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->blkno = blkno;
		__entry->order = order;
		__entry->region = region;
		__entry->ret = ret;
	),

	TP_printk("blkno %llu order %d region %d ret %d",
		__entry->blkno, __entry->order, __entry->region, __entry->ret)
);


TRACE_EVENT(scoutfs_buddy_free,
	TP_PROTO(u64 blkno, int order, int region, int ret),

	TP_ARGS(blkno, order, region, ret),

	TP_STRUCT__entry(
		__field(u64, blkno)
		__field(int, order)
		__field(int, region)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->blkno = blkno;
		__entry->order = order;
		__entry->region = region;
		__entry->ret = ret;
	),

	TP_printk("blkno %llu order %d region %d ret %d",
		__entry->blkno, __entry->order, __entry->region, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_btree_op,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len),

	TP_STRUCT__entry(
		__field(	dev_t,	dev				)
		__field(	u64,	key_ino				)
		__field(	u64,	key_off				)
		__field(	u8,	key_type			)
		__field(	int,	val_len				)
	),

	TP_fast_assign(
		__entry->dev		= sb->s_dev;
		__entry->key_ino	= le64_to_cpu(key->inode);
		__entry->key_off	= le64_to_cpu(key->offset);
		__entry->key_type	= key->type;
		__entry->val_len	= len;
	),

	TP_printk("dev %d,%d key "TRACE_KEYF" size %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->key_ino, show_key_type(__entry->key_type),
		  __entry->key_off, __entry->val_len)
);

DEFINE_EVENT(scoutfs_btree_op, scoutfs_btree_lookup,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len)
);

DEFINE_EVENT(scoutfs_btree_op, scoutfs_btree_insert,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len)
);

DEFINE_EVENT(scoutfs_btree_op, scoutfs_btree_delete,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len)
);

DEFINE_EVENT(scoutfs_btree_op, scoutfs_btree_dirty,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len)
);

DEFINE_EVENT(scoutfs_btree_op, scoutfs_btree_update,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int len),

	TP_ARGS(sb, key, len)
);

DECLARE_EVENT_CLASS(scoutfs_btree_ranged_op,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *first,
		 struct scoutfs_key *last),

	TP_ARGS(sb, first, last),

	TP_STRUCT__entry(
		__field(	dev_t,	dev				)
		__field(	u64,	first_ino			)
		__field(	u64,	first_off			)
		__field(	u8,	first_type			)
		__field(	u64,	last_ino			)
		__field(	u64,	last_off			)
		__field(	u8,	last_type			)
	),

	TP_fast_assign(
		__entry->dev		= sb->s_dev;
		__entry->first_ino	= le64_to_cpu(first->inode);
		__entry->first_off	= le64_to_cpu(first->offset);
		__entry->first_type	= first->type;
		__entry->last_ino	= le64_to_cpu(last->inode);
		__entry->last_off	= le64_to_cpu(last->offset);
		__entry->last_type	= last->type;
	),

	TP_printk("dev %d,%d first key "TRACE_KEYF" last key "TRACE_KEYF,
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->first_ino,
		  show_key_type(__entry->first_type), __entry->first_off,
		  __entry->last_ino, show_key_type(__entry->last_type),
		  __entry->last_off)
);

DEFINE_EVENT(scoutfs_btree_ranged_op, scoutfs_btree_hole,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *first,
		 struct scoutfs_key *last),

	TP_ARGS(sb, first, last)
);

DEFINE_EVENT(scoutfs_btree_ranged_op, scoutfs_btree_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *first,
		 struct scoutfs_key *last),

	TP_ARGS(sb, first, last)
);

DEFINE_EVENT(scoutfs_btree_ranged_op, scoutfs_btree_since,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *first,
		 struct scoutfs_key *last),

	TP_ARGS(sb, first, last)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
