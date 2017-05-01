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
#include "kvec.h"
#include "lock.h"

struct scoutfs_sb_info;

#define show_key_type(type)						       \
	__print_symbolic(type,						       \
		{ SCOUTFS_INODE_KEY,		"INODE" },		       \
		{ SCOUTFS_XATTR_KEY,		"XATTR" },		       \
		{ SCOUTFS_DIRENT_KEY,		"DIRENT" },		       \
		{ SCOUTFS_LINK_BACKREF_KEY,	"LINK_BACKREF"},	       \
		{ SCOUTFS_SYMLINK_KEY,		"SYMLINK" },		       \
		{ SCOUTFS_EXTENT_KEY,		"EXTENT" })

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

TRACE_EVENT(scoutfs_orphan_inode,
	TP_PROTO(struct super_block *sb, struct inode *inode),

	TP_ARGS(sb, inode),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = scoutfs_ino(inode);
	),

	TP_printk("dev %d,%d ino %llu", MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->ino)
);

TRACE_EVENT(delete_inode,
	TP_PROTO(struct super_block *sb, u64 ino, umode_t mode),

	TP_ARGS(sb, ino, mode),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
		__field(umode_t, mode)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = ino;
		__entry->mode = mode;
	),

	TP_printk("dev %d,%d ino %llu, mode 0x%x", MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->ino, __entry->mode)
);

TRACE_EVENT(scoutfs_scan_orphans,
	TP_PROTO(struct super_block *sb),

	TP_ARGS(sb),

	TP_STRUCT__entry(
		__field(dev_t, dev)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
	),

	TP_printk("dev %d,%d", MAJOR(__entry->dev), MINOR(__entry->dev))
);

TRACE_EVENT(scoutfs_manifest_add,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *first,
		 struct scoutfs_key_buf *last, u64 segno, u64 seq, u8 level),
        TP_ARGS(sb, first, last, segno, seq, level),
        TP_STRUCT__entry(
                __dynamic_array(char, first, scoutfs_key_str(NULL, first))
                __dynamic_array(char, last, scoutfs_key_str(NULL, last))
		__field(u64, segno)
		__field(u64, seq)
		__field(u8, level)
        ),
        TP_fast_assign(
		scoutfs_key_str(__get_dynamic_array(first), first);
		scoutfs_key_str(__get_dynamic_array(last), last);
		__entry->segno = segno;
		__entry->seq = seq;
		__entry->level = level;
        ),
        TP_printk("first %s last %s segno %llu seq %llu level %u",
		  __get_str(first), __get_str(last), __entry->segno,
		  __entry->seq, __entry->level)
);

TRACE_EVENT(scoutfs_item_lookup,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key,
		 struct kvec *val),
        TP_ARGS(sb, key, val),
        TP_STRUCT__entry(
                __dynamic_array(char, key, scoutfs_key_str(NULL, key))
        ),
        TP_fast_assign(
		scoutfs_key_str(__get_dynamic_array(key), key);
        ),
        TP_printk("key %s", __get_str(key))
);

TRACE_EVENT(scoutfs_item_insertion,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key,
		 struct kvec *val),
        TP_ARGS(sb, key, val),
        TP_STRUCT__entry(
                __dynamic_array(char, key, scoutfs_key_str(NULL, key))
        ),
        TP_fast_assign(
		scoutfs_key_str(__get_dynamic_array(key), key);
        ),
        TP_printk("key %s", __get_str(key))
);

TRACE_EVENT(scoutfs_item_insert_batch,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *start,
		 struct scoutfs_key_buf *end),
        TP_ARGS(sb, start, end),
        TP_STRUCT__entry(
                __dynamic_array(char, start, scoutfs_key_str(NULL, start))
                __dynamic_array(char, end, scoutfs_key_str(NULL, end))
        ),
        TP_fast_assign(
		scoutfs_key_str(__get_dynamic_array(start), start);
		scoutfs_key_str(__get_dynamic_array(end), end);
        ),
        TP_printk("start %s end %s", __get_str(start), __get_str(end))
);

#define lock_mode(mode)							\
	__print_symbolic(mode,						\
		{ SCOUTFS_LOCK_MODE_READ,	"READ" },		\
		{ SCOUTFS_LOCK_MODE_WRITE,	"WRITE" })

DECLARE_EVENT_CLASS(scoutfs_lock_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
        TP_ARGS(sb, lck),
        TP_STRUCT__entry(
		__field(int, mode)
                __dynamic_array(char, start, scoutfs_key_str(NULL, lck->start))
                __dynamic_array(char, end, scoutfs_key_str(NULL, lck->end))
        ),
        TP_fast_assign(
		__entry->mode = lck->mode;
		scoutfs_key_str(__get_dynamic_array(start), lck->start);
		scoutfs_key_str(__get_dynamic_array(end), lck->end);
        ),
        TP_printk("mode %s start %s end %s",
		  lock_mode(__entry->mode), __get_str(start), __get_str(end))
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_range,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_unlock_range,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

TRACE_EVENT(scoutfs_lock_invalidate_sb,
        TP_PROTO(struct super_block *sb, int mode,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, mode, start, end),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(int, mode)
                __dynamic_array(char, start, scoutfs_key_str(NULL, start))
                __dynamic_array(char, end, scoutfs_key_str(NULL, end))
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->mode = mode;
		scoutfs_key_str(__get_dynamic_array(start), start);
		scoutfs_key_str(__get_dynamic_array(end), end);
        ),
        TP_printk("sb %p mode %s start %s end %s",
		  __entry->sb, lock_mode(__entry->mode),
		  __get_str(start), __get_str(end))
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
