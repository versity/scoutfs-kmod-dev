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

#include "key.h"
#include "format.h"

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

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
