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

TRACE_EVENT(scoutfs_bloom_hit,
	TP_PROTO(struct scoutfs_key *key),

	TP_ARGS(key),

	TP_STRUCT__entry(
		__field(__u64, inode)
		__field(__u8, type)
		__field(__u64, offset)
	),

	TP_fast_assign(
		__entry->inode = le64_to_cpu(key->inode);
		__entry->type = key->type;
		__entry->offset = le64_to_cpu(key->offset);
	),

	TP_printk("key %llu.%u.%llu",
		  __entry->inode, __entry->type, __entry->offset)
);

TRACE_EVENT(scoutfs_bloom_miss,
	TP_PROTO(struct scoutfs_key *key),

	TP_ARGS(key),

	TP_STRUCT__entry(
		__field(__u64, inode)
		__field(__u8, type)
		__field(__u64, offset)
	),

	TP_fast_assign(
		__entry->inode = le64_to_cpu(key->inode);
		__entry->type = key->type;
		__entry->offset = le64_to_cpu(key->offset);
	),

	TP_printk("key %llu.%u.%llu",
		  __entry->inode, __entry->type, __entry->offset)
);

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

TRACE_EVENT(scoutfs_dirty_super,
	TP_PROTO(struct scoutfs_super_block *super),

	TP_ARGS(super),

	TP_STRUCT__entry(
		__field(__u64, blkno)
		__field(__u64, seq)
	),

	TP_fast_assign(
		__entry->blkno = le64_to_cpu(super->hdr.blkno);
		__entry->seq = le64_to_cpu(super->hdr.seq);
	),

	TP_printk("blkno %llu seq %llu",
		__entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_write_super,
	TP_PROTO(struct scoutfs_super_block *super),

	TP_ARGS(super),

	TP_STRUCT__entry(
		__field(__u64, blkno)
		__field(__u64, seq)
	),

	TP_fast_assign(
		__entry->blkno = le64_to_cpu(super->hdr.blkno);
		__entry->seq = le64_to_cpu(super->hdr.seq);
	),

	TP_printk("blkno %llu seq %llu",
		__entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_insert_manifest,
	TP_PROTO(struct scoutfs_ring_manifest_entry *ment),

	TP_ARGS(ment),

	TP_STRUCT__entry(
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(__u8, level)
		__field(__u64, first_inode)
		__field(__u8, first_type)
		__field(__u64, first_offset)
		__field(__u64, last_inode)
		__field(__u8, last_type)
		__field(__u64, last_offset)
	),

	TP_fast_assign(
		__entry->blkno = le64_to_cpu(ment->blkno);
		__entry->seq = le64_to_cpu(ment->seq);
		__entry->level = ment->level;
		__entry->first_inode = le64_to_cpu(ment->first.inode);
		__entry->first_type = ment->first.type;
		__entry->first_offset = le64_to_cpu(ment->first.offset);
		__entry->last_inode = le64_to_cpu(ment->last.inode);
		__entry->last_type = ment->last.type;
		__entry->last_offset = le64_to_cpu(ment->last.offset);
	),

	TP_printk("blkno %llu seq %llu level %u first "CKF" last "CKF,
		__entry->blkno, __entry->seq, __entry->level,
		__entry->first_inode, __entry->first_type,
		__entry->first_offset, __entry->last_inode,
		__entry->last_type, __entry->last_offset)
);

TRACE_EVENT(scoutfs_delete_manifest,
	TP_PROTO(struct scoutfs_ring_manifest_entry *ment),

	TP_ARGS(ment),

	TP_STRUCT__entry(
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(__u8, level)
		__field(__u64, first_inode)
		__field(__u8, first_type)
		__field(__u64, first_offset)
		__field(__u64, last_inode)
		__field(__u8, last_type)
		__field(__u64, last_offset)
	),

	TP_fast_assign(
		__entry->blkno = le64_to_cpu(ment->blkno);
		__entry->seq = le64_to_cpu(ment->seq);
		__entry->level = ment->level;
		__entry->first_inode = le64_to_cpu(ment->first.inode);
		__entry->first_type = ment->first.type;
		__entry->first_offset = le64_to_cpu(ment->first.offset);
		__entry->last_inode = le64_to_cpu(ment->last.inode);
		__entry->last_type = ment->last.type;
		__entry->last_offset = le64_to_cpu(ment->last.offset);
	),

	TP_printk("blkno %llu seq %llu level %u first "CKF" last "CKF,
		__entry->blkno, __entry->seq, __entry->level,
		__entry->first_inode, __entry->first_type,
		__entry->first_offset, __entry->last_inode,
		__entry->last_type, __entry->last_offset)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
