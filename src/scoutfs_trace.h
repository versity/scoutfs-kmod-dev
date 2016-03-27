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


#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
