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
#include <linux/in.h>
#include <linux/unaligned/access_ok.h>

#include "key.h"
#include "format.h"
#include "kvec.h"
#include "lock.h"
#include "seg.h"
#include "super.h"

#define FSID_ARG(sb)	le64_to_cpu(SCOUTFS_SB(sb)->super.hdr.fsid)
#define FSID_FMT	"%llx"

TRACE_EVENT(scoutfs_alloc_free,
	TP_PROTO(struct super_block *sb, __u64 segno, __u64 index, int nr,
		 int ret),

	TP_ARGS(sb, segno, index, nr, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, segno)
		__field(__u64, index)
		__field(int, nr)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
		__entry->index = index;
		__entry->nr = nr;
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" freeing segno %llu ind %llu nr %d ret %d",
		  __entry->fsid, __entry->segno, __entry->index, __entry->nr,
		  __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_segno,
	TP_PROTO(struct super_block *sb, __u64 segno, int ret),

	TP_ARGS(sb, segno, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, segno)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" segno %llu ret %d", __entry->fsid, __entry->segno,
		  __entry->ret)
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

DECLARE_EVENT_CLASS(scoutfs_manifest_class,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key_buf *first, struct scoutfs_key_buf *last),
        TP_ARGS(sb, level, segno, seq, first, last),
        TP_STRUCT__entry(
		__field(u8, level)
		__field(u64, segno)
		__field(u64, seq)
                __dynamic_array(char, first, scoutfs_key_str(NULL, first))
                __dynamic_array(char, last, scoutfs_key_str(NULL, last))
        ),
        TP_fast_assign(
		__entry->level = level;
		__entry->segno = segno;
		__entry->seq = seq;
		scoutfs_key_str(__get_dynamic_array(first), first);
		scoutfs_key_str(__get_dynamic_array(last), last);
        ),
        TP_printk("level %u segno %llu seq %llu first %s last %s",
		  __entry->level, __entry->segno, __entry->seq,
		  __get_str(first), __get_str(last))
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_manifest_add,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key_buf *first, struct scoutfs_key_buf *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_manifest_delete,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key_buf *first, struct scoutfs_key_buf *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_compact_input,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key_buf *first, struct scoutfs_key_buf *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_read_item_segment,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key_buf *first, struct scoutfs_key_buf *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DECLARE_EVENT_CLASS(scoutfs_key_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key),
        TP_ARGS(sb, key),
        TP_STRUCT__entry(
                __dynamic_array(char, key, scoutfs_key_str(NULL, key))
        ),
        TP_fast_assign(
		scoutfs_key_str(__get_dynamic_array(key), key);
        ),
        TP_printk("key %s", __get_str(key))
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_lookup,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key),
        TP_ARGS(sb, key)
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_insertion,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key),
        TP_ARGS(sb, key)
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_shrink,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key),
        TP_ARGS(sb, key)
);

DECLARE_EVENT_CLASS(scoutfs_range_class,
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

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_set_batch,
	TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *start,
		 struct scoutfs_key_buf *end),
        TP_ARGS(sb, start, end)
);

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_insert_batch,
	TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *start,
		 struct scoutfs_key_buf *end),
        TP_ARGS(sb, start, end)
);

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_shrink_range,
	TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *start,
		 struct scoutfs_key_buf *end),
        TP_ARGS(sb, start, end)
);

DEFINE_EVENT(scoutfs_range_class, scoutfs_read_items,
	TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *start,
		 struct scoutfs_key_buf *end),
        TP_ARGS(sb, start, end)
);

#define lock_mode(mode)			\
	__print_symbolic(mode,		\
		{ DLM_LOCK_IV,	"IV" },	\
		{ DLM_LOCK_NL,	"NL" },	\
		{ DLM_LOCK_CR,	"CR" },	\
		{ DLM_LOCK_CW,	"CW" },	\
		{ DLM_LOCK_PR,	"PR" },	\
		{ DLM_LOCK_PW,	"PW" },	\
		{ DLM_LOCK_EX,	"EX" })

DECLARE_EVENT_CLASS(scoutfs_lock_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
        TP_ARGS(sb, lck),
        TP_STRUCT__entry(
		__field(u8, name_scope)
		__field(u8, name_zone)
		__field(u8, name_type)
		__field(u64, name_first)
		__field(u64, name_second)
		__field(unsigned int, seq)
		__field(unsigned int, refcnt)
		__field(unsigned int, users)
	),
        TP_fast_assign(
		__entry->name_scope = lck->lock_name.scope;
		__entry->name_zone = lck->lock_name.zone;
		__entry->name_type = lck->lock_name.type;
		__entry->name_first = le64_to_cpu(lck->lock_name.first);
		__entry->name_second = le64_to_cpu(lck->lock_name.second);
		__entry->seq = lck->sequence;
		__entry->refcnt = lck->refcnt;
		__entry->users = lck->users;
        ),
        TP_printk("name %u.%u.%u.%llu.%llu seq %u refs %d users %d",
		  __entry->name_scope, __entry->name_zone, __entry->name_type,
		  __entry->name_first, __entry->name_second, __entry->seq,
		  __entry->refcnt, __entry->users)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_resource,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_unlock,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_ast,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_bast,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_reclaim,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, shrink_lock_tree,
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

DECLARE_EVENT_CLASS(scoutfs_seg_class,
        TP_PROTO(struct scoutfs_segment *seg),
        TP_ARGS(seg),
        TP_STRUCT__entry(
		__field(unsigned int, major)
		__field(unsigned int, minor)
		__field(struct scoutfs_segment *, seg)
		__field(int, refcount)
		__field(u64, segno)
		__field(unsigned long, flags)
		__field(int, err)
        ),
        TP_fast_assign(
		__entry->major = MAJOR(seg->sb->s_bdev->bd_dev);
		__entry->minor = MINOR(seg->sb->s_bdev->bd_dev);
		__entry->seg = seg;
		__entry->refcount = atomic_read(&seg->refcount);
		__entry->segno = seg->segno;
		__entry->flags = seg->flags;
		__entry->err = seg->err;
        ),
        TP_printk("dev %u:%u seg %p refcount %d segno %llu flags %lx err %d",
		  __entry->major, __entry->minor, __entry->seg, __entry->refcount,
		  __entry->segno, __entry->flags, __entry->err)
);

DEFINE_EVENT(scoutfs_seg_class, scoutfs_seg_alloc,
	TP_PROTO(struct scoutfs_segment *seg),
        TP_ARGS(seg)
);

DEFINE_EVENT(scoutfs_seg_class, scoutfs_seg_shrink,
	TP_PROTO(struct scoutfs_segment *seg),
        TP_ARGS(seg)
);

DEFINE_EVENT(scoutfs_seg_class, scoutfs_seg_free,
	TP_PROTO(struct scoutfs_segment *seg),
        TP_ARGS(seg)
);

DECLARE_EVENT_CLASS(scoutfs_net_class,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh),
        TP_STRUCT__entry(
		__field(unsigned int, major)
		__field(unsigned int, minor)
		__field(u32, name_addr)
		__field(u16, name_port)
		__field(u32, peer_addr)
		__field(u16, peer_port)
		__field(u64, id)
		__field(u8, type)
		__field(u8, status)
		__field(u16, data_len)
        ),
        TP_fast_assign(
		__entry->major = MAJOR(sb->s_bdev->bd_dev);
		__entry->minor = MINOR(sb->s_bdev->bd_dev);
		/* sparse can't handle this cpp nightmare */
		__entry->name_addr = (u32 __force)name->sin_addr.s_addr;
		__entry->name_port = be16_to_cpu(name->sin_port);
		__entry->peer_addr = (u32 __force)peer->sin_addr.s_addr;
		__entry->peer_port = be16_to_cpu(peer->sin_port);
		__entry->id = le64_to_cpu(nh->id);
		__entry->type = nh->type;
		__entry->status = nh->status;
		__entry->data_len = le16_to_cpu(nh->data_len);
        ),
        TP_printk("dev %u:%u %pI4:%u -> %pI4:%u id %llu type %u status %u data_len %u",
		  __entry->major, __entry->minor,
		  &__entry->name_addr, __entry->name_port,
		  &__entry->peer_addr, __entry->peer_port,
		  __entry->id, __entry->type, __entry->status,
		  __entry->data_len)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_client_send_request,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_server_recv_request,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_server_send_reply,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_client_recv_reply,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

TRACE_EVENT(scoutfs_item_next_range_check,
        TP_PROTO(struct super_block *sb, int cached,
		 struct scoutfs_key_buf *key, struct scoutfs_key_buf *pos,
		 struct scoutfs_key_buf *last, struct scoutfs_key_buf *end,
		 struct scoutfs_key_buf *range_end),
        TP_ARGS(sb, cached, key, pos, last, end, range_end),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(int, cached)
                __dynamic_array(char, key, scoutfs_key_str(NULL, key))
                __dynamic_array(char, pos, scoutfs_key_str(NULL, pos))
                __dynamic_array(char, last, scoutfs_key_str(NULL, last))
                __dynamic_array(char, end, scoutfs_key_str(NULL, end))
                __dynamic_array(char, range_end,
				scoutfs_key_str(NULL, range_end))
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->cached = cached;
		scoutfs_key_str(__get_dynamic_array(key), key);
		scoutfs_key_str(__get_dynamic_array(pos), pos);
		scoutfs_key_str(__get_dynamic_array(last), last);
		scoutfs_key_str(__get_dynamic_array(end), end);
		scoutfs_key_str(__get_dynamic_array(range_end), range_end);
        ),
        TP_printk("sb %p cached %d key %s pos %s last %s end %s range_end %s",
		  __entry->sb, __entry->cached, __get_str(key), __get_str(pos),
		  __get_str(last), __get_str(end), __get_str(range_end))
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
