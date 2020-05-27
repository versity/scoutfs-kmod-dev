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
#include "lock.h"
#include "super.h"
#include "ioctl.h"
#include "count.h"
#include "export.h"
#include "dir.h"
#include "server.h"
#include "net.h"
#include "data.h"

struct lock_info;

#define STE_FMT "[%llu %llu %llu 0x%x]"
#define STE_ARGS(te) (te)->iblock, (te)->count, (te)->blkno, (te)->flags
#define STE_FIELDS(pref)			\
	__field(__u64, pref##_iblock)		\
	__field(__u64, pref##_count)		\
	__field(__u64, pref##_blkno)		\
	__field(__u8, pref##_flags)
#define STE_ASSIGN(pref, te)			\
	__entry->pref##_iblock = (te)->iblock;	\
	__entry->pref##_count = (te)->count;	\
	__entry->pref##_blkno = (te)->blkno;	\
	__entry->pref##_flags = (te)->flags;
#define STE_ENTRY_ARGS(pref)			\
	__entry->pref##_iblock,			\
	__entry->pref##_count,			\
	__entry->pref##_blkno,			\
	__entry->pref##_flags

#define DECLARE_TRACED_EXTENT(name) \
	struct scoutfs_traced_extent name = {0}

DECLARE_EVENT_CLASS(scoutfs_ino_ret_class,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),

	TP_ARGS(sb, ino, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->ret)
);

TRACE_EVENT(scoutfs_setattr,
	TP_PROTO(struct dentry *dentry, struct iattr *attr),

	TP_ARGS(dentry, attr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, d_len)
		__string(d_name, dentry->d_name.name)
		__field(__u64, i_size)
		__field(__u64, ia_size)
		__field(unsigned int, ia_valid)
		__field(int, size_change)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(dentry->d_inode->i_sb);
		__entry->ino = scoutfs_ino(dentry->d_inode);
		__entry->d_len = dentry->d_name.len;
		__assign_str(d_name, dentry->d_name.name);
		__entry->ia_valid = attr->ia_valid;
		__entry->size_change = !!(attr->ia_valid & ATTR_SIZE);
		__entry->ia_size = attr->ia_size;
		__entry->i_size = i_size_read(dentry->d_inode);
	),

	TP_printk(SCSBF" %s ino %llu ia_valid 0x%x size change %d ia_size "
		  "%llu i_size %llu", SCSB_TRACE_ARGS, __get_str(d_name),
		  __entry->ino, __entry->ia_valid, __entry->size_change,
		  __entry->ia_size, __entry->i_size)
);

TRACE_EVENT(scoutfs_complete_truncate,
	TP_PROTO(struct inode *inode, __u32 flags),

	TP_ARGS(inode, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, i_size)
		__field(__u32, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(inode->i_sb);
		__entry->ino = scoutfs_ino(inode);
		__entry->i_size = i_size_read(inode);
		__entry->flags = flags;
	),

	TP_printk(SCSBF" ino %llu i_size %llu flags 0x%x",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->i_size,
		  __entry->flags)
);

TRACE_EVENT(scoutfs_data_fallocate,
	TP_PROTO(struct super_block *sb, u64 ino, int mode, loff_t offset,
		 loff_t len, int ret),

	TP_ARGS(sb, ino, mode, offset, len, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, mode)
		__field(__u64, offset)
		__field(__u64, len)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->mode = mode;
		__entry->offset = offset;
		__entry->len = len;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu mode 0x%x offset %llu len %llu ret %d",
		SCSB_TRACE_ARGS, __entry->ino, __entry->mode, __entry->offset,
		__entry->len, __entry->ret)
);

TRACE_EVENT(scoutfs_data_fiemap,
	TP_PROTO(struct super_block *sb, __u64 off, int i, __u64 blkno),


	TP_ARGS(sb, off, i, blkno),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, off)
		__field(int, i)
		__field(__u64, blkno)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->off = off;
		__entry->i = i;
		__entry->blkno = blkno;
	),

	TP_printk(SCSBF" blk_off %llu i %u blkno %llu", SCSB_TRACE_ARGS,
		  __entry->off, __entry->i, __entry->blkno)
);

TRACE_EVENT(scoutfs_get_block,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 iblock,
		 int create, struct scoutfs_traced_extent *te,
		 int ret, __u64 blkno, size_t size),

	TP_ARGS(sb, ino, iblock, create, te, ret, blkno, size),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, iblock)
		__field(int, create)
		STE_FIELDS(ext)
		__field(int, ret)
		__field(__u64, blkno)
		__field(size_t, size)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->iblock = iblock;
		__entry->create = create;
		STE_ASSIGN(ext, te)
		__entry->ret = ret;
		__entry->blkno = blkno;
		__entry->size = size;
	),

	TP_printk(SCSBF" ino %llu iblock %llu create %d ext "STE_FMT" ret %d bnr %llu size %zu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->iblock,
		  __entry->create, STE_ENTRY_ARGS(ext), __entry->ret,
		  __entry->blkno, __entry->size)
);

TRACE_EVENT(scoutfs_data_file_extent_class,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),

	TP_ARGS(sb, ino, te),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		STE_FIELDS(ext)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		STE_ASSIGN(ext, te)
	),

	TP_printk(SCSBF" ino %llu ext "STE_FMT,
		  SCSB_TRACE_ARGS, __entry->ino, STE_ENTRY_ARGS(ext))
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_alloc_block,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),
	TP_ARGS(sb, ino, te)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_convert_unwritten,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),
	TP_ARGS(sb, ino, te)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_prealloc_unwritten,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),
	TP_ARGS(sb, ino, te)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_extent_truncated,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),
	TP_ARGS(sb, ino, te)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_fiemap_extent,
	TP_PROTO(struct super_block *sb, __u64 ino,
		 struct scoutfs_traced_extent *te),
	TP_ARGS(sb, ino, te)
);

TRACE_EVENT(scoutfs_data_truncate_items,
	TP_PROTO(struct super_block *sb, __u64 iblock, __u64 last, int offline),

	TP_ARGS(sb, iblock, last, offline),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, iblock)
		__field(__u64, last)
		__field(int, offline)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->iblock = iblock;
		__entry->last = last;
		__entry->offline = offline;
	),

	TP_printk(SCSBF" iblock %llu last %llu offline %u", SCSB_TRACE_ARGS,
		  __entry->iblock, __entry->last, __entry->offline)
);

TRACE_EVENT(scoutfs_data_wait_check,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 pos, __u64 len,
		 __u8 sef, __u8 op, struct scoutfs_traced_extent *te, int ret),

	TP_ARGS(sb, ino, pos, len, sef, op, te, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, pos)
		__field(__u64, len)
		__field(__u8, sef)
		__field(__u8, op)
		STE_FIELDS(ext)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->pos = pos;
		__entry->len = len;
		__entry->sef = sef;
		__entry->op = op;
		STE_ASSIGN(ext, te)
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu pos %llu len %llu sef 0x%x op 0x%x ext "STE_FMT" ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->pos, __entry->len,
		  __entry->sef, __entry->op, STE_ENTRY_ARGS(ext), __entry->ret)
);

TRACE_EVENT(scoutfs_sync_fs,
	TP_PROTO(struct super_block *sb, int wait),

	TP_ARGS(sb, wait),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, wait)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->wait = wait;
	),

	TP_printk(SCSBF" wait %d", SCSB_TRACE_ARGS, __entry->wait)
);

TRACE_EVENT(scoutfs_trans_write_func,
	TP_PROTO(struct super_block *sb, unsigned long dirty),

	TP_ARGS(sb, dirty),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(unsigned long, dirty)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->dirty = dirty;
	),

	TP_printk(SCSBF" dirty %lu", SCSB_TRACE_ARGS, __entry->dirty)
);

TRACE_EVENT(scoutfs_release_trans,
	TP_PROTO(struct super_block *sb, void *rsv, unsigned int rsv_holders,
		 struct scoutfs_item_count *res,
		 struct scoutfs_item_count *act, unsigned int tri_holders,
		 unsigned int tri_writing, unsigned int tri_items,
		 unsigned int tri_vals),

	TP_ARGS(sb, rsv, rsv_holders, res, act, tri_holders, tri_writing,
		tri_items, tri_vals),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, rsv)
		__field(unsigned int, rsv_holders)
		__field(int, res_items)
		__field(int, res_vals)
		__field(int, act_items)
		__field(int, act_vals)
		__field(unsigned int, tri_holders)
		__field(unsigned int, tri_writing)
		__field(unsigned int, tri_items)
		__field(unsigned int, tri_vals)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->rsv = rsv;
		__entry->rsv_holders = rsv_holders;
		__entry->res_items = res->items;
		__entry->res_vals = res->vals;
		__entry->act_items = act->items;
		__entry->act_vals = act->vals;
		__entry->tri_holders = tri_holders;
		__entry->tri_writing = tri_writing;
		__entry->tri_items = tri_items;
		__entry->tri_vals = tri_vals;
	),

	TP_printk(SCSBF" rsv %p holders %u reserved %u.%u actual "
		  "%d.%d, trans holders %u writing %u reserved "
		  "%u.%u", SCSB_TRACE_ARGS, __entry->rsv, __entry->rsv_holders,
		  __entry->res_items, __entry->res_vals, __entry->act_items,
		  __entry->act_vals, __entry->tri_holders, __entry->tri_writing,
		  __entry->tri_items, __entry->tri_vals)
);

TRACE_EVENT(scoutfs_trans_acquired_hold,
	TP_PROTO(struct super_block *sb, const struct scoutfs_item_count *cnt,
		 void *rsv, unsigned int rsv_holders,
		 struct scoutfs_item_count *res,
		 struct scoutfs_item_count *act, unsigned int tri_holders,
		 unsigned int tri_writing, unsigned int tri_items,
		 unsigned int tri_vals),

	TP_ARGS(sb, cnt, rsv, rsv_holders, res, act, tri_holders, tri_writing,
		tri_items, tri_vals),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, cnt_items)
		__field(int, cnt_vals)
		__field(void *, rsv)
		__field(unsigned int, rsv_holders)
		__field(int, res_items)
		__field(int, res_vals)
		__field(int, act_items)
		__field(int, act_vals)
		__field(unsigned int, tri_holders)
		__field(unsigned int, tri_writing)
		__field(unsigned int, tri_items)
		__field(unsigned int, tri_vals)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->cnt_items = cnt->items;
		__entry->cnt_vals = cnt->vals;
		__entry->rsv = rsv;
		__entry->rsv_holders = rsv_holders;
		__entry->res_items = res->items;
		__entry->res_vals = res->vals;
		__entry->act_items = act->items;
		__entry->act_vals = act->vals;
		__entry->tri_holders = tri_holders;
		__entry->tri_writing = tri_writing;
		__entry->tri_items = tri_items;
		__entry->tri_vals = tri_vals;
	),

	TP_printk(SCSBF" cnt %u.%u, rsv %p holders %u reserved %u.%u "
		  "actual %d.%d, trans holders %u writing %u reserved "
		  "%u.%u", SCSB_TRACE_ARGS, __entry->cnt_items,
		  __entry->cnt_vals, __entry->rsv, __entry->rsv_holders,
		  __entry->res_items, __entry->res_vals, __entry->act_items,
		  __entry->act_vals, __entry->tri_holders, __entry->tri_writing,
		  __entry->tri_items, __entry->tri_vals)
);

TRACE_EVENT(scoutfs_trans_track_item,
	TP_PROTO(struct super_block *sb, int delta_items, int delta_vals,
		 int act_items, int act_vals, int res_items, int res_vals),

	TP_ARGS(sb, delta_items, delta_vals, act_items, act_vals, res_items,
		res_vals),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, delta_items)
		__field(int, delta_vals)
		__field(int, act_items)
		__field(int, act_vals)
		__field(int, res_items)
		__field(int, res_vals)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->delta_items = delta_items;
		__entry->delta_vals = delta_vals;
		__entry->act_items = act_items;
		__entry->act_vals = act_vals;
		__entry->res_items = res_items;
		__entry->res_vals = res_vals;
	),

	TP_printk(SCSBF" delta_items %d delta_vals %d act_items %d act_vals %d res_items %d res_vals %d",
		  SCSB_TRACE_ARGS, __entry->delta_items, __entry->delta_vals,
		  __entry->act_items, __entry->act_vals, __entry->res_items,
		  __entry->res_vals)
);

TRACE_EVENT(scoutfs_ioc_release,
	TP_PROTO(struct super_block *sb, u64 ino,
		 struct scoutfs_ioctl_release *args),

	TP_ARGS(sb, ino, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, block)
		__field(__u64, count)
		__field(__u64, vers)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->block = args->block;
		__entry->count = args->count;
		__entry->vers = args->data_version;
	),

	TP_printk(SCSBF" ino %llu block %llu count %llu vers %llu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->block,
		  __entry->count, __entry->vers)
);

DEFINE_EVENT(scoutfs_ino_ret_class, scoutfs_ioc_release_ret,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),
	TP_ARGS(sb, ino, ret)
);

TRACE_EVENT(scoutfs_ioc_stage,
	TP_PROTO(struct super_block *sb, u64 ino,
		 struct scoutfs_ioctl_stage *args),

	TP_ARGS(sb, ino, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, vers)
		__field(__u64, offset)
		__field(__s32, count)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->vers = args->data_version;
		__entry->offset = args->offset;
		__entry->count = args->count;
	),

	TP_printk(SCSBF" ino %llu vers %llu offset %llu count %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->vers,
		  __entry->offset, __entry->count)
);

TRACE_EVENT(scoutfs_ioc_data_wait_err,
	TP_PROTO(struct super_block *sb,
		 struct scoutfs_ioctl_data_wait_err *args),

	TP_ARGS(sb, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, vers)
		__field(__u64, offset)
		__field(__u64, count)
		__field(__u64, op)
		__field(__s64, err)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = args->ino;
		__entry->vers = args->data_version;
		__entry->offset = args->offset;
		__entry->count = args->count;
		__entry->op = args->op;
		__entry->err = args->err;
	),

	TP_printk(SCSBF" ino %llu vers %llu offset %llu count %llu op %llx err %lld",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->vers,
		  __entry->offset, __entry->count, __entry->op, __entry->err)
);

DEFINE_EVENT(scoutfs_ino_ret_class, scoutfs_ioc_stage_ret,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),
	TP_ARGS(sb, ino, ret)
);

TRACE_EVENT(scoutfs_ioc_walk_inodes,
	TP_PROTO(struct super_block *sb, struct scoutfs_ioctl_walk_inodes *walk),

	TP_ARGS(sb, walk),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, index)
		__field(__u64, first_major)
		__field(__u32, first_minor)
		__field(__u64, first_ino)
		__field(__u64, last_major)
		__field(__u32, last_minor)
		__field(__u64, last_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->index = walk->index;
		__entry->first_major = walk->first.major;
		__entry->first_minor = walk->first.minor;
		__entry->first_ino = walk->first.ino;
		__entry->last_major = walk->last.major;
		__entry->last_minor = walk->last.minor;
		__entry->last_ino = walk->last.ino;
	),

	TP_printk(SCSBF" index %u first %llu.%u.%llu last %llu.%u.%llu",
		  SCSB_TRACE_ARGS, __entry->index, __entry->first_major,
		  __entry->first_minor, __entry->first_ino, __entry->last_major,
		  __entry->last_minor, __entry->last_ino)
);

TRACE_EVENT(scoutfs_i_callback,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(struct inode *, inode)
	),

	TP_fast_assign(
		__entry->inode = inode;
	),

	/* don't print fsid as we may not have our sb private available */
	TP_printk("freeing inode %p", __entry->inode)
);

DECLARE_EVENT_CLASS(scoutfs_index_item_class,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),

	TP_ARGS(sb, type, major, minor, ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u8, type)
		__field(__u64, major)
		__field(__u32, minor)
		__field(__u64, ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->type = type;
		__entry->major = major;
		__entry->minor = minor;
		__entry->ino = ino;
	),

	TP_printk(SCSBF" type %u major %llu minor %u ino %llu",
		  SCSB_TRACE_ARGS, __entry->type, __entry->major,
		  __entry->minor, __entry->ino)
);

DEFINE_EVENT(scoutfs_index_item_class, scoutfs_create_index_item,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),
	TP_ARGS(sb, type, major, minor, ino)
);

DEFINE_EVENT(scoutfs_index_item_class, scoutfs_delete_index_item,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),
	TP_ARGS(sb, type, major, minor, ino)
);

TRACE_EVENT(scoutfs_alloc_ino,
	TP_PROTO(struct super_block *sb, int ret, __u64 ino, __u64 next_ino,
		 __u64 next_nr),

	TP_ARGS(sb, ret, ino, next_ino, next_nr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
		__field(__u64, ino)
		__field(__u64, next_ino)
		__field(__u64, next_nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
		__entry->ino = ino;
		__entry->next_ino = next_ino;
		__entry->next_nr = next_nr;
	),

	TP_printk(SCSBF" ret %d ino %llu next_ino %llu next_nr %llu",
		  SCSB_TRACE_ARGS, __entry->ret, __entry->ino,
		  __entry->next_ino, __entry->next_nr)
);

TRACE_EVENT(scoutfs_evict_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int is_bad_ino),

	TP_ARGS(sb, ino, nlink, is_bad_ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, is_bad_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->is_bad_ino = is_bad_ino;
	),

	TP_printk(SCSBF" ino %llu nlink %u bad %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->nlink, __entry->is_bad_ino)
);

TRACE_EVENT(scoutfs_drop_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int unhashed),

	TP_ARGS(sb, ino, nlink, unhashed),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, unhashed)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->unhashed = unhashed;
	),

	TP_printk(SCSBF" ino %llu nlink %u unhashed %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->nlink, __entry->unhashed)
);

TRACE_EVENT(scoutfs_inode_walk_writeback,
	TP_PROTO(struct super_block *sb, __u64 ino, int write, int ret),

	TP_ARGS(sb, ino, write, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, write)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->write = write;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu write %d ret %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->write, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_lock_info_class,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),

	TP_ARGS(sb, linfo),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(struct lock_info *, linfo)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->linfo = linfo;
	),

	TP_printk(SCSBF" linfo %p", SCSB_TRACE_ARGS, __entry->linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_setup,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_shutdown,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_destroy,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

TRACE_EVENT(scoutfs_xattr_set,
	TP_PROTO(struct super_block *sb, size_t name_len, const void *value,
		 size_t size, int flags),

	TP_ARGS(sb, name_len, value, size, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(size_t, name_len)
		__field(const void *, value)
		__field(size_t, size)
		__field(int, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->name_len = name_len;
		__entry->value = value;
		__entry->size = size;
		__entry->flags = flags;
	),

	TP_printk(SCSBF" name_len %zu value %p size %zu flags 0x%x",
		  SCSB_TRACE_ARGS, __entry->name_len, __entry->value,
		  __entry->size, __entry->flags)
);

TRACE_EVENT(scoutfs_advance_dirty_super,
	TP_PROTO(struct super_block *sb, __u64 seq),

	TP_ARGS(sb, seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->seq = seq;
	),

	TP_printk(SCSBF" super seq now %llu", SCSB_TRACE_ARGS, __entry->seq)
);

TRACE_EVENT(scoutfs_dir_add_next_linkref,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 dir_ino,
		 __u64 dir_pos, int ret, __u64 found_dir_ino,
		 __u64 found_dir_pos, unsigned int name_len),

	TP_ARGS(sb, ino, dir_ino, dir_pos, ret, found_dir_pos, found_dir_ino,
		name_len),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(__u64, dir_pos)
		__field(int, ret)
		__field(__u64, found_dir_ino)
		__field(__u64, found_dir_pos)
		__field(unsigned int, name_len)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->dir_ino = dir_ino;
		__entry->dir_pos = dir_pos;
		__entry->ret = ret;
		__entry->found_dir_ino = dir_ino;
		__entry->found_dir_pos = dir_pos;
		__entry->name_len = name_len;
	),

	TP_printk(SCSBF" ino %llu dir_ino %llu dir_pos %llu ret %d found_dir_ino %llu found_dir_pos %llu name_len %u",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->dir_pos,
		  __entry->dir_ino, __entry->ret, __entry->found_dir_pos,
		  __entry->found_dir_ino, __entry->name_len)
);

TRACE_EVENT(scoutfs_write_begin,
	TP_PROTO(struct super_block *sb, u64 ino, loff_t pos, unsigned len),

	TP_ARGS(sb, ino, pos, len),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, inode)
		__field(__u64, pos)
		__field(__u32, len)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->inode = ino;
		__entry->pos = pos;
		__entry->len = len;
	),

	TP_printk(SCSBF" ino %llu pos %llu len %u", SCSB_TRACE_ARGS,
		  __entry->inode, __entry->pos, __entry->len)
);

TRACE_EVENT(scoutfs_write_end,
	TP_PROTO(struct super_block *sb, u64 ino, unsigned long idx, u64 pos,
		 unsigned len, unsigned copied),

	TP_ARGS(sb, ino, idx, pos, len, copied),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned long, idx)
		__field(__u64, pos)
		__field(__u32, len)
		__field(__u32, copied)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->idx = idx;
		__entry->pos = pos;
		__entry->len = len;
		__entry->copied = copied;
	),

	TP_printk(SCSBF" ino %llu pgind %lu pos %llu len %u copied %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->idx, __entry->pos,
		  __entry->len, __entry->copied)
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

TRACE_EVENT(scoutfs_delete_inode,
	TP_PROTO(struct super_block *sb, u64 ino, umode_t mode, u64 size),

	TP_ARGS(sb, ino, mode, size),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
		__field(umode_t, mode)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = ino;
		__entry->mode = mode;
		__entry->size = size;
	),

	TP_printk("dev %d,%d ino %llu, mode 0x%x size %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->ino,
		  __entry->mode, __entry->size)
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

DECLARE_EVENT_CLASS(scoutfs_key_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
        ),
	TP_printk(SCSBF" key "SK_FMT, SCSB_TRACE_ARGS, sk_trace_args(key))
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_xattr_get_next_key,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

#define lock_mode(mode)						\
	__print_symbolic(mode,					\
		{ SCOUTFS_LOCK_NULL,		"NULL" },	\
		{ SCOUTFS_LOCK_READ,		"READ" },	\
		{ SCOUTFS_LOCK_WRITE,		"WRITE" },	\
		{ SCOUTFS_LOCK_WRITE_ONLY,	"WRITE_ONLY" })

DECLARE_EVENT_CLASS(scoutfs_lock_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
        TP_ARGS(sb, lck),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(start)
		sk_trace_define(end)
		__field(u64, refresh_gen)
		__field(unsigned char, request_pending)
		__field(unsigned char, invalidate_pending)
		__field(int, mode)
		__field(unsigned int, waiters_cw)
		__field(unsigned int, waiters_pr)
		__field(unsigned int, waiters_ex)
		__field(unsigned int, users_cw)
		__field(unsigned int, users_pr)
		__field(unsigned int, users_ex)
	),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(start, &lck->start);
		sk_trace_assign(end, &lck->end);
		__entry->refresh_gen = lck->refresh_gen;
		__entry->request_pending = lck->request_pending;
		__entry->invalidate_pending = lck->invalidate_pending;
		__entry->mode = lck->mode;
		__entry->waiters_pr = lck->waiters[SCOUTFS_LOCK_READ];
		__entry->waiters_ex = lck->waiters[SCOUTFS_LOCK_WRITE];
		__entry->waiters_cw = lck->waiters[SCOUTFS_LOCK_WRITE_ONLY];
		__entry->users_pr = lck->users[SCOUTFS_LOCK_READ];
		__entry->users_ex = lck->users[SCOUTFS_LOCK_WRITE];
		__entry->users_cw = lck->users[SCOUTFS_LOCK_WRITE_ONLY];
        ),
        TP_printk(SCSBF" start "SK_FMT" end "SK_FMT" mode %u reqpnd %u invpnd %u rfrgen %llu waiters: pr %u ex %u cw %u users: pr %u ex %u cw %u",
		  SCSB_TRACE_ARGS, sk_trace_args(start), sk_trace_args(end),
		  __entry->mode, __entry->request_pending,
		  __entry->invalidate_pending, __entry->refresh_gen,
		  __entry->waiters_pr, __entry->waiters_ex, __entry->waiters_cw,
		  __entry->users_pr, __entry->users_ex, __entry->users_cw)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_free,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_alloc,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_grant_response,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_granted,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate_request,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidated,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_locked,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_wait,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_unlock,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_shrink,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DECLARE_EVENT_CLASS(scoutfs_net_class,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		si4_trace_define(name)
		si4_trace_define(peer)
		snh_trace_define(nh)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		si4_trace_assign(name, name);
		si4_trace_assign(peer, peer);
		snh_trace_assign(nh, nh);
        ),
        TP_printk(SCSBF" name "SI4_FMT" peer "SI4_FMT" nh "SNH_FMT,
		  SCSB_TRACE_ARGS, si4_trace_args(name), si4_trace_args(peer),
		  snh_trace_args(nh))
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_net_send_message,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_net_recv_message,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

#define conn_flag_entry(which) \
	CONN_FL_##which, __stringify(which)

#define print_conn_flags(flags) __print_flags(flags, "|",	\
	{ conn_flag_entry(valid_greeting) },			\
	{ conn_flag_entry(established) },			\
	{ conn_flag_entry(shutting_down) },			\
	{ conn_flag_entry(saw_greeting) },			\
	{ conn_flag_entry(saw_farewell) },			\
	{ conn_flag_entry(reconn_wait) },			\
	{ conn_flag_entry(reconn_freeing) })

/*
 * This is called from alloc and free when the caller only has safe
 * access to the struct itself, be very careful not to follow any
 * indirection out of the storage for the conn struct.
 */
DECLARE_EVENT_CLASS(scoutfs_net_conn_class,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn),

        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(unsigned long, flags)
		__field(unsigned long, reconn_deadline)
		__field(unsigned long, connect_timeout_ms)
		__field(void *, sock)
		__field(__u64, c_rid)
		__field(__u64, greeting_id)
		si4_trace_define(sockname)
		si4_trace_define(peername)
		__field(unsigned char, e_accepted_head)
		__field(void *, listening_conn)
		__field(unsigned char, e_accepted_list)
		__field(__u64, next_send_seq)
		__field(__u64, next_send_id)
		__field(unsigned char, e_send_queue)
		__field(unsigned char, e_resend_queue)
		__field(__u64, recv_seq)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(conn->sb);
		__entry->flags = conn->flags;
		__entry->reconn_deadline = conn->reconn_deadline;
		__entry->connect_timeout_ms = conn->connect_timeout_ms;
		__entry->sock = conn->sock;
		__entry->c_rid = conn->rid;
		__entry->greeting_id = conn->greeting_id;
		si4_trace_assign(sockname, &conn->sockname);
		si4_trace_assign(peername, &conn->peername);
		__entry->e_accepted_head = !!list_empty(&conn->accepted_head);
		__entry->listening_conn = conn->listening_conn;
		__entry->e_accepted_list = !!list_empty(&conn->accepted_list);
		__entry->next_send_seq = conn->next_send_seq;
		__entry->next_send_id = conn->next_send_id;
		__entry->e_send_queue = !!list_empty(&conn->send_queue);
		__entry->e_resend_queue = !!list_empty(&conn->resend_queue);
		__entry->recv_seq = atomic64_read(&conn->recv_seq);
        ),
        TP_printk(SCSBF" flags %s rc_dl %lu cto %lu sk %p rid %llu grid %llu sn "SI4_FMT" pn "SI4_FMT" eah %u lc %p eal %u nss %llu nsi %llu esq %u erq %u rs %llu",
		  SCSB_TRACE_ARGS,
		  print_conn_flags(__entry->flags),
		  __entry->reconn_deadline,
		  __entry->connect_timeout_ms,
		  __entry->sock,
		  __entry->c_rid,
		  __entry->greeting_id,
		  si4_trace_args(sockname),
		  si4_trace_args(peername),
		  __entry->e_accepted_head,
		  __entry->listening_conn,
		  __entry->e_accepted_list,
		  __entry->next_send_seq,
		  __entry->next_send_id,
		  __entry->e_send_queue,
		  __entry->e_resend_queue,
		  __entry->recv_seq)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_alloc,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_result,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_complete,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_accept,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_reconn_migrate,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_queued,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_complete,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_destroy_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_destroy_free,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);

DECLARE_EVENT_CLASS(scoutfs_work_class,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, data)
		__field(int, ret)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->data = data;
		__entry->ret = ret;
        ),
	TP_printk(SCSBF" data %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->data, __entry->ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_commit_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_commit_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_proc_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_proc_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_listen_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_listen_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_connect_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_connect_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_shutdown_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_shutdown_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_destroy_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_destroy_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_reconn_free_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_reconn_free_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_send_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_send_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_recv_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_recv_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_workqueue_destroy,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_data_return_server_extents_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_data_return_server_extents_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);

DECLARE_EVENT_CLASS(scoutfs_shrink_exit_class,
        TP_PROTO(struct super_block *sb, unsigned long nr_to_scan, int ret),
        TP_ARGS(sb, nr_to_scan, ret),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(unsigned long, nr_to_scan)
		__field(int, ret)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->nr_to_scan = nr_to_scan;
		__entry->ret = ret;
        ),
        TP_printk("sb %p nr_to_scan %lu ret %d",
		  __entry->sb, __entry->nr_to_scan, __entry->ret)
);

DEFINE_EVENT(scoutfs_shrink_exit_class, scoutfs_lock_shrink_exit,
        TP_PROTO(struct super_block *sb, unsigned long nr_to_scan, int ret),
        TP_ARGS(sb, nr_to_scan, ret)
);

TRACE_EVENT(scoutfs_rename,
	TP_PROTO(struct super_block *sb, struct inode *old_dir,
		 struct dentry *old_dentry, struct inode *new_dir,
		 struct dentry *new_dentry),

	TP_ARGS(sb, old_dir, old_dentry, new_dir, new_dentry),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, old_dir_ino)
		__string(old_name, old_dentry->d_name.name)
		__field(__u64, new_dir_ino)
		__string(new_name, new_dentry->d_name.name)
		__field(__u64, new_inode_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->old_dir_ino = scoutfs_ino(old_dir);
		__assign_str(old_name, old_dentry->d_name.name)
		__entry->new_dir_ino = scoutfs_ino(new_dir);
		__assign_str(new_name, new_dentry->d_name.name)
		__entry->new_inode_ino = new_dentry->d_inode ?
					 scoutfs_ino(new_dentry->d_inode) : 0;
	),

	TP_printk(SCSBF" old_dir_ino %llu old_name %s new_dir_ino %llu new_name %s new_inode_ino %llu",
		  SCSB_TRACE_ARGS, __entry->old_dir_ino, __get_str(old_name),
		  __entry->new_dir_ino, __get_str(new_name),
		  __entry->new_inode_ino)
);

TRACE_EVENT(scoutfs_d_revalidate,
	TP_PROTO(struct super_block *sb,
		 struct dentry *dentry, int flags, struct dentry *parent,
		 bool is_covered, int ret),

	TP_ARGS(sb, dentry, flags, parent, is_covered, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__string(name, dentry->d_name.name)
		__field(__u64, ino)
		__field(__u64, parent_ino)
		__field(int, flags)
		__field(int, is_root)
		__field(int, is_covered)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__assign_str(name, dentry->d_name.name)
		__entry->ino = dentry->d_inode ?
			       scoutfs_ino(dentry->d_inode) : 0;
		__entry->parent_ino = parent->d_inode ?
			       scoutfs_ino(parent->d_inode) : 0;
		__entry->flags = flags;
		__entry->is_root = IS_ROOT(dentry);
		__entry->is_covered = is_covered;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" name %s ino %llu parent_ino %llu flags 0x%x s_root %u is_covered %u ret %d",
		  SCSB_TRACE_ARGS, __get_str(name), __entry->ino,
		  __entry->parent_ino, __entry->flags,
		  __entry->is_root,
		  __entry->is_covered,
		  __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_super_lifecycle_class,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, sb)
		__field(void *, sbi)
		__field(void *, s_root)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->sb = sb;
		__entry->sbi = SCOUTFS_SB(sb);
		__entry->s_root = sb->s_root;
        ),
	TP_printk(SCSBF" sb %p sbi %p s_root %p",
		  SCSB_TRACE_ARGS, __entry->sb, __entry->sbi, __entry->s_root)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_fill_super,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_put_super,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_kill_sb,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DECLARE_EVENT_CLASS(scoutfs_fileid_class,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, fh_type)
		__field(u64, ino)
		__field(u64, parent_ino)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->fh_type = fh_type;
		__entry->ino = le64_to_cpu(fid->ino);
		__entry->parent_ino = fh_type == FILEID_SCOUTFS_WITH_PARENT ?
				le64_to_cpu(fid->parent_ino) : 0ULL;
	),
	TP_printk(SCSBF" type %d ino %llu parent %llu",
		  SCSB_TRACE_ARGS, __entry->fh_type, __entry->ino,
		  __entry->parent_ino)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_encode_fh,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_fh_to_dentry,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_fh_to_parent,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

TRACE_EVENT(scoutfs_get_parent,
	TP_PROTO(struct super_block *sb, struct inode *inode, u64 parent),

	TP_ARGS(sb, inode, parent),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, parent)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = scoutfs_ino(inode);
		__entry->parent = parent;
	),

	TP_printk(SCSBF" child %llu parent %llu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->parent)
);

TRACE_EVENT(scoutfs_get_name,
	TP_PROTO(struct super_block *sb, struct inode *parent,
		 struct inode *child, char *name),

	TP_ARGS(sb, parent, child, name),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, parent_ino)
		__field(__u64, child_ino)
		__string(name, name)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->parent_ino = scoutfs_ino(parent);
		__entry->child_ino = scoutfs_ino(child);
		__assign_str(name, name);
	),

	TP_printk(SCSBF" parent %llu child %llu name: %s",
		  SCSB_TRACE_ARGS, __entry->parent_ino, __entry->child_ino,
		  __get_str(name))
);

TRACE_EVENT(scoutfs_btree_read_error,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_ref *ref),

	TP_ARGS(sb, ref),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = le64_to_cpu(ref->blkno);
		__entry->seq = le64_to_cpu(ref->seq);
	),

	TP_printk(SCSBF" blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_btree_dirty_block,
	TP_PROTO(struct super_block *sb, u64 blkno, u64 seq,
		 u64 bt_blkno, u64 bt_seq),

	TP_ARGS(sb, blkno, seq, bt_blkno, bt_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(__u64, bt_blkno)
		__field(__u64, bt_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->seq = seq;
		__entry->bt_blkno = bt_blkno;
		__entry->bt_seq = bt_seq;
	),

	TP_printk(SCSBF" blkno %llu seq %llu bt_blkno %llu bt_seq %llu",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->seq,
		  __entry->bt_blkno, __entry->bt_seq)
);

TRACE_EVENT(scoutfs_btree_walk,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 struct scoutfs_key *key, int flags, int level,
		 struct scoutfs_btree_ref *ref),

	TP_ARGS(sb, root, key, flags, level, ref),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(key)
		__field(int, flags)
		__field(int, level)
		__field(__u64, ref_blkno)
		__field(__u64, ref_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(key, key);
		__entry->flags = flags;
		__entry->level = level;
		__entry->ref_blkno = le64_to_cpu(ref->blkno);
		__entry->ref_seq = le64_to_cpu(ref->seq);
	),

	TP_printk(SCSBF" root blkno %llu seq %llu height %u key "SK_FMT" flags 0x%x level %d ref blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->root_seq,
		  __entry->root_height, sk_trace_args(key), __entry->flags,
		  __entry->level, __entry->ref_blkno, __entry->ref_seq)
);

TRACE_EVENT(scoutfs_online_offline_blocks,
	TP_PROTO(struct inode *inode, s64 on_delta, s64 off_delta,
		 u64 on_now, u64 off_now),

	TP_ARGS(inode, on_delta, off_delta, on_now, off_now),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, on_delta)
		__field(__s64, off_delta)
		__field(__u64, on_now)
		__field(__u64, off_now)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(inode->i_sb);
		__entry->on_delta = on_delta;
		__entry->off_delta = off_delta;
		__entry->on_now = on_now;
		__entry->off_now = off_now;
	),

	TP_printk(SCSBF" on_delta %lld off_delta %lld on_now %llu off_now %llu ",
		  SCSB_TRACE_ARGS, __entry->on_delta, __entry->off_delta,
		  __entry->on_now, __entry->off_now)
);

DECLARE_EVENT_CLASS(scoutfs_server_client_count_class,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),

	TP_ARGS(sb, rid, nr_clients),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, c_rid)
		__field(unsigned long, nr_clients)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->c_rid = rid;
		__entry->nr_clients = nr_clients;
	),

	TP_printk(SCSBF" rid %016llx nr_clients %lu",
		  SCSB_TRACE_ARGS, __entry->c_rid, __entry->nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_up,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),
	TP_ARGS(sb, rid, nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_down,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),
	TP_ARGS(sb, rid, nr_clients)
);

#define slt_symbolic(mode)						\
	__print_symbolic(mode,					\
		{ SLT_CLIENT,		"client" },	\
		{ SLT_SERVER,		"server" },	\
		{ SLT_GRANT,		"grant" },	\
		{ SLT_INVALIDATE,	"invalidate" },	\
		{ SLT_REQUEST,		"request" },	\
		{ SLT_RESPONSE,		"response" })

TRACE_EVENT(scoutfs_lock_message,
	TP_PROTO(struct super_block *sb, int who, int what, int dir,
		 u64 rid, u64 net_id, struct scoutfs_net_lock *nl),

	TP_ARGS(sb, who, what, dir, rid, net_id, nl),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, who)
		__field(int, what)
		__field(int, dir)
		__field(__u64, m_rid)
		__field(__u64, net_id)
		sk_trace_define(key)
		__field(__u8, old_mode)
		__field(__u8, new_mode)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->who = who;
		__entry->what = what;
		__entry->dir = dir;
		__entry->m_rid = rid;
		__entry->net_id = net_id;
		sk_trace_assign(key, &nl->key);
		__entry->old_mode = nl->old_mode;
		__entry->new_mode = nl->new_mode;
	),

	TP_printk(SCSBF" %s %s %s rid %016llx net_id %llu key "SK_FMT" old_mode %u new_mode %u",
		  SCSB_TRACE_ARGS, slt_symbolic(__entry->who),
		  slt_symbolic(__entry->what), slt_symbolic(__entry->dir),
		  __entry->m_rid, __entry->net_id, sk_trace_args(key),
		  __entry->old_mode, __entry->new_mode)
);


TRACE_EVENT(scoutfs_quorum_election,
	TP_PROTO(struct super_block *sb, u64 prev_term),

	TP_ARGS(sb, prev_term),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, prev_term)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->prev_term = prev_term;
	),

	TP_printk(SCSBF" prev_term %llu",
		  SCSB_TRACE_ARGS, __entry->prev_term)
);

TRACE_EVENT(scoutfs_quorum_election_ret,
	TP_PROTO(struct super_block *sb, int ret, u64 elected_term),

	TP_ARGS(sb, ret, elected_term),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
		__field(__u64, elected_term)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
		__entry->elected_term = elected_term;
	),

	TP_printk(SCSBF" ret %d elected_term %llu",
		  SCSB_TRACE_ARGS, __entry->ret, __entry->elected_term)
);

TRACE_EVENT(scoutfs_quorum_election_vote,
	TP_PROTO(struct super_block *sb, int role, u64 term, u64 vote_for_rid,
		 int votes, int log_cycles, int quorum_count),

	TP_ARGS(sb, role, term, vote_for_rid, votes, log_cycles, quorum_count),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, role)
		__field(__u64, term)
		__field(__u64, vote_for_rid)
		__field(int, votes)
		__field(int, log_cycles)
		__field(int, quorum_count)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->role = role;
		__entry->term = term;
		__entry->vote_for_rid = vote_for_rid;
		__entry->votes = votes;
		__entry->log_cycles = log_cycles;
		__entry->quorum_count = quorum_count;
	),

	TP_printk(SCSBF" role %d term %llu vote_for_rid %016llx votes %d log_cycles %d quorum_count %d",
		  SCSB_TRACE_ARGS, __entry->role, __entry->term,
		  __entry->vote_for_rid, __entry->votes, __entry->log_cycles,
		  __entry->quorum_count)
);

DECLARE_EVENT_CLASS(scoutfs_quorum_block_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_quorum_block *blk),

	TP_ARGS(sb, blk),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, term)
		__field(__u64, write_nr)
		__field(__u64, voter_rid)
		__field(__u64, vote_for_rid)
		__field(__u32, crc)
		__field(__u8, log_nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = le64_to_cpu(blk->blkno);
		__entry->term = le64_to_cpu(blk->term);
		__entry->write_nr = le64_to_cpu(blk->write_nr);
		__entry->voter_rid = le64_to_cpu(blk->voter_rid);
		__entry->vote_for_rid = le64_to_cpu(blk->vote_for_rid);
		__entry->crc = le32_to_cpu(blk->crc);
		__entry->log_nr = blk->log_nr;
	),

	TP_printk(SCSBF" blkno %llu term %llu write_nr %llu voter_rid %016llx vote_for_rid %016llx crc 0x%08x log_nr %u",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->term,
		  __entry->write_nr, __entry->voter_rid, __entry->vote_for_rid,
		  __entry->crc, __entry->log_nr)
);
DEFINE_EVENT(scoutfs_quorum_block_class, scoutfs_quorum_read_block,
	TP_PROTO(struct super_block *sb, struct scoutfs_quorum_block *blk),
	TP_ARGS(sb, blk)
);
DEFINE_EVENT(scoutfs_quorum_block_class, scoutfs_quorum_write_block,
	TP_PROTO(struct super_block *sb, struct scoutfs_quorum_block *blk),
	TP_ARGS(sb, blk)
);

/*
 * We can emit trace events to make it easier to synchronize the
 * monotonic clocks in trace logs between nodes.  By looking at the send
 * and recv times of many messages flowing between nodes we can get
 * surprisingly good estimates of the clock offset between them.
 */
DECLARE_EVENT_CLASS(scoutfs_clock_sync_class,
	TP_PROTO(__le64 clock_sync_id),
	TP_ARGS(clock_sync_id),
	TP_STRUCT__entry(
		__field(__u64, clock_sync_id)
	),
	TP_fast_assign(
		__entry->clock_sync_id = le64_to_cpu(clock_sync_id);
	),
	TP_printk("clock_sync_id %016llx", __entry->clock_sync_id)
);
DEFINE_EVENT(scoutfs_clock_sync_class, scoutfs_send_clock_sync,
	TP_PROTO(__le64 clock_sync_id),
	TP_ARGS(clock_sync_id)
);
DEFINE_EVENT(scoutfs_clock_sync_class, scoutfs_recv_clock_sync,
	TP_PROTO(__le64 clock_sync_id),
	TP_ARGS(clock_sync_id)
);

TRACE_EVENT(scoutfs_trans_seq_advance,
	TP_PROTO(struct super_block *sb, u64 rid, u64 prev_seq,
		 u64 next_seq),

	TP_ARGS(sb, rid, prev_seq, next_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, prev_seq)
		__field(__u64, next_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->prev_seq = prev_seq;
		__entry->next_seq = next_seq;
	),

	TP_printk(SCSBF" rid %016llx prev_seq %llu next_seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->prev_seq,
		  __entry->next_seq)
);

TRACE_EVENT(scoutfs_trans_seq_farewell,
	TP_PROTO(struct super_block *sb, u64 rid, u64 trans_seq),

	TP_ARGS(sb, rid, trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->trans_seq = trans_seq;
	),

	TP_printk(SCSBF" rid %016llx trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->trans_seq)
);

TRACE_EVENT(scoutfs_trans_seq_last,
	TP_PROTO(struct super_block *sb, u64 rid, u64 trans_seq),

	TP_ARGS(sb, rid, trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->trans_seq = trans_seq;
	),

	TP_printk(SCSBF" rid %016llx trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->trans_seq)
);

DECLARE_EVENT_CLASS(scoutfs_forest_bloom_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		__field(__u64, b_rid)
		__field(__u64, nr)
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(unsigned int, count)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		__entry->b_rid = rid;
		__entry->nr = nr;
		__entry->blkno = blkno;
		__entry->seq = seq;
		__entry->count = count;
	),
	TP_printk(SCSBF" key "SK_FMT" rid %016llx nr %llu blkno %llu seq %llx count %u",
		  SCSB_TRACE_ARGS, sk_trace_args(key), __entry->b_rid,
		  __entry->nr, __entry->blkno, __entry->seq, __entry->count)
);
DEFINE_EVENT(scoutfs_forest_bloom_class, scoutfs_forest_bloom_set,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count)
);
DEFINE_EVENT(scoutfs_forest_bloom_class, scoutfs_forest_bloom_search,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count)
);

TRACE_EVENT(scoutfs_forest_prepare_commit,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_ref *item_ref,
		 struct scoutfs_btree_ref *bloom_ref),
	TP_ARGS(sb, item_ref, bloom_ref),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, item_blkno)
		__field(__u64, item_seq)
		__field(__u64, bloom_blkno)
		__field(__u64, bloom_seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->item_blkno = le64_to_cpu(item_ref->blkno);
		__entry->item_seq = le64_to_cpu(item_ref->seq);
		__entry->bloom_blkno = le64_to_cpu(bloom_ref->blkno);
		__entry->bloom_seq = le64_to_cpu(bloom_ref->seq);
	),
	TP_printk(SCSBF" item blkno %llu seq %llu bloom blkno %llu seq %llu",
		  SCSB_TRACE_ARGS,  __entry->item_blkno, __entry->item_seq,
		  __entry->bloom_blkno, __entry->bloom_seq)
);

TRACE_EVENT(scoutfs_forest_using_roots,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *fs_root,
		 struct scoutfs_btree_root *logs_root),
	TP_ARGS(sb, fs_root, logs_root),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, fs_blkno)
		__field(__u64, fs_seq)
		__field(__u64, logs_blkno)
		__field(__u64, logs_seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->fs_blkno = le64_to_cpu(fs_root->ref.blkno);
		__entry->fs_seq = le64_to_cpu(fs_root->ref.seq);
		__entry->logs_blkno = le64_to_cpu(logs_root->ref.blkno);
		__entry->logs_seq = le64_to_cpu(logs_root->ref.seq);
	),
	TP_printk(SCSBF" fs blkno %llu seq %llu logs blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->fs_blkno, __entry->fs_seq,
		  __entry->logs_blkno, __entry->logs_seq)
);

TRACE_EVENT(scoutfs_forest_add_root,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, u64 rid,
		 u64 nr, u64 blkno, u64 seq),
	TP_ARGS(sb, key, rid, nr, blkno, seq),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		__field(__u64, b_rid)
		__field(__u64, nr)
		__field(__u64, blkno)
		__field(__u64, seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		__entry->b_rid = rid;
		__entry->nr = nr;
		__entry->blkno = blkno;
		__entry->seq = seq;
	),
	TP_printk(SCSBF" key "SK_FMT" rid %016llx nr %llu blkno %llu seq %llx",
		  SCSB_TRACE_ARGS, sk_trace_args(key),
		  __entry->b_rid, __entry->nr, __entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_forest_iter_search,
	TP_PROTO(struct super_block *sb, u64 rid, u64 nr, u64 vers,
		 u8 flags, struct scoutfs_key *key),
	TP_ARGS(sb, rid, nr, vers, flags, key),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, b_rid)
		__field(__u64, nr)
		__field(__u64, vers)
		__field(__u8, flags)
		sk_trace_define(key)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->b_rid = rid;
		__entry->nr = nr;
		__entry->vers = vers;
		__entry->flags = flags;
		sk_trace_assign(key, key);
	),
	TP_printk(SCSBF" rid %016llx nr %llu vers %llu flags %x key "SK_FMT,
		  SCSB_TRACE_ARGS, __entry->b_rid, __entry->nr,
		  __entry->vers, __entry->flags, sk_trace_args(key))
);

TRACE_EVENT(scoutfs_forest_iter_ret,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 struct scoutfs_key *end, bool forward, int ret,
		 u64 found_vers, int found_ret, struct scoutfs_key *found),
	TP_ARGS(sb, key, end, forward, ret, found_vers, found_ret, found),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		sk_trace_define(end)
		__field(char, forward)
		__field(int, ret)
		__field(__u64, found_vers)
		__field(int, found_ret)
		sk_trace_define(found)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		sk_trace_assign(end, end);
		__entry->forward = !!forward;
		__entry->ret = ret;
		__entry->found_vers = found_vers;
		__entry->found_ret = found_ret;
		sk_trace_assign(found, found);
	),
	TP_printk(SCSBF" key "SK_FMT" end "SK_FMT" fwd %u ret %d fv %llu fc %d f "SK_FMT,
		  SCSB_TRACE_ARGS, sk_trace_args(key), sk_trace_args(end),
		  __entry->forward, __entry->ret, __entry->found_vers,
		  __entry->found_ret, sk_trace_args(found))
);

DECLARE_EVENT_CLASS(scoutfs_block_class,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, bp)
		__field(__u64, blkno)
		__field(int, refcount)
		__field(int, io_count)
		__field(unsigned long, bits)
		__field(__u64, lru_moved)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->bp = bp;
		__entry->blkno = blkno;
		__entry->refcount = refcount;
		__entry->io_count = io_count;
		__entry->bits = bits;
		__entry->lru_moved = lru_moved;
	),
	TP_printk(SCSBF" bp %p blkno %llu refcount %d io_count %d bits 0x%lx lru_moved %llu",
		  SCSB_TRACE_ARGS, __entry->bp, __entry->blkno,
		  __entry->refcount, __entry->io_count, __entry->bits,
		  __entry->lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_allocate,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_free,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_insert,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_end_io,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_submit,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_invalidate,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_mark_dirty,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_forget,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_shrink,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits, u64 lru_moved),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits, lru_moved)
);

TRACE_EVENT(scoutfs_radix_get_block,
	TP_PROTO(struct super_block *sb, struct scoutfs_radix_root *root,
		 int glf, int level, u64 par_blkno, u64 ref_blkno, u64 blkno),
	TP_ARGS(sb, root, glf, level, par_blkno, ref_blkno, blkno),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(int, glf)
		__field(int, level)
		__field(__u64, par_blkno)
		__field(__u64, ref_blkno)
		__field(__u64, blkno)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->glf = glf;
		__entry->level = level;
		__entry->par_blkno = par_blkno;
		__entry->ref_blkno = ref_blkno;
		__entry->blkno = blkno;
	),
	TP_printk(SCSBF" root_blkno %llu glf 0x%x level %u par_blkno %llu ref_blkno %llu blkno %llu",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->glf,
		  __entry->level, __entry->par_blkno, __entry->ref_blkno,
		  __entry->blkno)
);

TRACE_EVENT(scoutfs_radix_walk,
	TP_PROTO(struct super_block *sb, struct scoutfs_radix_root *root,
		 int glf, int level, u64 blkno, int ind, u64 bit),
	TP_ARGS(sb, root, glf, level, blkno, ind, bit),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(unsigned int, glf)
		__field(__u64, blkno)
		__field(int, level)
		__field(int, ind)
		__field(__u64, bit)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->glf = glf;
		__entry->blkno = blkno;
		__entry->level = level;
		__entry->ind = ind;
		__entry->bit = bit;
	),
	TP_printk(SCSBF" root_blkno %llu glf 0x%x blkno %llu level %d par_ind %d bit %llu",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->glf,
		  __entry->blkno, __entry->level, __entry->ind, __entry->bit)
);

DECLARE_EVENT_CLASS(scoutfs_radix_bitop,
	TP_PROTO(struct super_block *sb, u64 blkno, int ind, int nbits),
	TP_ARGS(sb, blkno, ind, nbits),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(int, ind)
		__field(int, nbits)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->ind = ind;
		__entry->nbits = nbits;
	),
	TP_printk(SCSBF" blkno %llu ind %d nbits %d",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->ind,
		  __entry->nbits)
);
DEFINE_EVENT(scoutfs_radix_bitop, scoutfs_radix_clear_bits,
	TP_PROTO(struct super_block *sb, u64 blkno, int ind, int nbits),
	TP_ARGS(sb, blkno, ind, nbits)
);
DEFINE_EVENT(scoutfs_radix_bitop, scoutfs_radix_set_bits,
	TP_PROTO(struct super_block *sb, u64 blkno, int ind, int nbits),
	TP_ARGS(sb, blkno, ind, nbits)
);

TRACE_EVENT(scoutfs_radix_merge,
	TP_PROTO(struct super_block *sb,
		 struct scoutfs_radix_root *inp, u64 inp_blkno,
		 struct scoutfs_radix_root *src, u64 src_blkno,
		 struct scoutfs_radix_root *dst, u64 dst_blkno,
		 u64 count, u64 leaf_bit, int ind, int sm_delta,
		 int src_lg_delta, int dst_lg_delta),
	TP_ARGS(sb, inp, inp_blkno, src, src_blkno, dst, dst_blkno, count,
		leaf_bit, ind, sm_delta, src_lg_delta, dst_lg_delta),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, inp_root_blkno)
		__field(__u64, inp_blkno)
		__field(__u64, src_root_blkno)
		__field(__u64, src_blkno)
		__field(__u64, dst_root_blkno)
		__field(__u64, dst_blkno)
		__field(__u64, count)
		__field(__u64, leaf_bit)
		__field(int, ind)
		__field(int, sm_delta)
		__field(int, src_lg_delta)
		__field(int, dst_lg_delta)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->inp_root_blkno = le64_to_cpu(inp->ref.blkno);
		__entry->inp_blkno = inp_blkno;
		__entry->src_root_blkno = le64_to_cpu(src->ref.blkno);
		__entry->src_blkno = src_blkno;
		__entry->dst_root_blkno = le64_to_cpu(dst->ref.blkno);
		__entry->dst_blkno = dst_blkno;
		__entry->count = count;
		__entry->leaf_bit = leaf_bit;
		__entry->ind = ind;
		__entry->sm_delta = sm_delta;
		__entry->src_lg_delta = src_lg_delta;
		__entry->dst_lg_delta = dst_lg_delta;
	),
	TP_printk(SCSBF" irb %llu ib %llu srb %llu sb %llu drb %llu db %llu cnt %llu lb %llu ind %u smd %d sld %d dld %d",
		  SCSB_TRACE_ARGS, __entry->inp_root_blkno, __entry->inp_blkno,
		  __entry->src_root_blkno, __entry->src_blkno,
		  __entry->dst_root_blkno, __entry->dst_blkno,
		  __entry->count, __entry->leaf_bit, __entry->ind,
		  __entry->sm_delta, __entry->src_lg_delta,
		  __entry->dst_lg_delta)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
