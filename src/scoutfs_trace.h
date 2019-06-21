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
#include "seg.h"
#include "super.h"
#include "ioctl.h"
#include "count.h"
#include "bio.h"
#include "export.h"
#include "dir.h"
#include "extents.h"
#include "server.h"

struct lock_info;

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

DECLARE_EVENT_CLASS(scoutfs_comp_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_bio_completion *comp),

	TP_ARGS(sb, comp),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(struct scoutfs_bio_completion *, comp)
		__field(int, pending)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->comp = comp;
		__entry->pending = atomic_read(&comp->pending);
	),

	TP_printk(SCSBF" comp %p pending before %d", SCSB_TRACE_ARGS,
		  __entry->comp, __entry->pending)
);
DEFINE_EVENT(scoutfs_comp_class, comp_end_io,
	TP_PROTO(struct super_block *sb, struct scoutfs_bio_completion *comp),
	TP_ARGS(sb, comp)
);
DEFINE_EVENT(scoutfs_comp_class, scoutfs_bio_submit_comp,
	TP_PROTO(struct super_block *sb, struct scoutfs_bio_completion *comp),
	TP_ARGS(sb, comp)
);
DEFINE_EVENT(scoutfs_comp_class, scoutfs_bio_wait_comp,
	TP_PROTO(struct super_block *sb, struct scoutfs_bio_completion *comp),
	TP_ARGS(sb, comp)
);

TRACE_EVENT(scoutfs_bio_init_comp,
	TP_PROTO(void *comp),

	TP_ARGS(comp),

	TP_STRUCT__entry(
		__field(void *, comp)
	),

	TP_fast_assign(
		__entry->comp = comp;
	),

	TP_printk("initing comp %p", __entry->comp)
);

DECLARE_EVENT_CLASS(scoutfs_bio_class,
	TP_PROTO(struct super_block *sb, void *bio, void *args, int in_flight),

	TP_ARGS(sb, bio, args, in_flight),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, bio)
		__field(void *, args)
		__field(int, in_flight)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->bio = bio;
		__entry->args = args;
		__entry->in_flight = in_flight;
	),

	TP_printk(SCSBF" bio %p args %p in_flight %d", SCSB_TRACE_ARGS,
		  __entry->bio, __entry->args, __entry->in_flight)
);

DEFINE_EVENT(scoutfs_bio_class, scoutfs_bio_submit,
	TP_PROTO(struct super_block *sb, void *bio, void *args, int in_flight),
	TP_ARGS(sb, bio, args, in_flight)
);

DEFINE_EVENT(scoutfs_bio_class, scoutfs_bio_submit_partial,
	TP_PROTO(struct super_block *sb, void *bio, void *args, int in_flight),
	TP_ARGS(sb, bio, args, in_flight)
);

TRACE_EVENT(scoutfs_bio_end_io,
	TP_PROTO(struct super_block *sb, void *bio, int size, int err),

	TP_ARGS(sb, bio, size, err),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, bio)
		__field(int, size)
		__field(int, err)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->bio = bio;
		__entry->size = size;
		__entry->err = err;
	),

	TP_printk(SCSBF" bio %p size %u err %d", SCSB_TRACE_ARGS,
		  __entry->bio, __entry->size, __entry->err)
);

TRACE_EVENT(scoutfs_dec_end_io,
	TP_PROTO(struct super_block *sb, void *args, int in_flight, int err),

	TP_ARGS(sb, args, in_flight, err),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, args)
		__field(int, in_flight)
		__field(int, err)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->args = args;
		__entry->in_flight = in_flight;
		__entry->err = err;
	),

	TP_printk(SCSBF" args %p in_flight %d err %d", SCSB_TRACE_ARGS,
		  __entry->args, __entry->in_flight, __entry->err)
);

DECLARE_EVENT_CLASS(scoutfs_key_ret_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int ret),

	TP_ARGS(sb, key, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" key "SK_FMT" ret %d",
		  SCSB_TRACE_ARGS, sk_trace_args(key), __entry->ret)
);

DEFINE_EVENT(scoutfs_key_ret_class, scoutfs_item_create,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int ret),
	TP_ARGS(sb, key, ret)
);
DEFINE_EVENT(scoutfs_key_ret_class, scoutfs_item_delete,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int ret),
	TP_ARGS(sb, key, ret)
);
DEFINE_EVENT(scoutfs_key_ret_class, scoutfs_item_delete_save,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int ret),
	TP_ARGS(sb, key, ret)
);

TRACE_EVENT(scoutfs_item_dirty_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

TRACE_EVENT(scoutfs_item_update_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

TRACE_EVENT(scoutfs_item_next_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

TRACE_EVENT(scoutfs_item_prev_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

TRACE_EVENT(scoutfs_erase_item,
	TP_PROTO(struct super_block *sb, void *item),

	TP_ARGS(sb, item),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, item)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->item = item;
	),

	TP_printk(SCSBF" erasing item %p", SCSB_TRACE_ARGS, __entry->item)
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
		 int create, int ret, __u64 blkno, size_t size),

	TP_ARGS(sb, ino, iblock, create, ret, blkno, size),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, iblock)
		__field(int, create)
		__field(int, ret)
		__field(__u64, blkno)
		__field(size_t, size)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->iblock = iblock;
		__entry->create = create;
		__entry->ret = ret;
		__entry->blkno = blkno;
		__entry->size = size;
	),

	TP_printk(SCSBF" ino %llu iblock %llu create %d ret %d bnr %llu "
		  "size %zu", SCSB_TRACE_ARGS, __entry->ino, __entry->iblock,
		  __entry->create, __entry->ret, __entry->blkno, __entry->size)
);

TRACE_EVENT(scoutfs_data_alloc_block,
	TP_PROTO(struct super_block *sb, struct inode *inode,
		 struct scoutfs_extent *ext, u64 iblock, u64 len,
		 u64 online_blocks, u64 offline_blocks),

	TP_ARGS(sb, inode, ext, iblock, len, online_blocks, offline_blocks),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		se_trace_define(ext)
		__field(__u64, iblock)
		__field(__u64, len)
		__field(__u64, online_blocks)
		__field(__u64, offline_blocks)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = scoutfs_ino(inode);
		se_trace_assign(ext, ext);
		__entry->iblock = iblock;
		__entry->len = len;
		__entry->online_blocks = online_blocks;
		__entry->offline_blocks = offline_blocks;
	),

	TP_printk(SCSBF" ino %llu ext "SE_FMT" iblock %llu len %llu online_blocks %llu offline_blocks %llu",
		  SCSB_TRACE_ARGS, __entry->ino, se_trace_args(ext),
		  __entry->iblock, __entry->len, __entry->online_blocks,
		  __entry->offline_blocks)
);

TRACE_EVENT(scoutfs_data_alloc_block_ret,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext, int ret),

	TP_ARGS(sb, ext, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		se_trace_define(ext)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		se_trace_assign(ext, ext);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ext "SE_FMT" ret %d", SCSB_TRACE_ARGS,
		se_trace_args(ext), __entry->ret)
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
		 __u8 sef, __u8 op, __u64 ext_start, __u64 ext_len,
		 __u8 ext_flags, int ret),

	TP_ARGS(sb, ino, pos, len, sef, op, ext_start, ext_len, ext_flags, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, pos)
		__field(__u64, len)
		__field(__u8, sef)
		__field(__u8, op)
		__field(__u64, ext_start)
		__field(__u64, ext_len)
		__field(__u8, ext_flags)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->pos = pos;
		__entry->len = len;
		__entry->sef = sef;
		__entry->op = op;
		__entry->ext_start = ext_start;
		__entry->ext_len = ext_len;
		__entry->ext_flags = ext_flags;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu pos %llu len %llu sef 0x%x op 0x%x ext_start %llu ext_len %llu ext_flags 0x%x ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->pos, __entry->len,
		  __entry->sef, __entry->op, __entry->ext_start,
		  __entry->ext_len, __entry->ext_flags, __entry->ret)
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
	TP_PROTO(struct super_block *sb, int dirty),

	TP_ARGS(sb, dirty),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, dirty)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->dirty = dirty;
	),

	TP_printk(SCSBF" dirty %d", SCSB_TRACE_ARGS, __entry->dirty)
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

TRACE_EVENT(scoutfs_ioc_release_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

TRACE_EVENT(scoutfs_ioc_release,
	TP_PROTO(struct super_block *sb, struct scoutfs_ioctl_release *args),

	TP_ARGS(sb, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, block)
		__field(__u64, count)
		__field(__u64, vers)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->block = args->block;
		__entry->count = args->count;
		__entry->vers = args->data_version;
	),

	TP_printk(SCSBF" block %llu count %llu vers %llu", SCSB_TRACE_ARGS,
		  __entry->block, __entry->count, __entry->vers)
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

DECLARE_EVENT_CLASS(scoutfs_segment_class,
	TP_PROTO(struct super_block *sb, __u64 segno),

	TP_ARGS(sb, segno),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, segno)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->segno = segno;
	),

	TP_printk(SCSBF" segno %llu", SCSB_TRACE_ARGS, __entry->segno)
);

DEFINE_EVENT(scoutfs_segment_class, scoutfs_seg_submit_read,
	TP_PROTO(struct super_block *sb, __u64 segno),
	TP_ARGS(sb, segno)
);

DEFINE_EVENT(scoutfs_segment_class, scoutfs_seg_submit_write,
	TP_PROTO(struct super_block *sb, __u64 segno),
	TP_ARGS(sb, segno)
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

TRACE_EVENT(scoutfs_manifest_next_compact,
	TP_PROTO(struct super_block *sb, int level, int ret),

	TP_ARGS(sb, level, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, level)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->level = level;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" level %d ret %d", SCSB_TRACE_ARGS, __entry->level,
		  __entry->ret)
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

TRACE_EVENT(scoutfs_client_compact_start,
	TP_PROTO(struct super_block *sb, u64 id, u8 last_level, u8 flags),

	TP_ARGS(sb, id, last_level, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(__u8, last_level)
		__field(__u8, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = id;
		__entry->last_level = last_level;
		__entry->flags = flags;
	),

	TP_printk(SCSBF" id %llu last_level %u flags 0x%x",
		  SCSB_TRACE_ARGS, __entry->id, __entry->last_level,
		  __entry->flags)
);

TRACE_EVENT(scoutfs_client_compact_stop,
	TP_PROTO(struct super_block *sb, u64 id, int ret),

	TP_ARGS(sb, id, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = id;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" id %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->id, __entry->ret)
);

TRACE_EVENT(scoutfs_server_compact_start,
	TP_PROTO(struct super_block *sb, u64 id, u8 level, u64 node_id,
		 unsigned long client_nr, unsigned long server_nr,
		 unsigned long per_client),

	TP_ARGS(sb, id, level, node_id, client_nr, server_nr, per_client),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(__u8, level)
		__field(__u64, node_id)
		__field(unsigned long, client_nr)
		__field(unsigned long, server_nr)
		__field(unsigned long, per_client)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = id;
		__entry->level = level;
		__entry->node_id = node_id;
		__entry->client_nr = client_nr;
		__entry->server_nr = server_nr;
		__entry->per_client = per_client;
	),

	TP_printk(SCSBF" id %llu level %u node_id %llu client_nr %lu server_nr %lu per_client %lu",
		  SCSB_TRACE_ARGS, __entry->id, __entry->level,
		  __entry->node_id, __entry->client_nr, __entry->server_nr,
		  __entry->per_client)
);

TRACE_EVENT(scoutfs_server_compact_done,
	TP_PROTO(struct super_block *sb, u64 id, u64 node_id,
		 unsigned long server_nr),

	TP_ARGS(sb, id, node_id, server_nr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(__u64, node_id)
		__field(unsigned long, server_nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = id;
		__entry->node_id = node_id;
		__entry->server_nr = server_nr;
	),

	TP_printk(SCSBF" id %llu node_id %llu server_nr %lu",
		  SCSB_TRACE_ARGS, __entry->id, __entry->node_id,
		  __entry->server_nr)
);

TRACE_EVENT(scoutfs_server_compact_response,
	TP_PROTO(struct super_block *sb, u64 id, int error),

	TP_ARGS(sb, id, error),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(int, error)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = id;
		__entry->error = error;
	),

	TP_printk(SCSBF" id %llu error %d",
		  SCSB_TRACE_ARGS, __entry->id, __entry->error)
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

DECLARE_EVENT_CLASS(scoutfs_manifest_class,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last),
        TP_STRUCT__entry(
		__field(u8, level)
		__field(u64, segno)
		__field(u64, seq)
		sk_trace_define(first)
		sk_trace_define(last)
        ),
        TP_fast_assign(
		__entry->level = level;
		__entry->segno = segno;
		__entry->seq = seq;
		sk_trace_assign(first, first);
		sk_trace_assign(last, last);
        ),
        TP_printk("level %u segno %llu seq %llu first "SK_FMT" last "SK_FMT,
		  __entry->level, __entry->segno, __entry->seq,
		  sk_trace_args(first), sk_trace_args(last))
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_manifest_add,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_manifest_delete,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_compact_input,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_compact_output,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

DEFINE_EVENT(scoutfs_manifest_class, scoutfs_read_item_segment,
        TP_PROTO(struct super_block *sb, u8 level, u64 segno, u64 seq,
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last)
);

TRACE_EVENT(scoutfs_read_item_keys,
        TP_PROTO(struct super_block *sb,
		 struct scoutfs_key *key,
		 struct scoutfs_key *start,
		 struct scoutfs_key *end,
		 struct scoutfs_key *seg_start,
		 struct scoutfs_key *seg_end),
        TP_ARGS(sb, key, start, end, seg_start, seg_end),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		sk_trace_define(start)
		sk_trace_define(end)
		sk_trace_define(seg_start)
		sk_trace_define(seg_end)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		sk_trace_assign(seg_start, seg_start);
		sk_trace_assign(seg_end, seg_end);
        ),
        TP_printk(SCSBF" key "SK_FMT" start "SK_FMT" end "SK_FMT" seg_start "SK_FMT" seg_end "SK_FMT"",
		  SCSB_TRACE_ARGS, sk_trace_args(key), sk_trace_args(start),
		  sk_trace_args(end), sk_trace_args(seg_start),
		  sk_trace_args(seg_end))
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

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_lookup,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

TRACE_EVENT(scoutfs_item_lookup_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ret %d", SCSB_TRACE_ARGS, __entry->ret)
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_insertion,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_shrink,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_xattr_get_next_key,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

DECLARE_EVENT_CLASS(scoutfs_range_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *start,
		 struct scoutfs_key *end),
        TP_ARGS(sb, start, end),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(start)
		sk_trace_define(end)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
        ),
        TP_printk(SCSBF" start "SK_FMT" end "SK_FMT,
		  SCSB_TRACE_ARGS, sk_trace_args(start), sk_trace_args(end))
);

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_insert_batch,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *start,
		 struct scoutfs_key *end),
        TP_ARGS(sb, start, end)
);

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_invalidate_range,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *start,
		 struct scoutfs_key *end),
        TP_ARGS(sb, start, end)
);

DECLARE_EVENT_CLASS(scoutfs_cached_range_class,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, rng)
		sk_trace_define(start)
		sk_trace_define(end)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->rng = rng;
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
        ),
        TP_printk(SCSBF" rng %p start "SK_FMT" end "SK_FMT,
		  SCSB_TRACE_ARGS, __entry->rng, sk_trace_args(start),
		  sk_trace_args(end))
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_free,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_ins_rb_insert,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_mid_left,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_start,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_end,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_rem_rb_insert,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_shrink_start,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_shrink_end,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end)
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

TRACE_EVENT(scoutfs_seg_append_item,
	TP_PROTO(struct super_block *sb, u64 segno, u64 seq, u32 nr_items,
		 u32 total_bytes, struct scoutfs_key *key, u16 val_len),

	TP_ARGS(sb, segno, seq, nr_items, total_bytes, key, val_len),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, segno)
		__field(__u64, seq)
		__field(__u32, nr_items)
		__field(__u32, total_bytes)
		sk_trace_define(key)
		__field(__u16, val_len)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->segno = segno;
		__entry->seq = seq;
		__entry->nr_items = nr_items;
		__entry->total_bytes = total_bytes;
		sk_trace_assign(key, key);
		__entry->val_len = val_len;
	),

	TP_printk(SCSBF" segno %llu seq %llu nr_items %u total_bytes %u key "SK_FMT" val_len %u",
		  SCSB_TRACE_ARGS, __entry->segno, __entry->seq,
		  __entry->nr_items, __entry->total_bytes,
		  sk_trace_args(key), __entry->val_len)
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
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_compact_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_compact_work_exit,
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

TRACE_EVENT(scoutfs_item_next_range_check,
        TP_PROTO(struct super_block *sb, int cached,
		 struct scoutfs_key *key, struct scoutfs_key *pos,
		 struct scoutfs_key *last, struct scoutfs_key *end,
		 struct scoutfs_key *range_end),
        TP_ARGS(sb, cached, key, pos, last, end, range_end),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(int, cached)
		sk_trace_define(key)
		sk_trace_define(pos)
		sk_trace_define(last)
		sk_trace_define(end)
		sk_trace_define(range_end)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->cached = cached;
		sk_trace_assign(key, key);
		sk_trace_assign(pos, pos);
		sk_trace_assign(last, last);
		sk_trace_assign(end, end);
		sk_trace_assign(range_end, range_end);
        ),
        TP_printk("sb %p cached %d key "SK_FMT" pos "SK_FMT" last "SK_FMT" end "SK_FMT" range_end "SK_FMT,
		  __entry->sb, __entry->cached, sk_trace_args(key),
		  sk_trace_args(pos), sk_trace_args(last),
		  sk_trace_args(end), sk_trace_args(range_end))
);

TRACE_EVENT(scoutfs_item_prev_range_check,
        TP_PROTO(struct super_block *sb, int cached,
		 struct scoutfs_key *key, struct scoutfs_key *pos,
		 struct scoutfs_key *first, struct scoutfs_key *start,
		 struct scoutfs_key *range_start),
        TP_ARGS(sb, cached, key, pos, first, start, range_start),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(int, cached)
		sk_trace_define(key)
		sk_trace_define(pos)
		sk_trace_define(first)
		sk_trace_define(start)
		sk_trace_define(range_start)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->cached = cached;
		sk_trace_assign(key, key);
		sk_trace_assign(pos, pos);
		sk_trace_assign(first, first);
		sk_trace_assign(start, start);
		sk_trace_assign(range_start, range_start);
        ),
        TP_printk("sb %p cached %d key "SK_FMT" pos "SK_FMT" first "SK_FMT" start "SK_FMT" range_start "SK_FMT,
		  __entry->sb, __entry->cached, sk_trace_args(key),
		  sk_trace_args(pos), sk_trace_args(first),
		  sk_trace_args(start), sk_trace_args(range_start))
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

DEFINE_EVENT(scoutfs_shrink_exit_class, scoutfs_seg_shrink_exit,
        TP_PROTO(struct super_block *sb, unsigned long nr_to_scan, int ret),
        TP_ARGS(sb, nr_to_scan, ret)
);

DEFINE_EVENT(scoutfs_shrink_exit_class, scoutfs_item_shrink_exit,
        TP_PROTO(struct super_block *sb, unsigned long nr_to_scan, int ret),
        TP_ARGS(sb, nr_to_scan, ret)
);

TRACE_EVENT(scoutfs_item_shrink_around,
        TP_PROTO(struct super_block *sb,
		 struct scoutfs_key *rng_start,
		 struct scoutfs_key *rng_end, struct scoutfs_key *item,
		 struct scoutfs_key *prev, struct scoutfs_key *first,
		 struct scoutfs_key *last, struct scoutfs_key *next),
        TP_ARGS(sb, rng_start, rng_end, item, prev, first, last, next),
        TP_STRUCT__entry(
		__field(void *, sb)
		sk_trace_define(rng_start)
		sk_trace_define(rng_end)
		sk_trace_define(item)
		sk_trace_define(prev)
		sk_trace_define(first)
		sk_trace_define(last)
		sk_trace_define(next)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		sk_trace_assign(rng_start, rng_start);
		sk_trace_assign(rng_end, rng_end);
		sk_trace_assign(item, item);
		sk_trace_assign(prev, prev);
		sk_trace_assign(first, first);
		sk_trace_assign(last, last);
		sk_trace_assign(next, next);
        ),
        TP_printk("sb %p rng_start "SK_FMT" rng_end "SK_FMT" item "SK_FMT" prev "SK_FMT" first "SK_FMT" last "SK_FMT" next "SK_FMT,
		  __entry->sb, sk_trace_args(rng_start),
		  sk_trace_args(rng_end), sk_trace_args(item),
		  sk_trace_args(prev), sk_trace_args(first),
		  sk_trace_args(last), sk_trace_args(next))
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
	TP_PROTO(struct super_block *sb, u64 blkno, u64 seq, u64 next_block,
		u64 next_seq, unsigned long cur_dirtied,
		unsigned long old_dirtied, u64 bt_blkno, u64 bt_seq),

	TP_ARGS(sb, blkno, seq, next_block, next_seq, cur_dirtied, old_dirtied,
		bt_blkno, bt_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(__u64, next_block)
		__field(__u64, next_seq)
		__field(unsigned long, cur_dirtied)
		__field(unsigned long, old_dirtied)
		__field(__u64, bt_blkno)
		__field(__u64, bt_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->seq = seq;
		__entry->next_block = next_block;
		__entry->next_seq = next_seq;
		__entry->cur_dirtied = cur_dirtied;
		__entry->old_dirtied = old_dirtied;
		__entry->bt_blkno = bt_blkno;
		__entry->bt_seq = bt_seq;
	),

	TP_printk(SCSBF" blkno %llu seq %llu next_block %llu next_seq %llu cur_dirtied %lu old_dirtied %lu bt_blkno %llu bt_seq %llu",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->seq,
		  __entry->next_block, __entry->next_seq, __entry->cur_dirtied,
		  __entry->old_dirtied, __entry->bt_blkno, __entry->bt_seq)
);

DECLARE_EVENT_CLASS(scoutfs_extent_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),

	TP_ARGS(sb, ext),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		se_trace_define(ext)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		se_trace_assign(ext, ext);
	),

	TP_printk(SCSBF" ext "SE_FMT,
		  SCSB_TRACE_ARGS, se_trace_args(ext))
);

DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_insert,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_delete,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_next_input,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_next_output,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_prev_input,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_prev_output,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_add,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_extent_remove,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);

DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_truncate_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_truncate_remove,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_truncate_offline,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_get_server_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_find_free_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_alloc_block_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_get_block_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_get_block_intersection,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_fiemap_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_return_server_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_alloc_extent_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_alloc_extent_allocated,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_alloc_segno_next,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_alloc_segno_allocated,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_free_pending_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_server_extent_io,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
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

DECLARE_EVENT_CLASS(scoutfs_segno_class,
	TP_PROTO(struct super_block *sb, u64 segno),

	TP_ARGS(sb, segno),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, segno)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->segno = segno;
	),

	TP_printk(SCSBF" segno %llu",
		  SCSB_TRACE_ARGS, __entry->segno)
);
DEFINE_EVENT(scoutfs_segno_class, scoutfs_alloc_segno,
	TP_PROTO(struct super_block *sb, u64 segno),
	TP_ARGS(sb, segno)
);
DEFINE_EVENT(scoutfs_segno_class, scoutfs_free_segno,
	TP_PROTO(struct super_block *sb, u64 segno),
	TP_ARGS(sb, segno)
);
DEFINE_EVENT(scoutfs_segno_class, scoutfs_remove_segno,
	TP_PROTO(struct super_block *sb, u64 segno),
	TP_ARGS(sb, segno)
);

DECLARE_EVENT_CLASS(scoutfs_server_client_count_class,
	TP_PROTO(struct super_block *sb, u64 node_id, unsigned long nr_clients),

	TP_ARGS(sb, node_id, nr_clients),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, node_id)
		__field(unsigned long, nr_clients)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->node_id = node_id;
		__entry->nr_clients = nr_clients;
	),

	TP_printk(SCSBF" node_id %llu nr_clients %lu",
		  SCSB_TRACE_ARGS, __entry->node_id, __entry->nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_up,
	TP_PROTO(struct super_block *sb, u64 node_id, unsigned long nr_clients),
	TP_ARGS(sb, node_id, nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_down,
	TP_PROTO(struct super_block *sb, u64 node_id, unsigned long nr_clients),
	TP_ARGS(sb, node_id, nr_clients)
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
		 u64 node_id, u64 net_id, struct scoutfs_net_lock *nl),

	TP_ARGS(sb, who, what, dir, node_id, net_id, nl),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, who)
		__field(int, what)
		__field(int, dir)
		__field(__u64, node_id)
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
		__entry->node_id = node_id;
		__entry->net_id = net_id;
		sk_trace_assign(key, &nl->key);
		__entry->old_mode = nl->old_mode;
		__entry->new_mode = nl->new_mode;
	),

	TP_printk(SCSBF" %s %s %s node_id %llu net_id %llu key "SK_FMT" old_mode %u new_mode %u",
		  SCSB_TRACE_ARGS, slt_symbolic(__entry->who),
		  slt_symbolic(__entry->what), slt_symbolic(__entry->dir),
		  __entry->node_id, __entry->net_id, sk_trace_args(key),
		  __entry->old_mode, __entry->new_mode)
);

DECLARE_EVENT_CLASS(scoutfs_quorum_block_class,
	TP_PROTO(struct super_block *sb, u64 io_blkno,
		 struct scoutfs_quorum_block *blk),

	TP_ARGS(sb, io_blkno, blk),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, io_blkno)
		__field(__u64, hdr_blkno)
		__field(__u64, config_gen)
		__field(__u64, write_nr)
		__field(__u64, elected_nr)
		__field(__u64, unmount_barrier)
		__field(__u32, crc)
		__field(__u8, vote_slot)
		__field(__u8, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->io_blkno = io_blkno;
		__entry->hdr_blkno = le64_to_cpu(blk->blkno);
		__entry->config_gen = le64_to_cpu(blk->config_gen);
		__entry->write_nr = le64_to_cpu(blk->write_nr);
		__entry->elected_nr = le64_to_cpu(blk->elected_nr);
		__entry->unmount_barrier = le64_to_cpu(blk->unmount_barrier);
		__entry->crc = le32_to_cpu(blk->crc);
		__entry->vote_slot = blk->vote_slot;
		__entry->flags = blk->flags;
	),

	TP_printk(SCSBF" io_blkno %llu hdr_blkno %llu config_gen %llu write_nr %llu elected_nr %llu umb %llu crc 0x%08x vote_slot %u flags %02x",
		  SCSB_TRACE_ARGS, __entry->io_blkno, __entry->hdr_blkno,
		  __entry->config_gen, __entry->write_nr, __entry->elected_nr,
		  __entry->unmount_barrier, __entry->crc, __entry->vote_slot,
		  __entry->flags)
);
DEFINE_EVENT(scoutfs_quorum_block_class, scoutfs_quorum_read_block,
	TP_PROTO(struct super_block *sb, u64 io_blkno,
		 struct scoutfs_quorum_block *blk),
	TP_ARGS(sb, io_blkno, blk)
);
DEFINE_EVENT(scoutfs_quorum_block_class, scoutfs_quorum_write_block,
	TP_PROTO(struct super_block *sb, u64 io_blkno,
		 struct scoutfs_quorum_block *blk),
	TP_ARGS(sb, io_blkno, blk)
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
	TP_PROTO(struct super_block *sb, u64 node_id, u64 prev_seq,
		 u64 next_seq),

	TP_ARGS(sb, node_id, prev_seq, next_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, node_id)
		__field(__u64, prev_seq)
		__field(__u64, next_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->node_id = node_id;
		__entry->prev_seq = prev_seq;
		__entry->next_seq = next_seq;
	),

	TP_printk(SCSBF" node_id %llu prev_seq %llu next_seq %llu",
		  SCSB_TRACE_ARGS, __entry->node_id, __entry->prev_seq,
		  __entry->next_seq)
);

TRACE_EVENT(scoutfs_trans_seq_farewell,
	TP_PROTO(struct super_block *sb, u64 node_id, u64 trans_seq),

	TP_ARGS(sb, node_id, trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, node_id)
		__field(__u64, trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->node_id = node_id;
		__entry->trans_seq = trans_seq;
	),

	TP_printk(SCSBF" node_id %llu trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->node_id, __entry->trans_seq)
);

TRACE_EVENT(scoutfs_trans_seq_last,
	TP_PROTO(struct super_block *sb, u64 node_id, u64 trans_seq),

	TP_ARGS(sb, node_id, trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, node_id)
		__field(__u64, trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->node_id = node_id;
		__entry->trans_seq = trans_seq;
	),

	TP_printk(SCSBF" node_id %llu trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->node_id, __entry->trans_seq)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
