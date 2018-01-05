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
#include "ioctl.h"
#include "count.h"
#include "bio.h"
#include "dlmglue.h"
#include "stackglue.h"
#include "export.h"

struct lock_info;

#define FSID_ARG(sb)	le64_to_cpu(SCOUTFS_SB(sb)->super.hdr.fsid)
#define FSID_FMT	"%llx"

TRACE_EVENT(scoutfs_setattr,
	TP_PROTO(struct dentry *dentry, struct iattr *attr),

	TP_ARGS(dentry, attr),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(unsigned int, d_len)
		__string(d_name, dentry->d_name.name)
		__field(__u64, i_size)
		__field(__u64, ia_size)
		__field(unsigned int, ia_valid)
		__field(int, size_change)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(dentry->d_inode->i_sb);
		__entry->ino = scoutfs_ino(dentry->d_inode);
		__entry->d_len = dentry->d_name.len;
		__assign_str(d_name, dentry->d_name.name);
		__entry->ia_valid = attr->ia_valid;
		__entry->size_change = !!(attr->ia_valid & ATTR_SIZE);
		__entry->ia_size = attr->ia_size;
		__entry->i_size = i_size_read(dentry->d_inode);
	),

	TP_printk(FSID_FMT" %s ino %llu ia_valid 0x%x size change %d ia_size "
		  "%llu i_size %llu", __entry->fsid, __get_str(d_name),
		  __entry->ino, __entry->ia_valid, __entry->size_change,
		  __entry->ia_size, __entry->i_size)
);

TRACE_EVENT(scoutfs_complete_truncate,
	TP_PROTO(struct inode *inode, __u32 flags),

	TP_ARGS(inode, flags),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, i_size)
		__field(__u32, flags)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(inode->i_sb);
		__entry->ino = scoutfs_ino(inode);
		__entry->i_size = i_size_read(inode);
		__entry->flags = flags;
	),

	TP_printk(FSID_FMT" ino %llu i_size %llu flags 0x%x",
		  __entry->fsid, __entry->ino, __entry->i_size,
		  __entry->flags)
);

DECLARE_EVENT_CLASS(scoutfs_comp_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_bio_completion *comp),

	TP_ARGS(sb, comp),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(struct scoutfs_bio_completion *, comp)
		__field(int, pending)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->comp = comp;
		__entry->pending = atomic_read(&comp->pending);
	),

	TP_printk(FSID_FMT" comp %p pending before %d", __entry->fsid,
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

TRACE_EVENT(scoutfs_bio_submit_added,
	TP_PROTO(struct super_block *sb, void *page, void *bio),

	TP_ARGS(sb, page, bio),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, page)
		__field(void *, bio)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->page = page;
		__entry->bio = bio;
	),

	TP_printk(FSID_FMT" added page %p to bio %p", __entry->fsid,
		  __entry->page, __entry->bio)
);

DECLARE_EVENT_CLASS(scoutfs_bio_class,
	TP_PROTO(struct super_block *sb, void *bio, void *args, int in_flight),

	TP_ARGS(sb, bio, args, in_flight),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, bio)
		__field(void *, args)
		__field(int, in_flight)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->bio = bio;
		__entry->args = args;
		__entry->in_flight = in_flight;
	),

	TP_printk(FSID_FMT" bio %p args %p in_flight %d", __entry->fsid,
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
		__field(__u64, fsid)
		__field(void *, bio)
		__field(int, size)
		__field(int, err)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->bio = bio;
		__entry->size = size;
		__entry->err = err;
	),

	TP_printk(FSID_FMT" bio %p size %u err %d", __entry->fsid,
		  __entry->bio, __entry->size, __entry->err)
);

TRACE_EVENT(scoutfs_dec_end_io,
	TP_PROTO(struct super_block *sb, void *args, int in_flight, int err),

	TP_ARGS(sb, args, in_flight, err),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, args)
		__field(int, in_flight)
		__field(int, err)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->args = args;
		__entry->in_flight = in_flight;
		__entry->err = err;
	),

	TP_printk(FSID_FMT" args %p in_flight %d err %d", __entry->fsid,
		  __entry->args, __entry->in_flight, __entry->err)
);

TRACE_EVENT(scoutfs_item_delete_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_item_dirty_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_item_update_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_item_next_same,
	TP_PROTO(struct super_block *sb, unsigned int key_len),

	TP_ARGS(sb, key_len),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(unsigned int, key_len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->key_len = key_len;
	),

	TP_printk(FSID_FMT" key len %u", __entry->fsid, __entry->key_len)
);

TRACE_EVENT(scoutfs_item_next_same_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_item_next_same_min,
	TP_PROTO(struct super_block *sb, int key_len, int len),

	TP_ARGS(sb, key_len, len),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, key_len)
		__field(int, len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->key_len = key_len;
		__entry->len = len;
	),

	TP_printk(FSID_FMT" key len %u min val len %d", __entry->fsid,
		  __entry->key_len, __entry->len)
);

TRACE_EVENT(scoutfs_item_next_same_min_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_item_next_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_erase_item,
	TP_PROTO(struct super_block *sb, void *item),

	TP_ARGS(sb, item),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, item)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->item = item;
	),

	TP_printk(FSID_FMT" erasing item %p", __entry->fsid, __entry->item)
);

TRACE_EVENT(scoutfs_data_fiemap,
	TP_PROTO(struct super_block *sb, __u64 off, int i, __u64 blkno),


	TP_ARGS(sb, off, i, blkno),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, off)
		__field(int, i)
		__field(__u64, blkno)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->off = off;
		__entry->i = i;
		__entry->blkno = blkno;
	),

	TP_printk(FSID_FMT" blk_off %llu i %u blkno %llu", __entry->fsid,
		  __entry->off, __entry->i, __entry->blkno)
);

TRACE_EVENT(scoutfs_get_block,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 iblock,
		 int create, int ret, __u64 blkno, size_t size),

	TP_ARGS(sb, ino, iblock, create, ret, blkno, size),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, iblock)
		__field(int, create)
		__field(int, ret)
		__field(__u64, blkno)
		__field(size_t, size)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->iblock = iblock;
		__entry->create = create;
		__entry->ret = ret;
		__entry->blkno = blkno;
		__entry->size = size;
	),

	TP_printk(FSID_FMT" ino %llu iblock %llu create %d ret %d bnr %llu "
		  "size %zu", __entry->fsid, __entry->ino, __entry->iblock,
		  __entry->create, __entry->ret, __entry->blkno, __entry->size)
);

TRACE_EVENT(scoutfs_data_find_alloc_block_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_data_find_alloc_block_found_seg,
	TP_PROTO(struct super_block *sb, __u64 segno, __u64 blkno),

	TP_ARGS(sb, segno, blkno),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, segno)
		__field(__u64, blkno)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
		__entry->blkno = blkno;
	),

	TP_printk(FSID_FMT" found free segno %llu blkno %llu", __entry->fsid,
		  __entry->segno, __entry->blkno)
);

TRACE_EVENT(scoutfs_data_find_alloc_block_curs,
	TP_PROTO(struct super_block *sb, void *curs, __u64 blkno),

	TP_ARGS(sb, curs, blkno),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, curs)
		__field(__u64, blkno)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->curs = curs;
		__entry->blkno = blkno;
	),

	TP_printk(FSID_FMT" got curs %p blkno %llu", __entry->fsid,
		  __entry->curs, __entry->blkno)
);

TRACE_EVENT(scoutfs_data_get_cursor,
	TP_PROTO(void *curs, void *task, unsigned int pid),

	TP_ARGS(curs, task, pid),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, curs)
		__field(void *, task)
		__field(unsigned int, pid)
	),

	TP_fast_assign(
		__entry->curs = curs;
		__entry->task = task;
		__entry->pid = pid;
	),

	TP_printk("resetting curs %p was task %p pid %u", __entry->curs,
		  __entry->task, __entry->pid)
);

TRACE_EVENT(scoutfs_data_truncate_items,
	TP_PROTO(struct super_block *sb, __u64 iblock, __u64 last, int offline),

	TP_ARGS(sb, iblock, last, offline),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, iblock)
		__field(__u64, last)
		__field(int, offline)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->iblock = iblock;
		__entry->last = last;
		__entry->offline = offline;
	),

	TP_printk(FSID_FMT" iblock %llu last %llu offline %u", __entry->fsid,
		  __entry->iblock, __entry->last, __entry->offline)
);

TRACE_EVENT(scoutfs_data_set_segno_free,
	TP_PROTO(struct super_block *sb, __u64 segno, __u64 base,
		 unsigned int bit, int ret),

	TP_ARGS(sb, segno, base, bit, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, segno)
		__field(__u64, base)
		__field(unsigned int, bit)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
		__entry->base = base;
		__entry->bit = bit;
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" segno %llu base %llu bit %u ret %d", __entry->fsid,
		  __entry->segno, __entry->base, __entry->bit, __entry->ret)
);

TRACE_EVENT(scoutfs_sync_fs,
	TP_PROTO(struct super_block *sb, int wait),

	TP_ARGS(sb, wait),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, wait)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->wait = wait;
	),

	TP_printk(FSID_FMT" wait %d", __entry->fsid, __entry->wait)
);

TRACE_EVENT(scoutfs_trans_write_func,
	TP_PROTO(struct super_block *sb, int dirty),

	TP_ARGS(sb, dirty),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, dirty)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->dirty = dirty;
	),

	TP_printk(FSID_FMT" dirty %d", __entry->fsid, __entry->dirty)
);

TRACE_EVENT(scoutfs_release_trans,
	TP_PROTO(struct super_block *sb, void *rsv, unsigned int rsv_holders,
		 struct scoutfs_item_count *res,
		 struct scoutfs_item_count *act, unsigned int tri_holders,
		 unsigned int tri_writing, unsigned int tri_items,
		 unsigned int tri_keys, unsigned int tri_vals),

	TP_ARGS(sb, rsv, rsv_holders, res, act, tri_holders, tri_writing,
		tri_items, tri_keys, tri_vals),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, rsv)
		__field(unsigned int, rsv_holders)
		__field(int, res_items)
		__field(int, res_keys)
		__field(int, res_vals)
		__field(int, act_items)
		__field(int, act_keys)
		__field(int, act_vals)
		__field(unsigned int, tri_holders)
		__field(unsigned int, tri_writing)
		__field(unsigned int, tri_items)
		__field(unsigned int, tri_keys)
		__field(unsigned int, tri_vals)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->rsv = rsv;
		__entry->rsv_holders = rsv_holders;
		__entry->res_items = res->items;
		__entry->res_keys = res->keys;
		__entry->res_vals = res->vals;
		__entry->act_items = act->items;
		__entry->act_keys = act->keys;
		__entry->act_vals = act->vals;
		__entry->tri_holders = tri_holders;
		__entry->tri_writing = tri_writing;
		__entry->tri_items = tri_items;
		__entry->tri_keys = tri_keys;
		__entry->tri_vals = tri_vals;
	),

	TP_printk(FSID_FMT" rsv %p holders %u reserved %u.%u.%u actual "
		  "%d.%d.%d, trans holders %u writing %u reserved "
		  "%u.%u.%u", __entry->fsid, __entry->rsv,
		  __entry->rsv_holders, __entry->res_items, __entry->res_keys,
		  __entry->res_vals, __entry->act_items, __entry->act_keys,
		  __entry->act_vals, __entry->tri_holders, __entry->tri_writing,
		  __entry->tri_items, __entry->tri_keys, __entry->tri_vals)
);

TRACE_EVENT(scoutfs_trans_acquired_hold,
	TP_PROTO(struct super_block *sb, const struct scoutfs_item_count *cnt,
		 void *rsv, unsigned int rsv_holders,
		 struct scoutfs_item_count *res,
		 struct scoutfs_item_count *act, unsigned int tri_holders,
		 unsigned int tri_writing, unsigned int tri_items,
		 unsigned int tri_keys, unsigned int tri_vals),

	TP_ARGS(sb, cnt, rsv, rsv_holders, res, act, tri_holders, tri_writing,
		tri_items, tri_keys, tri_vals),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, cnt_items)
		__field(int, cnt_keys)
		__field(int, cnt_vals)
		__field(void *, rsv)
		__field(unsigned int, rsv_holders)
		__field(int, res_items)
		__field(int, res_keys)
		__field(int, res_vals)
		__field(int, act_items)
		__field(int, act_keys)
		__field(int, act_vals)
		__field(unsigned int, tri_holders)
		__field(unsigned int, tri_writing)
		__field(unsigned int, tri_items)
		__field(unsigned int, tri_keys)
		__field(unsigned int, tri_vals)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->cnt_items = cnt->items;
		__entry->cnt_keys = cnt->keys;
		__entry->cnt_vals = cnt->vals;
		__entry->rsv = rsv;
		__entry->rsv_holders = rsv_holders;
		__entry->res_items = res->items;
		__entry->res_keys = res->keys;
		__entry->res_vals = res->vals;
		__entry->act_items = act->items;
		__entry->act_keys = act->keys;
		__entry->act_vals = act->vals;
		__entry->tri_holders = tri_holders;
		__entry->tri_writing = tri_writing;
		__entry->tri_items = tri_items;
		__entry->tri_keys = tri_keys;
		__entry->tri_vals = tri_vals;
	),

	TP_printk(FSID_FMT" cnt %u.%u.%u, rsv %p holders %u reserved %u.%u.%u "
		  "actual %d.%d.%d, trans holders %u writing %u reserved "
		  "%u.%u.%u", __entry->fsid, __entry->cnt_items,
		  __entry->cnt_keys, __entry->cnt_vals, __entry->rsv,
		  __entry->rsv_holders, __entry->res_items, __entry->res_keys,
		  __entry->res_vals, __entry->act_items, __entry->act_keys,
		  __entry->act_vals, __entry->tri_holders, __entry->tri_writing,
		  __entry->tri_items, __entry->tri_keys, __entry->tri_vals)
);

TRACE_EVENT(scoutfs_ioc_release_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

TRACE_EVENT(scoutfs_ioc_release,
	TP_PROTO(struct super_block *sb, struct scoutfs_ioctl_release *args),

	TP_ARGS(sb, args),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, block)
		__field(__u64, count)
		__field(__u64, vers)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->block = args->block;
		__entry->count = args->count;
		__entry->vers = args->data_version;
	),

	TP_printk(FSID_FMT" block %llu count %llu vers %llu", __entry->fsid,
		  __entry->block, __entry->count, __entry->vers)
);

TRACE_EVENT(scoutfs_ioc_walk_inodes,
	TP_PROTO(struct super_block *sb, struct scoutfs_ioctl_walk_inodes *walk),

	TP_ARGS(sb, walk),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, index)
		__field(__u64, first_major)
		__field(__u32, first_minor)
		__field(__u64, first_ino)
		__field(__u64, last_major)
		__field(__u32, last_minor)
		__field(__u64, last_ino)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->index = walk->index;
		__entry->first_major = walk->first.major;
		__entry->first_minor = walk->first.minor;
		__entry->first_ino = walk->first.ino;
		__entry->last_major = walk->last.major;
		__entry->last_minor = walk->last.minor;
		__entry->last_ino = walk->last.ino;
	),

	TP_printk(FSID_FMT" index %u first %llu.%u.%llu last %llu.%u.%llu",
		  __entry->fsid, __entry->index, __entry->first_major,
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
		__field(__u64, fsid)
		__field(__u8, type)
		__field(__u64, major)
		__field(__u32, minor)
		__field(__u64, ino)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->type = type;
		__entry->major = major;
		__entry->minor = minor;
		__entry->ino = ino;
	),

	TP_printk("fsid "FSID_FMT" type %u major %llu minor %u ino %llu",
		  __entry->fsid, __entry->type, __entry->major, __entry->minor,
		  __entry->ino)
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

TRACE_EVENT(scoutfs_inode_fill_pool,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 nr),

	TP_ARGS(sb, ino, nr),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, nr)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->nr = nr;
	),

	TP_printk(FSID_FMT" filling ino %llu nr %llu",  __entry->fsid,
		  __entry->ino, __entry->nr)
);

TRACE_EVENT(scoutfs_alloc_ino,
	TP_PROTO(struct super_block *sb, int ret, __u64 ino, __u64 pool_ino,
		 __u64 nr, unsigned int in_flight),

	TP_ARGS(sb, ret, ino, pool_ino, nr, in_flight),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
		__field(__u64, ino)
		__field(__u64, pool_ino)
		__field(__u64, nr)
		__field(unsigned int, in_flight)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
		__entry->ino = ino;
		__entry->pool_ino = pool_ino;
		__entry->nr = nr;
		__entry->in_flight = in_flight;
	),

	TP_printk(FSID_FMT" ret %d ino %llu pool ino %llu nr %llu req %u "
		  "(racey)", __entry->fsid, __entry->ret, __entry->ino,
		  __entry->pool_ino, __entry->nr, __entry->in_flight)
);

TRACE_EVENT(scoutfs_evict_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int is_bad_ino),

	TP_ARGS(sb, ino, nlink, is_bad_ino),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, is_bad_ino)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->is_bad_ino = is_bad_ino;
	),

	TP_printk(FSID_FMT" ino %llu nlink %u bad %d", __entry->fsid,
		  __entry->ino, __entry->nlink, __entry->is_bad_ino)
);

TRACE_EVENT(scoutfs_drop_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int unhashed),

	TP_ARGS(sb, ino, nlink, unhashed),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, unhashed)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->unhashed = unhashed;
	),

	TP_printk(FSID_FMT" ino %llu nlink %u unhashed %d", __entry->fsid,
		  __entry->ino, __entry->nlink, __entry->unhashed)
);

TRACE_EVENT(scoutfs_inode_walk_writeback,
	TP_PROTO(struct super_block *sb, __u64 ino, int write, int ret),

	TP_ARGS(sb, ino, write, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(int, write)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->write = write;
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ino %llu write %d ret %d", __entry->fsid,
		  __entry->ino, __entry->write, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_segment_class,
	TP_PROTO(struct super_block *sb, __u64 segno),

	TP_ARGS(sb, segno),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, segno)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
	),

	TP_printk(FSID_FMT" segno %llu", __entry->fsid, __entry->segno)
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
		__field(__u64, fsid)
		__field(struct lock_info *, linfo)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->linfo = linfo;
	),

	TP_printk(FSID_FMT" linfo %p", __entry->fsid, __entry->linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, init_lock_info,
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
		__field(__u64, fsid)
		__field(size_t, name_len)
		__field(const void *, value)
		__field(size_t, size)
		__field(int, flags)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->name_len = name_len;
		__entry->value = value;
		__entry->size = size;
		__entry->flags = flags;
	),

	TP_printk(FSID_FMT" name_len %zu value %p size %zu flags 0x%x",
		  __entry->fsid, __entry->name_len, __entry->value,
		  __entry->size, __entry->flags)
);

TRACE_EVENT(scoutfs_manifest_next_compact,
	TP_PROTO(struct super_block *sb, int level),

	TP_ARGS(sb, level),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, level)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->level = level;
	),

	TP_printk(FSID_FMT" level %d", __entry->fsid, __entry->level)
);

TRACE_EVENT(scoutfs_advance_dirty_super,
	TP_PROTO(struct super_block *sb, __u64 seq),

	TP_ARGS(sb, seq),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, seq)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->seq = seq;
	),

	TP_printk(FSID_FMT" super seq now %llu", __entry->fsid, __entry->seq)
);

TRACE_EVENT(scoutfs_dir_add_next_linkref,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 dir_ino, int ret,
		 unsigned int key_len),

	TP_ARGS(sb, ino, dir_ino, ret, key_len),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(int, ret)
		__field(unsigned int, key_len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->dir_ino = dir_ino;
		__entry->ret = ret;
		__entry->key_len = key_len;
	),

	TP_printk(FSID_FMT" ino %llu dir_ino %llu ret %d key_len %u",
		  __entry->fsid, __entry->ino, __entry->dir_ino, __entry->ret,
		  __entry->key_len)
);

TRACE_EVENT(scoutfs_compact_func,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
);

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
	TP_PROTO(struct super_block *sb, u64 ino, loff_t pos, unsigned len),

	TP_ARGS(sb, ino, pos, len),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, inode)
		__field(__u64, pos)
		__field(__u32, len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->inode = ino;
		__entry->pos = pos;
		__entry->len = len;
	),

	TP_printk(FSID_FMT" ino %llu pos %llu len %u", __entry->fsid,
		  __entry->inode, __entry->pos, __entry->len)
);

TRACE_EVENT(scoutfs_write_end,
	TP_PROTO(struct super_block *sb, u64 ino, unsigned long idx, u64 pos,
		 unsigned len, unsigned copied),

	TP_ARGS(sb, ino, idx, pos, len, copied),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(unsigned long, idx)
		__field(__u64, pos)
		__field(__u32, len)
		__field(__u32, copied)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->idx = idx;
		__entry->pos = pos;
		__entry->len = len;
		__entry->copied = copied;
	),

	TP_printk(FSID_FMT" ino %llu pgind %lu pos %llu len %u copied %d",
		  __entry->fsid, __entry->ino, __entry->idx, __entry->pos,
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
 		__field(__u64, fsid)
               __dynamic_array(char, key, scoutfs_key_str(NULL, key))
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		scoutfs_key_str(__get_dynamic_array(key), key);
        ),
	TP_printk(FSID_FMT" key %s", __entry->fsid, __get_str(key))
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_lookup,
        TP_PROTO(struct super_block *sb, struct scoutfs_key_buf *key),
        TP_ARGS(sb, key)
);

TRACE_EVENT(scoutfs_item_lookup_ret,
	TP_PROTO(struct super_block *sb, int ret),

	TP_ARGS(sb, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
	),

	TP_printk(FSID_FMT" ret %d", __entry->fsid, __entry->ret)
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
		__field(__u64, fsid)
                __dynamic_array(char, start, scoutfs_key_str(NULL, start))
                __dynamic_array(char, end, scoutfs_key_str(NULL, end))
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		scoutfs_key_str(__get_dynamic_array(start), start);
		scoutfs_key_str(__get_dynamic_array(end), end);
        ),
        TP_printk("fsid "FSID_FMT" start %s end %s",
		  __entry->fsid, __get_str(start), __get_str(end))
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

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_invalidate_range,
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

DECLARE_EVENT_CLASS(scoutfs_cached_range_class,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end),
        TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, rng)
                __dynamic_array(char, start, scoutfs_key_str(NULL, start))
                __dynamic_array(char, end, scoutfs_key_str(NULL, end))
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->rng = rng;
		scoutfs_key_str(__get_dynamic_array(start), start);
		scoutfs_key_str(__get_dynamic_array(end), end);
        ),
        TP_printk("fsid "FSID_FMT" rng %p start %s end %s",
		  __entry->fsid, __entry->rng, __get_str(start), __get_str(end))
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_free,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_ins_rb_insert,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_mid_left,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_start,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_remove_end,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_rem_rb_insert,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_delete_enoent,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_shrink_start,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
);

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_shrink_end,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key_buf *start, struct scoutfs_key_buf *end),
        TP_ARGS(sb, rng, start, end)
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
		__field(__u64, fsid)
		__field(u8, name_scope)
		__field(u8, name_zone)
		__field(u8, name_type)
		__field(u64, name_first)
		__field(u64, name_second)
		__field(unsigned int, seq)
		__field(unsigned int, refcnt)
		__field(unsigned int, users)
		__field(unsigned char, level)
		__field(unsigned char, blocking)
		__field(unsigned int, cw)
		__field(unsigned int, pr)
		__field(unsigned int, ex)
	),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->name_scope = lck->lock_name.scope;
		__entry->name_zone = lck->lock_name.zone;
		__entry->name_type = lck->lock_name.type;
		__entry->name_first = le64_to_cpu(lck->lock_name.first);
		__entry->name_second = le64_to_cpu(lck->lock_name.second);
		__entry->seq = lck->sequence;
		__entry->refcnt = lck->refcnt;
		__entry->users = lck->users;
		/* racey, but safe refs of embedded struct */
		__entry->level = lck->lockres.l_level;
		__entry->blocking = lck->lockres.l_blocking;
		__entry->cw = lck->lockres.l_cw_holders;
		__entry->pr = lck->lockres.l_ro_holders;
		__entry->ex = lck->lockres.l_ex_holders;
        ),
        TP_printk("fsid "FSID_FMT" name %u.%u.%u.%llu.%llu seq %u refs %d users %d level %u blocking %u cw %u pr %u ex %u",
		  __entry->fsid, __entry->name_scope, __entry->name_zone,
		  __entry->name_type, __entry->name_first,
		  __entry->name_second, __entry->seq, __entry->refcnt,
		  __entry->users, __entry->level, __entry->blocking,
		  __entry->cw, __entry->pr, __entry->ex)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_resource,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock,
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

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate_ret,
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

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_rb_insert,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_free,
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
		 struct scoutfs_key_buf *rng_start,
		 struct scoutfs_key_buf *rng_end, struct scoutfs_key_buf *item,
		 struct scoutfs_key_buf *prev, struct scoutfs_key_buf *first,
		 struct scoutfs_key_buf *last, struct scoutfs_key_buf *next),
        TP_ARGS(sb, rng_start, rng_end, item, prev, first, last, next),
        TP_STRUCT__entry(
		__field(void *, sb)
                __dynamic_array(char, rng_start,
				scoutfs_key_str(NULL, rng_start))
                __dynamic_array(char, rng_end,
				scoutfs_key_str(NULL, rng_end))
                __dynamic_array(char, item, scoutfs_key_str(NULL, item))
                __dynamic_array(char, prev, scoutfs_key_str(NULL, prev))
                __dynamic_array(char, first, scoutfs_key_str(NULL, first))
                __dynamic_array(char, last, scoutfs_key_str(NULL, last))
                __dynamic_array(char, next, scoutfs_key_str(NULL, next))
        ),
        TP_fast_assign(
		__entry->sb = sb;
		scoutfs_key_str(__get_dynamic_array(rng_start), rng_start);
		scoutfs_key_str(__get_dynamic_array(rng_end), rng_end);
		scoutfs_key_str(__get_dynamic_array(item), item);
		scoutfs_key_str(__get_dynamic_array(prev), prev);
		scoutfs_key_str(__get_dynamic_array(first), first);
		scoutfs_key_str(__get_dynamic_array(last), last);
		scoutfs_key_str(__get_dynamic_array(next), next);
        ),
        TP_printk("sb %p rng_start %s rng_end %s item %s prev %s first %s last %s next %s",
		  __entry->sb, __get_str(rng_start), __get_str(rng_end),
		  __get_str(item), __get_str(prev), __get_str(first),
		  __get_str(last), __get_str(next))
);

TRACE_EVENT(scoutfs_rename,
	TP_PROTO(struct super_block *sb, struct inode *old_dir,
		 struct dentry *old_dentry, struct inode *new_dir,
		 struct dentry *new_dentry),

	TP_ARGS(sb, old_dir, old_dentry, new_dir, new_dentry),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, old_dir_ino)
		__field(char *, old_name)
		__field(unsigned int, old_name_len)
		__field(__u64, new_dir_ino)
		__field(char *, new_name)
		__field(unsigned int, new_name_len)
		__field(__u64, new_inode_ino)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->old_dir_ino = scoutfs_ino(old_dir);
		__entry->old_name = (char *)old_dentry->d_name.name;
		__entry->old_name_len = old_dentry->d_name.len;
		__entry->new_dir_ino = scoutfs_ino(new_dir);
		__entry->new_name = (char *)new_dentry->d_name.name;
		__entry->new_name_len = new_dentry->d_name.len;
		__entry->new_inode_ino = new_dentry->d_inode ?
					 scoutfs_ino(new_dentry->d_inode) : 0;
	),

	TP_printk("fsid "FSID_FMT" old_dir_ino %llu old_name %.*s (len %u) new_dir_ino %llu new_name %.*s (len %u) new_inode_ino %llu",
		  __entry->fsid, __entry->old_dir_ino, __entry->old_name_len,
		  __entry->old_name, __entry->old_name_len,
		  __entry->new_dir_ino, __entry->new_name_len,
		  __entry->new_name, __entry->new_name_len,
		  __entry->new_inode_ino)
);

DECLARE_EVENT_CLASS(scoutfs_super_lifecycle_class,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb),
        TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, sb)
		__field(void *, sbi)
		__field(void *, s_root)
        ),
        TP_fast_assign(
		__entry->fsid = SCOUTFS_SB(sb) ? FSID_ARG(sb) : 0;
		__entry->sb = sb;
		__entry->sbi = SCOUTFS_SB(sb);
		__entry->s_root = sb->s_root;
        ),
	TP_printk("fsid "FSID_FMT" sb %p sbi %p s_root %p",
		  __entry->fsid, __entry->sb, __entry->sbi, __entry->s_root)
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

TRACE_EVENT(ocfs2_cluster_lock,
	TP_PROTO(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres,
		 int requested, unsigned int lkm_flags, unsigned int arg_flags),

	TP_ARGS(osb, lockres, requested, lkm_flags, arg_flags),

	TP_STRUCT__entry(
		__string(lockspace, osb->cconn->cc_name)
		__string(lockname, lockres->l_pretty_name)
		__field(int, requested)
		__field(unsigned int, lkm_flags)
		__field(unsigned int, arg_flags)
		__field(unsigned int, lockres_flags)
		__field(int, lockres_level)
		__field(int, blocking)
		__field(unsigned int, cw_holders)
		__field(unsigned int, pr_holders)
		__field(unsigned int, ex_holders)
	),

	TP_fast_assign(
		__assign_str(lockspace, osb->cconn->cc_name);
		__assign_str(lockname, lockres->l_pretty_name);
		__entry->requested = requested;
		__entry->lkm_flags = lkm_flags;
		__entry->arg_flags = arg_flags;
		__entry->lockres_flags = lockres->l_flags;
		__entry->lockres_level = lockres->l_level;
		__entry->blocking = lockres->l_blocking;
		__entry->cw_holders = lockres->l_cw_holders;
		__entry->pr_holders = lockres->l_ro_holders;
		__entry->ex_holders = lockres->l_ex_holders;
	),

	TP_printk("lockspace %s lock %s requested %d lkm_flags 0x%x arg_flags 0x%x lockres->level %d lockres->flags 0x%x lockres->blocking %d holders cw/pr/ex %u/%u/%u",
		  __get_str(lockspace), __get_str(lockname), __entry->requested,
		  __entry->lkm_flags, __entry->arg_flags,
		  __entry->lockres_level, __entry->lockres_flags,
		  __entry->blocking, __entry->cw_holders, __entry->pr_holders,
		  __entry->ex_holders)
);

TRACE_EVENT(ocfs2_cluster_unlock,
	TP_PROTO(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres,
		 int level),

	TP_ARGS(osb, lockres, level),

	TP_STRUCT__entry(
		__string(lockspace, osb->cconn->cc_name)
		__string(lockname, lockres->l_pretty_name)
		__field(int, level)
		__field(unsigned int, lockres_flags)
		__field(int, lockres_level)
		__field(int, blocking)
		__field(unsigned int, cw_holders)
		__field(unsigned int, pr_holders)
		__field(unsigned int, ex_holders)
	),

	TP_fast_assign(
		__assign_str(lockspace, osb->cconn->cc_name);
		__assign_str(lockname, lockres->l_pretty_name);
		__entry->level = level;
		__entry->lockres_flags = lockres->l_flags;
		__entry->lockres_level = lockres->l_level;
		__entry->blocking = lockres->l_blocking;
		__entry->cw_holders = lockres->l_cw_holders;
		__entry->pr_holders = lockres->l_ro_holders;
		__entry->ex_holders = lockres->l_ex_holders;
	),

	TP_printk("lockspace %s lock %s level %d lockres->level %d lockres->flags 0x%x lockres->blocking %d holders cw/pr/ex: %u/%u/%u",
		  __get_str(lockspace), __get_str(lockname), __entry->level,
		  __entry->lockres_level, __entry->lockres_flags,
		  __entry->blocking, __entry->cw_holders, __entry->pr_holders,
		  __entry->ex_holders)
);

DECLARE_EVENT_CLASS(ocfs2_lock_res_class,
	TP_PROTO(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres),

	TP_ARGS(osb, lockres),

	TP_STRUCT__entry(
		__string(lockspace, osb->cconn->cc_name)
		__string(lockname, lockres->l_pretty_name)
		__field(unsigned int, lockres_flags)
		__field(int, lockres_level)
		__field(int, blocking)
		__field(unsigned int, cw_holders)
		__field(unsigned int, pr_holders)
		__field(unsigned int, ex_holders)
	),

	TP_fast_assign(
		__assign_str(lockspace, osb->cconn->cc_name);
		__assign_str(lockname, lockres->l_pretty_name);
		__entry->lockres_flags = lockres->l_flags;
		__entry->lockres_level = lockres->l_level;
		__entry->blocking = lockres->l_blocking;
		__entry->cw_holders = lockres->l_cw_holders;
		__entry->pr_holders = lockres->l_ro_holders;
		__entry->ex_holders = lockres->l_ex_holders;
	),

	TP_printk("lockspace %s lock %s lockres->level %d lockres->flags 0x%x lockres->blocking %d holders cw/pr/ex: %u/%u/%u",
		  __get_str(lockspace), __get_str(lockname),
		  __entry->lockres_level, __entry->lockres_flags,
		  __entry->blocking, __entry->cw_holders,
		  __entry->pr_holders, __entry->ex_holders)
);

DEFINE_EVENT(ocfs2_lock_res_class, ocfs2_simple_drop_lockres,
	TP_PROTO(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres),
	TP_ARGS(osb, lockres)
);
DEFINE_EVENT(ocfs2_lock_res_class, ocfs2_unblock_lock,
	TP_PROTO(struct ocfs2_super *osb, struct ocfs2_lock_res *lockres),
	TP_ARGS(osb, lockres)
);

DECLARE_EVENT_CLASS(scoutfs_fileid_class,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid),
	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, fh_type)
		__field(u64, ino)
		__field(u64, parent_ino)
	),
	TP_fast_assign(
		__entry->fsid = SCOUTFS_SB(sb) ? FSID_ARG(sb) : 0;
		__entry->fh_type = fh_type;
		__entry->ino = le64_to_cpu(fid->ino);
		__entry->parent_ino = fh_type == FILEID_SCOUTFS_WITH_PARENT ?
				le64_to_cpu(fid->parent_ino) : 0ULL;
	),
	TP_printk("fsid "FSID_FMT" type %d ino %llu parent %llu",
		  __entry->fsid, __entry->fh_type, __entry->ino,
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
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, parent)
	),

	TP_fast_assign(
		__entry->fsid = SCOUTFS_SB(sb) ? FSID_ARG(sb) : 0;
		__entry->ino = scoutfs_ino(inode);
		__entry->parent = parent;
	),

	TP_printk("fsid "FSID_FMT" child %llu parent %llu",
		  __entry->fsid, __entry->ino, __entry->parent)
);

TRACE_EVENT(scoutfs_get_name,
	TP_PROTO(struct super_block *sb, struct inode *parent,
		 struct inode *child, char *name),

	TP_ARGS(sb, parent, child, name),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, parent_ino)
		__field(__u64, child_ino)
		__string(name, name)
	),

	TP_fast_assign(
		__entry->fsid = SCOUTFS_SB(sb) ? FSID_ARG(sb) : 0;
		__entry->parent_ino = scoutfs_ino(parent);
		__entry->child_ino = scoutfs_ino(child);
		__assign_str(name, name);
	),

	TP_printk("fsid "FSID_FMT" parent %llu child %llu name: %s",
		  __entry->fsid, __entry->parent_ino, __entry->child_ino,
		  __get_str(name))
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
