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

DECLARE_EVENT_CLASS(scoutfs_key_ret_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, int ret),

	TP_ARGS(sb, key, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field_struct(struct scoutfs_key, key)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->key = *key;
		__entry->ret = ret;
	),

	TP_printk("fsid "FSID_FMT" key "SK_FMT" ret %d",
		  __entry->fsid, SK_ARG(&__entry->key), __entry->ret)
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
		 unsigned int tri_vals),

	TP_ARGS(sb, rsv, rsv_holders, res, act, tri_holders, tri_writing,
		tri_items, tri_vals),

	TP_STRUCT__entry(
		__field(__u64, fsid)
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
		__entry->fsid = FSID_ARG(sb);
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

	TP_printk(FSID_FMT" rsv %p holders %u reserved %u.%u actual "
		  "%d.%d, trans holders %u writing %u reserved "
		  "%u.%u", __entry->fsid, __entry->rsv, __entry->rsv_holders,
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
		__field(__u64, fsid)
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
		__entry->fsid = FSID_ARG(sb);
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

	TP_printk(FSID_FMT" cnt %u.%u, rsv %p holders %u reserved %u.%u "
		  "actual %d.%d, trans holders %u writing %u reserved "
		  "%u.%u", __entry->fsid, __entry->cnt_items,
		  __entry->cnt_vals, __entry->rsv, __entry->rsv_holders,
		  __entry->res_items, __entry->res_vals, __entry->act_items,
		  __entry->act_vals, __entry->tri_holders, __entry->tri_writing,
		  __entry->tri_items, __entry->tri_vals)
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
	TP_PROTO(struct super_block *sb, int ret, __u64 ino, __u64 next_ino,
		 __u64 next_nr),

	TP_ARGS(sb, ret, ino, next_ino, next_nr),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(int, ret)
		__field(__u64, ino)
		__field(__u64, next_ino)
		__field(__u64, next_nr)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ret = ret;
		__entry->ino = ino;
		__entry->next_ino = next_ino;
		__entry->next_nr = next_nr;
	),

	TP_printk(FSID_FMT" ret %d ino %llu next_ino %llu next_nr %llu",
		  __entry->fsid, __entry->ret, __entry->ino, __entry->next_ino,
		  __entry->next_nr)
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
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 dir_ino,
		 __u64 dir_pos, int ret, __u64 found_dir_ino,
		 __u64 found_dir_pos, unsigned int name_len),

	TP_ARGS(sb, ino, dir_ino, dir_pos, ret, found_dir_pos, found_dir_ino,
		name_len),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(__u64, dir_pos)
		__field(int, ret)
		__field(__u64, found_dir_ino)
		__field(__u64, found_dir_pos)
		__field(unsigned int, name_len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->ino = ino;
		__entry->dir_ino = dir_ino;
		__entry->dir_pos = dir_pos;
		__entry->ret = ret;
		__entry->found_dir_ino = dir_ino;
		__entry->found_dir_pos = dir_pos;
		__entry->name_len = name_len;
	),

	TP_printk("fsid "FSID_FMT" ino %llu dir_ino %llu dir_pos %llu ret %d found_dir_ino %llu found_dir_pos %llu name_len %u",
		  __entry->fsid, __entry->ino, __entry->dir_pos,
		  __entry->dir_ino, __entry->ret, __entry->found_dir_pos,
		  __entry->found_dir_ino, __entry->name_len)
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
		 struct scoutfs_key *first, struct scoutfs_key *last),
        TP_ARGS(sb, level, segno, seq, first, last),
        TP_STRUCT__entry(
		__field(u8, level)
		__field(u64, segno)
		__field(u64, seq)
		__field_struct(struct scoutfs_key, first)
		__field_struct(struct scoutfs_key, last)
        ),
        TP_fast_assign(
		__entry->level = level;
		__entry->segno = segno;
		__entry->seq = seq;
		scoutfs_key_copy_or_zeros(&__entry->first, first);
		scoutfs_key_copy_or_zeros(&__entry->last, last);
        ),
        TP_printk("level %u segno %llu seq %llu first "SK_FMT" last "SK_FMT,
		  __entry->level, __entry->segno, __entry->seq,
		  SK_ARG(&__entry->first), SK_ARG(&__entry->last))
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
		__field(__u64, fsid)
		__field_struct(struct scoutfs_key, key)
		__field_struct(struct scoutfs_key, start)
		__field_struct(struct scoutfs_key, end)
		__field_struct(struct scoutfs_key, seg_start)
		__field_struct(struct scoutfs_key, seg_end)
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		scoutfs_key_copy_or_zeros(&__entry->key, key);
		scoutfs_key_copy_or_zeros(&__entry->start, start);
		scoutfs_key_copy_or_zeros(&__entry->end, end);
		scoutfs_key_copy_or_zeros(&__entry->seg_start, seg_start);
		scoutfs_key_copy_or_zeros(&__entry->seg_end, seg_end);
        ),
        TP_printk("fsid "FSID_FMT" key "SK_FMT" start "SK_FMT" end "SK_FMT" seg_start "SK_FMT" seg_end "SK_FMT"",
		  __entry->fsid, SK_ARG(&__entry->key), SK_ARG(&__entry->start),
		  SK_ARG(&__entry->end), SK_ARG(&__entry->seg_start),
		  SK_ARG(&__entry->seg_end))
);

DECLARE_EVENT_CLASS(scoutfs_key_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key),
        TP_STRUCT__entry(
 		__field(__u64, fsid)
		__field_struct(struct scoutfs_key, key)
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		scoutfs_key_copy_or_zeros(&__entry->key, key);
        ),
	TP_printk(FSID_FMT" key "SK_FMT, __entry->fsid, SK_ARG(&__entry->key))
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_item_lookup,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
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
		__field(__u64, fsid)
		__field_struct(struct scoutfs_key, start)
		__field_struct(struct scoutfs_key, end)
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		scoutfs_key_copy_or_zeros(&__entry->start, start);
		scoutfs_key_copy_or_zeros(&__entry->end, end);
        ),
        TP_printk("fsid "FSID_FMT" start "SK_FMT" end "SK_FMT,
		  __entry->fsid, SK_ARG(&__entry->start),
		  SK_ARG(&__entry->end))
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

DEFINE_EVENT(scoutfs_range_class, scoutfs_item_shrink_range,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *start,
		 struct scoutfs_key *end),
        TP_ARGS(sb, start, end)
);

DECLARE_EVENT_CLASS(scoutfs_cached_range_class,
        TP_PROTO(struct super_block *sb, void *rng,
		 struct scoutfs_key *start, struct scoutfs_key *end),
        TP_ARGS(sb, rng, start, end),
        TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(void *, rng)
		__field_struct(struct scoutfs_key, start)
		__field_struct(struct scoutfs_key, end)
        ),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->rng = rng;
		scoutfs_key_copy_or_zeros(&__entry->start, start);
		scoutfs_key_copy_or_zeros(&__entry->end, end);
        ),
        TP_printk("fsid "FSID_FMT" rng %p start "SK_FMT" end "SK_FMT,
		  __entry->fsid, __entry->rng, SK_ARG(&__entry->start),
		  SK_ARG(&__entry->end))
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

DEFINE_EVENT(scoutfs_cached_range_class, scoutfs_item_range_delete_enoent,
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
		__field(u64, refresh_gen)
		__field(int, error)
		__field(int, granted_mode)
		__field(int, bast_mode)
		__field(int, work_prev_mode)
		__field(int, work_mode)
		__field(unsigned int, waiters_cw)
		__field(unsigned int, waiters_pr)
		__field(unsigned int, waiters_ex)
		__field(unsigned int, users_cw)
		__field(unsigned int, users_pr)
		__field(unsigned int, users_ex)
	),
        TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->name_scope = lck->name.scope;
		__entry->name_zone = lck->name.zone;
		__entry->name_type = lck->name.type;
		__entry->name_first = le64_to_cpu(lck->name.first);
		__entry->name_second = le64_to_cpu(lck->name.second);

		__entry->refresh_gen = lck->refresh_gen;
		__entry->error = lck->error;
		__entry->granted_mode = lck->granted_mode;
		__entry->bast_mode = lck->bast_mode;
		__entry->work_prev_mode = lck->work_prev_mode;
		__entry->work_mode = lck->work_mode;
		__entry->waiters_pr = lck->waiters[DLM_LOCK_PR];
		__entry->waiters_ex = lck->waiters[DLM_LOCK_EX];
		__entry->waiters_cw = lck->waiters[DLM_LOCK_CW];
		__entry->users_pr = lck->users[DLM_LOCK_PR];
		__entry->users_ex = lck->users[DLM_LOCK_EX];
		__entry->users_cw = lck->users[DLM_LOCK_CW];
        ),
        TP_printk("fsid "FSID_FMT" name %u.%u.%u.%llu.%llu refresh_gen %llu error %d granted %d bast %d prev %d work %d waiters: pr %u ex %u cw %u users: pr %u ex %u cw %u",
		  __entry->fsid, __entry->name_scope, __entry->name_zone,
		  __entry->name_type, __entry->name_first, __entry->name_second,
		  __entry->refresh_gen, __entry->error, __entry->granted_mode,
		  __entry->bast_mode, __entry->work_prev_mode,
		  __entry->work_mode, __entry->waiters_pr,
		  __entry->waiters_ex, __entry->waiters_cw, __entry->users_pr,
		  __entry->users_ex, __entry->users_cw)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_free,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_alloc,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_ast,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_bast,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_work,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_grace_work,
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
		__field(__u64, fsid)
		__field(__u64, segno)
		__field(__u64, seq)
		__field(__u32, nr_items)
		__field(__u32, total_bytes)
		__field_struct(struct scoutfs_key, key)
		__field(__u16, val_len)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->segno = segno;
		__entry->seq = seq;
		__entry->nr_items = nr_items;
		__entry->total_bytes = total_bytes;
		__entry->key = *key;
		__entry->val_len = val_len;
	),

	TP_printk("fsid "FSID_FMT" segno %llu seq %llu nr_items %u total_bytes %u key "SK_FMT" val_len %u",
		  __entry->fsid, __entry->segno, __entry->seq,
		  __entry->nr_items, __entry->total_bytes,
		  SK_ARG(&__entry->key),
		  __entry->val_len)
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
		 struct scoutfs_key *key, struct scoutfs_key *pos,
		 struct scoutfs_key *last, struct scoutfs_key *end,
		 struct scoutfs_key *range_end),
        TP_ARGS(sb, cached, key, pos, last, end, range_end),
        TP_STRUCT__entry(
		__field(void *, sb)
		__field(int, cached)
		__field_struct(struct scoutfs_key, key)
		__field_struct(struct scoutfs_key, pos)
		__field_struct(struct scoutfs_key, last)
		__field_struct(struct scoutfs_key, end)
		__field_struct(struct scoutfs_key, range_end)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		__entry->cached = cached;
		scoutfs_key_copy_or_zeros(&__entry->key, key);
		scoutfs_key_copy_or_zeros(&__entry->pos, pos);
		scoutfs_key_copy_or_zeros(&__entry->last, last);
		scoutfs_key_copy_or_zeros(&__entry->end, end);
		scoutfs_key_copy_or_zeros(&__entry->range_end, range_end);
        ),
        TP_printk("sb %p cached %d key "SK_FMT" pos "SK_FMT" last "SK_FMT" end "SK_FMT" range_end "SK_FMT,
		  __entry->sb, __entry->cached, SK_ARG(&__entry->key),
		  SK_ARG(&__entry->pos), SK_ARG(&__entry->last),
		  SK_ARG(&__entry->end), SK_ARG(&__entry->range_end))
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
		__field_struct(struct scoutfs_key, rng_start)
		__field_struct(struct scoutfs_key, rng_end)
		__field_struct(struct scoutfs_key, item)
		__field_struct(struct scoutfs_key, prev)
		__field_struct(struct scoutfs_key, first)
		__field_struct(struct scoutfs_key, last)
		__field_struct(struct scoutfs_key, next)
        ),
        TP_fast_assign(
		__entry->sb = sb;
		scoutfs_key_copy_or_zeros(&__entry->rng_start, rng_start);
		scoutfs_key_copy_or_zeros(&__entry->rng_end, rng_end);
		scoutfs_key_copy_or_zeros(&__entry->item, item);
		scoutfs_key_copy_or_zeros(&__entry->prev, prev);
		scoutfs_key_copy_or_zeros(&__entry->first, first);
		scoutfs_key_copy_or_zeros(&__entry->last, last);
		scoutfs_key_copy_or_zeros(&__entry->next, next);
        ),
        TP_printk("sb %p rng_start "SK_FMT" rng_end "SK_FMT" item "SK_FMT" prev "SK_FMT" first "SK_FMT" last "SK_FMT" next "SK_FMT,
		  __entry->sb, SK_ARG(&__entry->rng_start),
		  SK_ARG(&__entry->rng_end), SK_ARG(&__entry->item),
		  SK_ARG(&__entry->prev), SK_ARG(&__entry->first),
		  SK_ARG(&__entry->last), SK_ARG(&__entry->next))
);

TRACE_EVENT(scoutfs_rename,
	TP_PROTO(struct super_block *sb, struct inode *old_dir,
		 struct dentry *old_dentry, struct inode *new_dir,
		 struct dentry *new_dentry),

	TP_ARGS(sb, old_dir, old_dentry, new_dir, new_dentry),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, old_dir_ino)
		__string(old_name, old_dentry->d_name.name)
		__field(__u64, new_dir_ino)
		__string(new_name, new_dentry->d_name.name)
		__field(__u64, new_inode_ino)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->old_dir_ino = scoutfs_ino(old_dir);
		__assign_str(old_name, old_dentry->d_name.name)
		__entry->new_dir_ino = scoutfs_ino(new_dir);
		__assign_str(new_name, new_dentry->d_name.name)
		__entry->new_inode_ino = new_dentry->d_inode ?
					 scoutfs_ino(new_dentry->d_inode) : 0;
	),

	TP_printk("fsid "FSID_FMT" old_dir_ino %llu old_name %s new_dir_ino %llu new_name %s new_inode_ino %llu",
		  __entry->fsid, __entry->old_dir_ino, __get_str(old_name),
		  __entry->new_dir_ino, __get_str(new_name),
		  __entry->new_inode_ino)
);

TRACE_EVENT(scoutfs_d_revalidate,
	TP_PROTO(struct super_block *sb,
		 struct dentry *dentry, int flags, struct dentry *parent,
		 bool is_covered, int ret),

	TP_ARGS(sb, dentry, flags, parent, is_covered, ret),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__string(name, dentry->d_name.name)
		__field(__u64, ino)
		__field(__u64, parent_ino)
		__field(int, flags)
		__field(int, is_root)
		__field(int, is_covered)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
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

	TP_printk("fsid "FSID_FMT" name %s ino %llu parent_ino %llu flags 0x%x s_root %u is_covered %u ret %d",
		  __entry->fsid, __get_str(name), __entry->ino,
		  __entry->parent_ino, __entry->flags,
		  __entry->is_root,
		  __entry->is_covered,
		  __entry->ret)
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

TRACE_EVENT(scoutfs_btree_read_error,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_ref *ref),

	TP_ARGS(sb, ref),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__u64, blkno)
		__field(__u64, seq)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(sb);
		__entry->blkno = le64_to_cpu(ref->blkno);
		__entry->seq = le64_to_cpu(ref->seq);
	),

	TP_printk("fsid "FSID_FMT" blkno %llu seq %llu",
		  __entry->fsid, __entry->blkno, __entry->seq)
);

DECLARE_EVENT_CLASS(scoutfs_extent_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),

	TP_ARGS(sb, ext),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field_struct(struct scoutfs_extent, ext)
	),

	TP_fast_assign(
		__entry->fsid = SCOUTFS_SB(sb) ? FSID_ARG(sb) : 0;
		__entry->ext = *ext;
	),

	TP_printk("fsid "FSID_FMT" ext "SE_FMT,
		  __entry->fsid, SE_ARG(&__entry->ext))
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
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_bulk_alloc,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_alloc_block_cursor,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_alloc_block_free,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_extent_class, scoutfs_data_alloc_block,
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

TRACE_EVENT(scoutfs_online_offline_blocks,
	TP_PROTO(struct inode *inode, s64 on_delta, s64 off_delta,
		 u64 on_now, u64 off_now),

	TP_ARGS(inode, on_delta, off_delta, on_now, off_now),

	TP_STRUCT__entry(
		__field(__u64, fsid)
		__field(__s64, on_delta)
		__field(__s64, off_delta)
		__field(__u64, on_now)
		__field(__u64, off_now)
	),

	TP_fast_assign(
		__entry->fsid = FSID_ARG(inode->i_sb);
		__entry->on_delta = on_delta;
		__entry->off_delta = off_delta;
		__entry->on_now = on_now;
		__entry->off_now = off_now;
	),

	TP_printk("fsid "FSID_FMT" on_delta %lld off_delta %lld on_now %llu off_now %llu ",
		  __entry->fsid, __entry->on_delta, __entry->off_delta,
		  __entry->on_now, __entry->off_now)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
