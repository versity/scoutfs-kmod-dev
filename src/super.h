#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"

struct scoutfs_counters;
struct item_cache;
struct manifest;
struct segment_cache;
struct compact_info;
struct data_info;
struct lock_info;
struct net_info;
struct free_ino_pool;

struct scoutfs_sb_info {
	struct super_block *sb;

	struct scoutfs_super_block super;

	spinlock_t next_ino_lock;

	struct manifest *manifest;
	struct item_cache *item_cache;
	struct segment_cache *segment_cache;
	struct seg_alloc *seg_alloc;
	struct compact_info *compact_info;
	struct data_info *data_info;
	struct free_ino_pool *free_ino_pool;

	atomic_t trans_holds;
	wait_queue_head_t trans_hold_wq;
	struct task_struct *trans_task;

	spinlock_t trans_write_lock;
	u64 trans_write_count;
	int trans_write_ret;
	struct work_struct trans_write_work;
	wait_queue_head_t trans_write_wq;
	struct workqueue_struct *trans_write_workq;

	struct lock_info *lock_info;
	struct net_info *net_info;

	/* $sysfs/fs/scoutfs/$id/ */
	struct kset *kset;

	struct scoutfs_counters *counters;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

void scoutfs_advance_dirty_super(struct super_block *sb);
int scoutfs_write_dirty_super(struct super_block *sb);

#endif
