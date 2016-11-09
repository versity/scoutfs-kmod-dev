#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"
#include "buddy.h"

struct scoutfs_counters;
struct buddy_info;

struct scoutfs_sb_info {
	struct super_block *sb;

	struct scoutfs_super_block super;
	struct scoutfs_super_block stable_super;

	spinlock_t next_ino_lock;

	spinlock_t block_lock;
	struct radix_tree_root block_radix;
	wait_queue_head_t block_wq;
	atomic_t block_writes;
	int block_write_err;
	/* block cache lru */
	struct shrinker block_shrinker;
	struct list_head block_lru_list;
	unsigned long block_lru_nr;

	struct buddy_info *buddy_info;

	struct rw_semaphore btree_rwsem;

	atomic_t trans_holds;
	wait_queue_head_t trans_hold_wq;
	struct task_struct *trans_task;

	spinlock_t trans_write_lock;
	u64 trans_write_count;
	int trans_write_ret;
	struct work_struct trans_write_work;
	wait_queue_head_t trans_write_wq;
	struct workqueue_struct *trans_write_workq;

	/* $sysfs/fs/scoutfs/$id/ */
	struct kset *kset;

	struct scoutfs_counters *counters;

	/* XXX we'd like this to be per task, not per super */
	spinlock_t file_alloc_lock;
	u64 file_alloc_blkno;
	u64 file_alloc_count;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/* The root of the metadata btree */
static inline struct scoutfs_btree_root *SCOUTFS_META(struct super_block *sb)
{
	return &SCOUTFS_SB(sb)->super.btree_root;
}

static inline struct scoutfs_btree_root *SCOUTFS_STABLE_META(struct super_block *sb)
{
	return &SCOUTFS_SB(sb)->stable_super.btree_root;
}

void scoutfs_advance_dirty_super(struct super_block *sb);
int scoutfs_write_dirty_super(struct super_block *sb);

#endif
