#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"
#include "buddy.h"

struct scoutfs_counters;
struct buddy_alloc;
struct wrlock_context;

struct scoutfs_sb_info {
	struct super_block *sb;

	u64 ctr;

	struct scoutfs_super_block super;

	spinlock_t next_ino_lock;
	u64 next_ino;
	u64 next_ino_count;

	spinlock_t block_lock;
	struct radix_tree_root block_radix;
	wait_queue_head_t block_wq;
	atomic_t block_writes;
	int block_write_err;

	struct mutex buddy_mutex;
	struct buddy_alloc *bud;

	/* XXX there will be a lot more of these :) */
	struct rw_semaphore btree_rwsem;

	atomic_t trans_holds;
	wait_queue_head_t trans_hold_wq;

	spinlock_t trans_write_lock;
	u64 trans_write_count;
	int trans_write_ret;
	struct work_struct trans_write_work;
	wait_queue_head_t trans_write_wq;
	struct workqueue_struct *trans_write_workq;

	/* $sysfs/fs/scoutfs/$id/ */
	struct kset *kset;

	struct scoutfs_counters *counters;

	struct list_head roster_head;
	u64 roster_id;

	struct wrlock_context *wrlock_context;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

void scoutfs_advance_dirty_super(struct super_block *sb);
int scoutfs_write_dirty_super(struct super_block *sb);

#endif
