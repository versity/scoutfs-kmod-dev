#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"

struct scoutfs_counters;

struct scoutfs_sb_info {
	struct scoutfs_super_block super;

	spinlock_t block_lock;
	struct radix_tree_root block_radix;
	wait_queue_head_t block_wq;

	atomic64_t next_ino;
	atomic64_t next_blkno;

	/* XXX there will be a lot more of these :) */
	struct rw_semaphore btree_rwsem;

	/* $sysfs/fs/scoutfs/$id/ */
	struct kset *kset;

	struct scoutfs_counters *counters;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

#endif
