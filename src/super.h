#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/rbtree.h>
#include "format.h"

struct scoutfs_manifest;

struct scoutfs_sb_info {
	struct scoutfs_super_block super;

	atomic64_t next_ino;
	atomic64_t next_blkno;

	spinlock_t item_lock;
	struct rb_root item_root;
	struct rb_root dirty_item_root;

	struct scoutfs_manifest *mani;

	__le64 *chunk_alloc_bits;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

#endif
