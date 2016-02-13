#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/rbtree.h>
#include "format.h"

struct scoutfs_sb_info {
	struct scoutfs_super super;

	atomic64_t next_ino;
	atomic64_t next_blkno;

	__le64 bloom_hash_keys[6]; /* XXX */

	spinlock_t item_lock;
	struct rb_root item_root;
	struct rb_root dirty_item_root;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

#endif
