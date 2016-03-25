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

	spinlock_t chunk_alloc_lock;
	__le64 *chunk_alloc_bits;

	/* pinned dirty ring block during commit */
	struct buffer_head *dirty_ring_bh;
	struct scoutfs_ring_entry *dirty_ring_ent;
	unsigned int dirty_ring_ent_avail;

	/* pinned log segment during fs modifications */
	struct mutex dirty_mutex;
	u64 dirty_blkno;
	int dirty_item_off;
	int dirty_val_off;
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

int scoutfs_advance_dirty_super(struct super_block *sb);
int scoutfs_write_dirty_super(struct super_block *sb);

#endif
