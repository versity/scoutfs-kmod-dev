#ifndef _SCOUTFS_BALLOC_H_
#define _SCOUTFS_BALLOC_H_

#include "per_task.h"

struct scoutfs_block_writer;

struct scoutfs_balloc_allocator {
	struct mutex mutex;
	struct scoutfs_per_task pt_caller_blknos;
	struct scoutfs_balloc_root alloc_root;
	struct scoutfs_balloc_root free_root;
};

void scoutfs_balloc_init(struct scoutfs_balloc_allocator *alloc,
			 struct scoutfs_balloc_root *alloc_root,
			 struct scoutfs_balloc_root *free_root);
int scoutfs_balloc_add_alloc_bulk(struct super_block *sb,
				  struct scoutfs_balloc_allocator *alloc,
				  struct scoutfs_block_writer *wri,
				  u64 blkno, u64 count);
int scoutfs_balloc_alloc(struct super_block *sb,
			 struct scoutfs_balloc_allocator *alloc,
			 struct scoutfs_block_writer *wri, u64 *blkno_ret);
int scoutfs_balloc_free(struct super_block *sb,
			struct scoutfs_balloc_allocator *alloc,
			struct scoutfs_block_writer *wri,
			u64 blkno);
int scoutfs_balloc_move(struct super_block *sb,
			struct scoutfs_balloc_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_balloc_root *dst,
			struct scoutfs_balloc_root *src,
			u64 from, u64 at_least, u64 *next_past);

#endif
