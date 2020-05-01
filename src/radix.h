#ifndef _SCOUTFS_RADIX_H_
#define _SCOUTFS_RADIX_H_

#include "per_task.h"

struct scoutfs_block_writer;

struct scoutfs_radix_allocator {
	struct mutex mutex;
	struct scoutfs_radix_root avail;
	struct scoutfs_radix_root freed;
};

int scoutfs_radix_alloc(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri, u64 *blkno);
int scoutfs_radix_alloc_data(struct super_block *sb,
			     struct scoutfs_radix_allocator *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_radix_root *root,
			     int count, u64 *blkno_ret, int *count_ret);
int scoutfs_radix_free(struct super_block *sb,
		       struct scoutfs_radix_allocator *alloc,
		       struct scoutfs_block_writer *wri, u64 blkno);
int scoutfs_radix_free_data(struct super_block *sb,
			    struct scoutfs_radix_allocator *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_radix_root *root,
			    u64 blkno, int count);
int scoutfs_radix_merge(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_radix_root *dst,
			struct scoutfs_radix_root *src,
			struct scoutfs_radix_root *inp, bool meta, u64 count);
void scoutfs_radix_init_alloc(struct scoutfs_radix_allocator *alloc,
			      struct scoutfs_radix_root *avail,
			      struct scoutfs_radix_root *freed);
void scoutfs_radix_root_init(struct super_block *sb,
			     struct scoutfs_radix_root *root, bool meta);
u64 scoutfs_radix_root_free_blocks(struct super_block *sb,
				   struct scoutfs_radix_root *root);
u64 scoutfs_radix_bit_leaf_nr(u64 bit);

#endif
