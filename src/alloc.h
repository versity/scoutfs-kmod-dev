#ifndef _SCOUTFS_ALLOC_H_
#define _SCOUTFS_ALLOC_H_

#include "ext.h"

/*
 * These are implementation-specific metrics, they don't need to be
 * consistent across implementations.  They should probably be run-time
 * knobs.
 */

/*
 * The largest extent that we'll try to allocate with fallocate.  We're
 * trying not to completely consume a transactions data allocation all
 * at once.  This is only allocation granularity, repeated allocations
 * can produce large contiguous extents.
 */
#define SCOUTFS_FALLOCATE_ALLOC_LIMIT \
	(128ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * The largest aligned region that we'll try to allocate at the end of
 * the file as it's extended.  This is also limited to the current file
 * size so we can only waste at most twice the total file size when
 * files are less than this.  We try to keep this around the point of
 * diminishing returns in streaming performance of common data devices
 * to limit waste.
 */
#define SCOUTFS_DATA_EXTEND_PREALLOC_LIMIT \
	(8ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Small data allocations are satisfied by cached extents stored in
 * the run-time alloc struct to minimize item operations for small
 * block allocations.  Large allocations come directly from btree
 * extent items, and this defines the threshold beetwen them.
 */
#define SCOUTFS_ALLOC_DATA_LG_THRESH \
	(8ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Fill client alloc roots to the target when they fall below the lo
 * threshold.
 */
#define SCOUTFS_SERVER_META_FILL_TARGET \
	(256ULL * 1024 * 1024 >> SCOUTFS_BLOCK_LG_SHIFT)
#define SCOUTFS_SERVER_META_FILL_LO \
	(64ULL * 1024 * 1024 >> SCOUTFS_BLOCK_LG_SHIFT)
#define SCOUTFS_SERVER_DATA_FILL_TARGET \
	(4ULL * 1024 * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)
#define SCOUTFS_SERVER_DATA_FILL_LO \
	(1ULL * 1024 * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Each of the server meta_alloc roots will try to keep a minimum amount
 * of free blocks.  The server will use the next root once its current
 * root gets this low.  It must have room for all the largest allocation
 * attempted in a transaction on the server.
 */
#define SCOUTFS_SERVER_META_ALLOC_MIN \
	(SCOUTFS_SERVER_META_FILL_TARGET * 2)

/*
 * A run-time use of a pair of persistent avail/freed roots as a
 * metadata allocator.  It has the machinery needed to lock and avoid
 * recursion when dirtying the list blocks that are used during the
 * transaction.
 */
struct scoutfs_alloc {
	spinlock_t lock;
	struct mutex mutex;
	struct scoutfs_block *dirty_avail_bl;
	struct scoutfs_block *dirty_freed_bl;
	struct scoutfs_alloc_list_head avail;
	struct scoutfs_alloc_list_head freed;
};

void scoutfs_alloc_init(struct scoutfs_alloc *alloc,
			struct scoutfs_alloc_list_head *avail,
			struct scoutfs_alloc_list_head *freed);
int scoutfs_alloc_prepare_commit(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri);

int scoutfs_alloc_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri, u64 *blkno);
int scoutfs_free_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri, u64 blkno);

int scoutfs_alloc_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *root,
		       struct scoutfs_extent *cached, u64 count,
		       u64 *blkno_ret, u64 *count_ret);
int scoutfs_free_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_alloc_root *root, u64 blkno, u64 count);

int scoutfs_alloc_move(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *dst,
		       struct scoutfs_alloc_root *src, u64 total);

int scoutfs_alloc_fill_list(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_alloc_list_head *lhead,
			    struct scoutfs_alloc_root *root,
			    u64 lo, u64 target);
int scoutfs_alloc_empty_list(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_alloc_root *root,
			     struct scoutfs_alloc_list_head *lhead);
int scoutfs_alloc_splice_list(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_alloc_list_head *dst,
			      struct scoutfs_alloc_list_head *src);

bool scoutfs_alloc_meta_lo_thresh(struct super_block *sb,
				  struct scoutfs_alloc *alloc);

#endif
