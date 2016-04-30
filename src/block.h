#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

#include <linux/fs.h>
#include <linux/rwlock.h>
#include <linux/atomic.h>

#define SCOUTFS_BLOCK_BIT_UPTODATE (1 << 0)
#define SCOUTFS_BLOCK_BIT_ERROR (1 << 1)

struct scoutfs_block {
	struct rw_semaphore rwsem;
	atomic_t refcount;
	u64 blkno;

	unsigned long bits;

	struct super_block *sb;
	/* only high order page alloc for now */
	struct page *page;
	void *data;
};

struct scoutfs_block *scoutfs_read_block(struct super_block *sb, u64 blkno);
struct scoutfs_block *scoutfs_new_block(struct super_block *sb, u64 blkno);
struct scoutfs_block *scoutfs_alloc_block(struct super_block *sb);

struct scoutfs_block *scoutfs_read_ref(struct super_block *sb,
				       struct scoutfs_block_ref *ref);
struct scoutfs_block *scoutfs_dirty_ref(struct super_block *sb,
				        struct scoutfs_block_ref *ref);

int scoutfs_has_dirty_blocks(struct super_block *sb);
int scoutfs_write_block(struct scoutfs_block *bl);
int scoutfs_write_dirty_blocks(struct super_block *sb);

void scoutfs_put_block(struct scoutfs_block *bl);

void scoutfs_calc_hdr_crc(struct scoutfs_block *bl);
void scoutfs_zero_block_tail(struct scoutfs_block *bl, size_t off);

#endif
