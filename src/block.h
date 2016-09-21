#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

#include <linux/fs.h>
#include <linux/buffer_head.h>

struct buffer_head *scoutfs_block_read(struct super_block *sb, u64 blkno);
struct buffer_head *scoutfs_block_read_ref(struct super_block *sb,
					   struct scoutfs_block_ref *ref);

struct buffer_head *scoutfs_block_dirty(struct super_block *sb, u64 blkno);
struct buffer_head *scoutfs_block_dirty_alloc(struct super_block *sb);
struct buffer_head *scoutfs_block_dirty_ref(struct super_block *sb,
					    struct scoutfs_block_ref *ref);

int scoutfs_block_has_dirty(struct super_block *sb);
int scoutfs_block_write_dirty(struct super_block *sb);

void scoutfs_block_set_crc(struct buffer_head *bh);
void scoutfs_block_zero(struct buffer_head *bh, size_t off);

void scoutfs_block_set_lock_class(struct buffer_head *bh,
			          struct lock_class_key *class);
void scoutfs_block_lock(struct buffer_head *bh, bool write, int subclass);
void scoutfs_block_unlock(struct buffer_head *bh, bool write);

/* XXX seems like this should be upstream :) */
static inline void *bh_data(struct buffer_head *bh)
{
	return (void *)bh->b_data;
}

static inline void scoutfs_block_put(struct buffer_head *bh)
{
	if (!IS_ERR_OR_NULL(bh))
		brelse(bh);
}

#endif
