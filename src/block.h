#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct scoutfs_block;

#include <linux/fs.h>

struct scoutfs_block *scoutfs_block_read(struct super_block *sb, u64 blkno);
struct scoutfs_block *scoutfs_block_read_ref(struct super_block *sb,
					   struct scoutfs_block_ref *ref);

struct scoutfs_block *scoutfs_block_dirty(struct super_block *sb, u64 blkno);
struct scoutfs_block *scoutfs_block_dirty_alloc(struct super_block *sb);
struct scoutfs_block *scoutfs_block_dirty_ref(struct super_block *sb,
					    struct scoutfs_block_ref *ref);

int scoutfs_block_has_dirty(struct super_block *sb);
int scoutfs_block_write_dirty(struct super_block *sb);

void scoutfs_block_set_crc(struct scoutfs_block *bl);
void scoutfs_block_zero(struct scoutfs_block *bl, size_t off);
void scoutfs_block_zero_from(struct scoutfs_block *bl, void *ptr);

void scoutfs_block_set_lock_class(struct scoutfs_block *bl,
			          struct lock_class_key *class);
void scoutfs_block_lock(struct scoutfs_block *bl, bool write, int subclass);
void scoutfs_block_unlock(struct scoutfs_block *bl, bool write);

void scoutfs_block_forget(struct super_block *sb, u64 blkno);

void *scoutfs_block_data(struct scoutfs_block *bl);
void *scoutfs_block_data_from_contents(const void *ptr);
void scoutfs_block_put(struct scoutfs_block *bl);

#endif
