#ifndef _SCOUTFS_BUDDY_H_
#define _SCOUTFS_BUDDY_H_

int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order);
int scoutfs_buddy_free(struct super_block *sb, u64 blkno, int order);

int scoutfs_read_buddy_chunks(struct super_block *sb);
void scoutfs_reset_buddy_chunks(struct super_block *sb);
int scoutfs_dirty_buddy_chunks(struct super_block *sb);

#endif
