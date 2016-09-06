#ifndef _SCOUTFS_BUDDY_H_
#define _SCOUTFS_BUDDY_H_

int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order);
int scoutfs_buddy_alloc_same(struct super_block *sb, u64 *blkno, int order,
			     u64 existing);
int scoutfs_buddy_free(struct super_block *sb, u64 blkno, int order);
void scoutfs_buddy_free_extent(struct super_block *sb, u64 blkno, u64 count);

int scoutfs_buddy_was_free(struct super_block *sb, u64 blkno, int order);
int scoutfs_buddy_bfree(struct super_block *sb, u64 *bfree);

unsigned int scoutfs_buddy_alloc_count(struct super_block *sb);
void scoutfs_buddy_reset_count(struct super_block *sb);

#endif
