#ifndef _SCOUTFS_BUDDY_H_
#define _SCOUTFS_BUDDY_H_

int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order);
int scoutfs_buddy_alloc_same(struct super_block *sb, u64 *blkno, u64 existing);
int scoutfs_buddy_free(struct super_block *sb, __le64 seq, u64 blkno,
		       int order);
void scoutfs_buddy_free_extent(struct super_block *sb, u64 blkno, u64 count);

int scoutfs_buddy_was_free(struct super_block *sb, u64 blkno, int order);
u64 scoutfs_buddy_bfree(struct super_block *sb);

unsigned int scoutfs_buddy_alloc_count(struct super_block *sb);
int scoutfs_buddy_apply_pending(struct super_block *sb, bool alloc);
void scoutfs_buddy_committed(struct super_block *sb);

int scoutfs_buddy_setup(struct super_block *sb);
void scoutfs_buddy_destroy(struct super_block *sb);

#endif
