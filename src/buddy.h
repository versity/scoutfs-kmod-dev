#ifndef _SCOUTFS_BUDDY_H_
#define _SCOUTFS_BUDDY_H_

int scoutfs_buddy_alloc(struct super_block *sb, u64 *blkno, int order);
int scoutfs_buddy_alloc_same(struct super_block *sb, u64 *blkno, int order,
			     u64 existing);
int scoutfs_buddy_free(struct super_block *sb, u64 blkno, int order);

#endif
