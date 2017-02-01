#ifndef _SCOUTFS_ALLOC_H_
#define _SCOUTFS_ALLOC_H_

struct scoutfs_alloc_region;

int scoutfs_alloc_segno(struct super_block *sb, u64 *segno);
int scoutfs_alloc_free(struct super_block *sb, u64 segno);

int scoutfs_alloc_has_dirty(struct super_block *sb);
int scoutfs_alloc_dirty_ring(struct super_block *sb);
u64 scoutfs_alloc_bfree(struct super_block *sb);

int scoutfs_alloc_setup(struct super_block *sb);
void scoutfs_alloc_destroy(struct super_block *sb);

#endif
