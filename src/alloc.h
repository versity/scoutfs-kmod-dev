#ifndef _SCOUTFS_ALLOC_H_
#define _SCOUTFS_ALLOC_H_

struct scoutfs_alloc_region;
struct scoutfs_bio_completion;

int scoutfs_alloc_segno(struct super_block *sb, u64 *segno);
int scoutfs_alloc_free(struct super_block *sb, u64 segno);

int scoutfs_alloc_has_dirty(struct super_block *sb);
int scoutfs_alloc_submit_write(struct super_block *sb,
			       struct scoutfs_bio_completion *comp);
void scoutfs_alloc_write_complete(struct super_block *sb);
u64 scoutfs_alloc_bfree(struct super_block *sb);

int scoutfs_alloc_setup(struct super_block *sb);
void scoutfs_alloc_destroy(struct super_block *sb);

#endif
