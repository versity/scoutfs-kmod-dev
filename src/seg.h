#ifndef _SCOUTFS_SEG_H_
#define _SCOUTFS_SEG_H_

struct scoutfs_segment;
struct kvec;

struct scoutfs_segment *scoutfs_seg_submit_read(struct super_block *sb,
						u64 segno);
int scoutfs_seg_wait(struct super_block *sb, struct scoutfs_segment *seg);

int scoutfs_seg_find_pos(struct scoutfs_segment *seg, struct kvec *key);
int scoutfs_seg_item_kvecs(struct scoutfs_segment *seg, int pos,
			   struct kvec *key, struct kvec *val);

void scoutfs_seg_put(struct scoutfs_segment *seg);

int scoutfs_seg_setup(struct super_block *sb);
void scoutfs_seg_destroy(struct super_block *sb);

#endif
