#ifndef _SCOUTFS_SEGMENT_H_
#define _SCOUTFS_SEGMENT_H_

int scoutfs_read_item(struct super_block *sb, struct scoutfs_key *key);
int scoutfs_read_next_item(struct super_block *sb,
			   struct scoutfs_key *first_key);
int scoutfs_write_dirty_items(struct super_block *sb);

#endif
