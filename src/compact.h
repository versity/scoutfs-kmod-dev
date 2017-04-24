#ifndef _SCOUTFS_COMPACT_H_
#define _SCOUTFS_COMPACT_H_

void scoutfs_compact_kick(struct super_block *sb);

void scoutfs_compact_describe(struct super_block *sb, void *data,
			      u8 upper_level, u8 last_level);
int scoutfs_compact_add(struct super_block *sb, void *data,
			struct scoutfs_key_buf *first,
			struct scoutfs_key_buf *last, u64 segno, u64 seq,
			u8 level);
void scoutfs_compact_add_segno(struct super_block *sb, void *data, u64 segno);
int scoutfs_compact_commit(struct super_block *sb, void *c, void *r);

int scoutfs_compact_setup(struct super_block *sb);
void scoutfs_compact_destroy(struct super_block *sb);

#endif
