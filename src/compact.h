#ifndef _SCOUTFS_COMPACT_H_
#define _SCOUTFS_COMPACT_H_

void scoutfs_compact_kick(struct super_block *sb);

int scoutfs_compact_add(struct super_block *sb, void *data, struct kvec *first,
			u64 segno, u64 seq, u8 level);

int scoutfs_compact_setup(struct super_block *sb);
void scoutfs_compact_destroy(struct super_block *sb);

#endif
