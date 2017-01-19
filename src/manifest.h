#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

struct scoutfs_key_buf;

int scoutfs_manifest_add(struct super_block *sb,
			 struct scoutfs_key_buf *first,
			 struct scoutfs_key_buf *last, u64 segno, u64 seq,
			 u8 level);
int scoutfs_manifest_dirty(struct super_block *sb,
			   struct scoutfs_key_buf *first, u64 seq, u8 level);
int scoutfs_manifest_del(struct super_block *sb, struct scoutfs_key_buf *first,
			 u64 seq, u8 level);
int scoutfs_manifest_has_dirty(struct super_block *sb);
int scoutfs_manifest_dirty_ring(struct super_block *sb);

int scoutfs_manifest_lock(struct super_block *sb);
int scoutfs_manifest_unlock(struct super_block *sb);

int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key_buf *key,
				struct scoutfs_key_buf *end);

u64 scoutfs_manifest_level_count(struct super_block *sb, u8 level);
int scoutfs_manifest_next_compact(struct super_block *sb, void *data);

int scoutfs_manifest_setup(struct super_block *sb);
void scoutfs_manifest_destroy(struct super_block *sb);

#endif
