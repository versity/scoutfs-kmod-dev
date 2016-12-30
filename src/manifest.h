#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

int scoutfs_manifest_add(struct super_block *sb, struct kvec *first,
			 struct kvec *last, u64 segno, u64 seq, u8 level);
int scoutfs_manifest_has_dirty(struct super_block *sb);
int scoutfs_manifest_dirty_ring(struct super_block *sb);

int scoutfs_manifest_read_items(struct super_block *sb, struct kvec *key,
				struct kvec *until);

int scoutfs_manifest_setup(struct super_block *sb);
void scoutfs_manifest_destroy(struct super_block *sb);

#endif
