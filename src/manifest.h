#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

int scoutfs_setup_manifest(struct super_block *sb);
void scoutfs_destroy_manifest(struct super_block *sb);

int scoutfs_add_manifest(struct super_block *sb,
		         struct scoutfs_ring_manifest_entry *ment);
void scoutfs_delete_manifest(struct super_block *sb, u64 blkno);

bool scoutfs_next_manifest_segment(struct super_block *sb,
				   struct scoutfs_key *key,
				   struct scoutfs_ring_manifest_entry *ment);

#endif
