#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

int scoutfs_setup_manifest(struct super_block *sb);
void scoutfs_destroy_manifest(struct super_block *sb);

int scoutfs_add_manifest(struct super_block *sb,
		         struct scoutfs_ring_manifest_entry *ment);
int scoutfs_new_manifest(struct super_block *sb,
			 struct scoutfs_ring_manifest_entry *ment);
void scoutfs_delete_manifest(struct super_block *sb, u64 blkno);

bool scoutfs_foreach_range_segment(struct super_block *sb,
				   struct scoutfs_key *first,
				   struct scoutfs_key *last,
				   struct scoutfs_ring_manifest_entry *ment);

#endif
