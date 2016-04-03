#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

int scoutfs_setup_manifest(struct super_block *sb);
void scoutfs_destroy_manifest(struct super_block *sb);

int scoutfs_insert_manifest(struct super_block *sb,
			    struct scoutfs_manifest_entry *ment);
void scoutfs_delete_manifest(struct super_block *sb,
			     struct scoutfs_manifest_entry *ment);
int scoutfs_finalize_manifest(struct super_block *sb,
			      struct scoutfs_manifest_entry *existing,
			      struct scoutfs_manifest_entry *updated);

int scoutfs_manifest_find_key(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_manifest_entry **ments_ret);

#endif
