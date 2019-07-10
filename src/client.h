#ifndef _SCOUTFS_CLIENT_H_
#define _SCOUTFS_CLIENT_H_

int scoutfs_client_alloc_inodes(struct super_block *sb, u64 count,
				u64 *ino, u64 *nr);
int scoutfs_client_alloc_extent(struct super_block *sb, u64 blocks, u64 *start,
				u64 *len);
int scoutfs_client_free_extents(struct super_block *sb,
				struct scoutfs_net_extent_list *nexl);
int scoutfs_client_alloc_segno(struct super_block *sb, u64 *segno);
int scoutfs_client_record_segment(struct super_block *sb,
				  struct scoutfs_segment *seg, u8 level);
u64 *scoutfs_client_bulk_alloc(struct super_block *sb);
int scoutfs_client_advance_seq(struct super_block *sb, u64 *seq);
int scoutfs_client_get_last_seq(struct super_block *sb, u64 *seq);
int scoutfs_client_get_manifest_root(struct super_block *sb,
				     struct scoutfs_btree_root *root);
int scoutfs_client_statfs(struct super_block *sb,
			  struct scoutfs_net_statfs *nstatfs);
int scoutfs_client_lock_request(struct super_block *sb,
				struct scoutfs_net_lock *nl);
int scoutfs_client_lock_response(struct super_block *sb, u64 net_id,
				struct scoutfs_net_lock *nl);
int scoutfs_client_lock_recover_response(struct super_block *sb, u64 net_id,
					 struct scoutfs_net_lock_recover *nlr);

int scoutfs_client_setup(struct super_block *sb);
void scoutfs_client_destroy(struct super_block *sb);

#endif
