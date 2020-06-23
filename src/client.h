#ifndef _SCOUTFS_CLIENT_H_
#define _SCOUTFS_CLIENT_H_

int scoutfs_client_alloc_inodes(struct super_block *sb, u64 count,
				u64 *ino, u64 *nr);
int scoutfs_client_get_log_trees(struct super_block *sb,
				 struct scoutfs_log_trees *lt);
int scoutfs_client_commit_log_trees(struct super_block *sb,
				    struct scoutfs_log_trees *lt);
int scoutfs_client_get_roots(struct super_block *sb,
			     struct scoutfs_net_roots *roots);
u64 *scoutfs_client_bulk_alloc(struct super_block *sb);
int scoutfs_client_advance_seq(struct super_block *sb, u64 *seq);
int scoutfs_client_get_last_seq(struct super_block *sb, u64 *seq);
int scoutfs_client_statfs(struct super_block *sb,
			  struct scoutfs_net_statfs *nstatfs);
int scoutfs_client_lock_request(struct super_block *sb,
				struct scoutfs_net_lock *nl);
int scoutfs_client_lock_response(struct super_block *sb, u64 net_id,
				struct scoutfs_net_lock *nl);
int scoutfs_client_lock_recover_response(struct super_block *sb, u64 net_id,
					 struct scoutfs_net_lock_recover *nlr);
int scoutfs_client_srch_get_compact(struct super_block *sb,
				    struct scoutfs_srch_compact_input *scin);
int scoutfs_client_srch_commit_compact(struct super_block *sb,
				struct scoutfs_srch_compact_result *scres);

int scoutfs_client_setup(struct super_block *sb);
void scoutfs_client_destroy(struct super_block *sb);

#endif
