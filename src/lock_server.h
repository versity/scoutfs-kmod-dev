#ifndef _SCOUTFS_LOCK_SERVER_H_
#define _SCOUTFS_LOCK_SERVER_H_

int scoutfs_lock_server_recover_response(struct super_block *sb, u64 rid,
					 struct scoutfs_net_lock_recover *nlr);
int scoutfs_lock_server_request(struct super_block *sb, u64 rid,
				u64 net_id, struct scoutfs_net_lock *nl);
int scoutfs_lock_server_greeting(struct super_block *sb, u64 rid,
				 bool should_exist);
int scoutfs_lock_server_response(struct super_block *sb, u64 rid,
				 struct scoutfs_net_lock *nl);
int scoutfs_lock_server_farewell(struct super_block *sb, u64 rid);

int scoutfs_lock_server_setup(struct super_block *sb);
void scoutfs_lock_server_destroy(struct super_block *sb);

#endif
