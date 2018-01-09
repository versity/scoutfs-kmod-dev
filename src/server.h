#ifndef _SCOUTFS_SERVER_H_
#define _SCOUTFS_SERVER_H_

void scoutfs_init_ment_to_net(struct scoutfs_net_manifest_entry *net_ment,
			      struct scoutfs_manifest_entry *ment);
void scoutfs_init_ment_from_net(struct scoutfs_manifest_entry *ment,
				struct scoutfs_net_manifest_entry *net_ment);

int scoutfs_client_get_compaction(struct super_block *sb, void *curs);
int scoutfs_client_finish_compaction(struct super_block *sb, void *curs,
				     void *list);

int scoutfs_server_setup(struct super_block *sb);
void scoutfs_server_destroy(struct super_block *sb);

#endif
