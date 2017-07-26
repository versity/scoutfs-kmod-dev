#ifndef _SCOUTFS_SERVER_H_
#define _SCOUTFS_SERVER_H_

void scoutfs_init_net_ment_keys(struct scoutfs_net_manifest_entry *net_ment,
				struct scoutfs_key_buf *first,
				struct scoutfs_key_buf *last);
struct scoutfs_net_manifest_entry *
scoutfs_alloc_net_ment(struct scoutfs_manifest_entry *ment);
void scoutfs_init_ment_net_ment(struct scoutfs_manifest_entry *ment,
				struct scoutfs_net_manifest_entry *net_ment);
unsigned scoutfs_net_ment_bytes(struct scoutfs_net_manifest_entry *net_ment);

int scoutfs_client_get_compaction(struct super_block *sb, void *curs);
int scoutfs_client_finish_compaction(struct super_block *sb, void *curs,
				     void *list);

int scoutfs_server_setup(struct super_block *sb);
void scoutfs_server_destroy(struct super_block *sb);

#endif
