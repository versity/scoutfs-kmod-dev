#ifndef _SCOUTFS_NET_H_
#define _SCOUTFS_NET_H_

struct scoutfs_key_buf;

int scoutfs_net_trade_time(struct super_block *sb);
int scoutfs_net_alloc_inodes(struct super_block *sb);
int scoutfs_net_manifest_range_entries(struct super_block *sb,
				       struct scoutfs_key_buf *start,
				       struct scoutfs_key_buf *end,
				       struct list_head *list);

int scoutfs_net_setup(struct super_block *sb);
void scoutfs_net_destroy(struct super_block *sb);

#endif
