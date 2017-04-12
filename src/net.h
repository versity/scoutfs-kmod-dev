#ifndef _SCOUTFS_NET_H_
#define _SCOUTFS_NET_H_

int scoutfs_net_trade_time(struct super_block *sb);
int scoutfs_net_alloc_inodes(struct super_block *sb);

int scoutfs_net_setup(struct super_block *sb);
void scoutfs_net_destroy(struct super_block *sb);

#endif
