#ifndef _SCOUTFS_TRANS_H_
#define _SCOUTFS_TRANS_H_

void scoutfs_trans_write_func(struct work_struct *work);
int scoutfs_sync_fs(struct super_block *sb, int wait);

int scoutfs_hold_trans(struct super_block *sb);
void scoutfs_release_trans(struct super_block *sb);

int scoutfs_setup_trans(struct super_block *sb);
void scoutfs_shutdown_trans(struct super_block *sb);

#endif
