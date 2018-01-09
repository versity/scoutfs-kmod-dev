#ifndef _SCOUTFS_TRANS_H_
#define _SCOUTFS_TRANS_H_

#include "count.h"

void scoutfs_trans_write_func(struct work_struct *work);
int scoutfs_trans_sync(struct super_block *sb, int wait);
int scoutfs_file_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync);
void scoutfs_trans_restart_sync_deadline(struct super_block *sb);

int scoutfs_hold_trans(struct super_block *sb,
		       const struct scoutfs_item_count cnt);
bool scoutfs_trans_held(void);
void scoutfs_release_trans(struct super_block *sb);
void scoutfs_trans_track_item(struct super_block *sb, signed items,
			      signed vals);

int scoutfs_setup_trans(struct super_block *sb);
void scoutfs_shutdown_trans(struct super_block *sb);

#endif
