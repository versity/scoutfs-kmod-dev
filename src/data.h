#ifndef _SCOUTFS_FILERW_H_
#define _SCOUTFS_FILERW_H_

extern const struct address_space_operations scoutfs_file_aops;
extern const struct file_operations scoutfs_file_fops;

int scoutfs_data_truncate_items(struct super_block *sb, u64 ino, u64 iblock,
				u64 len, bool offline);

int scoutfs_data_setup(struct super_block *sb);
void scoutfs_data_destroy(struct super_block *sb);

#endif
