#ifndef _SCOUTFS_FILERW_H_
#define _SCOUTFS_FILERW_H_

extern const struct address_space_operations scoutfs_file_aops;
extern const struct file_operations scoutfs_file_fops;

void scoutfs_filerw_free_alloc(struct super_block *sb);
int scoutfs_truncate_extent_items(struct super_block *sb, u64 ino, u64 iblock,
				  u64 len, bool offline);

#endif
