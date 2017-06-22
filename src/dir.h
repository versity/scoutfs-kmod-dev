#ifndef _SCOUTFS_DIR_H_
#define _SCOUTFS_DIR_H_

#include "format.h"

extern const struct file_operations scoutfs_dir_fops;
extern const struct inode_operations scoutfs_dir_iops;
extern const struct inode_operations scoutfs_symlink_iops;

struct scoutfs_link_backref_entry {
	struct list_head head;
	u16 name_len;
	struct scoutfs_link_backref_key lbkey;
};

int scoutfs_dir_get_backref_path(struct super_block *sb, u64 target_ino,
				 u64 dir_ino, char *name, u16 name_len,
				 struct list_head *list);
void scoutfs_dir_free_backref_path(struct super_block *sb,
				   struct list_head *list);

int scoutfs_symlink_drop(struct super_block *sb, u64 ino, u64 i_size);

int scoutfs_dir_init(void);
void scoutfs_dir_exit(void);

#endif
