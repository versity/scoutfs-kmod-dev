#ifndef _SCOUTFS_DIR_H_
#define _SCOUTFS_DIR_H_

extern const struct file_operations scoutfs_dir_fops;
extern const struct inode_operations scoutfs_dir_iops;

int scoutfs_dir_init(void);
void scoutfs_dir_exit(void);

#endif
