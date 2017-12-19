#ifndef _SCOUTFS_SYSFS_H_
#define _SCOUTFS_SYSFS_H_

struct kobject *scoutfs_sysfs_sb_dir(struct super_block *sb);

int scoutfs_setup_sysfs(struct super_block *sb);
void scoutfs_destroy_sysfs(struct super_block *sb);

int __init scoutfs_sysfs_init(void);
void __exit scoutfs_sysfs_exit(void);

#endif
