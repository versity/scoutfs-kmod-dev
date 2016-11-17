#ifndef _SCOUTFS_MSG_H_
#define _SCOUTFS_MSG_H_

void __printf(4, 5) scoutfs_msg(struct super_block *sb, const char *prefix,
				const char *str, const char *fmt, ...);

#define scoutfs_err(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_ERR, " error", fmt, ##args)

#define scoutfs_warn(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_WARNING, " warning", fmt, ##args)

#define scoutfs_info(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_INFO, "", fmt, ##args)

#endif
