#ifndef _SCOUTFS_MSG_H_
#define _SCOUTFS_MSG_H_

#include "key.h"

void __printf(4, 5) scoutfs_msg(struct super_block *sb, const char *prefix,
				const char *str, const char *fmt, ...);

/*
 * The _sk variants wrap the message in the SK_PCPU calls which safely
 * manage the use of per-cpu key buffers in the arguments.
 */

#define scoutfs_err(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_ERR, " error", fmt, ##args)

#define scoutfs_err_sk(sb, fmt, args...) \
	SK_PCPU(scoutfs_err(sb, fmt, ##args))

#define scoutfs_warn(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_WARNING, " warning", fmt, ##args)

#define scoutfs_warn_sk(sb, fmt, args...) \
	SK_PCPU(scoutfs_warn(sb, fmt, ##args))

#define scoutfs_info(sb, fmt, args...) \
	scoutfs_msg(sb, KERN_INFO, "", fmt, ##args)

#define scoutfs_info_sk(sb, fmt, args...) \
	SK_PCPU(scoutfs_info(sb, fmt, ##args))

#endif
