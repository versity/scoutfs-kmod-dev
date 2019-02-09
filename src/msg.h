#ifndef _SCOUTFS_MSG_H_
#define _SCOUTFS_MSG_H_

#include <linux/bitops.h>
#include "key.h"
#include "counters.h"

void __printf(4, 5) scoutfs_msg(struct super_block *sb, const char *prefix,
				const char *str, const char *fmt, ...);

#define scoutfs_msg_check(sb, pref, str, fmt, args...)	\
do {							\
	BUILD_BUG_ON(fmt[sizeof(fmt) - 2] == '\n');	\
	scoutfs_msg(sb, pref, str, fmt, ##args);	\
} while (0)

#define scoutfs_err(sb, fmt, args...) \
	scoutfs_msg_check(sb, KERN_ERR, " error", fmt, ##args)

#define scoutfs_warn(sb, fmt, args...) \
	scoutfs_msg_check(sb, KERN_WARNING, " warning", fmt, ##args)

#define scoutfs_info(sb, fmt, args...) \
	scoutfs_msg_check(sb, KERN_INFO, "", fmt, ##args)

#define scoutfs_bug_on(sb, cond, fmt, args...)				\
do {									\
	if (cond) {							\
		scoutfs_err(sb, "(" __stringify(cond) "), " fmt, ##args); \
		BUG();							\
	}								\
} while (0)								\

/*
 * Each message is only generated once per volume.  Remounting resets
 * the messages.
 */
#define scoutfs_corruption(sb, which, counter, fmt, args...)		\
do {									\
	__typeof__(sb) _sb = (sb);					\
	struct scoutfs_sb_info *_sbi = SCOUTFS_SB(_sb);			\
	unsigned int _bit = (which);					\
									\
	if (WARN_ON_ONCE(_bit >= SC_NR_SOURCES))			\
		break;							\
									\
	scoutfs_inc_counter(_sb, counter);				\
	if (!test_and_set_bit(_bit, _sbi->corruption_messages_once)) {	\
		scoutfs_err(_sb, "corruption (see scoutfs-corruption(5)): " \
			    #which ": " fmt, ##args);			\
		dump_stack();						\
	}								\
} while (0)								\

#endif
