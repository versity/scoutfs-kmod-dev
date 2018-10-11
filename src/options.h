#ifndef	_SCOUTFS_OPTIONS_H_
#define	_SCOUTFS_OPTIONS_H_

#include <linux/fs.h>
#include "format.h"

enum {
	/*
	 * For debugging we can quickly create huge trees by limiting
	 * the number of items in each block as though the blocks were tiny.
	 */
	Opt_btree_force_tiny_blocks,
	Opt_uniq_name,
	Opt_err,
};

struct mount_options {
	char uniq_name[SCOUTFS_UNIQUE_NAME_MAX_BYTES];
};

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed);
int scoutfs_options_setup(struct super_block *sb);
void scoutfs_options_destroy(struct super_block *sb);

u32 scoutfs_option_u32(struct super_block *sb, int token);
#define scoutfs_option_bool scoutfs_option_u32

#endif	/* _SCOUTFS_OPTIONS_H_ */
