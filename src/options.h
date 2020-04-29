#ifndef	_SCOUTFS_OPTIONS_H_
#define	_SCOUTFS_OPTIONS_H_

#include <linux/fs.h>
#include <linux/in.h>
#include "format.h"

enum {
	Opt_server_addr,
	Opt_err,
};

struct mount_options {
	struct sockaddr_in server_addr;
};

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed);
int scoutfs_options_setup(struct super_block *sb);
void scoutfs_options_destroy(struct super_block *sb);

u32 scoutfs_option_u32(struct super_block *sb, int token);
#define scoutfs_option_bool scoutfs_option_u32

#endif	/* _SCOUTFS_OPTIONS_H_ */
