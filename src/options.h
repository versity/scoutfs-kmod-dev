#ifndef	_SCOUTFS_OPTIONS_H_
#define	_SCOUTFS_OPTIONS_H_

#include <linux/fs.h>
#include "format.h"

#define MAX_CLUSTER_NAME_LEN 17
struct mount_options
{
	struct scoutfs_inet_addr	listen_addr;
	char				cluster_name[MAX_CLUSTER_NAME_LEN];
};

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed);

#endif	/* _SCOUTFS_OPTIONS_H_ */
