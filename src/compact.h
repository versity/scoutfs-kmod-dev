#ifndef _SCOUTFS_COMPACT_H_
#define _SCOUTFS_COMPACT_H_

int scoutfs_compact(struct super_block *sb,
		    struct scoutfs_net_compact_request *req,
		    struct scoutfs_net_compact_response *resp);

#endif
