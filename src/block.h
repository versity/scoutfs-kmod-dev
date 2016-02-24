#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct buffer_head *scoutfs_read_block(struct super_block *sb, u64 blkno);

#endif
