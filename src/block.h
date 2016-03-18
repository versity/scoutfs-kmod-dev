#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct buffer_head *scoutfs_read_block(struct super_block *sb, u64 blkno);
struct buffer_head *scoutfs_dirty_bh(struct super_block *sb, u64 blkno);
struct buffer_head *scoutfs_dirty_block(struct super_block *sb, u64 blkno);
void scoutfs_calc_hdr_crc(struct buffer_head *bh);

#endif
