#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct buffer_head *scoutfs_read_block(struct super_block *sb, u64 blkno);
struct buffer_head *scoutfs_read_block_off(struct super_block *sb, u64 blkno,
					   u32 off);
struct buffer_head *scoutfs_new_block(struct super_block *sb, u64 blkno);
void scoutfs_calc_hdr_crc(struct buffer_head *bh);

#endif
