#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

__le32 scoutfs_block_calc_crc(struct scoutfs_block_header *hdr);
bool scoutfs_block_valid_crc(struct scoutfs_block_header *hdr);
bool scoutfs_block_valid_ref(struct super_block *sb,
			     struct scoutfs_block_header *hdr,
			     __le64 seq, __le64 blkno);

#endif
