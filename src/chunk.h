#ifndef _SCOUTFS_CHUNK_H_
#define _SCOUTFS_CHUNK_H_

void scoutfs_set_chunk_alloc_bits(struct super_block *sb,
				  struct scoutfs_ring_bitmap *bm);
int scoutfs_alloc_chunk(struct super_block *sb, u64 *blkno);

#endif
