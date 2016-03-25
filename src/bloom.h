#ifndef _SCOUTFS_BLOOM_H_
#define _SCOUTFS_BLOOM_H_

struct scoutfs_bloom_bits {
	u16 bit_off[SCOUTFS_BLOOM_BITS];
	u8 block[SCOUTFS_BLOOM_BITS];
};

void scoutfs_calc_bloom_bits(struct scoutfs_bloom_bits *bits,
			     struct scoutfs_key *key, __le32 *salts);
int scoutfs_test_bloom_bits(struct super_block *sb, u64 blkno,
			    struct scoutfs_bloom_bits *bits);
int scoutfs_set_bloom_bits(struct super_block *sb, u64 blkno,
			   struct scoutfs_bloom_bits *bits);

#endif
