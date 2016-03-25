#ifndef _SCOUTFS_SKIP_H_
#define _SCOUTFS_SKIP_H_

u8 scoutfs_skip_random_height(void);
int scoutfs_skip_insert(struct super_block *sb, u64 blkno,
			struct scoutfs_item *item, u32 off);
int scoutfs_skip_lookup(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key, struct buffer_head **bh,
			struct scoutfs_item **item);
int scoutfs_skip_search(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key, struct buffer_head **bh,
			struct scoutfs_item **item);
int scoutfs_skip_delete(struct super_block *sb, u64 blkno,
			struct scoutfs_key *key);
int scoutfs_skip_next(struct super_block *sb, u64 blkno,
		      struct buffer_head **bh, struct scoutfs_item **item);

#endif
