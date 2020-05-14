#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct scoutfs_block_writer {
	spinlock_t lock;
	struct list_head dirty_list;
	u64 nr_dirty_blocks;
};

struct scoutfs_block {
	u64 blkno;
	void *data;
	void *priv;
};

__le32 scoutfs_block_calc_crc(struct scoutfs_block_header *hdr, u32 size);
bool scoutfs_block_valid_crc(struct scoutfs_block_header *hdr, u32 size);
bool scoutfs_block_valid_ref(struct super_block *sb,
			     struct scoutfs_block_header *hdr,
			     __le64 seq, __le64 blkno);

struct scoutfs_block *scoutfs_block_create(struct super_block *sb, u64 blkno);
struct scoutfs_block *scoutfs_block_read(struct super_block *sb, u64 blkno);
void scoutfs_block_invalidate(struct super_block *sb, struct scoutfs_block *bl);
bool scoutfs_block_consistent_ref(struct super_block *sb,
				  struct scoutfs_block *bl,
				  __le64 seq, __le64 blkno, u32 magic);
void scoutfs_block_put(struct super_block *sb, struct scoutfs_block *bl);

void scoutfs_block_writer_init(struct super_block *sb,
			       struct scoutfs_block_writer *wri);
void scoutfs_block_writer_mark_dirty(struct super_block *sb,
				     struct scoutfs_block_writer *wri,
				     struct scoutfs_block *bl);
bool scoutfs_block_writer_is_dirty(struct super_block *sb,
				   struct scoutfs_block *bl);
int scoutfs_block_writer_write(struct super_block *sb,
			       struct scoutfs_block_writer *wri);
void scoutfs_block_writer_forget_all(struct super_block *sb,
				     struct scoutfs_block_writer *wri);
void scoutfs_block_writer_forget(struct super_block *sb,
			         struct scoutfs_block_writer *wri,
				 struct scoutfs_block *bl);
bool scoutfs_block_writer_has_dirty(struct super_block *sb,
				    struct scoutfs_block_writer *wri);
u64 scoutfs_block_writer_dirty_bytes(struct super_block *sb,
				     struct scoutfs_block_writer *wri);

int scoutfs_block_read_sm(struct super_block *sb, u64 blkno,
			  struct scoutfs_block_header *hdr, size_t len,
			  __le32 *blk_crc);
int scoutfs_block_write_sm(struct super_block *sb, u64 blkno,
			   struct scoutfs_block_header *hdr, size_t len);

int scoutfs_block_setup(struct super_block *sb);
void scoutfs_block_destroy(struct super_block *sb);

#endif
