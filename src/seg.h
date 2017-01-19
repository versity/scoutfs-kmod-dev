#ifndef _SCOUTFS_SEG_H_
#define _SCOUTFS_SEG_H_

struct scoutfs_bio_completion;
struct scoutfs_segment;
struct scoutfs_key_buf;
struct kvec;

struct scoutfs_segment *scoutfs_seg_submit_read(struct super_block *sb,
						u64 segno);
int scoutfs_seg_wait(struct super_block *sb, struct scoutfs_segment *seg);

int scoutfs_seg_find_pos(struct scoutfs_segment *seg,
			 struct scoutfs_key_buf *key);
int scoutfs_seg_item_ptrs(struct scoutfs_segment *seg, int pos,
			  struct scoutfs_key_buf *key, struct kvec *val);

void scoutfs_seg_get(struct scoutfs_segment *seg);
void scoutfs_seg_put(struct scoutfs_segment *seg);

int scoutfs_seg_alloc(struct super_block *sb, struct scoutfs_segment **seg_ret);
int scoutfs_seg_free_segno(struct super_block *sb,
			   struct scoutfs_segment *seg);
bool scoutfs_seg_fits_single(u32 nr_items, u32 key_bytes, u32 val_bytes);
void scoutfs_seg_first_item(struct super_block *sb, struct scoutfs_segment *seg,
			    struct scoutfs_key_buf *key, struct kvec *val,
			    unsigned int nr_items, unsigned int key_bytes);
void scoutfs_seg_append_item(struct super_block *sb,
			     struct scoutfs_segment *seg,
			     struct scoutfs_key_buf *key, struct kvec *val);
int scoutfs_seg_manifest_add(struct super_block *sb,
			     struct scoutfs_segment *seg, u8 level);
int scoutfs_seg_manifest_del(struct super_block *sb,
			     struct scoutfs_segment *seg, u8 level);

int scoutfs_seg_submit_write(struct super_block *sb,
			     struct scoutfs_segment *seg,
			     struct scoutfs_bio_completion *comp);

int scoutfs_seg_setup(struct super_block *sb);
void scoutfs_seg_destroy(struct super_block *sb);

#endif
