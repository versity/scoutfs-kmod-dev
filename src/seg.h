#ifndef _SCOUTFS_SEG_H_
#define _SCOUTFS_SEG_H_

struct scoutfs_bio_completion;
struct scoutfs_key;
struct scoutfs_manifest_entry;
struct kvec;

/* this is only visible for trace events */
struct scoutfs_segment {
	struct super_block *sb;
	struct rb_node node;
	struct list_head lru_entry;
	atomic_t refcount;
	u64 segno;
	unsigned long flags;
	int err;
	struct page *pages[SCOUTFS_SEGMENT_PAGES];
};

struct scoutfs_segment *scoutfs_seg_submit_read(struct super_block *sb,
						u64 segno);
int scoutfs_seg_wait(struct super_block *sb, struct scoutfs_segment *seg,
		     u64 segno, u64 seq);

int scoutfs_seg_find_off(struct scoutfs_segment *seg, struct scoutfs_key *key);
int scoutfs_seg_next_off(struct scoutfs_segment *seg, int off);
u32 scoutfs_seg_total_bytes(struct scoutfs_segment *seg);
int scoutfs_seg_get_item(struct scoutfs_segment *seg, int off,
			 struct scoutfs_key *key, struct kvec *val, u8 *flags);

void scoutfs_seg_get(struct scoutfs_segment *seg);
void scoutfs_seg_put(struct scoutfs_segment *seg);

int scoutfs_seg_alloc(struct super_block *sb, u64 segno,
		      struct scoutfs_segment **seg_ret);
bool scoutfs_seg_fits_single(u32 nr_items, u32 val_bytes);
bool scoutfs_seg_append_item(struct super_block *sb, struct scoutfs_segment *seg,
			     struct scoutfs_key *key, struct kvec *val,
			     u8 flags, __le32 **links);
void scoutfs_seg_init_ment(struct scoutfs_manifest_entry *ment, int level,
			   struct scoutfs_segment *seg);

int scoutfs_seg_submit_write(struct super_block *sb,
			     struct scoutfs_segment *seg,
			     struct scoutfs_bio_completion *comp);

int scoutfs_seg_setup(struct super_block *sb);
void scoutfs_seg_destroy(struct super_block *sb);

#endif
