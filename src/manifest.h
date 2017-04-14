#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

struct scoutfs_key_buf;
struct scoutfs_bio_completion;

int scoutfs_manifest_add(struct super_block *sb,
			 struct scoutfs_key_buf *first,
			 struct scoutfs_key_buf *last, u64 segno, u64 seq,
			 u8 level);
int scoutfs_manifest_add_ment(struct super_block *sb,
			      struct scoutfs_manifest_entry *add);
int scoutfs_manifest_dirty(struct super_block *sb,
			   struct scoutfs_key_buf *first, u64 seq, u8 level);
int scoutfs_manifest_del(struct super_block *sb, struct scoutfs_key_buf *first,
			 u64 seq, u8 level);
int scoutfs_manifest_has_dirty(struct super_block *sb);
int scoutfs_manifest_submit_write(struct super_block *sb,
				  struct scoutfs_bio_completion *comp);
void scoutfs_manifest_write_complete(struct super_block *sb);

int scoutfs_manifest_bytes(struct scoutfs_manifest_entry *ment);

struct scoutfs_manifest_entry *
scoutfs_manifest_alloc_entry(struct super_block *sb,
			     struct scoutfs_key_buf *first,
			     struct scoutfs_key_buf *last, u64 segno, u64 seq,
			     u8 level);

int scoutfs_manifest_lock(struct super_block *sb);
int scoutfs_manifest_unlock(struct super_block *sb);

struct scoutfs_manifest_entry **
scoutfs_manifest_find_range_entries(struct super_block *sb,
				    struct scoutfs_key_buf *key,
				    struct scoutfs_key_buf *end,
				    unsigned *found_bytes);

int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key_buf *key,
				struct scoutfs_key_buf *end);
int scoutfs_manifest_add_ment_ref(struct super_block *sb,
				  struct list_head *list,
				  struct scoutfs_manifest_entry *ment);

u64 scoutfs_manifest_level_count(struct super_block *sb, u8 level);
int scoutfs_manifest_next_compact(struct super_block *sb, void *data);

int scoutfs_manifest_setup(struct super_block *sb);
void scoutfs_manifest_destroy(struct super_block *sb);

#endif
