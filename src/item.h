#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

#include <linux/uio.h>

struct scoutfs_segment;
struct scoutfs_key_buf;

int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val);
int scoutfs_item_lookup_exact(struct super_block *sb,
			      struct scoutfs_key_buf *key, struct kvec *val,
			      int size);
int scoutfs_item_next(struct super_block *sb, struct scoutfs_key_buf *key,
		      struct scoutfs_key_buf *last, struct kvec *val);
int scoutfs_item_next_same_min(struct super_block *sb,
			       struct scoutfs_key_buf *key,
			       struct scoutfs_key_buf *last,
			       struct kvec *val, int len);
int scoutfs_item_next_same(struct super_block *sb, struct scoutfs_key_buf *key,
			   struct scoutfs_key_buf *last, struct kvec *val);
int scoutfs_item_insert(struct super_block *sb, struct scoutfs_key_buf *key,
		        struct kvec *val);
int scoutfs_item_create(struct super_block *sb, struct scoutfs_key_buf *key,
		        struct kvec *val);
int scoutfs_item_create_ephemeral(struct super_block *sb,
			          struct scoutfs_key_buf *key,
				  struct kvec *val);
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key_buf *key);
int scoutfs_item_update(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val);
void scoutfs_item_update_ephemeral(struct super_block *sb,
				   struct scoutfs_key_buf *key,
				   struct kvec *val);
void scoutfs_item_delete_dirty(struct super_block *sb,
			       struct scoutfs_key_buf *key);
int scoutfs_item_delete_many(struct super_block *sb,
			     struct scoutfs_key_buf **keys, unsigned nr);
int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key_buf *key);
void scoutfs_item_forget(struct super_block *sb, struct scoutfs_key_buf *key);

int scoutfs_item_add_batch(struct super_block *sb, struct list_head *list,
			   struct scoutfs_key_buf *key, struct kvec *val);
int scoutfs_item_insert_batch(struct super_block *sb, struct list_head *list,
			      struct scoutfs_key_buf *start,
			      struct scoutfs_key_buf *end);
void scoutfs_item_free_batch(struct super_block *sb, struct list_head *list);

bool scoutfs_item_has_dirty(struct super_block *sb);
bool scoutfs_item_dirty_fits_single(struct super_block *sb, u32 nr_items,
			            u32 key_bytes, u32 val_bytes);
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
