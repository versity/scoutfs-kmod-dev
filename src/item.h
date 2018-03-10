#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

#include <linux/uio.h>

struct scoutfs_segment;
struct scoutfs_key_buf;

int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_item_lookup_exact(struct super_block *sb,
			      struct scoutfs_key_buf *key, struct kvec *val,
			      int size, struct scoutfs_lock *lock);
int scoutfs_item_next(struct super_block *sb, struct scoutfs_key_buf *key,
		      struct scoutfs_key_buf *last, struct kvec *val,
		      struct scoutfs_lock *lock);
int scoutfs_item_next_same_min(struct super_block *sb,
			       struct scoutfs_key_buf *key,
			       struct scoutfs_key_buf *last,
			       struct kvec *val, int len,
			       struct scoutfs_lock *lock);
int scoutfs_item_next_same(struct super_block *sb, struct scoutfs_key_buf *key,
			   struct scoutfs_key_buf *last, struct kvec *val,
			   struct scoutfs_lock *lock);
int scoutfs_item_create(struct super_block *sb, struct scoutfs_key_buf *key,
		        struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_item_create_force(struct super_block *sb,
			      struct scoutfs_key_buf *key,
			      struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key_buf *key,
		       struct scoutfs_lock *lock);
int scoutfs_item_update(struct super_block *sb, struct scoutfs_key_buf *key,
			struct kvec *val, struct scoutfs_lock *lock);
void scoutfs_item_delete_dirty(struct super_block *sb,
			       struct scoutfs_key_buf *key);
void scoutfs_item_update_dirty(struct super_block *sb,
			       struct scoutfs_key_buf *key, struct kvec *val);
int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key_buf *key,
			struct scoutfs_lock *lock);
int scoutfs_item_delete_force(struct super_block *sb,
			      struct scoutfs_key_buf *key,
			      struct scoutfs_lock *lock);
int scoutfs_item_delete_save(struct super_block *sb,
			     struct scoutfs_key_buf *key,
			     struct list_head *list,
			     struct scoutfs_lock *lock);
int scoutfs_item_restore(struct super_block *sb, struct list_head *list,
			 struct scoutfs_lock *lock);

int scoutfs_item_add_batch(struct super_block *sb, struct list_head *list,
			   struct scoutfs_key_buf *key, struct kvec *val);
int scoutfs_item_insert_batch(struct super_block *sb, struct list_head *list,
			      struct scoutfs_key_buf *start,
			      struct scoutfs_key_buf *end);
void scoutfs_item_free_batch(struct super_block *sb, struct list_head *list);

bool scoutfs_item_has_dirty(struct super_block *sb);
bool scoutfs_item_range_cached(struct super_block *sb,
			       struct scoutfs_key_buf *start,
			       struct scoutfs_key_buf *end, bool dirty);
bool scoutfs_item_dirty_fits_single(struct super_block *sb, u32 nr_items,
			            u32 key_bytes, u32 val_bytes);
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg);
int scoutfs_item_writeback(struct super_block *sb,
			   struct scoutfs_key_buf *start,
			   struct scoutfs_key_buf *end);
int scoutfs_item_invalidate(struct super_block *sb,
			    struct scoutfs_key_buf *start,
			    struct scoutfs_key_buf *end);

int scoutfs_item_copy_range_keys(struct super_block *sb,
				 struct scoutfs_key_buf *key, void *data,
				 unsigned len);
int scoutfs_item_copy_keys(struct super_block *sb, struct scoutfs_key_buf *key,
			   void *data, unsigned len);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
