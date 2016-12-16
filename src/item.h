#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

#include <linux/uio.h>

struct scoutfs_segment;

int scoutfs_item_lookup(struct super_block *sb, struct kvec *key,
			struct kvec *val);
int scoutfs_item_lookup_exact(struct super_block *sb, struct kvec *key,
			      struct kvec *val, int size);
int scoutfs_item_next(struct super_block *sb, struct kvec *key,
		      struct kvec *last, struct kvec *val);
int scoutfs_item_next_same_min(struct super_block *sb, struct kvec *key,
			       struct kvec *last, struct kvec *val, int len);
int scoutfs_item_insert(struct super_block *sb, struct kvec *key,
		        struct kvec *val);
int scoutfs_item_create(struct super_block *sb, struct kvec *key,
		        struct kvec *val);
int scoutfs_item_dirty(struct super_block *sb, struct kvec *key);
int scoutfs_item_update(struct super_block *sb, struct kvec *key,
			struct kvec *val);
int scoutfs_item_delete(struct super_block *sb, struct kvec *key);

int scoutfs_item_add_batch(struct super_block *sb, struct list_head *list,
			   struct kvec *key, struct kvec *val);
int scoutfs_item_insert_batch(struct super_block *sb, struct list_head *list,
			      struct kvec *start, struct kvec *end);
void scoutfs_item_free_batch(struct list_head *list);

long scoutfs_item_dirty_bytes(struct super_block *sb);
int scoutfs_item_dirty_seg(struct super_block *sb, struct scoutfs_segment *seg);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
