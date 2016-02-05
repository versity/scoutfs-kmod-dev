#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

#include "format.h"

struct scoutfs_item {
	struct rb_node node;
	struct rb_node dirty_node;
	atomic_t refcount;

	/* the key is constant for the life of the item */
	struct scoutfs_key key;

	/* the value can be changed by expansion or shrinking */
	unsigned int val_len;
	void *val;
};

struct scoutfs_item *scoutfs_item_create(struct super_block *sb,
					 struct scoutfs_key *key,
					 unsigned int val_len);
struct scoutfs_item *scoutfs_item_lookup(struct super_block *sb,
					 struct scoutfs_key *key);
struct scoutfs_item *scoutfs_item_next(struct super_block *sb,
				       struct scoutfs_key *key);
struct scoutfs_item *scoutfs_item_prev(struct super_block *sb,
				       struct scoutfs_key *key);
int scoutfs_item_expand(struct scoutfs_item *item, int off, int bytes);
int scoutfs_item_shrink(struct scoutfs_item *item, int off, int bytes);
void scoutfs_item_delete(struct super_block *sb, struct scoutfs_item *item);
void scoutfs_item_mark_dirty(struct super_block *sb, struct scoutfs_item *item);
struct scoutfs_item *scoutfs_item_next_dirty(struct super_block *sb,
					     struct scoutfs_item *item);
void scoutfs_item_all_clean(struct super_block *sb);
void scoutfs_item_put(struct scoutfs_item *item);

#endif
