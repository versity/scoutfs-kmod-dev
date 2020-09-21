#ifndef _SCOUTFS_FOREST_H_
#define _SCOUTFS_FOREST_H_

struct scoutfs_alloc;
struct scoutfs_block_writer;
struct scoutfs_block;

#include "btree.h"

/* caller gives an item to the callback */
typedef int (*scoutfs_forest_item_cb)(struct super_block *sb,
				      struct scoutfs_key *key,
				      struct scoutfs_log_item_value *liv,
				      void *val, int val_len, void *arg);

int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next);
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_lock *lock,
			      struct scoutfs_key *key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg);
int scoutfs_forest_set_bloom_bits(struct super_block *sb,
				  struct scoutfs_lock *lock);
int scoutfs_forest_insert_list(struct super_block *sb,
			       struct scoutfs_btree_item_list *lst);
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id);

void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt);
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt);

int scoutfs_forest_setup(struct super_block *sb);
void scoutfs_forest_destroy(struct super_block *sb);

#endif
