#ifndef _SCOUTFS_FOREST_H_
#define _SCOUTFS_FOREST_H_

struct scoutfs_radix_allocator;
struct scoutfs_block_writer;

int scoutfs_forest_lookup(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_forest_lookup_exact(struct super_block *sb,
				struct scoutfs_key *key, struct kvec *val,
				struct scoutfs_lock *lock);
int scoutfs_forest_next(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_key *last, struct kvec *val,
			struct scoutfs_lock *lock);
int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next);
int scoutfs_forest_prev(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_key *first, struct kvec *val,
			struct scoutfs_lock *lock);
int scoutfs_forest_create(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_forest_create_force(struct super_block *sb,
				struct scoutfs_key *key, struct kvec *val,
				struct scoutfs_lock *lock);
int scoutfs_forest_update(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock);
int scoutfs_forest_delete_dirty(struct super_block *sb,
			        struct scoutfs_key *key);
int scoutfs_forest_delete(struct super_block *sb, struct scoutfs_key *key,
			  struct scoutfs_lock *lock);
int scoutfs_forest_delete_force(struct super_block *sb,
				struct scoutfs_key *key,
				struct scoutfs_lock *lock);
int scoutfs_forest_delete_save(struct super_block *sb,
			       struct scoutfs_key *key,
			       struct list_head *list,
			       struct scoutfs_lock *lock);
int scoutfs_forest_restore(struct super_block *sb, struct list_head *list,
			   struct scoutfs_lock *lock);
void scoutfs_forest_free_batch(struct super_block *sb, struct list_head *list);
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id);

void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt);
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt);

void scoutfs_forest_clear_lock(struct super_block *sb,
			       struct scoutfs_lock *lock);

int scoutfs_forest_setup(struct super_block *sb);
void scoutfs_forest_destroy(struct super_block *sb);

#endif
