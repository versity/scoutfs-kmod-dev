#ifndef _SCOUTFS_FOREST_H_
#define _SCOUTFS_FOREST_H_

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

int scoutfs_forest_get_log_trees(struct super_block *sb);
bool scoutfs_forest_has_dirty(struct super_block *sb);
unsigned long scoutfs_forest_dirty_bytes(struct super_block *sb);
int scoutfs_forest_write(struct super_block *sb);
int scoutfs_forest_commit(struct super_block *sb);

void scoutfs_forest_clear_lock(struct super_block *sb,
			       struct scoutfs_lock *lock);

int scoutfs_forest_setup(struct super_block *sb);
void scoutfs_forest_destroy(struct super_block *sb);

#endif
