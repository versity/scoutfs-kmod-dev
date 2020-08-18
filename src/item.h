#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock);
int scoutfs_item_lookup_exact(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock);
int scoutfs_item_next(struct super_block *sb, struct scoutfs_key *key,
		      struct scoutfs_key *last, void *val, int val_len,
		      struct scoutfs_lock *lock);
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key *key,
		       struct scoutfs_lock *lock);
int scoutfs_item_create(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock);
int scoutfs_item_create_force(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock);
int scoutfs_item_update(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock);
int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key *key,
			  struct scoutfs_lock *lock);
int scoutfs_item_delete_force(struct super_block *sb,
				struct scoutfs_key *key,
				struct scoutfs_lock *lock);

u64 scoutfs_item_dirty_bytes(struct super_block *sb);
int scoutfs_item_write_dirty(struct super_block *sb);
int scoutfs_item_write_done(struct super_block *sb);
bool scoutfs_item_range_cached(struct super_block *sb,
			       struct scoutfs_key *start,
			       struct scoutfs_key *end, bool *dirty);
void scoutfs_item_invalidate(struct super_block *sb, struct scoutfs_key *start,
			     struct scoutfs_key *end);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
