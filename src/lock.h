#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include "key.h"
#include "tseq.h"

#define SCOUTFS_LKF_REFRESH_INODE	0x01 /* update stale inode from item */
#define SCOUTFS_LKF_NONBLOCK		0x02 /* only use already held locks */
#define SCOUTFS_LKF_INVALID		(~((SCOUTFS_LKF_NONBLOCK << 1) - 1))

#define SCOUTFS_LOCK_NR_MODES		SCOUTFS_LOCK_INVALID

/*
 * A few fields (start, end, refresh_gen, write_version, granted_mode)
 * are referenced by code outside lock.c.
 */
struct scoutfs_lock {
	struct super_block *sb;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct rb_node node;
	struct rb_node range_node;
	u64 refresh_gen;
	u64 write_version;
	struct scoutfs_btree_root fs_root;
	struct scoutfs_btree_root logs_root;
	struct list_head lru_head;
	wait_queue_head_t waitq;
	struct work_struct shrink_work;
	ktime_t grace_deadline;
	unsigned long request_pending:1,
		      invalidate_pending:1;

	spinlock_t cov_list_lock;
	struct list_head cov_list;

	int mode;
	unsigned int waiters[SCOUTFS_LOCK_NR_MODES];
	unsigned int users[SCOUTFS_LOCK_NR_MODES];

	struct scoutfs_tseq_entry tseq_entry;

	/* the forest btree code stores data per lock */
	struct forest_lock_private *forest_private;
};

struct scoutfs_lock_coverage {
	spinlock_t cov_lock;
	struct scoutfs_lock *lock;
	struct list_head head;
};

int scoutfs_lock_grant_response(struct super_block *sb,
				struct scoutfs_net_lock_grant_response *gr);
int scoutfs_lock_invalidate_request(struct super_block *sb, u64 net_id,
				    struct scoutfs_net_lock *nl);
int scoutfs_lock_recover_request(struct super_block *sb, u64 net_id,
				 struct scoutfs_key *key);

int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **ret_lock);
int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock);
void scoutfs_lock_get_index_item_range(u8 type, u64 major, u64 ino,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end);
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock);
int scoutfs_lock_xattr_index(struct super_block *sb, int mode, int flags,
			     u64 hash, struct scoutfs_lock **ret_lock);
int scoutfs_lock_inodes(struct super_block *sb, int mode, int flags,
			struct inode *a, struct scoutfs_lock **a_lock,
			struct inode *b, struct scoutfs_lock **b_lock,
			struct inode *c, struct scoutfs_lock **c_lock,
			struct inode *d, struct scoutfs_lock **D_lock);
int scoutfs_lock_rename(struct super_block *sb, int mode, int flags,
			struct scoutfs_lock **lock);
int scoutfs_lock_rid(struct super_block *sb, int mode, int flags,
		     u64 rid, struct scoutfs_lock **lock);
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    int level);

void scoutfs_lock_init_coverage(struct scoutfs_lock_coverage *cov);
void scoutfs_lock_add_coverage(struct super_block *sb,
			       struct scoutfs_lock *lock,
			       struct scoutfs_lock_coverage *cov);
bool scoutfs_lock_is_covered(struct super_block *sb,
			     struct scoutfs_lock_coverage *cov);
void scoutfs_lock_del_coverage(struct super_block *sb,
			       struct scoutfs_lock_coverage *cov);
bool scoutfs_lock_protected(struct scoutfs_lock *lock, struct scoutfs_key *key,
			    int mode);

void scoutfs_free_unused_locks(struct super_block *sb, unsigned long nr);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
