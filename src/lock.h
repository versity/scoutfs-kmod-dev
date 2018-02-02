#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include <linux/dlm.h>
#include "key.h"

#define SCOUTFS_LKF_REFRESH_INODE	0x01 /* update stale inode from item */
#define SCOUTFS_LKF_NONBLOCK		0x02 /* only use already held locks */

#define SCOUTFS_LOCK_NR_MODES (DLM_LOCK_EX + 1)

/*
 * A few fields (start, end, refresh_gen, granted_mode) are referenced
 * by code outside lock.c.
 */
struct scoutfs_lock {
	struct super_block *sb;
	struct scoutfs_lock_name name;
	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
	struct rb_node node;
	struct rb_node range_node;
	unsigned int debug_locks_id;
	u64 refresh_gen;
	struct list_head lru_head;
	wait_queue_head_t waitq;
	struct work_struct work;
	struct dlm_lksb lksb;
	ktime_t grace_deadline;
	struct delayed_work grace_work;
	bool grace_pending;

	int error;
	int granted_mode;
	int bast_mode;
	int work_prev_mode;
	int work_mode;
	unsigned int waiters[SCOUTFS_LOCK_NR_MODES];
	unsigned int users[SCOUTFS_LOCK_NR_MODES];
};

int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **ret_lock);
int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock);
void scoutfs_lock_get_index_item_range(u8 type, u64 major, u64 ino,
				       struct scoutfs_inode_index_key *start,
				       struct scoutfs_inode_index_key *end);
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock);
int scoutfs_lock_inodes(struct super_block *sb, int mode, int flags,
			struct inode *a, struct scoutfs_lock **a_lock,
			struct inode *b, struct scoutfs_lock **b_lock,
			struct inode *c, struct scoutfs_lock **c_lock,
			struct inode *d, struct scoutfs_lock **D_lock);
int scoutfs_lock_global(struct super_block *sb, int mode, int flags, int type,
			struct scoutfs_lock **lock);
int scoutfs_lock_node_id(struct super_block *sb, int mode, int flags,
			 u64 node_id, struct scoutfs_lock **lock);
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    int level);
void scoutfs_unlock_flags(struct super_block *sb, struct scoutfs_lock *lock,
			  int level, int flags);

void scoutfs_free_unused_locks(struct super_block *sb, unsigned long nr);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
