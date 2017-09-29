#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include <linux/dlm.h>
#include "key.h"
#include "dlmglue.h"

#define SCOUTFS_LKF_REFRESH_INODE	0x01 /* update stale inode from item */
#define SCOUTFS_LKF_TRYLOCK		0x02 /* EAGAIN if contention */

/* flags for scoutfs_lock->flags */
enum {
	SCOUTFS_LOCK_RECLAIM = 0, /* lock is queued for reclaim */
	SCOUTFS_LOCK_DROPPED, /* lock is going away, drop reference */
};

struct scoutfs_lock {
	struct super_block *sb;
	struct scoutfs_lock_name lock_name;
	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
	struct dlm_lksb lksb;
	unsigned int sequence; /* for debugging and sanity checks */
	struct rb_node node;
	unsigned int refcnt;
	struct ocfs2_lock_res lockres;
	struct list_head lru_entry;
	struct work_struct reclaim_work;
	unsigned int users; /* Tracks active users of this lock */
	unsigned long flags;
	wait_queue_head_t waitq;
};

u64 scoutfs_lock_refresh_gen(struct scoutfs_lock *lock);
int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **ret_lock);
int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock);
void scoutfs_lock_clamp_inode_index(u8 type, u64 *major, u32 *minor, u64 *ino);
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

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
