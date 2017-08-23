#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include <linux/dlm.h>
#include "key.h"
#include "dlmglue.h"

#define	SCOUTFS_LOCK_BLOCKING	0x01 /* Blocking another lock request */
#define	SCOUTFS_LOCK_QUEUED	0x02 /* Put on drop workqueue */

#define SCOUTFS_LKF_REFRESH_INODE	0x01 /* update stale inode from item */

struct scoutfs_lock {
	struct super_block *sb;
	struct scoutfs_lock_name lock_name;
	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
	int mode;
	int rqmode;
	struct dlm_lksb lksb;
	unsigned int sequence; /* for debugging and sanity checks */
	struct rb_node node;
	struct list_head lru_entry;
	unsigned int refcnt;
	unsigned int holders; /* Tracks active users of this lock */
	unsigned int flags;
	struct work_struct dc_work;
	struct ocfs2_lock_res lockres;
};

u64 scoutfs_lock_refresh_gen(struct scoutfs_lock *lock);
int scoutfs_lock_inode(struct super_block *sb, int mode, int flags,
		       struct inode *inode, struct scoutfs_lock **ret_lock);
int scoutfs_lock_ino(struct super_block *sb, int mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock);
int scoutfs_lock_inode_index(struct super_block *sb, int mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock);
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    int level);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
