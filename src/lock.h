#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include <linux/dlm.h>
#include "key.h"

#define	SCOUTFS_LOCK_BLOCKING	0x01 /* Blocking another lock request */
#define	SCOUTFS_LOCK_QUEUED	0x02 /* Put on drop workqueue */

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
	struct delayed_work dc_work;
};

int scoutfs_lock_ino_group(struct super_block *sb, int mode, u64 ino,
			   struct scoutfs_lock **ret_lock);
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock);

int scoutfs_lock_addr(struct super_block *sb, int wanted_mode,
		      void *caller_lvb, unsigned lvb_len);
void scoutfs_unlock_addr(struct super_block *sb, void *caller_lvb,
			 unsigned lvb_len);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
