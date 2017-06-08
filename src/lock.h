#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include "../dlm/include/linux/dlm.h"

struct scoutfs_lock {
	struct list_head head;
	struct super_block *sb;
	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
	int mode;
	int rqmode;
	struct dlm_lksb lksb;
	struct dlm_key dlm_start;
	struct dlm_key dlm_end;
	unsigned int sequence; /* for debugging and sanity checks */
};

enum {
	SCOUTFS_LOCK_MODE_IV = DLM_LOCK_IV,
	SCOUTFS_LOCK_MODE_READ = DLM_LOCK_PR,
	SCOUTFS_LOCK_MODE_WRITE = DLM_LOCK_EX,
};

int scoutfs_lock_range(struct super_block *sb, int mode,
		       struct scoutfs_key_buf *start,
		       struct scoutfs_key_buf *end,
		       struct scoutfs_lock *lck);
void scoutfs_unlock_range(struct super_block *sb, struct scoutfs_lock *lck);

int scoutfs_lock_addr(struct super_block *sb, int wanted_mode,
		      void *caller_lvb, unsigned lvb_len);
void scoutfs_unlock_addr(struct super_block *sb, void *caller_lvb,
			 unsigned lvb_len);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
