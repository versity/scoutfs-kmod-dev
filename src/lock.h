#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

struct scoutfs_lock {
	struct list_head head;
	struct super_block *sb;
	struct scoutfs_key_buf *start;
	struct scoutfs_key_buf *end;
	int mode;
};

enum {
	SCOUTFS_LOCK_MODE_READ,
	SCOUTFS_LOCK_MODE_WRITE,
};

int scoutfs_lock_range(struct super_block *sb, int mode,
		       struct scoutfs_key_buf *start,
		       struct scoutfs_key_buf *end,
		       struct scoutfs_lock *lck);
void scoutfs_unlock_range(struct super_block *sb, struct scoutfs_lock *lck);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
