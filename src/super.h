#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"
#include "options.h"

struct scoutfs_counters;
struct scoutfs_triggers;
struct item_cache;
struct manifest;
struct segment_cache;
struct compact_info;
struct data_info;
struct trans_info;
struct lock_info;
struct client_info;
struct server_info;
struct inode_sb_info;
struct btree_info;
struct sysfs_info;
struct options_sb_info;
struct net_info;

struct scoutfs_sb_info {
	struct super_block *sb;

	/* assigned once at the start of each mount, read-only */
	u64 node_id;
	struct scoutfs_lock *node_id_lock;

	struct scoutfs_super_block super;

	spinlock_t next_ino_lock;

	struct manifest *manifest;
	struct item_cache *item_cache;
	struct segment_cache *segment_cache;
	struct seg_alloc *seg_alloc;
	struct compact_info *compact_info;
	struct data_info *data_info;
	struct inode_sb_info *inode_sb_info;
	struct btree_info *btree_info;
	struct net_info *net_info;

	wait_queue_head_t trans_hold_wq;
	struct task_struct *trans_task;

	spinlock_t trans_write_lock;
	u64 trans_write_count;
	u64 trans_seq;
	int trans_write_ret;
	struct delayed_work trans_write_work;
	wait_queue_head_t trans_write_wq;
	struct workqueue_struct *trans_write_workq;
	bool trans_deadline_expired;

	struct trans_info *trans_info;
	struct lock_info *lock_info;
	struct client_info *client_info;
	struct server_info *server_info;
	struct sysfs_info *sfsinfo;

	struct scoutfs_counters *counters;
	struct scoutfs_triggers *triggers;

	struct mount_options opts;
	struct options_sb_info *options;

	struct dentry *debug_root;

	bool shutdown;

	unsigned long corruption_messages_once[SC_NR_LONGS];
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

int scoutfs_read_super(struct super_block *sb,
		       struct scoutfs_super_block *super_res);
void scoutfs_advance_dirty_super(struct super_block *sb);
int scoutfs_write_dirty_super(struct super_block *sb);

/* to keep this out of the ioctl.h public interface definition */
long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
