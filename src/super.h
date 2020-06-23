#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"
#include "options.h"
#include "data.h"
#include "sysfs.h"

struct scoutfs_counters;
struct scoutfs_triggers;
struct manifest;
struct data_info;
struct trans_info;
struct lock_info;
struct lock_server_info;
struct client_info;
struct server_info;
struct inode_sb_info;
struct btree_info;
struct sysfs_info;
struct options_sb_info;
struct net_info;
struct block_info;
struct forest_info;
struct srch_info;

struct scoutfs_sb_info {
	struct super_block *sb;

	/* assigned once at the start of each mount, read-only */
	u64 rid;
	struct scoutfs_lock *rid_lock;

	struct scoutfs_super_block super;

	spinlock_t next_ino_lock;

	struct data_info *data_info;
	struct inode_sb_info *inode_sb_info;
	struct btree_info *btree_info;
	struct net_info *net_info;
	struct quorum_info *quorum_info;
	struct block_info *block_info;
	struct forest_info *forest_info;
	struct srch_info *srch_info;

	wait_queue_head_t trans_hold_wq;
	struct task_struct *trans_task;

	/* tracks tasks waiting for data extents */
	struct scoutfs_data_wait_root data_wait_root;

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
	struct lock_server_info *lock_server_info;
	struct client_info *client_info;
	struct server_info *server_info;
	struct sysfs_info *sfsinfo;

	struct scoutfs_counters *counters;
	struct scoutfs_triggers *triggers;

	struct mount_options opts;
	struct options_sb_info *options;
	struct scoutfs_sysfs_attrs mopts_ssa;

	struct dentry *debug_root;

	bool shutdown;

	unsigned long corruption_messages_once[SC_NR_LONGS];
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline bool SCOUTFS_HAS_SBI(struct super_block *sb)
{
	return (sb != NULL) && (SCOUTFS_SB(sb) != NULL);
}

/*
 * A small string embedded in messages that's used to identify a
 * specific mount.  It's the three most significant bytes of the fsid
 * and the rid.  That gives us a strong chance of avoiding collisions
 * with typical numbers of mounts.  We give it a bit of structure to
 * make it searchable and to be able to identify format changes, should
 * we need to.  The fsid will be 0 until the super has been read and the
 * fsid discovered.
 */
#define SCSBF		"f.%.06x.r.%.06x"
#define SCSB_SHIFT	(64 - (8 * 3))
#define SCSB_LEFR_ARGS(fsid, rid)					    \
	(int)(le64_to_cpu(fsid) >> SCSB_SHIFT),				    \
	(int)(le64_to_cpu(rid) >> SCSB_SHIFT)
#define SCSB_ARGS(sb)							    \
	(int)(le64_to_cpu(SCOUTFS_SB(sb)->super.hdr.fsid) >> SCSB_SHIFT),   \
	(int)(SCOUTFS_SB(sb)->rid >> SCSB_SHIFT)
#define SCSB_TRACE_FIELDS	\
	__field(__u64, fsid)	\
	__field(__u64, rid)
#define SCSB_TRACE_ASSIGN(sb)						\
	__entry->fsid = SCOUTFS_HAS_SBI(sb) ?				\
			le64_to_cpu(SCOUTFS_SB(sb)->super.hdr.fsid) : 0;\
	__entry->rid = SCOUTFS_HAS_SBI(sb) ?				\
		       SCOUTFS_SB(sb)->rid : 0;
#define SCSB_TRACE_ARGS				\
	(int)(__entry->fsid >> SCSB_SHIFT),	\
	(int)(__entry->rid >> SCSB_SHIFT)

int scoutfs_read_super(struct super_block *sb,
		       struct scoutfs_super_block *super_res);
int scoutfs_write_super(struct super_block *sb,
		        struct scoutfs_super_block *super);

/* to keep this out of the ioctl.h public interface definition */
long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

__le64 scoutfs_clock_sync_id(void);

#endif
