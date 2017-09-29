#ifndef _SCOUTFS_INODE_H_
#define _SCOUTFS_INODE_H_

#include "key.h"
#include "lock.h"
#include "per_task.h"

struct scoutfs_lock;

struct scoutfs_inode_info {
	/* read or initialized for each inode instance */
	u64 ino;
	u64 next_readdir_pos;
	u64 meta_seq;
	u64 data_seq;
	u64 data_version;

	/*
	 * The in-memory item info caches the current index item values
	 * so that we can decide to update them with comparisons instead
	 * of by maintaining state that tracks the inode differing from
	 * the item.  The "item_" prefix is a bit clumsy :/.
	 */
	struct mutex item_mutex;
	bool have_item;
	u64 item_size;
	struct timespec item_ctime;
	struct timespec item_mtime;
	u64 item_meta_seq;
	u64 item_data_seq;

	/* updated at on each new lock acquisition */
	atomic64_t last_refreshed;

	/* initialized once for slab object */
	seqcount_t seqcount;
	bool staging;			/* holder of i_mutex is staging */
	struct scoutfs_per_task pt_data_lock;
	struct rw_semaphore xattr_rwsem;
	struct rb_node writeback_node;

	struct inode inode;
};

static inline struct scoutfs_inode_info *SCOUTFS_I(struct inode *inode)
{
	return container_of(inode, struct scoutfs_inode_info, inode);
}

static inline u64 scoutfs_ino(struct inode *inode)
{
	return SCOUTFS_I(inode)->ino;
}

void scoutfs_inode_init_key(struct scoutfs_key_buf *key,
			    struct scoutfs_inode_key *ikey, u64 ino);

struct inode *scoutfs_alloc_inode(struct super_block *sb);
void scoutfs_destroy_inode(struct inode *inode);
int scoutfs_drop_inode(struct inode *inode);
void scoutfs_evict_inode(struct inode *inode);
int scoutfs_orphan_inode(struct inode *inode);

struct inode *scoutfs_iget(struct super_block *sb, u64 ino);
struct inode *scoutfs_ilookup(struct super_block *sb, u64 ino);
int scoutfs_dirty_inode_item(struct inode *inode, struct scoutfs_lock *lock);
void scoutfs_update_inode_item(struct inode *inode, struct scoutfs_lock *lock);
void scoutfs_inode_fill_pool(struct super_block *sb, u64 ino, u64 nr);
int scoutfs_alloc_ino(struct super_block *sb, u64 *ino);
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev, u64 ino,
				struct scoutfs_lock *lock);
void scoutfs_inode_set_meta_seq(struct inode *inode);
void scoutfs_inode_set_data_seq(struct inode *inode);
void scoutfs_inode_inc_data_version(struct inode *inode);
u64 scoutfs_inode_meta_seq(struct inode *inode);
u64 scoutfs_inode_data_seq(struct inode *inode);
u64 scoutfs_inode_data_version(struct inode *inode);

int scoutfs_inode_refresh(struct inode *inode, struct scoutfs_lock *lock,
			  int flags);

int scoutfs_scan_orphans(struct super_block *sb);

void scoutfs_inode_queue_writeback(struct inode *inode);
int scoutfs_inode_walk_writeback(struct super_block *sb, bool write);

u64 scoutfs_last_ino(struct super_block *sb);

void scoutfs_inode_exit(void);
int scoutfs_inode_init(void);

int scoutfs_inode_setup(struct super_block *sb);
void scoutfs_inode_destroy(struct super_block *sb);

#endif
