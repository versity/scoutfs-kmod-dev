#ifndef _SCOUTFS_INODE_H_
#define _SCOUTFS_INODE_H_

#include "key.h"

struct scoutfs_inode_info {
	/* read or initialized for each inode instance */
	u64 ino;
	u64 data_version;
	u64 next_readdir_pos;

	/* initialized once for slab object */
	seqcount_t seqcount;
	bool staging;			/* holder of i_mutex is staging */
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
int scoutfs_dirty_inode_item(struct inode *inode);
void scoutfs_dirty_inode(struct inode *inode, int flags);
void scoutfs_update_inode_item(struct inode *inode);
void scoutfs_inode_fill_pool(struct super_block *sb, u64 ino, u64 nr);
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev);
void scoutfs_inode_inc_data_version(struct inode *inode);
u64 scoutfs_inode_get_data_version(struct inode *inode);

int scoutfs_scan_orphans(struct super_block *sb);

void scoutfs_inode_queue_writeback(struct inode *inode);
int scoutfs_inode_walk_writeback(struct super_block *sb, bool write);

u64 scoutfs_last_ino(struct super_block *sb);

void scoutfs_inode_exit(void);
int scoutfs_inode_init(void);

int scoutfs_inode_setup(struct super_block *sb);
void scoutfs_inode_destroy(struct super_block *sb);

#endif
