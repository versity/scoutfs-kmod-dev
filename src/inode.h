#ifndef _SCOUTFS_INODE_H_
#define _SCOUTFS_INODE_H_

struct scoutfs_inode_info {
	u64 ino;
	u32 salt;

	seqcount_t seqcount;
	u64 data_version;
	u64 next_readdir_pos;

	/* holder of i_mutex is staging */
	bool staging;

	atomic64_t link_counter;
	struct rw_semaphore xattr_rwsem;

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

struct inode *scoutfs_alloc_inode(struct super_block *sb);
void scoutfs_destroy_inode(struct inode *inode);
int scoutfs_drop_inode(struct inode *inode);
void scoutfs_evict_inode(struct inode *inode);
int scoutfs_orphan_inode(struct inode *inode);

struct inode *scoutfs_iget(struct super_block *sb, u64 ino);
int scoutfs_dirty_inode_item(struct inode *inode);
void scoutfs_dirty_inode(struct inode *inode, int flags);
void scoutfs_update_inode_item(struct inode *inode);
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev);
void scoutfs_inode_inc_data_version(struct inode *inode);
u64 scoutfs_inode_get_data_version(struct inode *inode);

int scoutfs_scan_orphans(struct super_block *sb);

u64 scoutfs_last_ino(struct super_block *sb);

void scoutfs_inode_exit(void);
int scoutfs_inode_init(void);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
