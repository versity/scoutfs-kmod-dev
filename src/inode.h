#ifndef _SCOUTFS_INODE_H_
#define _SCOUTFS_INODE_H_

struct scoutfs_inode_info {
	u64 ino;
	u32 salt;

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

struct inode *scoutfs_iget(struct super_block *sb, u64 ino);
int scoutfs_dirty_inode_item(struct inode *inode);
void scoutfs_update_inode_item(struct inode *inode);
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev);

u64 scoutfs_last_ino(struct super_block *sb);

void scoutfs_inode_exit(void);
int scoutfs_inode_init(void);

#endif
