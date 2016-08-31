#ifndef _SCOUTFS_XATTR_H_
#define _SCOUTFS_XATTR_H_

ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size);
int scoutfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags);
int scoutfs_removexattr(struct dentry *dentry, const char *name);
ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

int scoutfs_xattr_drop(struct super_block *sb, u64 ino);

#endif
