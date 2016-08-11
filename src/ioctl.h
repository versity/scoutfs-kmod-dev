#ifndef _SCOUTFS_IOCTL_H_
#define _SCOUTFS_IOCTL_H_

long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* XXX I have no idea how these are chosen. */
#define SCOUTFS_IOCTL_MAGIC 's'

struct scoutfs_ioctl_ino_seq {
	__u64 ino;
	__u64 seq;
} __packed;

struct scoutfs_ioctl_inodes_since {
	__u64 first_ino;
	__u64 last_ino;
	__u64 seq;
	__u64 buf_ptr;
	__u32 buf_len;
} __packed;

/*
 * Adds entries to the user's buffer for each inode whose sequence
 * number is greater than or equal to the given seq.
 */
#define SCOUTFS_IOC_INODES_SINCE _IOW(SCOUTFS_IOCTL_MAGIC, 1, \
				      struct scoutfs_ioctl_inodes_since)

struct scoutfs_ioctl_inode_paths {
	__u64 ino;
	__u64 buf_ptr;
	__u32 buf_len;
} __packed;

/*
 * Fills the callers buffer with all the paths from the root to the
 * target inode.
 */
#define SCOUTFS_IOC_INODE_PATHS _IOW(SCOUTFS_IOCTL_MAGIC, 2, \
				      struct scoutfs_ioctl_inode_paths)

#endif
