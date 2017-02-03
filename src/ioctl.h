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

/*
 * Fill the path buffer with the next path to the target inode.  An
 * iteration cursor is stored in the cursor buffer which advances
 * through the paths to the inode at each call.
 *
 * @ino: The target ino that we're finding paths to.  Constant across
 * all the calls that make up an iteration over all the inode's paths.
 *
 * @cursor_ptr: A pointer to the buffer that will hold the iteration
 * cursor.  It must be initialized to 0 before iterating.  Each call
 * modifies it to skip past the result of that call.
 *
 * @cusur_bytes: The length of the cursor buffer.  Must be
 * SCOUTFS_IOC_INO_PATH_CURSOR_BYTES.
 *
 * @path_ptr: The buffer to store each found path.
 *
 * @path_bytes: The size of the buffer that will the found path
 * including null termination.  (PATH_MAX is a solid choice.)
 *
 * This only walks back through full hard links.  None of the returned
 * paths will reflect symlinks to components in the path.
 *
 * This doesn't ensure that the caller has permissions to traverse the
 * returned paths to the inode.  It requires CAP_DAC_READ_SEARCH which
 * bypasses permissions checking.
 *
 * ENAMETOOLONG is returned when the next path found from the cursor
 * doesn't fit in the path buffer.
 *
 * This call is not serialized with any modification (create, rename,
 * unlink) of the path components.  It will return all the paths that
 * were stable both before and after the call.  It may or may not return
 * paths which are created or unlinked during the call.
 *
 * The number of bytes in the path, including the null terminator, are
 * returned when a path is found.  0 is returned when there are no more
 * paths to the link to the inode from the cursor.
 */
struct scoutfs_ioctl_ino_path {
	__u64 ino;
	__u64 cursor_ptr;
	__u64 path_ptr;
	__u16 cursor_bytes;
	__u16 path_bytes;
} __packed;

#define SCOUTFS_IOC_INO_PATH_CURSOR_BYTES \
	(sizeof(u64) + SCOUTFS_NAME_LEN + 1)

/* Get a single path from the root to the given inode number */
#define SCOUTFS_IOC_INO_PATH _IOW(SCOUTFS_IOCTL_MAGIC, 2, \
				      struct scoutfs_ioctl_ino_path)

/* XXX might as well include a seq?  0 for current behaviour? */
struct scoutfs_ioctl_find_xattr {
	__u64 first_ino;
	__u64 last_ino;
	__u64 str_ptr;
	__u32 str_len;
	__u64 ino_ptr;
	__u32 ino_count;
} __packed;

#define SCOUTFS_IOC_FIND_XATTR_NAME _IOW(SCOUTFS_IOCTL_MAGIC, 3, \
				      struct scoutfs_ioctl_find_xattr)
#define SCOUTFS_IOC_FIND_XATTR_VAL _IOW(SCOUTFS_IOCTL_MAGIC, 4, \
				      struct scoutfs_ioctl_find_xattr)

#define SCOUTFS_IOC_INODE_DATA_SINCE _IOW(SCOUTFS_IOCTL_MAGIC, 5, \
					  struct scoutfs_ioctl_inodes_since)

#define SCOUTFS_IOC_DATA_VERSION _IOW(SCOUTFS_IOCTL_MAGIC, 6, u64)

struct scoutfs_ioctl_release {
	__u64 offset;
	__u64 count;
	__u64 data_version;
} __packed;

#define SCOUTFS_IOC_RELEASE _IOW(SCOUTFS_IOCTL_MAGIC, 7, \
				  struct scoutfs_ioctl_release)

struct scoutfs_ioctl_stage {
	__u64 data_version;
	__u64 buf_ptr;
	__u64 offset;
	__s32 count;
} __packed;

#define SCOUTFS_IOC_STAGE _IOW(SCOUTFS_IOCTL_MAGIC, 8, \
			       struct scoutfs_ioctl_stage)

#endif
