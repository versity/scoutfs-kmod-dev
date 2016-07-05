#ifndef _SCOUTFS_IOCTL_H_
#define _SCOUTFS_IOCTL_H_

int scoutfs_copy_ibuf(struct iovec *iov, unsigned long arg);
long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* XXX I have no idea how these are chosen. */
#define SCOUTFS_IOCTL_MAGIC 's'

struct scoutfs_ioctl_buf {
	__u64 ptr;
	__s32 len;
} __packed;

/*
 * Fills the buffer with a packed array of format strings.  Trace records
 * refer to the format strings in the buffer by their byte offset.
 */
#define SCOUTFS_IOC_GET_TRACE_FORMATS _IOW(SCOUTFS_IOCTL_MAGIC, 1, \
					   struct scoutfs_ioctl_buf)

struct scoutfs_trace_record {
	__u16 format_off;
	__u8 nr;
	__u8 data[0];
} __packed;
/*
 * Fills the buffer with trace records.
 */
#define SCOUTFS_IOC_GET_TRACE_RECORDS _IOW(SCOUTFS_IOCTL_MAGIC, 2, \
					   struct scoutfs_ioctl_buf)

struct scoutfs_ioctl_ino_seq {
	__u64 ino;
	__u64 seq;
} __packed;

struct scoutfs_ioctl_inodes_since {
	__u64 first_ino;
	__u64 last_ino;
	__u64 seq;
	struct scoutfs_ioctl_buf results;
} __packed;

/*
 * Adds entries to the user's buffer for each inode whose sequence
 * number is greater than or equal to the given seq.
 */
#define SCOUTFS_IOC_INODES_SINCE _IOW(SCOUTFS_IOCTL_MAGIC, 3, \
				      struct scoutfs_ioctl_inodes_since)

#endif
