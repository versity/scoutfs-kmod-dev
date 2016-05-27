#ifndef _SCOUTFS_IOCTL_H_
#define _SCOUTFS_IOCTL_H_

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

int scoutfs_copy_ibuf(struct iovec *iov, unsigned long arg);

#endif
