#ifndef _SCOUTFS_FILE_H_
#define _SCOUTFS_FILE_H_

ssize_t scoutfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos);
ssize_t scoutfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos);

#endif	/* _SCOUTFS_FILE_H_ */
