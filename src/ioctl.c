/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/aio.h>

#include "format.h"
#include "btree.h"
#include "key.h"
#include "dir.h"
#include "name.h"
#include "ioctl.h"
#include "super.h"
#include "inode.h"
#include "trans.h"
#include "filerw.h"

/*
 * Find all the inodes that have had keys of a given type modified since
 * a given sequence number.  The user's arg struct specifies the inode
 * range to search within and the sequence value to return results from.
 * Different ioctls call this for different key types.
 *
 * When this is used for file data items the user is trying to find
 * inodes whose data has changed since a given time in the past.
 *
 * XXX We'll need to improve the walk and search to notice when file
 * data items have been truncated away.
 *
 * Inodes and their sequence numbers are copied out to userspace in
 * inode order, not sequence order.
 */
static long scoutfs_ioc_inodes_since(struct file *file, unsigned long arg,
				     u8 type)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_STABLE_META(sb);
	struct scoutfs_ioctl_inodes_since __user *uargs = (void __user *)arg;
	struct scoutfs_ioctl_inodes_since args;
	struct scoutfs_ioctl_ino_seq __user *uiseq;
	struct scoutfs_ioctl_ino_seq iseq;
	struct scoutfs_key key;
	struct scoutfs_key last;
	u64 seq;
	long bytes;
	int ret;

	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	uiseq = (void __user *)(unsigned long)args.buf_ptr;
	if (args.buf_len < sizeof(iseq) || args.buf_len > INT_MAX)
		return -EINVAL;

	scoutfs_set_key(&key, args.first_ino, type, 0);
	scoutfs_set_key(&last, args.last_ino, type, 0);

	bytes = 0;
	for (;;) {
		ret = scoutfs_btree_since(sb, meta, &key, &last, args.seq,
					  &key, &seq, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		iseq.ino = scoutfs_key_inode(&key);
		iseq.seq = seq;

		if (copy_to_user(uiseq, &iseq, sizeof(iseq))) {
			ret = -EFAULT;
			break;
		}

		uiseq++;
		bytes += sizeof(iseq);
		if (bytes + sizeof(iseq) > args.buf_len) {
			ret = 0;
			break;
		}

		key.inode = cpu_to_le64(iseq.ino + 1);
	}

	if (bytes)
		ret = bytes;

	return ret;
}

/*
 * Fill the caller's buffer with one of the paths from the on-disk root
 * directory to the target inode.
 *
 * Userspace provides a u64 counter used to chose which path to return.
 * It should be initialized to zero to start iterating.  After each path
 * it is set to the next counter to search from.
 *
 * This only walks back through full hard links.  None of the returned
 * paths will reflect symlinks to components in the path.
 *
 * This doesn't ensure that the caller has permissions to traverse the
 * returned paths to the inode.  It requires CAP_DAC_READ_SEARCH which
 * bypasses permissions checking.
 *
 * ENAMETOOLONG is returned when the next path from the given counter
 * doesn't fit in the buffer.  Providing a buffer of PATH_MAX should
 * succeed.
 *
 * This call is not serialized with any modification (create, rename,
 * unlink) of the path components.  It will return all the paths that
 * were stable both before and after the call.  It may or may not return
 * paths which are created or unlinked during the call.
 *
 * The number of bytes in the path, including the null terminator, are
 * returned when a path is found.  0 is returned when there are no more
 * paths to the link from the given counter.  -errno is returned on
 * errors.
 *
 * XXX
 *  - can dir renaming trick us into returning garbage paths?  seems likely.
 */
static long scoutfs_ioc_ino_path(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_ino_path __user *uargs = (void __user *)arg;
	struct scoutfs_ioctl_ino_path args;
	unsigned int bytes;
	char __user *upath;
	char *comp;
	char *path;
	int ret;
	int len;

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	if (args.path_bytes <= 1)
		return -EINVAL;

	bytes = min_t(unsigned int, args.path_bytes, PATH_MAX);
	path = kmalloc(bytes, GFP_KERNEL);
	if (path == NULL)
		return -ENOMEM;

	/* positive ret is len of all components including null terminators */
	ret = scoutfs_dir_get_ino_path(sb, args.ino, &args.ctr, path, bytes);
	if (ret <= 0)
		goto out;

	/* reverse the components from backref order to path/ order */
	comp = path;
	upath = (void __user *)((unsigned long)args.path_ptr + ret);
	while (comp < (path + ret)) {
		len = strlen(comp);
		if (comp != path)
			comp[len] = '/';
		len++;

		upath -= len;
		if (copy_to_user(upath, comp, len)) {
			ret = -EFAULT;
			break;
		}
		comp += len;
	}

	if (ret > 0 && put_user(args.ctr, &uargs->ctr))
		ret = -EFAULT;
out:
	kfree(path);
	return ret;
}

/*
 * Find inodes that might contain a given xattr name or value.
 *
 * The inodes are filled in sorted order from the first to the last
 * inode.  The number of found inodes is returned.  If an error is hit
 * it can return the number of inodes found before the error.
 *
 * The search can be continued from the next inode after the last
 * returned.
 */
static long scoutfs_ioc_find_xattr(struct file *file, unsigned long arg,
				   bool find_name)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_STABLE_META(sb);
	struct scoutfs_ioctl_find_xattr args;
	struct scoutfs_key key;
	struct scoutfs_key last;
	char __user *ustr;
	u64 __user *uino;
	char *str;
	int copied = 0;
	int ret = 0;
	u64 ino;
	u8 type;
	u64 h;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	if (args.str_len > SCOUTFS_MAX_XATTR_LEN || args.ino_count > INT_MAX)
		return -EINVAL;

	if (args.first_ino > args.last_ino)
		return -EINVAL;

	if (args.ino_count == 0)
		return 0;

	ustr = (void __user *)(unsigned long)args.str_ptr;
	uino = (void __user *)(unsigned long)args.ino_ptr;

	str = kmalloc(args.str_len, GFP_KERNEL);
	if (!str)
		return -ENOMEM;

	if (copy_from_user(str, ustr, args.str_len)) {
		ret = -EFAULT;
		goto out;
	}

	h = scoutfs_name_hash(str, args.str_len);

	if (find_name) {
		h &= ~SCOUTFS_XATTR_NAME_HASH_MASK;
		type = SCOUTFS_XATTR_NAME_HASH_KEY;
	} else {
		type = SCOUTFS_XATTR_VAL_HASH_KEY;
	}

	scoutfs_set_key(&key, h, type, args.first_ino);
	scoutfs_set_key(&last, h, type, args.last_ino);

	while (copied < args.ino_count) {

		ret = scoutfs_btree_next(sb, meta, &key, &last, &key, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ino = scoutfs_key_offset(&key);
		if (put_user(ino, uino)) {
			ret = -EFAULT;
			break;
		}

		uino++;
		copied++;
		scoutfs_inc_key(&key);
	}

out:
	kfree(str);
	return copied ?: ret;
}

/*
 * Sample the inode's data_version.  It is not strictly serialized with
 * writes that are in flight.
 */
static long scoutfs_ioc_data_version(struct file *file, unsigned long arg)
{
	u64 __user *uvers = (void __user *)arg;
	u64 vers = scoutfs_inode_get_data_version(file_inode(file));

	if (put_user(vers, uvers))
		return -EFAULT;

	return 0;
}

/*
 * The caller has a version of the data available in the given byte
 * range in an external archive.  As long as the data version still
 * matches we free the blocks fully contained in the range and mark them
 * offline.  Attempts to use the blocks in the future will trigger
 * recall from the archive.
 *
 * XXX permissions?
 * XXX a lot of this could be generic file write prep
 */
static long scoutfs_ioc_release(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_ioctl_release args;
	loff_t start;
	loff_t end_inc;
	u64 iblock;
	u64 end_block;
	u64 len;
	int ret;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	if (args.count == 0)
		return 0;
	if ((args.offset + args.count) < args.offset)
		return -EINVAL;

	start = round_up(args.offset, SCOUTFS_BLOCK_SIZE);
	end_inc = round_down(args.offset + args.count, SCOUTFS_BLOCK_SIZE) - 1;
	if (end_inc > start)
		return 0;

	iblock = start >> SCOUTFS_BLOCK_SHIFT;
	end_block = end_inc >> SCOUTFS_BLOCK_SHIFT;
	len = end_block - iblock + 1;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);

	if (!S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	if (!(file->f_mode & FMODE_WRITE)) {
		ret = -EINVAL;
		goto out;
	}

	if (scoutfs_inode_get_data_version(inode) != args.data_version) {
		ret = -ESTALE;
		goto out;
	}

	inode_dio_wait(inode);

	/* drop all clean and dirty cached blocks in the range */
	truncate_inode_pages_range(&inode->i_data, start, end_inc);

	ret = scoutfs_hold_trans(sb);
	if (ret)
		goto out;

	ret = scoutfs_truncate_extent_items(sb, scoutfs_ino(inode),
					    iblock, len, true);
	scoutfs_release_trans(sb);
out:
	mutex_unlock(&inode->i_mutex);
	mnt_drop_write_file(file);

	return ret;
}

/*
 * Write the archived contents of the file back if the data_version
 * still matches.
 *
 * This is a data plane operation only.  We don't want the write to
 * change any fields in the inode.  It only changes the file contents.
 *
 * Keep in mind that the staging writes can easily span transactions and
 * can crash partway through.  If we called the normal write path and
 * restored the inode afterwards the modified inode could be commited
 * partway through by a transaction and then left that way by a crash
 * before the write finishes and we restore the fields.  It also
 * wouldn't be great if the temporarily updated inode was visible to
 * paths that don't serialize with write.
 *
 * We're implementing the buffered write path down to the start of
 * generic_file_buffered_writes() without all the stuff that would
 * change the inode: file_remove_suid(), file_update_time().  The
 * easiest way to do that is to call generic_file_buffered_write().
 * We're careful to only allow staging writes inside i_size.
 *
 * We set a  bool on the inode which tells our code to update the
 * offline extents and to not update the data_version counter.
 *
 * This doesn't support any fancy write modes or side-effects: aio,
 * direct, append, sync, breaking suid, sending rlimit signals.
 */
static long scoutfs_ioc_stage(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_ioctl_stage args;
	struct kiocb kiocb;
	struct iovec iov;
	size_t written;
	loff_t pos;
	int ret;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	if (args.count < 0 || (args.offset + args.count < args.offset))
		return -EINVAL;
	if (args.count == 0)
		return 0;

	/* the iocb is really only used for the file pointer :P */
	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = args.offset;
	kiocb.ki_left = args.count;
	kiocb.ki_nbytes = args.count;
	iov.iov_base = (void __user *)(unsigned long)args.buf_ptr;
	iov.iov_len = args.count;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);

	if (!S_ISREG(inode->i_mode) ||
	    !(file->f_mode & FMODE_WRITE) ||
	    (file->f_flags & (O_APPEND | O_DIRECT | O_DSYNC)) ||
	    IS_SYNC(file->f_mapping->host) ||
	    (args.offset + args.count > i_size_read(inode))) {
		ret = -EINVAL;
		goto out;
	}

	if (scoutfs_inode_get_data_version(inode) != args.data_version) {
		ret = -ESTALE;
		goto out;
	}

	si->staging = true;
	current->backing_dev_info = mapping->backing_dev_info;

	pos = args.offset;
	written = 0;
	do {
		ret = generic_file_buffered_write(&kiocb, &iov, 1, pos, &pos,
						  args.count, written);
		BUG_ON(ret == -EIOCBQUEUED);
		if (ret > 0)
			written += ret;
	} while (ret > 0 && written < args.count);

	si->staging = false;
	current->backing_dev_info = NULL;
out:
	mutex_unlock(&inode->i_mutex);
	mnt_drop_write_file(file);

	return ret;
}

long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SCOUTFS_IOC_INODES_SINCE:
		return scoutfs_ioc_inodes_since(file, arg, SCOUTFS_INODE_KEY);
	case SCOUTFS_IOC_INO_PATH:
		return scoutfs_ioc_ino_path(file, arg);
	case SCOUTFS_IOC_FIND_XATTR_NAME:
		return scoutfs_ioc_find_xattr(file, arg, true);
	case SCOUTFS_IOC_FIND_XATTR_VAL:
		return scoutfs_ioc_find_xattr(file, arg, false);
	case SCOUTFS_IOC_INODE_DATA_SINCE:
		return scoutfs_ioc_inodes_since(file, arg, SCOUTFS_EXTENT_KEY);
	case SCOUTFS_IOC_DATA_VERSION:
		return scoutfs_ioc_data_version(file, arg);
	case SCOUTFS_IOC_RELEASE:
		return scoutfs_ioc_release(file, arg);
	case SCOUTFS_IOC_STAGE:
		return scoutfs_ioc_stage(file, arg);
	}

	return -ENOTTY;
}
