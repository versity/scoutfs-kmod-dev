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
#include "key.h"
#include "dir.h"
#include "ioctl.h"
#include "super.h"
#include "inode.h"
#include "trans.h"
#include "data.h"

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
	struct scoutfs_ioctl_inodes_since __user *uargs = (void __user *)arg;
	struct scoutfs_ioctl_inodes_since args;
	struct scoutfs_ioctl_ino_seq __user *uiseq;
	struct scoutfs_ioctl_ino_seq iseq;
	struct scoutfs_inode_key last_ikey;
	struct scoutfs_inode_key ikey;
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	long bytes;
	u64 seq;
	int ret;

	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	uiseq = (void __user *)(unsigned long)args.buf_ptr;
	if (args.buf_len < sizeof(iseq) || args.buf_len > INT_MAX)
		return -EINVAL;

	scoutfs_inode_init_key(&key, &ikey, args.first_ino);
	scoutfs_inode_init_key(&last, &last_ikey, args.last_ino);

	bytes = 0;
	for (;;) {

		/* XXX item cache needs to search by seq */
		seq = !!sb;
		ret = WARN_ON_ONCE(-EINVAL);
//		ret = scoutfs_item_since(sb, &key, &last, args.seq, &seq, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		iseq.ino = be64_to_cpu(ikey.ino);
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

		last_ikey.ino = cpu_to_be64(iseq.ino + 1);
	}

	if (bytes)
		ret = bytes;

	return ret;
}

struct ino_path_cursor {
	__u64 dir_ino;
	__u8 name[SCOUTFS_NAME_LEN + 1];
} __packed;

/*
 * see the definition of scoutfs_ioctl_ino_path for ioctl semantics.
 *
 * The null termination of the cursor name is a trick to skip past the
 * last name we read without having to try and "increment" the name.
 * Adding a null sorts the cursor after the non-null name and before all
 * the next names because the item names aren't null terminated.
 */
static long scoutfs_ioc_ino_path(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_ino_path __user *uargs;
	struct scoutfs_link_backref_entry *ent;
	struct ino_path_cursor __user *ucurs;
	struct scoutfs_ioctl_ino_path args;
	char __user *upath;
	LIST_HEAD(list);
	u64 dir_ino;
	u16 name_len;
	char term;
	char *name;
	int ret;

	BUILD_BUG_ON(SCOUTFS_IOC_INO_PATH_CURSOR_BYTES !=
		     sizeof(struct ino_path_cursor));

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	uargs = (void __user *)arg;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	if (args.cursor_bytes != sizeof(struct ino_path_cursor))
		return -EINVAL;

	ucurs = (void __user *)(unsigned long)args.cursor_ptr;
	upath = (void __user *)(unsigned long)args.path_ptr;

	if (get_user(dir_ino, &ucurs->dir_ino))
		return -EFAULT;

	/* alloc/copy the small cursor name, requires and includes null */
	name_len = strnlen_user(ucurs->name, sizeof(ucurs->name));
	if (name_len < 1 || name_len > sizeof(ucurs->name))
		return -EINVAL;

	name = kmalloc(name_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	if (copy_from_user(name, ucurs->name, name_len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = scoutfs_dir_get_backref_path(sb, args.ino, dir_ino, name,
					   name_len, &list);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	ret = 0;
	list_for_each_entry(ent, &list, head) {
		if (ret + ent->name_len + 1 > args.path_bytes) {
			ret = -ENAMETOOLONG;
			goto out;
		}

		if (copy_to_user(upath, ent->lbkey.name, ent->name_len)) {
			ret = -EFAULT;
			goto out;
		}

		upath += ent->name_len;
		ret += ent->name_len;

		if (ent->head.next == &list)
			term = '\0';
		else
			term = '/';

		if (put_user(term, upath)) {
			ret = -EFAULT;
			break;
		}

		upath++;
		ret++;
	}

	/* copy the last entry into the cursor */
	ent = list_last_entry(&list, struct scoutfs_link_backref_entry, head);

	if (put_user(be64_to_cpu(ent->lbkey.dir_ino), &ucurs->dir_ino) ||
	    copy_to_user(ucurs->name, ent->lbkey.name, ent->name_len) ||
	    put_user('\0', &ucurs->name[ent->name_len])) {
		ret = -EFAULT;
	}

out:
	scoutfs_dir_free_backref_path(sb, &list);
	kfree(name);
	return ret;
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

	ret = scoutfs_data_truncate_items(sb, scoutfs_ino(inode), iblock, len,
					  true);
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
	case SCOUTFS_IOC_INODE_DATA_SINCE:
		return WARN_ON_ONCE(-EINVAL);
	case SCOUTFS_IOC_DATA_VERSION:
		return scoutfs_ioc_data_version(file, arg);
	case SCOUTFS_IOC_RELEASE:
		return scoutfs_ioc_release(file, arg);
	case SCOUTFS_IOC_STAGE:
		return scoutfs_ioc_stage(file, arg);
	}

	return -ENOTTY;
}
