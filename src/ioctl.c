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
#include "item.h"
#include "data.h"
#include "net.h"

/*
 * Walk one of the inode index items.  This is a thin ioctl wrapper
 * around the core item interface.
 */
static long scoutfs_ioc_walk_inodes(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_walk_inodes __user *uwalk = (void __user *)arg;
	struct scoutfs_ioctl_walk_inodes walk;
	struct scoutfs_ioctl_walk_inodes_entry ent;
	struct scoutfs_inode_index_key last_ikey;
	struct scoutfs_inode_index_key ikey;
	struct scoutfs_key_buf last_key;
	struct scoutfs_key_buf key;
	u64 last_seq;
	int ret = 0;
	u8 type;
	u32 nr;

	if (copy_from_user(&walk, uwalk, sizeof(walk)))
		return -EFAULT;

	trace_printk("index %u first %llu.%u.%llu last %llu.%u.%llu\n",
		     walk.index, walk.first.major, walk.first.minor,
		     walk.first.ino, walk.last.major, walk.last.minor,
		     walk.last.ino);

	if (walk.index == SCOUTFS_IOC_WALK_INODES_CTIME)
		type = SCOUTFS_INODE_INDEX_CTIME_TYPE;
	else if (walk.index == SCOUTFS_IOC_WALK_INODES_MTIME)
		type = SCOUTFS_INODE_INDEX_MTIME_TYPE;
	else if (walk.index == SCOUTFS_IOC_WALK_INODES_SIZE)
		type = SCOUTFS_INODE_INDEX_SIZE_TYPE;
	else if (walk.index == SCOUTFS_IOC_WALK_INODES_META_SEQ)
		type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	else if (walk.index == SCOUTFS_IOC_WALK_INODES_DATA_SEQ)
		type = SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE;
	else
		return -EINVAL;

	/* clamp results to the inodes in the farthest stable seq */
	if (type == SCOUTFS_INODE_INDEX_META_SEQ_TYPE ||
	    type == SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE) {

		ret = scoutfs_net_get_last_seq(sb, &last_seq);
		if (ret)
			return ret;

		if (last_seq < walk.last.major) {
			walk.last.major = last_seq;
			walk.last.minor = ~0;
			walk.last.ino = ~0ULL;
		}
	}

	ikey.zone = SCOUTFS_INODE_INDEX_ZONE;
	ikey.type = type;
	ikey.major = cpu_to_be64(walk.first.major);
	ikey.minor = cpu_to_be32(walk.first.minor);
	ikey.ino = cpu_to_be64(walk.first.ino);
	scoutfs_key_init(&key, &ikey, sizeof(ikey));

	last_ikey.zone = ikey.zone;
	last_ikey.type = ikey.type;
	last_ikey.major = cpu_to_be64(walk.last.major);
	last_ikey.minor = cpu_to_be32(walk.last.minor);
	last_ikey.ino = cpu_to_be64(walk.last.ino);
	scoutfs_key_init(&last_key, &last_ikey, sizeof(last_ikey));

	/* cap nr to the max the ioctl can return to a compat task */
	walk.nr_entries = min_t(u64, walk.nr_entries, INT_MAX);

	for (nr = 0; nr < walk.nr_entries;
	     nr++, walk.entries_ptr += sizeof(ent)) {

		ret = scoutfs_item_next_same(sb, &key, &last_key, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ent.major = be64_to_cpu(ikey.major);
		ent.minor = be32_to_cpu(ikey.minor);
		ent.ino = be64_to_cpu(ikey.ino);

		if (copy_to_user((void __user *)walk.entries_ptr, &ent,
				 sizeof(ent))) {
			ret = -EFAULT;
			break;
		}

		scoutfs_key_inc_cur_len(&key);
	}

	return nr ?: ret;
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

	trace_printk("offset %llu count %llu vers %llu\n",
			args.offset, args.count, args.data_version);

	if (args.count == 0)
		return 0;
	if ((args.offset + args.count) < args.offset)
		return -EINVAL;

	start = round_up(args.offset, SCOUTFS_BLOCK_SIZE);
	end_inc = round_down(args.offset + args.count, SCOUTFS_BLOCK_SIZE) - 1;
	if (end_inc < start)
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

	if (scoutfs_inode_data_version(inode) != args.data_version) {
		ret = -ESTALE;
		goto out;
	}

	inode_dio_wait(inode);

	/* drop all clean and dirty cached blocks in the range */
	truncate_inode_pages_range(&inode->i_data, start, end_inc);

	ret = scoutfs_data_truncate_items(sb, scoutfs_ino(inode), iblock, len,
					  true);
out:
	mutex_unlock(&inode->i_mutex);
	mnt_drop_write_file(file);

	trace_printk("ret %d\n", ret);
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

	if (scoutfs_inode_data_version(inode) != args.data_version) {
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

static long scoutfs_ioc_stat_more(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_ioctl_stat_more stm;

	if (get_user(stm.valid_bytes, (__u64 __user *)arg))
		return -EFAULT;

	stm.valid_bytes = min_t(u64, stm.valid_bytes,
				sizeof(struct scoutfs_ioctl_stat_more));
	stm.meta_seq = scoutfs_inode_meta_seq(inode);
	stm.data_seq = scoutfs_inode_data_seq(inode);
	stm.data_version = scoutfs_inode_data_version(inode);

	if (copy_to_user((void __user *)arg, &stm, stm.valid_bytes))
		return -EFAULT;

	return 0;
}

static long scoutfs_ioc_item_cache_keys(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_item_cache_keys ick;
	struct scoutfs_key_buf *key;
	struct page *page;
	unsigned bytes;
	void *buf;
	int total;
	int ret;

	if (copy_from_user(&ick, (void __user *)arg, sizeof(ick)))
		return -EFAULT;

	if ((!!ick.key_ptr != !!ick.key_len) ||
	    ick.key_len > SCOUTFS_MAX_KEY_SIZE ||
	    ick.which > SCOUTFS_IOC_ITEM_CACHE_KEYS_RANGES)
		return -EINVAL;

	/* don't overflow signed 32bit syscall return longs */
	ick.buf_len = min_t(u64, ick.buf_len, S32_MAX);

	key = scoutfs_key_alloc(sb, SCOUTFS_MAX_KEY_SIZE);
	page = alloc_page(GFP_KERNEL);
	if (!key || !page) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(key->data, (void __user *)ick.key_ptr, ick.key_len)) {
		ret = -EFAULT;
		goto out;
	}
	scoutfs_key_init_buf_len(key, key->data, ick.key_len,
				 SCOUTFS_MAX_KEY_SIZE);
	scoutfs_key_inc(key);

	buf = page_address(page);
	total = 0;
	ret = 0;
	while (ick.buf_len) {
		bytes = min_t(u64, ick.buf_len, PAGE_SIZE);

		if (ick.which == SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS)
			ret = scoutfs_item_copy_keys(sb, key, buf, bytes);
		else
			ret = scoutfs_item_copy_range_keys(sb, key, buf, bytes);

		if (ret > 0 && copy_to_user((void __user *)ick.buf_ptr, buf, ret))
			ret = -EFAULT;
		if (ret <= 0)
			break;

		ick.buf_len -= ret;
		ick.buf_ptr += ret;
		total += ret;
		ret = 0;
	}

out:
	scoutfs_key_free(sb, key);
	if (page)
		__free_page(page);

	return ret ?: total;
}

long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SCOUTFS_IOC_WALK_INODES:
		return scoutfs_ioc_walk_inodes(file, arg);
	case SCOUTFS_IOC_INO_PATH:
		return scoutfs_ioc_ino_path(file, arg);
	case SCOUTFS_IOC_RELEASE:
		return scoutfs_ioc_release(file, arg);
	case SCOUTFS_IOC_STAGE:
		return scoutfs_ioc_stage(file, arg);
	case SCOUTFS_IOC_STAT_MORE:
		return scoutfs_ioc_stat_more(file, arg);
	case SCOUTFS_IOC_ITEM_CACHE_KEYS:
		return scoutfs_ioc_item_cache_keys(file, arg);
	}

	return -ENOTTY;
}
