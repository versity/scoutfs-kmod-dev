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
#include <linux/pagemap.h>

#include "format.h"
#include "inode.h"
#include "key.h"
#include "filerw.h"
#include "wrlock.h"
#include "scoutfs_trace.h"
#include "btree.h"

/*
 * File data is stored in items just like everything else.  This is very
 * easy to implement but incurs a copying overhead.  We'll see how
 * expensive that gets.
 *
 * By making the max item size a bit less than the block size we can
 * still have room for the block header which gets us file data
 * checksums.  File item key offsets are multiples of this max block
 * size though items can be smaller if the data is sparse.  This lets us
 * do lookups for specific keys and take advantage of the bloom filters.
 *
 * This is a minimal first pass and will need more work.  It'll need to
 * worry about enospc in writepage and cluster access for a start.
 */

/*
* Track the intersection of the logical region of a file with a page
* and file data item.
*/
struct data_region {
	u64 item_key;
	unsigned int page_off;
	unsigned short len;
	unsigned short item_off;
};

/*
 * Map the file offset to its intersection with the page and item region.
 * Returns false if the byte position is outside the page.
*/
static bool map_data_region(struct data_region *dr, u64 pos, struct page *page)
{
	if (pos >> PAGE_SHIFT != page->index)
		return false;

	dr->page_off = pos & ~PAGE_MASK;

	dr->item_off = do_div(pos, SCOUTFS_MAX_ITEM_LEN);
	dr->item_key = pos;

	dr->len = min_t(int, SCOUTFS_MAX_ITEM_LEN - dr->item_off,
			PAGE_SIZE - dr->page_off);

	return true;
}

#define for_each_data_region(dr, page, pos) 			\
	for (pos = (u64)page->index << PAGE_SHIFT;		\
	     map_data_region(dr, pos, page); pos += (dr)->len)

/*
 * Copy the contents of file data items into the page.  If we don't
 * find an item then we zero that region of the page.
 *
 * XXX i_size?
 * XXX async?
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_mapping->host;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	struct data_region dr;
	int ret = 0;
	void *addr;
	u64 pos;

	for_each_data_region(&dr, page, pos) {
		scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_DATA_KEY,
				dr.item_key);

		scoutfs_btree_release(&curs);
		ret = scoutfs_btree_lookup(sb, &key, &curs);
		if (ret == -ENOENT) {
			addr = kmap_atomic(page);
			memset(addr + dr.page_off, 0, dr.len);
			kunmap_atomic(addr);
			continue;
		}
		if (ret)
			break;

		addr = kmap_atomic(page);
		memcpy(addr + dr.page_off, curs.val + dr.item_off, dr.len);
		kunmap_atomic(addr);
	}

	scoutfs_btree_release(&curs);

	if (!ret)
		SetPageUptodate(page);
	unlock_page(page);
	return ret;
}

/*
 * Copy the contents of the page into file items.  Data integrity syncs
 * will later write the dirty segment to the device.
 *
* XXX zeroing regions of data items?
* XXX wbc counters?
* XXX reserve space so dirty item doesn't get enospc -- our "delalloc"?
*/
static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	DECLARE_SCOUTFS_BTREE_CURSOR(curs);
	DECLARE_SCOUTFS_WRLOCK_HELD(held);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	struct data_region dr;
	void *addr;
	u64 pos;
	int ret;

	set_page_writeback(page);

	ret = scoutfs_wrlock_lock(sb, &held, 1, scoutfs_ino(inode));
	if (ret)
		goto out;

	for_each_data_region(&dr, page, pos) {
		scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_DATA_KEY,
				dr.item_key);

		/* XXX dirty */
		scoutfs_btree_release(&curs);
		ret = scoutfs_btree_insert(sb, &key, SCOUTFS_MAX_ITEM_LEN,
					   &curs);
		if (ret)
			break;

		addr = kmap_atomic(page);
		memcpy(curs.val + dr.item_off, addr + dr.page_off, dr.len);
		kunmap_atomic(addr);

	}

	scoutfs_btree_release(&curs);
	scoutfs_wrlock_unlock(sb, &held);
out:
	if (ret) {
		SetPageError(page);
		mapping_set_error(&inode->i_data, ret);
	}

	end_page_writeback(page);
	unlock_page(page);

	return ret;
}

static int scoutfs_write_begin(struct file *file, struct address_space *mapping,
			       loff_t pos, unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;

	trace_scoutfs_write_begin(scoutfs_ino(inode), pos, len);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	*pagep = page;
	return 0;
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	DECLARE_SCOUTFS_WRLOCK_HELD(held);
	unsigned off;

	trace_scoutfs_write_end(scoutfs_ino(inode), pos, len, copied);

	off = pos & (PAGE_CACHE_SIZE - 1);

	/* zero the stale part of the page if we did a short copy */
	if (copied < len)
		zero_user_segment(page, off + copied, len);

	if (pos + copied > inode->i_size) {
		i_size_write(inode, pos + copied);

		/*
		 * XXX This is a crazy hack that will go away when the
		 * file data paths are more robust.  We're barely
		 * holding them together with duct tape while building
		 * up the robust metadata support that's needed to do a
		 * good job with the data pats.
		 */
		if (!scoutfs_wrlock_lock(sb, &held, 1, scoutfs_ino(inode))) {
			if (!scoutfs_dirty_inode_item(inode))
				scoutfs_update_inode_item(inode);
			scoutfs_wrlock_unlock(sb, &held);
		}
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	set_page_dirty(page);
	unlock_page(page);
	page_cache_release(page);

	return copied;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.writepage		= scoutfs_writepage,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
};
