/*
* Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/delay.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"

/*
 * scoutfs stores data in items that can be up to the small 4K block
 * size.  The page cache address space callbacks work with the item
 * cache.  Each OS page can be stored in multiple of our smaller fixed
 * size items.  The code doesn't understand OS pages that are smaller
 * than our block size.
 *
 * readpage does a blocking read of the item and then copies its
 * contents into the page.  Since the segments are huge we sort of get
 * limited read-ahead by reading in segments at a time.
 *
 * Writing is quite a bit more fiddly.  We want to pack small files.
 * The item cache and transactions want to accurately track the size of
 * dirty items to fill the next segment.  And we would like to minimize
 * cpu copying as much as we can.
 *
 * This simplest first pass creates dirty items as pages are dirtied
 * whose values reference the page contents.  They're freed after
 * they're written to the segment so that we don't have to worry about
 * items that reference clean pages.  Invalidatepage forgets any items
 * if a dirty page is truncated away.
 *
 * Writeback is built around all the dirty items being written by a
 * commit.  This can happen naturally in the backgroud.  Or writepage
 * can initiate it to start by kicking the commit thread.  In either
 * case our dirty pages are "in writeback" by being put on a list that
 * is walked by the end of the commit.  Because writes and page dirtying
 * are serialized with the commit we know that there can be no dirty
 * pages after the commit and we can mark writeback complete on all the
 * pages that started writeback before the commit finished.  motivate
 * having items in the item cache while there are dirty pages.
 *
 * Data is copied from the dirty page contents into the segment pages
 * for writing.  This lets us easily pack small files without worrying
 * about DMA alignment and avoids the stable page problem of the page
 * being modified after the cpu calculates the checksum but before the
 * DMA reads to the device.
 *
 * XXX
 *  - truncate
 *  - mmap
 *  - better io error propagation
 *  - async readpages for more concurrent readahead
 *  - forced unmount with dirty data
 *  - direct IO
 *  - probably stitch page vecs into block struct page fragments for bios
 *  - maybe cut segment boundaries on aligned data offsets
 *  - maybe decouple metadata and data segment writes
 */

struct data_info {
	struct llist_head writeback_pages;
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

/*
 * trace_printk() doesn't support %c?
 *
 * 1 - 1ocked
 * a - uptodAte
 * d - Dirty
 * b - writeBack
 * e - Error
 */
#define page_hexflag(page, name, val, shift) \
	(Page##name(page) ? (val << (shift * 4)) : 0)

#define page_hexflags(page) \
	(page_hexflag(page, Locked, 0x1, 4)	|	\
	 page_hexflag(page, Uptodate, 0xa, 3)	|	\
	 page_hexflag(page, Dirty, 0xd, 2)	|	\
	 page_hexflag(page, Writeback, 0xb, 1)	|	\
	 page_hexflag(page, Error, 0xe, 0))

#define PGF "page %p [index %lu flags %x]"
#define PGA(page)					\
	(page), (page)->index, page_hexflags(page)	\

#define BHF "bh %p [blocknr %llu size %zu state %lx]"
#define BHA(bh)							\
	(bh), (u64)(bh)->b_blocknr, (bh)->b_size, (bh)->b_state	\

static void init_data_key(struct scoutfs_key_buf *key,
			  struct scoutfs_data_key *dkey, u64 ino, u64 block)
{
	dkey->type = SCOUTFS_DATA_KEY;
	dkey->ino = cpu_to_be64(ino);
	dkey->block = cpu_to_be64(block);

	scoutfs_key_init(key, dkey, sizeof(struct scoutfs_data_key));
}

/*
 * Delete the data block items in the given region.
 *
 * This is the low level extent item truncate code.  Callers manage
 * higher order truncation and orphan cleanup.
 *
 * XXX
 *  - restore support for releasing data.
 *  - for final unlink this would be better as a range deletion
 *  - probably don't want to read items to find them for removal
 */
int scoutfs_data_truncate_items(struct super_block *sb, u64 ino, u64 iblock,
				u64 len, bool offline)
{
	struct scoutfs_data_key last_dkey;
	struct scoutfs_data_key dkey;
	struct scoutfs_key_buf last;
	struct scoutfs_key_buf key;
	int ret;

	trace_printk("iblock %llu len %llu offline %u\n",
		     iblock, len, offline);

	if (WARN_ON_ONCE(iblock + len <= iblock) ||
	    WARN_ON_ONCE(offline))
		return -EINVAL;

	init_data_key(&key, &dkey, ino, iblock);
	init_data_key(&last, &last_dkey, ino, iblock + len - 1);

	for (;;) {
		ret = scoutfs_item_next(sb, &key, &last, NULL);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		/* XXX would set offline bit items here */

		ret = scoutfs_item_delete(sb, &key);
		if (ret)
			break;
	}

	return ret;
}

static inline struct page *page_from_llist_node(struct llist_node *node)
{
	BUILD_BUG_ON(member_sizeof(struct page, private) !=
		     sizeof(struct llist_node));

	return container_of((void *)node, struct page, private);
}

static inline struct llist_node *llist_node_from_page(struct page *page)
{
	return (void *)&page->private;
}

static inline void page_llist_add(struct page *page, struct llist_head *head)
{
	llist_add(llist_node_from_page(page), head);
}

/*
 * The transaction has committed so there are no more dirty items.  End
 * writeback on all the dirty pages that started writeback before the
 * commit finished.  The commit doesn't start until all holders which
 * could dirty are released so there couldn't have been new dirty pages
 * and writeback entries while the commit was in flight.
 */
void scoutfs_data_end_writeback(struct super_block *sb, int err)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct llist_node *node;
	struct page *page;

	/* XXX haven't thought about errors here */
	BUG_ON(err);

	node = llist_del_all(&datinf->writeback_pages);

	while (node) {
		page = page_from_llist_node(node);
		node = llist_next(node);

		trace_printk("ending writeback "PGF"\n", PGA(page));
		scoutfs_inc_counter(sb, data_end_writeback_page);


		set_page_private(page, 0);
		end_page_writeback(page);
		page_cache_release(page);
	}
}

#define for_each_page_block(page, start, loff, block, key, dkey, val)	   \
	for (start = 0;							   \
	     start < PAGE_CACHE_SIZE &&					   \
		(loff = ((loff_t)page->index << PAGE_CACHE_SHIFT) + start, \
		 block = loff >> SCOUTFS_BLOCK_SHIFT,			   \
		 init_data_key(&key, &dkey,				   \
			       scoutfs_ino(page->mapping->host), block),   \
		 scoutfs_kvec_init(val, page_address(page) + start,	   \
				   SCOUTFS_BLOCK_SIZE),			   \
		 1);							   \
	     start += SCOUTFS_BLOCK_SIZE)

/*
 * Copy the contents of each item that makes up the page into their
 * regions of the page, zeroing any page contents not covered by items.
 *
 * This is the simplest loop that looks up every possible block.  We
 * could instead have a readpages() that iterates over present items and
 * puts them in the pages in the batch.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	loff_t size = i_size_read(inode);
	struct scoutfs_data_key dkey;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	unsigned start;
	loff_t loff;
	u64 block;
	int ret = 0;


	trace_printk(PGF"\n", PGA(page));
	scoutfs_inc_counter(sb, data_readpage);

	for_each_page_block(page, start, loff, block, key, dkey, val) {
		/* the rest of the page is zero when block is past i_size */
		if (loff >= size)
			break;

		/* copy the block item contents into the page */
		ret = scoutfs_item_lookup(sb, &key, val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			else
				break;
		}

		/*
		 * XXX do we need to clamp the item length by i_size?
		 * truncate should purge the item cache and create
		 * truncation range items that'd merge away old data
		 * items, and invalidatepage should shrink any ephemeral
		 * vecs.  Seems like the item length should be accurate?
		 */

		/* zero the tail of the block */
		if (ret < SCOUTFS_BLOCK_SIZE)
			zero_user(page, start, SCOUTFS_BLOCK_SIZE - ret);
	}

	/* zero any remaining tail blocks */
	if (start < PAGE_CACHE_SIZE)
		zero_user(page, start, PAGE_CACHE_SIZE - start);

	if (ret == 0)
		SetPageUptodate(page);
	else
		SetPageError(page);

	trace_printk("ret %d\n", ret);
	unlock_page(page);
	return ret;
}

/*
 * Start writeback on a dirty page.  We always try to kick off a commit.
 * Repeated calls harmlessly bounce off the thread work's pending bit.
 * (we could probably test that the writeback pgaes list is empty before
 * trying to kick off a commit.)
 *
 * We add ourselves to a list of pages that the commit will end
 * writeback on once its done.  If there's no dirty data the commit
 * thread will end writeback after not doing anything.
 */
static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	DECLARE_DATA_INFO(sb, datinf);

	trace_printk(PGF"\n", PGA(page));
	scoutfs_inc_counter(sb, data_writepage);

	BUG_ON(PageWriteback(page));
	BUG_ON(page->private != 0);

	ClearPagePrivate(page); /* invalidatepage not needed */
	set_page_writeback(page);
	page_cache_get(page);
	page_llist_add(page, &datinf->writeback_pages);
	unlock_page(page);
	scoutfs_sync_fs(sb, 0);

	return 0;
}

/*
 * Truncate is invalidating part of the contents of a page.
 *
 * We can't return errors here so our job is not to create dirty items
 * that end up executing the truncate.  That's the job of higher level
 * callers.  Our job is to make sure that we update references to the
 * page from existing ephemeral items if they already exist.
 */
static void scoutfs_invalidatepage(struct page *page, unsigned long offset)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_data_key dkey;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	unsigned start;
	loff_t loff;
	u64 block;

	trace_printk(PGF"\n", PGA(page));
	scoutfs_inc_counter(sb, data_invalidatepage);

	for_each_page_block(page, start, loff, block, key, dkey, val) {
		if (offset) {
			/* XXX maybe integrate offset into foreach */
			/* XXX ugh, kvecs are still clumsy :) */
			if (start + SCOUTFS_BLOCK_SIZE > offset)
				val[0].iov_len = offset - start;
			scoutfs_item_update_ephemeral(sb, &key, val);
		} else {
			scoutfs_item_forget(sb, &key);
		}
	}
}

/*
 * Start modifying a page cache page.
 *
 * We hold the transaction for write_end's inode updates before
 * acquiring the page lock.
 *
 * We give the writer the current page contents in the relatively rare
 * case of writing a partial page inside i_size.  write_end will zero
 * any region around the write if the page isn't uptodate.
 */
static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
        pgoff_t index = pos >> PAGE_SHIFT;
	loff_t size = i_size_read(inode);
        struct page *page;
	int ret;

	trace_printk("ino %llu pos %llu len %u flags %x\n",
		     scoutfs_ino(inode), (u64)pos, len, flags);
	scoutfs_inc_counter(sb, data_write_begin);

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	ret = scoutfs_dirty_inode_item(inode);
	if (ret)
		goto out;

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	trace_printk(PGF"\n", PGA(page));

	if (!PageUptodate(page) && (pos < size && len < PAGE_CACHE_SIZE)) {
		ClearPageError(page);
		ret = scoutfs_readpage(file, page);
		if (!ret) {
			wait_on_page_locked(page);
			if (!PageUptodate(page))
				ret = -EIO;
		}
		page_cache_release(page);
		if (ret)
			goto out;

		/* let grab_ lock and check for truncated pages */
		goto retry;
	}

        *pagep = page;
	ret = 0;
out:
	if (ret)
		scoutfs_release_trans(sb);

	trace_printk("ret %d\n", ret);
        return ret;
}

/*
 * Finish modification of a page cache page.
 *
 * write_begin has held the transaction and dirtied the inode.  We
 * create items for each dirty block whose value references the page
 * contents that will be written.
 *
 * We Modify the dirty item and its dependent metadata items while
 * holding the transaction so that we never get missing data.
 *
 * XXX
 *  - detect no change with copied == 0?
 *  - only iterate over written blocks, not the whole page?
 *  - make sure page granular locking and concurrent extending writes works
 *  - error handling needs work, truncate partial writes on failure?
 */
static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_data_key dkey;
	struct scoutfs_key_buf key;
	SCOUTFS_DECLARE_KVEC(val);
	loff_t old_size = i_size_read(inode);
	bool update_inode = false;
	loff_t new_size;
	unsigned start;
	loff_t loff;
	u64 block;
	int ret;

	trace_printk("ino %llu "PGF" pos %llu len %u copied %d\n",
		     scoutfs_ino(inode), PGA(page), (u64)pos, len, copied);
	scoutfs_inc_counter(sb, data_write_end);

	/* zero any unwritten portions of a new page around the write */
	if (!PageUptodate(page)) {
		if (copied != PAGE_CACHE_SIZE) {
			start = pos & ~PAGE_CACHE_MASK;
			zero_user_segments(page, 0, start,
					   start + copied, PAGE_CACHE_SIZE);
		}
		SetPageUptodate(page);
	}

	new_size = pos + copied;

	for_each_page_block(page, start, loff, block, key, dkey, val) {

		/* only put data inside i_size in items */
		/* XXX ugh, kvecs are still clumsy :) */
		if (loff + SCOUTFS_BLOCK_SIZE > new_size)
			val[0].iov_len = new_size - loff;

		ret = scoutfs_item_create_ephemeral(sb, &key, val);
		if (ret)
			goto out;
	}

	/* update i_size if we extended */
        if (new_size > inode->i_size) {
                i_size_write(inode, new_size);
		update_inode = true;
        }

        if (old_size < pos)
                pagecache_isize_extended(inode, old_size, pos);

	if (copied) {
		scoutfs_inode_inc_data_version(inode);
		update_inode = true;
	}

	if (update_inode)
		scoutfs_update_inode_item(inode);

	flush_dcache_page(page);
	set_page_dirty(page);
	SetPagePrivate(page); /* call invalidatepage */

	ret = copied;
out:
	unlock_page(page);
	scoutfs_release_trans(sb);

	/* XXX error handling needs work */
	WARN_ON_ONCE(ret < 0);
	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.writepage		= scoutfs_writepage,
	.set_page_dirty		= __set_page_dirty_nobuffers,
	.invalidatepage		= scoutfs_invalidatepage,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
};

int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf;

	/* page block iteration doesn't understand multiple pages per block */
	BUILD_BUG_ON(PAGE_SIZE < SCOUTFS_BLOCK_SIZE);

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;
	sbi->data_info = datinf;

	init_llist_head(&datinf->writeback_pages);

	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		WARN_ON_ONCE(!llist_empty(&datinf->writeback_pages));
		kfree(datinf);
	}
}
