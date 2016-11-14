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
#include <linux/buffer_head.h>
#include <linux/mpage.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "filerw.h"
#include "trans.h"
#include "scoutfs_trace.h"
#include "btree.h"
#include "ioctl.h"

/*
 * scoutfs uses an extent item to map logical file data blocks to
 * physical block locations.
 *
 * The small block size is set to the smallest supported page size.
 * This means that our file IO code never has to worry about the
 * situation where a page write is smaller than the block size.  We
 * never have to perform RMW of blocks larger than pages, nor do we have
 * to punch a whole and worry about block tracking items that could be
 * sharing references to a block on either side of a smaller dirty page.
 * We can simply use the kernel's buffer head code, loathed though it
 * is, and have a 1:1 relationship between block writes and block
 * mapping item entries.
 *
 * Dirty extents are only written to free space.  The first time a block
 * hits write_page in a transaction it gets a newly allocated block.  We
 * get decent contiguous allocations by having per-task preallocation
 * streams.  These are trimmed back as the transaction is committed.  We
 * don't bother worrying about small transactions.
 *
 * Because we only write to allocated space we can't naively use the
 * buffer head get_blocks support functions.  They assume that they can
 * write dirty buffers to existing clean mappings which is absolutely
 * not true for us.  We clear mappings for clean pages before we call
 * block_write_begin() so that it won't write to blocks that were caned
 * from previous reads.  We make sure that the page is uptodate ourself
 * so that it won't use readpage to read the existing block and then
 * turn around and write to it.
 *
 * Data blocks aren't pinned for the duration of the transaction.  They
 * can be written out and read back in and redirtied during the lifetime
 * of a transaction.  As we map dirty pages we see if its current allocation
 * is newly allocated in the transaction and can reuse it.
 *
 * XXX
 *  - need to wire up dirty inode?
 *  - enforce writing to free blknos
 *  - per-task allocation regions
 *  - tear down dirty extents left by write errors on unmount
 *  - should invalidate dirty blocks if freed
 *  - data block checksumming (stable pages)
 *  - mmap creating dirty unmapped pages at writepage
 *  - pack small tails into inline items
 *  - direct IO
 */


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

/*
 * For now this is super cheesy.  We just have one allocation on the
 * super that is consumed as buffered writes make their way through unmapped
 * buffer heads and alloc in get_block.
 */
static int alloc_file_block(struct super_block *sb, u64 *blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 alloc_blkno;
	int order = 0;
	int ret;

	*blkno = 0;

	spin_lock(&sbi->file_alloc_lock);

	if (sbi->file_alloc_count == 0) {
		spin_unlock(&sbi->file_alloc_lock);

		order = scoutfs_buddy_alloc(sb, &alloc_blkno,
					    SCOUTFS_BUDDY_ORDERS - 1);
		if (order < 0) {
			ret = order;
			goto out;
		}

		spin_lock(&sbi->file_alloc_lock);

		if (sbi->file_alloc_count == 0) {
			sbi->file_alloc_blkno = alloc_blkno;
			sbi->file_alloc_count = 1 << order;
			order = -1;
		}
	}

	if (sbi->file_alloc_count) {
		*blkno = sbi->file_alloc_blkno;
		sbi->file_alloc_blkno++;
		sbi->file_alloc_count--;
		ret = 0;
	} else {
		ret = -ENOSPC;
	}

	spin_unlock(&sbi->file_alloc_lock);

	if (order > 0)
		scoutfs_buddy_free(sb, sbi->super.hdr.seq, alloc_blkno, order);

out:
	trace_printk("allocated blkno %llu ret %d\n", *blkno, ret);
	return ret;
}

/*
 * The caller didn't need an allocated file block after all.  We return
 * it to the pool.  This has to succeed because it's called after we've
 * done things that would be annoying to revert.
 */
static void return_file_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	spin_lock(&sbi->file_alloc_lock);

	BUG_ON(sbi->file_alloc_count &&
	       sbi->file_alloc_blkno != (blkno + 1));

	if (sbi->file_alloc_count == 0)
		sbi->file_alloc_blkno = blkno + 1;

	sbi->file_alloc_blkno--;
	sbi->file_alloc_count++;

	spin_unlock(&sbi->file_alloc_lock);
}

/*
 * Free mapped extents whose entire contents are past the new
 * specified size.  The caller holds a transaction.
 *
 * This is the low level extent item truncate code.
 * Callers manage higher order truncation and orphan cleanup.
 *
 * XXX probably should be a range
 */
int scoutfs_truncate_extent_items(struct super_block *sb, u64 ino, u64 size)
{
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_extent extent;
	struct scoutfs_btree_val val;
	struct scoutfs_key key;
	struct scoutfs_key first;
	u64 iblock;
	u64 len;
	u64 loff;
	u64 seq;
	int ret;

	iblock = DIV_ROUND_UP(size, SCOUTFS_BLOCK_SIZE);

	scoutfs_set_key(&first, ino, SCOUTFS_EXTENT_KEY, 0);
	scoutfs_set_key(&key, ino, SCOUTFS_EXTENT_KEY, ~0ULL);

	trace_printk("iblock %llu\n", iblock);

	scoutfs_btree_init_val(&val, &extent, sizeof(extent));
	val.check_size_eq = 1;

	for (;;) {
		ret = scoutfs_btree_prev(sb, meta, &first, &key, &key, &seq,
					 &val);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		loff = le64_to_cpu(key.offset);
		len = le64_to_cpu(extent.len);

		if (WARN_ON_ONCE(len != 1)) {
			ret = -EIO;
			break;
		}

		if ((loff + len) <= iblock)
			break;

		/* make sure we can delete the extent after freeing */
		ret = scoutfs_btree_dirty(sb, meta, &key);
		if (ret)
			break;

		ret = scoutfs_buddy_free(sb, cpu_to_le64(seq),
					 le64_to_cpu(extent.blkno), 0);
		if (ret)
			break;

		scoutfs_btree_delete(sb, meta, &key);

		/* XXX sync transaction if it's enormous */
		scoutfs_dec_key(&key);
	}

	return ret;
}

/*
 * The caller ensures that this is serialized against all other callers
 * and writers.
 */
void scoutfs_filerw_free_alloc(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	trace_printk("blkno %llu count %llu\n", sbi->file_alloc_blkno,
		     sbi->file_alloc_count);

	if (sbi->file_alloc_count)
		scoutfs_buddy_free_extent(sb, sbi->file_alloc_blkno,
					  sbi->file_alloc_count);

	sbi->file_alloc_blkno = 0;
	sbi->file_alloc_count = 0;
}

/*
 * Return the number of contiguously mapped blocks starting from the
 * given logical block in the inode.
 */
static int contig_mapped_blocks(struct inode *inode, u64 iblock, u64 *blkno)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_btree_val val;
	struct scoutfs_extent extent;
	struct scoutfs_key key;
	int ret;

	*blkno = 0;
	scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_EXTENT_KEY, iblock);
	scoutfs_btree_init_val(&val, &extent, sizeof(extent));

	ret = scoutfs_btree_lookup(sb, meta, &key, &val);
	if (ret == sizeof(extent)) {
		*blkno = le64_to_cpu(extent.blkno);
		ret = min_t(u64, le64_to_cpu(extent.len), INT_MAX);
	} else if (ret >= 0) {
		/* XXX corruption */
		ret = -EIO;
	} else if (ret == -ENOENT) {
		ret = 0;
	}

	trace_printk("ino %llu iblock %llu blkno %llu ret %d\n",
		     scoutfs_ino(inode), iblock, *blkno, ret);

	return ret;
}

/*
 * Make sure that the mapped block at the given logical block number is
 * writable in this transaction.  If it's not we allocate and reference
 * a new block.  If there was a previous stable block we free it.  We
 * give the caller the writable block number.
 *
 * Writeback is allowed during a transaction so we can get here with
 * buffer heads that are newly allocated and being written to but for
 * blocks that were allocated in the current transacation.  In that
 * case we re-use the existing mapping.  None of it will be stable until
 * there's a sync that writes all the referencing metadata.
 */
static int map_writable_block(struct inode *inode, u64 iblock, u64 *blkno_ret)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->stable_super;
	struct scoutfs_btree_root *meta = SCOUTFS_META(sb);
	struct scoutfs_extent extent;
	struct scoutfs_btree_val val;
	struct scoutfs_key first;
	struct scoutfs_key key;
	bool inserted = false;
	u64 old_blkno = 0;
	u64 new_blkno = 0;
	u64 seq;
	int ret;
	int err;

	scoutfs_set_key(&first, scoutfs_ino(inode), SCOUTFS_EXTENT_KEY, 0);
	scoutfs_set_key(&key, scoutfs_ino(inode), SCOUTFS_EXTENT_KEY, iblock);
	scoutfs_btree_init_val(&val, &extent, sizeof(extent));
	val.check_size_eq = 1;

	/* see if there's an existing mapping */
	ret = scoutfs_btree_prev(sb, meta, &first, &key, &key, &seq, &val);
	if (ret == 0 && ((le64_to_cpu(key.offset) +
			  le64_to_cpu(extent.len)) <= iblock))
		ret = -ENOENT;
	if (ret < 0 && ret != -ENOENT)
		goto out;

	/* make sure that updating the extent item won't fail */
	if (ret == -ENOENT) {
		memset(&extent, 0, sizeof(extent));
		ret = scoutfs_btree_insert(sb, meta, &key, &val);
		if (ret)
			goto out;
		inserted = true;
	} else {
		ret = scoutfs_btree_dirty(sb, meta, &key);
		if (ret)
			goto out;
	}

	old_blkno = le64_to_cpu(extent.blkno);

	/* If the existing block is dirty then we can use it */
	if (old_blkno && cpu_to_le64(seq) == super->hdr.seq) {
		*blkno_ret = old_blkno;
		ret = 0;
		goto out;
	}

	ret = alloc_file_block(sb, &new_blkno);
	if (ret < 0)
		goto out;

	if (old_blkno) {
		ret = scoutfs_buddy_free(sb, cpu_to_le64(seq), old_blkno, 0);
		if (ret)
			goto out;
	}

	extent.blkno = cpu_to_le64(new_blkno);
	extent.len = cpu_to_le64(1);

	/* dirtying guarantees success */
	err = scoutfs_btree_update(sb, meta, &key, &val);
	BUG_ON(err);

	*blkno_ret = new_blkno;
	new_blkno = 0;
	ret = 0;
out:
	if (ret) {
		if (new_blkno)
			return_file_block(sb, new_blkno);
		if (inserted) {
			err = scoutfs_btree_delete(sb, meta, &key);
			BUG_ON(err); /* always succeeds */
		}
	}

	return ret;
}

static int scoutfs_readpage_get_block(struct inode *inode, sector_t iblock,
				      struct buffer_head *bh, int create)
{
	u64 blkno;
	int ret;

	if (WARN_ON_ONCE(create))
		return -EINVAL;

	ret = contig_mapped_blocks(inode, iblock, &blkno);
	if (ret > 0) {
		map_bh(bh, inode->i_sb, blkno);
		bh->b_size = min_t(u64, bh->b_size,
				   (u64)ret << inode->i_blkbits);
		ret = 0;
	}

	trace_printk("ino %llu iblock %llu create %d "BHF"\n",
		     scoutfs_ino(inode), (u64)iblock, create, BHA(bh));

	return ret;
}

static int scoutfs_readpage(struct file *file, struct page *page)
{
	trace_printk(PGF"\n", PGA(page));

	return mpage_readpage(page, scoutfs_readpage_get_block);
}

static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages,
			       scoutfs_readpage_get_block);
}

/*
 * For now we don't know what to do if unmapped blocks make it to
 * writepage (mmap?).
 */
static int scoutfs_writepage_get_block(struct inode *inode, sector_t iblock,
				       struct buffer_head *bh, int create)
{
	trace_printk("ino %llu iblock %llu create %d "BHF"\n",
		     scoutfs_ino(inode), (u64)iblock, create, BHA(bh));

	return WARN_ON_ONCE(-EINVAL);
}

/*
 * Dirty file pages can be written to their newly allocated free extents
 * at any time.  They won't be referenced by metadata until the current
 * transaction is committed.  They can be re-read and re-dirtied at
 * their free block number in this transaction.
 */
static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	trace_printk(PGF"\n", PGA(page));

	return block_write_full_page(page, scoutfs_writepage_get_block, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	trace_printk("mapping %p\n", mapping);

	return mpage_writepages(mapping, wbc, scoutfs_writepage_get_block);
}

/*
 * Extent allocation during buffered writes needs to make sure that the
 * dirty blocks will be written to free space.
 */
static int scoutfs_write_begin_get_block(struct inode *inode, sector_t iblock,
					 struct buffer_head *bh, int create)
{
	u64 blkno = 0;
	int ret;

	if (WARN_ON_ONCE(!create))
		return -EINVAL;

	ret = map_writable_block(inode, iblock, &blkno);
	if (ret == 0) {
		map_bh(bh, inode->i_sb, blkno);
		bh->b_size = SCOUTFS_BLOCK_SIZE;
		ret = 0;
	}

	trace_printk("ino %llu iblock %llu create %d ret %d "BHF"\n",
		     scoutfs_ino(inode), (u64)iblock, create, ret, BHA(bh));
	return ret;
}

/* XXX could make a for_each wrapper if we get a few of these */
static inline void clear_mapped_page_buffers(struct page *page)
{
	struct buffer_head *head;
	struct buffer_head *bh;

	if (!page_has_buffers(page))
		return;

	head = page_buffers(page);
	bh = head;
	do {
		if (buffer_mapped(bh)) {
			trace_printk(BHF"\n", BHA(bh));
			clear_buffer_mapped(bh);
		}

		bh = bh->b_this_page;
	} while (bh != head);
}

/*
 * Dirty blocks have to be mapped to be written out to free space so
 * that we don't overwrite live data.  We're relying on
 * block_write_begin() to call get_block().  There are two problems with
 * this.
 *
 * First, if it's going to be trying to read a partial block before writing
 * then we can't give it the location to read.  It'll just mark the
 * block dirty and write to that same location.  We use readpage to make
 * the page uptodate if it's going to be satisfying a partial overwrite.
 *
 * Second, we can't let it use mappings that were used by readpage to
 * read the current stable data.  We need to have get_block be called
 * for existing clean uptodate pages so that we can reallocate them to
 * free space.  We do this by clearing the buffer mappings for every buffer
 * on the page for every call.  This is probably unnecessarily expensive
 * because we don't need to do it for clean buffers.  That optimization
 * would need to be done very carefully.
 */
static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
        pgoff_t index = pos >> PAGE_SHIFT;
        struct page *page;
	int ret;

	ret = scoutfs_hold_trans(sb);
	if (ret)
		return ret;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode);
	if (ret)
		goto out;

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * read in the page if we're going to be dirtying part of the
	 * page.  readpage catches when this is a read past i_size or
	 * from a hole and zeros the buffer.  We try to grab the page
	 * again to let it deal with locking and races.
	 */
	if (!PageUptodate(page) && !IS_ALIGNED(pos | len, SCOUTFS_BLOCK_SIZE)) {
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
		goto retry;
	}

	/* make sure our get_block gets a chance to alloc */
	clear_mapped_page_buffers(page);

        ret = __block_write_begin(page, pos, len,
				  scoutfs_write_begin_get_block);
        if (ret < 0) {
		/* XXX handle truncating? */
                unlock_page(page);
                put_page(page);
                page = NULL;
        }

        *pagep = page;
out:
	if (ret)
		scoutfs_release_trans(sb);
        return ret;
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	int ret;

	trace_printk("ino %llu "PGF" pos %llu len %u copied %d\n",
		     scoutfs_ino(inode), PGA(page), (u64)pos, len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		scoutfs_inode_inc_data_version(inode);
		/* XXX kind of a big hammer, inode life cycle needs work */
		scoutfs_update_inode_item(inode);
	}
	scoutfs_release_trans(sb);
	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.readpages		= scoutfs_readpages,
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
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
