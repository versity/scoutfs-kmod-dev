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
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/mm.h>
#include <linux/bio.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "crc.h"
#include "counters.h"

/*
 * XXX
 *  - tie into reclaim
 *  - per cpu lru of refs?
 *  - relax locking
 *  - get, check, and fill slots instead of full radix walks
 *  - block slab
 *  - maybe more clever wait functions
 */

static struct scoutfs_block *alloc_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_block *bl;
	struct page *page;

	/* we'd need to be just a bit more careful */
	BUILD_BUG_ON(PAGE_SIZE > SCOUTFS_BLOCK_SIZE);

	bl = kzalloc(sizeof(struct scoutfs_block), GFP_NOFS);
	if (bl) {
		page = alloc_pages(GFP_NOFS, SCOUTFS_BLOCK_PAGE_ORDER);
		WARN_ON_ONCE(!page);
		if (page) {
			init_rwsem(&bl->rwsem);
			atomic_set(&bl->refcount, 1);
			bl->blkno = blkno;
			bl->sb = sb;
			bl->page = page;
			bl->data = page_address(page);
			scoutfs_inc_counter(sb, block_mem_alloc);
		} else {
			kfree(bl);
			bl = NULL;
		}
	}

	return bl;
}	

void scoutfs_put_block(struct scoutfs_block *bl)
{
	if (!IS_ERR_OR_NULL(bl) && atomic_dec_and_test(&bl->refcount)) {
		trace_printk("freeing bl %p\n", bl);
		__free_pages(bl->page, SCOUTFS_BLOCK_PAGE_ORDER);
		kfree(bl);
		scoutfs_inc_counter(bl->sb, block_mem_free);
	}
}

static int verify_block_header(struct super_block *sb, struct scoutfs_block *bl)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_block_header *hdr = bl->data;
	u32 crc = scoutfs_crc_block(hdr);
	int ret = -EIO;

	if (le32_to_cpu(hdr->crc) != crc) {
		printk("blkno %llu hdr crc %x != calculated %x\n", bl->blkno,
			le32_to_cpu(hdr->crc), crc);
	} else if (super->hdr.fsid && hdr->fsid != super->hdr.fsid) {
		printk("blkno %llu fsid %llx != super fsid %llx\n", bl->blkno,
			le64_to_cpu(hdr->fsid), le64_to_cpu(super->hdr.fsid));
	} else if (le64_to_cpu(hdr->blkno) != bl->blkno) {
		printk("blkno %llu invalid hdr blkno %llx\n", bl->blkno,
			le64_to_cpu(hdr->blkno));
	} else {
		ret = 0;
	}

	return ret;
}

static void block_read_end_io(struct bio *bio, int err)
{
	struct scoutfs_block *bl = bio->bi_private;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(bl->sb);

	if (!err && !verify_block_header(bl->sb, bl))
		set_bit(SCOUTFS_BLOCK_BIT_UPTODATE, &bl->bits);
	else
		set_bit(SCOUTFS_BLOCK_BIT_ERROR, &bl->bits);

	/*
	 * uncontended spin_lock in wake_up and unconditional smp_mb to
	 * make waitqueue_active safe are about the same cost, so we
	 * prefer the obviously safe choice.
	 */
	wake_up(&sbi->block_wq);

	scoutfs_put_block(bl);
}

static int block_submit_bio(struct scoutfs_block *bl, int rw)
{
	struct super_block *sb = bl->sb;
	struct bio *bio;
	int ret;

	bio = bio_alloc(GFP_NOFS, SCOUTFS_PAGES_PER_BLOCK);
	if (WARN_ON_ONCE(!bio))
		return -ENOMEM;

	bio->bi_sector = bl->blkno << (SCOUTFS_BLOCK_SHIFT - 9);
	bio->bi_bdev = sb->s_bdev;
	/* XXX can we do that? */
	ret = bio_add_page(bio, bl->page, SCOUTFS_BLOCK_SIZE, 0);
	if (rw & WRITE)
		;
	else
		bio->bi_end_io = block_read_end_io;
	bio->bi_private = bl;
	atomic_inc(&bl->refcount);
	submit_bio(rw, bio);

	return 0;
}

/*
 * Read an existing block from the device and verify its metadata header.
 */
struct scoutfs_block *scoutfs_read_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block *found;
	struct scoutfs_block *bl;
	int ret;

	/* find an existing block, dropping if it's errored */
	spin_lock(&sbi->block_lock);

	bl = radix_tree_lookup(&sbi->block_radix, blkno);
	if (bl) {
		if (test_bit(SCOUTFS_BLOCK_BIT_ERROR, &bl->bits)) {
			radix_tree_delete(&sbi->block_radix, bl->blkno);
			scoutfs_put_block(bl);
			bl = NULL;
		} else {
			atomic_inc(&bl->refcount);
		}
	}

	spin_unlock(&sbi->block_lock);
	if (bl)
		goto wait;

	/* allocate a new block and try to insert it */
	bl = alloc_block(sb, blkno);
	if (!bl) {
		ret = -EIO;
		goto out;
	}

	ret = radix_tree_preload(GFP_NOFS);
	if (ret)
		goto out;

	spin_lock(&sbi->block_lock);

	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found) {
		scoutfs_put_block(bl);
		bl = found;
		atomic_inc(&bl->refcount);
	} else {
		radix_tree_insert(&sbi->block_radix, blkno, bl);
		atomic_inc(&bl->refcount);
	}

	spin_unlock(&sbi->block_lock);
	radix_tree_preload_end();

	if (!found) {
		ret = block_submit_bio(bl, READ_SYNC | REQ_META);
		if (ret)
			goto out;
	}

wait:
	ret = wait_event_interruptible(sbi->block_wq,
			test_bit(SCOUTFS_BLOCK_BIT_UPTODATE, &bl->bits) ||
			test_bit(SCOUTFS_BLOCK_BIT_ERROR, &bl->bits));
	if (test_bit(SCOUTFS_BLOCK_BIT_UPTODATE, &bl->bits))
		ret = 0;
	else if (test_bit(SCOUTFS_BLOCK_BIT_ERROR, &bl->bits))
		ret = -EIO;

out:
	if (ret) {
		scoutfs_put_block(bl);
		bl = ERR_PTR(ret);
	}

	return bl;
}

/*
 * Return the block pointed to by the caller's reference.
 *
 * If the reference sequence numbers don't match then we could be racing
 * with another writer. We back off and try again.  If it happens too
 * many times the caller assumes that we've hit persistent corruption
 * and returns an error.
 *
 * XXX how does this race with
 *  - reads that span transactions?
 *  - writers creating a new dirty block?
 */
struct scoutfs_block *scoutfs_read_ref(struct super_block *sb,
				       struct scoutfs_block_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *bl;
	struct scoutfs_block *found;

	bl = scoutfs_read_block(sb, le64_to_cpu(ref->blkno));
	if (!IS_ERR(bl)) {
		hdr = bl->data;

		if (WARN_ON_ONCE(hdr->seq != ref->seq)) {
			/* XXX hack, make this a function */
			spin_lock(&sbi->block_lock);
			found = radix_tree_lookup(&sbi->block_radix,
						  bl->blkno);
			if (found == bl) {
				radix_tree_delete(&sbi->block_radix, bl->blkno);
				scoutfs_put_block(bl);
			}
			spin_unlock(&sbi->block_lock);

			scoutfs_put_block(bl);
			bl = ERR_PTR(-EAGAIN);
		}
	}

	return bl;
}

/*
 * Give the caller a dirty block that they can safely modify.  If the
 * reference refers to a stable clean block then we allocate a new block
 * and update the reference.
 *
 * Blocks are dirtied and modified within a transaction that has a given
 * sequence number which we use to determine if the block is currently
 * dirty or not.
 *
 * For now we're using the dirty super block in the sb_info to track
 * the dirty seq.  That'll be different when we have multiple btrees.
 *
 * Callers are working in structures that have sufficient locking to
 * protect references to the source block.  If we've come to dirty it then
 * there won't be concurrent users and we can just move it in the cache.
 */
struct scoutfs_block *scoutfs_dirty_ref(struct super_block *sb,
				        struct scoutfs_block_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *found;
	struct scoutfs_block *bl;
	u64 blkno;
	int ret;

	bl = scoutfs_read_block(sb, le64_to_cpu(ref->blkno));
	if (IS_ERR(bl) || ref->seq == sbi->super.hdr.seq)
		return bl;

	ret = radix_tree_preload(GFP_NOFS);
	if (ret) {
		scoutfs_put_block(bl);
		return ERR_PTR(ret);
	}

	/* XXX cheesy */
	blkno = atomic64_inc_return(&sbi->next_blkno);
	hdr = bl->data;

	spin_lock(&sbi->block_lock);

	/* XXX don't really like this */
	found = radix_tree_lookup(&sbi->block_radix, bl->blkno);
	if (found == bl) {
		radix_tree_delete(&sbi->block_radix, bl->blkno);
		atomic_dec(&bl->refcount);
	}

	bl->blkno = blkno;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = sbi->super.hdr.seq;
	radix_tree_insert(&sbi->block_radix, blkno, bl);
	atomic_inc(&bl->refcount);

	spin_unlock(&sbi->block_lock);
	radix_tree_preload_end();

	ref->blkno = hdr->blkno;
	ref->seq = hdr->seq;

	return bl;
}

/*
 * Return a newly allocated metadata block with an updated block header
 * to match the current dirty seq.  Callers are responsible for
 * serializing access to the block and for zeroing unwritten block
 * contents.
 */
struct scoutfs_block *scoutfs_new_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *found;
	struct scoutfs_block *bl;
	int ret;

	/* allocate a new block and try to insert it */
	bl = alloc_block(sb, blkno);
	if (!bl) {
		ret = -EIO;
		goto out;
	}

	set_bit(SCOUTFS_BLOCK_BIT_UPTODATE, &bl->bits);

	ret = radix_tree_preload(GFP_NOFS);
	if (ret)
		goto out;

	hdr = bl->data;
	*hdr = sbi->super.hdr;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = sbi->super.hdr.seq;

	spin_lock(&sbi->block_lock);
	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found) {
		radix_tree_delete(&sbi->block_radix, blkno);
		scoutfs_put_block(found);
	}

	radix_tree_insert(&sbi->block_radix, blkno, bl);
	atomic_inc(&bl->refcount);
	spin_unlock(&sbi->block_lock);

	radix_tree_preload_end();
	ret = 0;
out:
	if (ret) {
		scoutfs_put_block(bl);
		bl = ERR_PTR(ret);
	}

	return bl;
}

/*
 * Allocate a new dirty writable block.  The caller must be in a
 * transaction so that we can assign the dirty seq.
 */
struct scoutfs_block *scoutfs_alloc_block(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 blkno;

	/* XXX cheesy */
	blkno = atomic64_inc_return(&sbi->next_blkno);

	return scoutfs_new_block(sb, blkno);
}

void scoutfs_calc_hdr_crc(struct scoutfs_block *bl)
{
	struct scoutfs_block_header *hdr = bl->data;

	hdr->crc = cpu_to_le32(scoutfs_crc_block(hdr));
}
