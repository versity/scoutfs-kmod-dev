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
#include "buddy.h"

#define DIRTY_RADIX_TAG 0

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
	bio_put(bio);
}

/*
 * Once a transaction block is persistent it's fine to drop the dirty
 * tag.  It's been checksummed so it can be read in again.  It's seq
 * will be in the current transaction so it'll simply be dirtied and
 * checksummed and written out again.
 */
static void block_write_end_io(struct bio *bio, int err)
{
	struct scoutfs_block *bl = bio->bi_private;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(bl->sb);
	unsigned long flags;

	if (!err) {
		spin_lock_irqsave(&sbi->block_lock, flags);
		radix_tree_tag_clear(&sbi->block_radix,
				     bl->blkno, DIRTY_RADIX_TAG);
		spin_unlock_irqrestore(&sbi->block_lock, flags);
	}

	/* not too worried about racing ints */
	if (err && !sbi->block_write_err)
		sbi->block_write_err = err;

	if (atomic_dec_and_test(&sbi->block_writes))
		wake_up(&sbi->block_wq);

	scoutfs_put_block(bl);
	bio_put(bio);

}

static int block_submit_bio(struct scoutfs_block *bl, int rw)
{
	struct super_block *sb = bl->sb;
	struct bio *bio;
	int ret;

	if (WARN_ON_ONCE(bl->blkno >=
		i_size_read(sb->s_bdev->bd_inode) >> SCOUTFS_BLOCK_SHIFT)) {
		printk("trying to read bad blkno %llu\n", bl->blkno);
	}


	bio = bio_alloc(GFP_NOFS, SCOUTFS_PAGES_PER_BLOCK);
	if (WARN_ON_ONCE(!bio))
		return -ENOMEM;

	bio->bi_sector = bl->blkno << (SCOUTFS_BLOCK_SHIFT - 9);
	bio->bi_bdev = sb->s_bdev;
	if (rw & WRITE) {
		bio->bi_end_io = block_write_end_io;
	} else
		bio->bi_end_io = block_read_end_io;
	bio->bi_private = bl;

	ret = bio_add_page(bio, bl->page, SCOUTFS_BLOCK_SIZE, 0);
	if (WARN_ON_ONCE(ret != SCOUTFS_BLOCK_SIZE)) {
		bio_put(bio);
		return -ENOMEM;
	}

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
	unsigned long flags;
	int ret;

	/* find an existing block, dropping if it's errored */
	spin_lock_irqsave(&sbi->block_lock, flags);

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

	spin_unlock_irqrestore(&sbi->block_lock, flags);
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

	spin_lock_irqsave(&sbi->block_lock, flags);

	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found) {
		scoutfs_put_block(bl);
		bl = found;
		atomic_inc(&bl->refcount);
	} else {
		radix_tree_insert(&sbi->block_radix, blkno, bl);
		atomic_inc(&bl->refcount);
	}

	spin_unlock_irqrestore(&sbi->block_lock, flags);
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
	unsigned long flags;

	bl = scoutfs_read_block(sb, le64_to_cpu(ref->blkno));
	if (!IS_ERR(bl)) {
		hdr = bl->data;

		if (WARN_ON_ONCE(hdr->seq != ref->seq)) {
			/* XXX hack, make this a function */
			spin_lock_irqsave(&sbi->block_lock, flags);
			found = radix_tree_lookup(&sbi->block_radix,
						  bl->blkno);
			if (found == bl) {
				radix_tree_delete(&sbi->block_radix, bl->blkno);
				scoutfs_put_block(bl);
			}
			spin_unlock_irqrestore(&sbi->block_lock, flags);

			scoutfs_put_block(bl);
			bl = ERR_PTR(-EAGAIN);
		}
	}

	return bl;
}

/*
 * XXX This is a gross hack for writing the super.  It doesn't have
 * per-block write completion indication, it just knows that it's the
 * only thing that will be writing.
 */
int scoutfs_write_block(struct scoutfs_block *bl)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(bl->sb);
	int ret;

	BUG_ON(atomic_read(&sbi->block_writes) != 0);

	atomic_inc(&sbi->block_writes);
	ret = block_submit_bio(bl, WRITE);
	if (ret)
		atomic_dec(&sbi->block_writes);
	else
		wait_event(sbi->block_wq, atomic_read(&sbi->block_writes) == 0);

	return ret ?: sbi->block_write_err;
}

/*
 * A quick cheap test so that write dirty blocks only has to return
 * success or error, not also the lack of dirty blocks.
 */
int scoutfs_has_dirty_blocks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return radix_tree_tagged(&sbi->block_radix, DIRTY_RADIX_TAG);
}

/*
 * Write out all the currently dirty blocks.  The caller has waited
 * for all the dirty blocks to be consistent and has prevented further
 * writes while we're working.
 *
 * The blocks are kept dirty so that they won't be evicted by reclaim
 * while they're in flight.  Reads can traverse the blocks while they're
 * in flight.
 */
int scoutfs_write_dirty_blocks(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block *blocks[16];
	struct scoutfs_block *bl;
	unsigned long flags;
	unsigned long blkno;
	int ret;
	int nr;
	int i;

	blkno = 0;
	sbi->block_write_err = 0;
	ret = 0;
	atomic_inc(&sbi->block_writes);

	do {
		/* get refs to a bunch of dirty blocks */
		spin_lock_irqsave(&sbi->block_lock, flags);
		nr = radix_tree_gang_lookup_tag(&sbi->block_radix,
						(void **)blocks, blkno,
						ARRAY_SIZE(blocks),
						DIRTY_RADIX_TAG);
		if (nr > 0)
			blkno = blocks[nr - 1]->blkno + 1;
		for (i = 0; i < nr; i++)
			atomic_inc(&blocks[i]->refcount);
		spin_unlock_irqrestore(&sbi->block_lock, flags);

		/* submit them in order, being careful to put all on err */
		for (i = 0; i < nr; i++) {
			bl = blocks[i];

			if (ret == 0) {
				/* XXX crc could be farmed out */
				scoutfs_calc_hdr_crc(bl);
				atomic_inc(&sbi->block_writes);
				ret = block_submit_bio(bl, WRITE);
				if (ret)
					atomic_dec(&sbi->block_writes);
			}
			scoutfs_put_block(bl);
		}
	} while (nr && !ret);

	/* wait for all io to drain */
	atomic_dec(&sbi->block_writes);
	wait_event(sbi->block_wq, atomic_read(&sbi->block_writes) == 0);

	return ret ?: sbi->block_write_err;
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
 * For now we're using the dirty super block in the sb_info to track the
 * dirty seq.  That'll be different when we have multiple btrees.
 *
 * Callers are working in structures that have sufficient locking to
 * protect references to the source block.  If we've come to dirty it
 * then there won't be concurrent users and we can just move it in the
 * cache.
 *
 * The caller can ask that we either move the existing cached block to
 * its new dirty blkno in the cache or copy its contents to a newly
 * allocated dirty block.  The caller knows if they'll ever reference
 * the old clean block again (buddy does, btree doesn't.)
 */
static struct scoutfs_block *dirty_ref(struct super_block *sb,
				       struct scoutfs_block_ref *ref, bool cow)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *copy_bl = NULL;
	struct scoutfs_block *found;
	struct scoutfs_block *bl;
	unsigned long flags;
	u64 blkno;
	int ret;
	int err;

	bl = scoutfs_read_block(sb, le64_to_cpu(ref->blkno));
	if (IS_ERR(bl) || ref->seq == sbi->super.hdr.seq)
		return bl;

	ret = scoutfs_buddy_alloc(sb, &blkno, 0);
	if (ret < 0)
		goto out;

	if (cow) {
		copy_bl = alloc_block(sb, blkno);
		if (IS_ERR(copy_bl)) {
			ret = PTR_ERR(copy_bl);
			goto out;
		}
		set_bit(SCOUTFS_BLOCK_BIT_UPTODATE, &copy_bl->bits);
	}

	ret = radix_tree_preload(GFP_NOFS);
	if (ret)
		goto out;

	spin_lock_irqsave(&sbi->block_lock, flags);

	/* delete anything at the new blkno */
	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found) {
		radix_tree_delete(&sbi->block_radix, blkno);
		scoutfs_put_block(found);
	}

	if (cow) {
		/* copy contents to the new block, hdr updated below */
		memcpy(copy_bl->data, bl->data, SCOUTFS_BLOCK_SIZE);
		scoutfs_put_block(bl);
		bl = copy_bl;
		copy_bl = NULL;
	} else {
		/* move the existing block to its new dirty blkno */
		found = radix_tree_lookup(&sbi->block_radix, bl->blkno);
		if (found == bl) {
			radix_tree_delete(&sbi->block_radix, bl->blkno);
			atomic_dec(&bl->refcount);
		}
	}

	bl->blkno = blkno;
	hdr = bl->data;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = sbi->super.hdr.seq;
	ref->blkno = hdr->blkno;
	ref->seq = hdr->seq;

	/* insert the dirty block at its new blkno */
	radix_tree_insert(&sbi->block_radix, blkno, bl);
	radix_tree_tag_set(&sbi->block_radix, blkno, DIRTY_RADIX_TAG);
	atomic_inc(&bl->refcount);

	spin_unlock_irqrestore(&sbi->block_lock, flags);
	radix_tree_preload_end();

	ret = 0;
out:
	scoutfs_put_block(copy_bl);
	if (ret) {
		if (blkno) {
			err = scoutfs_buddy_free(sb, blkno, 0);
			WARN_ON_ONCE(err); /* XXX hmm */
		}
		scoutfs_put_block(bl);
		bl = ERR_PTR(ret);
	}

	return bl;
}

struct scoutfs_block *scoutfs_block_cow_ref(struct super_block *sb,
					    struct scoutfs_block_ref *ref)
{
	return dirty_ref(sb, ref, true);
}
struct scoutfs_block *scoutfs_block_dirty_ref(struct super_block *sb,
				             struct scoutfs_block_ref *ref)
{
	return dirty_ref(sb, ref, false);
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
	unsigned long flags;
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

	spin_lock_irqsave(&sbi->block_lock, flags);
	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found) {
		radix_tree_delete(&sbi->block_radix, blkno);
		scoutfs_put_block(found);
	}

	radix_tree_insert(&sbi->block_radix, blkno, bl);
	radix_tree_tag_set(&sbi->block_radix, blkno, DIRTY_RADIX_TAG);
	atomic_inc(&bl->refcount);
	spin_unlock_irqrestore(&sbi->block_lock, flags);

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
	struct scoutfs_block *bl;
	u64 blkno;
	int ret;
	int err;

	ret = scoutfs_buddy_alloc(sb, &blkno, 0);
	if (ret < 0)
		return ERR_PTR(ret);

	bl = scoutfs_new_block(sb, blkno);
	if (IS_ERR(bl)) {
		err = scoutfs_buddy_free(sb, blkno, 0);
		WARN_ON_ONCE(err); /* XXX hmm */
	}
	return bl;
}

void scoutfs_calc_hdr_crc(struct scoutfs_block *bl)
{
	struct scoutfs_block_header *hdr = bl->data;

	hdr->crc = cpu_to_le32(scoutfs_crc_block(hdr));
}

void scoutfs_zero_block_tail(struct scoutfs_block *bl, size_t off)
{
	if (WARN_ON_ONCE(off > SCOUTFS_BLOCK_SIZE))
		return;

	if (off < SCOUTFS_BLOCK_SIZE)
		memset(bl->data + off, 0, SCOUTFS_BLOCK_SIZE - off);
}
