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
#include <linux/blkdev.h>
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "crc.h"
#include "counters.h"
#include "buddy.h"

/*
 * scoutfs maintains a cache of metadata blocks in a radix tree.  This
 * gives us blocks bigger than page size and avoids fixing the location
 * of a logical cached block in one possible position in a larger block
 * device page cache page.
 *
 * This does the work to cow dirty blocks, track dirty blocks, generate
 * checksums as they're written, only write them in transactions, verify
 * checksums on read, and invalidate and retry reads of stale cached
 * blocks.  (That last bit only has a hint of an implementation.)
 *
 * XXX
 *  - tear down dirty blocks left by write errors on unmount
 *  - multiple smaller page allocs
 *  - vmalloc?  vm_map_ram?
 *  - blocks allocated from per-cpu pages when page size > block size
 *  - cmwq crc calcs if that makes sense
 *  - slab of block structs
 *  - don't verify checksums in end_io context?
 *  - fall back to multiple single bios per block io if bio alloc fails?
 *  - fail mount if total_blocks is greater than long radix blkno
 */

struct scoutfs_block {
	struct rw_semaphore rwsem;
	atomic_t refcount;
	struct list_head lru_entry;
	u64 blkno;

	unsigned long bits;

	struct super_block *sb;
	struct page *page;
	void *data;
};

#define DIRTY_RADIX_TAG 0

enum {
	BLOCK_BIT_UPTODATE = 0,
	BLOCK_BIT_ERROR,
	BLOCK_BIT_CLASS_SET,
};

static struct scoutfs_block *alloc_block(struct super_block *sb, u64 blkno)
{
	struct scoutfs_block *bl;
	struct page *page;

	/* we'd need to be just a bit more careful */
	BUILD_BUG_ON(PAGE_SIZE > SCOUTFS_BLOCK_SIZE);

	bl = kzalloc(sizeof(struct scoutfs_block), GFP_NOFS);
	if (bl) {
		/* change _from_contents if allocs not aligned */
		page = alloc_pages(GFP_NOFS, SCOUTFS_BLOCK_PAGE_ORDER);
		WARN_ON_ONCE(!page);
		if (page) {
			init_rwsem(&bl->rwsem);
			atomic_set(&bl->refcount, 1);
			INIT_LIST_HEAD(&bl->lru_entry);
			bl->blkno = blkno;
			bl->sb = sb;
			bl->page = page;
			bl->data = page_address(page);
			trace_printk("allocated bl %p\n", bl);
		} else {
			kfree(bl);
			bl = NULL;
		}
	}

	return bl;
}

void scoutfs_block_put(struct scoutfs_block *bl)
{
	if (!IS_ERR_OR_NULL(bl) && atomic_dec_and_test(&bl->refcount)) {
		trace_printk("freeing bl %p\n", bl);
		WARN_ON_ONCE(!list_empty(&bl->lru_entry));
		__free_pages(bl->page, SCOUTFS_BLOCK_PAGE_ORDER);
		kfree(bl);
		scoutfs_inc_counter(bl->sb, block_mem_free);
	}
}

static void lru_add(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl)
{
	if (list_empty(&bl->lru_entry)) {
		list_add_tail(&bl->lru_entry, &sbi->block_lru_list);
		sbi->block_lru_nr++;
	}
}

static void lru_del(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl)
{
	if (!list_empty(&bl->lru_entry)) {
		list_del_init(&bl->lru_entry);
		sbi->block_lru_nr--;
	}
}

/*
 * The caller is referencing a block but doesn't know if its in the LRU
 * or not.  If it is move it to the tail so it's last to be dropped by
 * the shrinker.
 */
static void lru_move(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl)
{
	if (!list_empty(&bl->lru_entry))
		list_move_tail(&bl->lru_entry, &sbi->block_lru_list);
}

static void radix_insert(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl,
			 bool dirty)
{
	radix_tree_insert(&sbi->block_radix, bl->blkno, bl);
	if (dirty)
		radix_tree_tag_set(&sbi->block_radix, bl->blkno,
				   DIRTY_RADIX_TAG);
	else
		lru_add(sbi, bl);
	atomic_inc(&bl->refcount);
}

/* deleting the blkno from the radix also clears the dirty tag if it was set */
static void radix_delete(struct scoutfs_sb_info *sbi, struct scoutfs_block *bl)
{
	lru_del(sbi, bl);
	radix_tree_delete(&sbi->block_radix, bl->blkno);
	scoutfs_block_put(bl);
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
		set_bit(BLOCK_BIT_UPTODATE, &bl->bits);
	else
		set_bit(BLOCK_BIT_ERROR, &bl->bits);

	/*
	 * uncontended spin_lock in wake_up and unconditional smp_mb to
	 * make waitqueue_active safe are about the same cost, so we
	 * prefer the obviously safe choice.
	 */
	wake_up(&sbi->block_wq);

	scoutfs_block_put(bl);
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
		lru_add(sbi, bl);
		spin_unlock_irqrestore(&sbi->block_lock, flags);
	}

	/* not too worried about racing ints */
	if (err && !sbi->block_write_err)
		sbi->block_write_err = err;

	if (atomic_dec_and_test(&sbi->block_writes))
		wake_up(&sbi->block_wq);

	scoutfs_block_put(bl);
	bio_put(bio);

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
struct scoutfs_block *scoutfs_block_read(struct super_block *sb, u64 blkno)
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
		if (test_bit(BLOCK_BIT_ERROR, &bl->bits)) {
			radix_delete(sbi, bl);
			bl = NULL;
		} else {
			lru_move(sbi, bl);
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
		scoutfs_block_put(bl);
		bl = found;
		lru_move(sbi, bl);
		atomic_inc(&bl->refcount);
	} else {
		radix_insert(sbi, bl, false);
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
				test_bit(BLOCK_BIT_UPTODATE, &bl->bits) ||
				test_bit(BLOCK_BIT_ERROR, &bl->bits));
	if (ret == 0 && test_bit(BLOCK_BIT_ERROR, &bl->bits))
		ret = -EIO;
out:
	if (ret) {
		scoutfs_block_put(bl);
		bl = ERR_PTR(ret);
	}

	return bl;
}

/*
 * Read an existing block from the device described by the caller's
 * reference.
 *
 * If the reference sequence numbers don't match then we could be racing
 * with another writer. We back off and try again.  If it happens too
 * many times the caller assumes that we've hit persistent corruption
 * and returns an error.
 *
 * XXX:
 *  - actually implement this
 *  - reads that span transactions?
 *  - writers creating a new dirty block?
 */
struct scoutfs_block *scoutfs_block_read_ref(struct super_block *sb,
					     struct scoutfs_block_ref *ref)
{
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *bl;

	bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	if (!IS_ERR(bl)) {
		hdr = scoutfs_block_data(bl);
		if (WARN_ON_ONCE(hdr->seq != ref->seq)) {
			scoutfs_block_put(bl);
			bl = ERR_PTR(-EAGAIN);
		}
	}

	return bl;
}

/*
 * The caller knows that it's not racing with writers.
 */
int scoutfs_block_has_dirty(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return radix_tree_tagged(&sbi->block_radix, DIRTY_RADIX_TAG);
}

/*
 * Submit writes for all the blocks in the radix with their dirty tag
 * set.  The transaction machinery ensures that the dirty blocks form a
 * consistent image and excludes future dirtying while IO is in flight.
 *
 * Presence in the dirty tree holds a reference.  Blocks are only
 * removed from the tree which drops the ref when IO completes.
 *
 * Blocks that see write errors remain in the dirty tree and will try to
 * be written again in the next transaction commit.
 *
 * Reads can traverse the blocks while they're in flight.
 */
int scoutfs_block_write_dirty(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block *blocks[16];
	struct scoutfs_block *bl;
	struct blk_plug plug;
	unsigned long flags;
	u64 blkno;
	int ret;
	int nr;
	int i;

	atomic_set(&sbi->block_writes, 1);
	sbi->block_write_err = 0;
	blkno = 0;
	ret = 0;

	blk_start_plug(&plug);

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
				scoutfs_block_set_crc(bl);
				atomic_inc(&sbi->block_writes);
				ret = block_submit_bio(bl, WRITE);
				if (ret)
					atomic_dec(&sbi->block_writes);
			}
			scoutfs_block_put(bl);
		}
	} while (nr && !ret);

	blk_finish_plug(&plug);

	/* wait for all io to drain */
	atomic_dec(&sbi->block_writes);
	wait_event(sbi->block_wq, atomic_read(&sbi->block_writes) == 0);

	return ret ?: sbi->block_write_err;
}

/*
 * XXX This is a gross hack for writing the super.  It doesn't have
 * per-block write completion indication.  It knows that it's the only
 * thing that will be writing.
 */
int scoutfs_block_write_sync(struct scoutfs_block *bl)
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
 * Callers are responsible for serializing modification to the reference
 * which is probably embedded in some other dirty persistent structure.
 */
struct scoutfs_block *scoutfs_block_dirty_ref(struct super_block *sb,
					      struct scoutfs_block_ref *ref)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct scoutfs_block *copy_bl = NULL;
	struct scoutfs_block *bl;
	u64 blkno = 0;
	int ret;
	int err;

	bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	if (IS_ERR(bl) || ref->seq == sbi->super.hdr.seq)
		return bl;

	ret = scoutfs_buddy_alloc_same(sb, &blkno, le64_to_cpu(ref->blkno));
	if (ret < 0)
		goto out;

	copy_bl = scoutfs_block_dirty(sb, blkno);
	if (IS_ERR(copy_bl)) {
		ret = PTR_ERR(copy_bl);
		goto out;
	}

	hdr = scoutfs_block_data(bl);
	ret = scoutfs_buddy_free(sb, hdr->seq, le64_to_cpu(hdr->blkno), 0);
	if (ret)
		goto out;

	memcpy(scoutfs_block_data(copy_bl), scoutfs_block_data(bl),
	       SCOUTFS_BLOCK_SIZE);

	hdr = scoutfs_block_data(copy_bl);
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = sbi->super.hdr.seq;
	ref->blkno = hdr->blkno;
	ref->seq = hdr->seq;

	ret = 0;
out:
	scoutfs_block_put(bl);
	if (ret) {
		if (!IS_ERR_OR_NULL(copy_bl)) {
			err = scoutfs_buddy_free(sb, sbi->super.hdr.seq,
						 blkno, 0);
			WARN_ON_ONCE(err); /* freeing dirty must work */
		}
		scoutfs_block_put(copy_bl);
		copy_bl = ERR_PTR(ret);
	}

	return copy_bl;
}

/*
 * Return a dirty metadata block with an updated block header to match
 * the current dirty seq.  Callers are responsible for serializing
 * access to the block and for zeroing unwritten block contents.
 *
 * Always allocating a new block and replacing any old cached block
 * serves a very specific purpose.  We can have an unlocked reader
 * traversing stable structures actively using a clean block while a
 * writer gets that same blkno from the allocator and starts modifying
 * it.  By always allocating a new block we let the reader continue
 * safely using their old immutable block while the writer works on the
 * newly allocated block.  The old stable block will be freed once the
 * reader drops their reference.
 */
struct scoutfs_block *scoutfs_block_dirty(struct super_block *sb, u64 blkno)
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

	set_bit(BLOCK_BIT_UPTODATE, &bl->bits);

	ret = radix_tree_preload(GFP_NOFS);
	if (ret)
		goto out;

	hdr = bl->data;
	*hdr = sbi->super.hdr;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = sbi->super.hdr.seq;

	spin_lock_irqsave(&sbi->block_lock, flags);
	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found)
		radix_delete(sbi, found);
	radix_insert(sbi, bl, true);
	spin_unlock_irqrestore(&sbi->block_lock, flags);

	radix_tree_preload_end();
	ret = 0;
out:
	if (ret) {
		scoutfs_block_put(bl);
		bl = ERR_PTR(ret);
	}

	return bl;
}

/*
 * Allocate a new dirty writable block.  The caller must be in a
 * transaction so that we can assign the dirty seq.
 */
struct scoutfs_block *scoutfs_block_dirty_alloc(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->stable_super;
	struct scoutfs_block *bl;
	u64 blkno;
	int ret;
	int err;

	ret = scoutfs_buddy_alloc(sb, &blkno, 0);
	if (ret < 0)
		return ERR_PTR(ret);

	bl = scoutfs_block_dirty(sb, blkno);
	if (IS_ERR(bl)) {
		err = scoutfs_buddy_free(sb, super->hdr.seq, blkno, 0);
		WARN_ON_ONCE(err); /* freeing dirty must work */
	}
	return bl;
}

/*
 * Forget the given block by removing it from the radix and clearing its
 * dirty tag.  It will not be found by future lookups and will not be
 * written out.  The caller can still use it until it drops its
 * reference.
 */
void scoutfs_block_forget(struct scoutfs_block *bl)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(bl->sb);
	struct scoutfs_block *found;
	unsigned long flags;
	u64 blkno = bl->blkno;

	spin_lock_irqsave(&sbi->block_lock, flags);
	found = radix_tree_lookup(&sbi->block_radix, blkno);
	if (found == bl)
		radix_delete(sbi, bl);
	spin_unlock_irqrestore(&sbi->block_lock, flags);
}

/*
 * We maintain an LRU of blocks so that the shrinker can free the oldest
 * under memory pressure.  We can't reclaim dirty blocks so only clean
 * blocks are kept in the LRU.  Blocks are only in the LRU while their
 * presence in the radix holds a reference.  We don't care if a reader
 * has an active ref on a clean block that gets reclaimed.  All we're
 * doing is removing from the radix.  The caller can still work with the
 * block and it will be freed once they drop their ref.
 *
 * If this is called with nr_to_scan == 0 then it only returns the nr.
 * We avoid acquiring the lock in that case.
 *
 * Lookup code only moves blocks around in the LRU while they're in the
 * radix. Once we remove the block from the radix we're able to use the
 * lru_entry to drop all the blocks outside the lock.
 *
 * XXX:
 *  - are sc->nr_to_scan and our return meant to be in units of pages?
 *  - should we sync a transaction here?
 */
int scoutfs_block_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
	struct scoutfs_sb_info *sbi = container_of(shrink,
						   struct scoutfs_sb_info,
						   block_shrinker);
	struct scoutfs_block *tmp;
	struct scoutfs_block *bl;
	unsigned long flags;
	unsigned long nr;
	LIST_HEAD(list);

	nr = sc->nr_to_scan;
	if (!nr)
		goto out;

	spin_lock_irqsave(&sbi->block_lock, flags);

	list_for_each_entry_safe(bl, tmp, &sbi->block_lru_list, lru_entry) {
		if (nr-- == 0)
			break;
		atomic_inc(&bl->refcount);
		radix_delete(sbi, bl);
		list_add(&bl->lru_entry, &list);
	}

	spin_unlock_irqrestore(&sbi->block_lock, flags);

	list_for_each_entry_safe(bl, tmp, &list, lru_entry) {
		list_del_init(&bl->lru_entry);
		scoutfs_block_put(bl);
	}

out:
	return min_t(unsigned long, sbi->block_lru_nr, INT_MAX);
}

void scoutfs_block_set_crc(struct scoutfs_block *bl)
{
	struct scoutfs_block_header *hdr = scoutfs_block_data(bl);

	hdr->crc = cpu_to_le32(scoutfs_crc_block(hdr));
}

/*
 * Zero the block from the given byte to the end of the block.
 */
void scoutfs_block_zero(struct scoutfs_block *bl, size_t off)
{
	if (WARN_ON_ONCE(off > SCOUTFS_BLOCK_SIZE))
		return;

	if (off < SCOUTFS_BLOCK_SIZE)
		memset(scoutfs_block_data(bl) + off, 0,
		       SCOUTFS_BLOCK_SIZE - off);
}

/*
 * Zero the block from the given byte to the end of the block.
 */
void scoutfs_block_zero_from(struct scoutfs_block *bl, void *ptr)
{
	return scoutfs_block_zero(bl, (char *)ptr -
				  (char *)scoutfs_block_data(bl));
}

void scoutfs_block_set_lock_class(struct scoutfs_block *bl,
			          struct lock_class_key *class)
{
	if (!test_bit(BLOCK_BIT_CLASS_SET, &bl->bits)) {
		lockdep_set_class(&bl->rwsem, class);
		set_bit(BLOCK_BIT_CLASS_SET, &bl->bits);
	}
}

void scoutfs_block_lock(struct scoutfs_block *bl, bool write, int subclass)
{
	if (write)
		down_write_nested(&bl->rwsem, subclass);
	else
		down_read_nested(&bl->rwsem, subclass);
}

void scoutfs_block_unlock(struct scoutfs_block *bl, bool write)
{
	if (write)
		up_write(&bl->rwsem);
	else
		up_read(&bl->rwsem);
}

void *scoutfs_block_data(struct scoutfs_block *bl)
{
	return bl->data;
}

void *scoutfs_block_data_from_contents(const void *ptr)
{
	unsigned long addr = (unsigned long)ptr;

	return (void *)(addr & ~((unsigned long)SCOUTFS_BLOCK_MASK));
}

void scoutfs_block_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block *blocks[16];
	struct scoutfs_block *bl;
	unsigned long blkno = 0;
	int nr;
	int i;

	do {
		nr = radix_tree_gang_lookup(&sbi->block_radix, (void **)blocks,
					    blkno, ARRAY_SIZE(blocks));
		for (i = 0; i < nr; i++) {
			bl = blocks[i];
			blkno = bl->blkno + 1;
			radix_delete(sbi, bl);
		}
	} while (nr);
}
