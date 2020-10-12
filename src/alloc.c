/*
 * Copyright (C) 2020 Versity Software, Inc.  All rights reserved.
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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/random.h>

#include "super.h"
#include "block.h"
#include "btree.h"
#include "trans.h"
#include "alloc.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * The core allocator uses extent items in btrees rooted in the super.
 * Each free extent is stored in two items.  The first item is indexed
 * by block location and is used to merge adjacent extents when freeing.
 * The second item is indexed by length and is used to find large
 * extents to allocate from.
 *
 * Free extent always consumes the front of the largest extent.  This
 * attempts to discourage fragmentation by given smaller freed extents
 * time for an adjacent free to merge before we attempt to re-use them.
 *
 * The metadata btrees that store extents are updated with cow.  This
 * requires allocation during extent item modification on behalf of
 * allocation.  Avoiding this recursion introduces the second structure,
 * persistent singly linked lists of individual blknos.
 *
 * The alloc lists are used for metadata allocation during a
 * transaction.  Before each transaction lists of blknos are prepared
 * for use during the transaction.  This ensures a small predictable
 * number of cows needed to fully dirty the metadata allocator
 * structures during the transaction.  As the transaction proceeds
 * allocations are made from a list of available meta blknos, and frees
 * are performed by adding blknos to another list of freed blknos.
 * After transactions these lists are merged back in to extents.
 *
 * Data allocations are performed directly on a btree of extent items,
 * with a bit of caching to stream small file data allocations from
 * memory instead of performing multiple btree calls per block
 * allocation.
 *
 * Every transaction has exclusive access to its metadata list blocks
 * and data extent trees which are prepared by the server.  For client
 * metadata and srch transactions the server moved extents and blocks
 * into persistent items that are communicated with the server.  For
 * server transactions metadata the server has to prepare structures for
 * itself.  To avoid modifying the same structure both explicitly
 * (refilling an allocator) and implicitly (using the current allocator
 * for cow allocations), it double buffers list blocks.  It uses current
 * blocks to modify the next blocks, and swaps them at each transaction.
 */

/*
 * Free extents don't have flags and are stored in two indexes sorted by
 * block location and by length, largest first.  The block location key
 * is set to the final block in the extent so that we can find
 * intersections by calling _next() iterators starting with the block
 * we're searching for.
 */
static void init_ext_key(struct scoutfs_key *key, int type, u64 start, u64 len)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FREE_EXTENT_ZONE,
		.sk_type = type,
	};

	if (type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE) {
		key->skfb_end = cpu_to_le64(start + len - 1);
		key->skfb_len = cpu_to_le64(len);
	} else if (type == SCOUTFS_FREE_EXTENT_LEN_TYPE) {
		key->skfl_neglen = cpu_to_le64(-len);
		key->skfl_blkno = cpu_to_le64(start);
	} else {
		BUG();
	}
}

static void ext_from_key(struct scoutfs_extent *ext, struct scoutfs_key *key)
{
	if (key->sk_type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE) {
		ext->start = le64_to_cpu(key->skfb_end) -
			     le64_to_cpu(key->skfb_len) + 1;
		ext->len = le64_to_cpu(key->skfb_len);
	} else {
		ext->start = le64_to_cpu(key->skfl_blkno);
		ext->len = -le64_to_cpu(key->skfl_neglen);
	}
	ext->map = 0;
	ext->flags = 0;
}

struct alloc_ext_args {
	struct scoutfs_alloc *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_alloc_root *root;
	int type;
};

static int alloc_ext_next(struct super_block *sb, void *arg,
			  u64 start, u64 len, struct scoutfs_extent *ext)
{
	struct alloc_ext_args *args = arg;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	init_ext_key(&key, args->type, start, len);

	ret = scoutfs_btree_next(sb, &args->root->root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len != 0)
			ret = -EIO;
		else if (iref.key->sk_type != args->type)
			ret = -ENOENT;
		else
			ext_from_key(ext, iref.key);
		scoutfs_btree_put_iref(&iref);
	}

	if (ret < 0)
		memset(ext, 0, sizeof(struct scoutfs_extent));

	return ret;
}

static int other_type(int type)
{
	if (type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE)
		return SCOUTFS_FREE_EXTENT_LEN_TYPE;
	else if (type == SCOUTFS_FREE_EXTENT_LEN_TYPE)
		return SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
	else
		BUG();
}

/*
 * Insert an extent along with its matching item which is indexed by
 * opposite of its len or blkno.  If we succeed we update the root's
 * record of the total length of all the stored extents.
 */
static int alloc_ext_insert(struct super_block *sb, void *arg,
			    u64 start, u64 len, u64 map, u8 flags)
{
	struct alloc_ext_args *args = arg;
	struct scoutfs_key other;
	struct scoutfs_key key;
	int ret;
	int err;

	/* allocator extents don't have mappings or flags */
	if (WARN_ON_ONCE(map || flags))
		return -EINVAL;

	init_ext_key(&key, args->type, start, len);
	init_ext_key(&other, other_type(args->type), start, len);

	ret = scoutfs_btree_insert(sb, args->alloc, args->wri,
				   &args->root->root, &key, NULL, 0);
	if (ret == 0) {
		ret = scoutfs_btree_insert(sb, args->alloc, args->wri,
					   &args->root->root, &other, NULL, 0);
		if (ret < 0) {
			err = scoutfs_btree_delete(sb, args->alloc, args->wri,
						   &args->root->root, &key);
			BUG_ON(err);
		} else {
			le64_add_cpu(&args->root->total_len, len);
		}
	}

	return ret;
}

static int alloc_ext_remove(struct super_block *sb, void *arg,
			    u64 start, u64 len, u64 map, u8 flags)
{
	struct alloc_ext_args *args = arg;
	struct scoutfs_key other;
	struct scoutfs_key key;
	int ret;
	int err;

	init_ext_key(&key, args->type, start, len);
	init_ext_key(&other, other_type(args->type), start, len);

	ret = scoutfs_btree_delete(sb, args->alloc, args->wri,
				   &args->root->root, &key);
	if (ret == 0) {
		ret = scoutfs_btree_delete(sb, args->alloc, args->wri,
					   &args->root->root, &other);
		if (ret < 0) {
			err = scoutfs_btree_insert(sb, args->alloc, args->wri,
						   &args->root->root, &key,
						   NULL, 0);
			BUG_ON(err);
		} else {
			le64_add_cpu(&args->root->total_len, -len);
		}
	}

	return ret;
}

static struct scoutfs_ext_ops alloc_ext_ops = {
	.next = alloc_ext_next,
	.insert = alloc_ext_insert,
	.remove = alloc_ext_remove,
};

static bool invalid_extent(u64 start, u64 end, u64 first, u64 last)
{
	return start > end || start < first || end > last;
}

static bool invalid_meta_blkno(struct super_block *sb, u64 blkno)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	return invalid_extent(blkno, blkno,
			      le64_to_cpu(super->first_meta_blkno),
			      le64_to_cpu(super->last_meta_blkno));
}

static bool invalid_data_extent(struct super_block *sb, u64 start, u64 len)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	return invalid_extent(start, start + len - 1,
			      le64_to_cpu(super->first_data_blkno),
			      le64_to_cpu(super->last_data_blkno));
}

void scoutfs_alloc_init(struct scoutfs_alloc *alloc,
			struct scoutfs_alloc_list_head *avail,
			struct scoutfs_alloc_list_head *freed)
{
	memset(alloc, 0, sizeof(struct scoutfs_alloc));

	spin_lock_init(&alloc->lock);
	mutex_init(&alloc->mutex);
	alloc->avail = *avail;
	alloc->freed = *freed;
}

/*
 * We're about to commit the transaction that used this allocator, drop
 * its block references.
 */
int scoutfs_alloc_prepare_commit(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri)
{
	scoutfs_block_put(sb, alloc->dirty_avail_bl);
	alloc->dirty_avail_bl = NULL;
	scoutfs_block_put(sb, alloc->dirty_freed_bl);
	alloc->dirty_freed_bl = NULL;

	return 0;
}

static u32 list_block_space(__le32 nr)
{
	return SCOUTFS_ALLOC_LIST_MAX_BLOCKS - le32_to_cpu(nr);
}

static u64 list_block_peek(struct scoutfs_alloc_list_block *lblk,
			   unsigned int skip)
{
	BUG_ON(skip >= le32_to_cpu(lblk->nr));

	return le64_to_cpu(lblk->blknos[le32_to_cpu(lblk->start) + skip]);
}

/*
 * Add a blkno to the array.  Typically we append of the array.  But we
 * can also prepend once there's no more room at the end.  Consumers of
 * the blocks sort before removing them.
 */
static void list_block_add(struct scoutfs_alloc_list_head *lhead,
			   struct scoutfs_alloc_list_block *lblk, u64 blkno)
{
	u32 start = le32_to_cpu(lblk->start);
	u32 nr = le32_to_cpu(lblk->nr);

	BUG_ON(lhead->ref.blkno != lblk->hdr.blkno);
	BUG_ON(list_block_space(lblk->nr) == 0);

	if (start + nr < SCOUTFS_ALLOC_LIST_MAX_BLOCKS) {
		lblk->blknos[start + nr] = cpu_to_le64(blkno);
	} else {
		start--;
		lblk->blknos[start] = cpu_to_le64(blkno);
		lblk->start = cpu_to_le32(start);
	}

	le32_add_cpu(&lblk->nr, 1);
	le64_add_cpu(&lhead->total_nr, 1);
	le32_add_cpu(&lhead->first_nr, 1);
}

/*
 * Remove blknos from the start of the array.
 */
static void list_block_remove(struct scoutfs_alloc_list_head *lhead,
			      struct scoutfs_alloc_list_block *lblk,
			      unsigned int count)
{
	BUG_ON(lhead->ref.blkno != lblk->hdr.blkno);
	BUG_ON(count > SCOUTFS_ALLOC_LIST_MAX_BLOCKS);
	BUG_ON(le32_to_cpu(lblk->nr) < count);

	le32_add_cpu(&lblk->nr, -count);
	if (lblk->nr == 0)
		lblk->start = 0;
	else
		le32_add_cpu(&lblk->start, count);
	le64_add_cpu(&lhead->total_nr, -(u64)count);
	le32_add_cpu(&lhead->first_nr, -count);
}

static int cmp_le64(const void *A, const void *B)
{
	const __le64 *a = A;
	const __le64 *b = B;

	return scoutfs_cmp_u64s(le64_to_cpu(*a), le64_to_cpu(*b));
}

static void swap_le64(void *A, void *B, int size)
{
	__le64 *a = A;
	__le64 *b = B;

	swap(*a, *b);
}

static void list_block_sort(struct scoutfs_alloc_list_block *lblk)
{
	sort(&lblk->blknos[le32_to_cpu(lblk->start)], le32_to_cpu(lblk->nr),
			   sizeof(lblk->blknos[0]), cmp_le64, swap_le64);
}

/*
 * We're always reading blocks that we own, so we shouldn't see stale
 * references.  But the cached block can be stale and we can need to
 * invalidate it.
 */
static int read_list_block(struct super_block *sb,
			   struct scoutfs_alloc_list_ref *ref,
			   struct scoutfs_block **bl_ret)
{
	struct scoutfs_block *bl = NULL;

	bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	if (!IS_ERR_OR_NULL(bl) &&
	    !scoutfs_block_consistent_ref(sb, bl, ref->seq, ref->blkno,
					  SCOUTFS_BLOCK_MAGIC_ALLOC_LIST)) {
		scoutfs_inc_counter(sb, alloc_stale_cached_list_block);
		scoutfs_block_invalidate(sb, bl);
		scoutfs_block_put(sb, bl);
		bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	}
	if (IS_ERR(bl)) {
		*bl_ret = NULL;
		return PTR_ERR(bl);
	}

	*bl_ret = bl;
	return 0;
}

/*
 * Give the caller a dirty list block, always allocating a new block if
 * the ref is empty.
 *
 * If the caller gives us an allocated blkno for the cow then we know
 * that they're taking care of allocating and freeing the blknos, if not
 * we call meta alloc and free.
 */
static int dirty_list_block(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_alloc_list_ref *ref,
			    u64 dirty, u64 *old,
			    struct scoutfs_block **bl_ret)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_block *cow_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_alloc_list_block *lblk;
	bool undo_alloc = false;
	u64 blkno;
	int ret;
	int err;

	blkno = le64_to_cpu(ref->blkno);
	if (blkno) {
		ret = read_list_block(sb, ref, &bl);
		if (ret < 0)
			goto out;

		if (scoutfs_block_writer_is_dirty(sb, bl)) {
			ret = 0;
			goto out;
		}
	}

	if (dirty == 0) {
		ret = scoutfs_alloc_meta(sb, alloc, wri, &dirty);
		if (ret < 0)
			goto out;
		undo_alloc = true;
	}

	cow_bl = scoutfs_block_create(sb, dirty);
	if (IS_ERR(cow_bl)) {
		ret = PTR_ERR(cow_bl);
		goto out;
	}

	if (old) {
		*old = blkno;
	} else if (blkno) {
		ret = scoutfs_free_meta(sb, alloc, wri, blkno);
		if (ret < 0)
			goto out;
	}

	if (bl)
		memcpy(cow_bl->data, bl->data, SCOUTFS_BLOCK_LG_SIZE);
	else
		memset(cow_bl->data, 0, SCOUTFS_BLOCK_LG_SIZE);
	scoutfs_block_put(sb, bl);
	bl = cow_bl;
	cow_bl = NULL;

	lblk = bl->data;
	lblk->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_ALLOC_LIST);
	lblk->hdr.fsid = super->hdr.fsid;
	lblk->hdr.blkno = cpu_to_le64(bl->blkno);
	prandom_bytes(&lblk->hdr.seq, sizeof(lblk->hdr.seq));

	ref->blkno = lblk->hdr.blkno;
	ref->seq = lblk->hdr.seq;

	scoutfs_block_writer_mark_dirty(sb, wri, bl);
	ret = 0;

out:
	scoutfs_block_put(sb, cow_bl);
	if (ret < 0 && undo_alloc) {
		err = scoutfs_free_meta(sb, alloc, wri, dirty);
		BUG_ON(err); /* inconsistent */
	}

	if (ret < 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}
	*bl_ret = bl;

	return ret;
}

/* Allocate a new dirty list block if we fill up more than 3/4 of the block. */
#define EMPTY_FREED_THRESH	(SCOUTFS_ALLOC_LIST_MAX_BLOCKS / 4)

/*
 * Get dirty avail and freed list blocks that will be used for meta
 * allocations during our transaction.  We peek at the next avail blknos
 * for the cow allocations and manually record the cow frees rather than
 * recursively calling into alloc_meta and free_meta.
 *
 * In the client the server will have emptied the freed list so it will
 * always allocate a new first empty block for frees.  But in the server
 * it might have long lists of frees that it's trying to merge in to
 * extents over multiple transactions.  If the head of the freed list
 * doesn't have room we add a new empty block.
 */
static int dirty_alloc_blocks(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri)
{
	struct scoutfs_alloc_list_ref orig_freed;
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block *av_bl = NULL;
	struct scoutfs_block *fr_bl = NULL;
	struct scoutfs_block *bl;
	bool link_orig = false;
	u64 av_peek;
	u64 av_old;
	u64 fr_peek;
	u64 fr_old;
	int ret;

	if (alloc->dirty_avail_bl != NULL)
		return 0;

	mutex_lock(&alloc->mutex);

	/* undo dirty freed if we get an error after */
	orig_freed = alloc->freed.ref;

	if (alloc->dirty_avail_bl != NULL) {
		ret = 0;
		goto out;
	}

	/* caller must ensure that transactions commit before running out */
	if (WARN_ON_ONCE(alloc->avail.ref.blkno == 0) ||
	    WARN_ON_ONCE(le32_to_cpu(alloc->avail.first_nr) < 2)) {
		ret = -ENOSPC;
		goto out;
	}

	ret = read_list_block(sb, &alloc->avail.ref, &bl);
	if (ret < 0)
		goto out;

	lblk = bl->data;
	av_peek = list_block_peek(lblk, 0);
	fr_peek = list_block_peek(lblk, 1);
	scoutfs_block_put(sb, bl);
	lblk = NULL;

	if (alloc->freed.ref.blkno &&
	    list_block_space(alloc->freed.first_nr) < EMPTY_FREED_THRESH) {
		/* zero ref to force alloc of new block... */
		memset(&alloc->freed.ref, 0, sizeof(alloc->freed.ref));
		alloc->freed.first_nr = 0;
		link_orig = true;
	}

	/* dirty the first free block */
	ret = dirty_list_block(sb, alloc, wri, &alloc->freed.ref,
			       fr_peek, &fr_old, &fr_bl);
	if (ret < 0)
		goto out;

	if (link_orig) {
		/* .. and point the new block at the rest of the list */
		lblk = fr_bl->data;
		lblk->next = orig_freed;
		lblk = NULL;
	}

	ret = dirty_list_block(sb, alloc, wri, &alloc->avail.ref,
			       av_peek, &av_old, &av_bl);
	if (ret < 0)
		goto out;

	list_block_remove(&alloc->avail, av_bl->data, 2);
	/* sort dirty avail to encourage contiguous sorted meta blocks */
	list_block_sort(av_bl->data);

	if (av_old)
		list_block_add(&alloc->freed, fr_bl->data, av_old);
	if (fr_old)
		list_block_add(&alloc->freed, fr_bl->data, fr_old);

	alloc->dirty_avail_bl = av_bl;
	av_bl = NULL;
	alloc->dirty_freed_bl = fr_bl;
	fr_bl = NULL;
	ret = 0;

out:
	if (ret < 0 && alloc->freed.ref.blkno != orig_freed.blkno) {
		if (fr_bl)
			scoutfs_block_writer_forget(sb, wri, fr_bl);
		alloc->freed.ref = orig_freed;
	}

	mutex_unlock(&alloc->mutex);
	scoutfs_block_put(sb, av_bl);
	scoutfs_block_put(sb, fr_bl);
	return ret;
}

/*
 * Alloc a metadata block for a transaction in either the client or the
 * server.  The list block in the allocator was prepared for the transaction.
 */
int scoutfs_alloc_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri, u64 *blkno)
{
	struct scoutfs_alloc_list_block *lblk;
	int ret;

	ret = dirty_alloc_blocks(sb, alloc, wri);
	if (ret < 0)
		goto out;

	spin_lock(&alloc->lock);
	lblk = alloc->dirty_avail_bl->data;
	if (WARN_ON_ONCE(lblk->nr == 0)) {
		/* shouldn't happen, transaction should commit first */
		ret = -ENOSPC;
	} else {
		*blkno = list_block_peek(lblk, 0);
		list_block_remove(&alloc->avail, lblk, 1);
		ret = 0;
	}
	spin_unlock(&alloc->lock);

out:
	if (ret < 0)
		*blkno = 0;
	scoutfs_inc_counter(sb, alloc_alloc_meta);
	trace_scoutfs_alloc_alloc_meta(sb, *blkno, ret);
	return ret;
}

int scoutfs_free_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri, u64 blkno)
{
	struct scoutfs_alloc_list_block *lblk;
	int ret;

	if (WARN_ON_ONCE(invalid_meta_blkno(sb, blkno)))
		return -EINVAL;

	ret = dirty_alloc_blocks(sb, alloc, wri);
	if (ret < 0)
		goto out;

	spin_lock(&alloc->lock);
	lblk = alloc->dirty_freed_bl->data;
	if (WARN_ON_ONCE(list_block_space(lblk->nr) == 0)) {
		/* shouldn't happen, transaction should commit first */
		ret = -EIO;
	} else {
		list_block_add(&alloc->freed, lblk, blkno);
		ret = 0;
	}
	spin_unlock(&alloc->lock);

out:
	scoutfs_inc_counter(sb, alloc_free_meta);
	trace_scoutfs_alloc_free_meta(sb, blkno, ret);
	return ret;
}

/*
 * Allocate a data extent.  An extent that's smaller than the requested
 * size can be returned.
 *
 * The caller can provide a cached extent that can satisfy allocations
 * and will be refilled by allocations.  The caller is responsible for
 * freeing any remaining cached extent back into persistent items before
 * committing.
 *
 * Unlike meta allocations, the caller is expected to serialize
 * allocations from the root.
 */
int scoutfs_alloc_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *root,
		       struct scoutfs_extent *cached, u64 count,
		       u64 *blkno_ret, u64 *count_ret)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.type = SCOUTFS_FREE_EXTENT_LEN_TYPE,
	};
	struct scoutfs_extent ext;
	u64 len;
	int ret;

	/* large allocations come straight from the allocator */
	if (count >= SCOUTFS_ALLOC_DATA_LG_THRESH) {
		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args,
					0, 0, count, &ext);
		if (ret < 0)
			goto out;

		*blkno_ret = ext.start;
		*count_ret = ext.len;
		ret = 0;
		goto out;
	}

	/* smaller allocations come from a cached extent */
	if (cached->len == 0) {
		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args, 0, 0,
					SCOUTFS_ALLOC_DATA_LG_THRESH, cached);
		if (ret < 0)
			goto out;
	}

	len = min(count, cached->len);

	*blkno_ret = cached->start;
	*count_ret = len;

	cached->start += len;
	cached->len -= len;
	ret = 0;
out:
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = -ENOSPC;
		*blkno_ret = 0;
		*count_ret = 0;
	}

	scoutfs_inc_counter(sb, alloc_alloc_data);
	trace_scoutfs_alloc_alloc_data(sb, count, *blkno_ret, *count_ret, ret);
	return ret;
}

/*
 * Free data extents into the freed tree that will be reclaimed by the
 * server and made available for future allocators only if our
 * transaction succeeds.  We don't want to overwrite existing data if
 * our transaction fails.
 *
 * Unlike meta allocations, the caller is expected to serialize data
 * allocations.
 */
int scoutfs_free_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_alloc_root *root, u64 blkno, u64 count)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
	};
	int ret;

	if (WARN_ON_ONCE(invalid_data_extent(sb, blkno, count)))
		return -EINVAL;

	ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args, blkno, count, 0, 0);
	scoutfs_inc_counter(sb, alloc_free_data);
	trace_scoutfs_alloc_free_data(sb, blkno, count, ret);
	return ret;
}


/*
 * Move extent items adding up to the requested total length from the
 * src to the dst tree.  The caller is responsible for locking the
 * trees, usually because they're also looking at total_len to decide
 * how much to move.
 *
 * -ENOENT is returned if we run out of extents in the source tree
 * before moving the total.
 *
 * This first pass is not optimal because it performs full btree walks
 * per extent.  We could optimize this with more clever btree item
 * manipulation functions which can iterate through src and dst blocks
 * and let callbacks indicate how to change items.
 */
int scoutfs_alloc_move(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *dst,
		       struct scoutfs_alloc_root *src, u64 total)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
	};
	struct scoutfs_extent ext;
	u64 moved = 0;
	int ret = 0;
	int err;

	while (moved < total) {
		args.root = src;
		args.type = SCOUTFS_FREE_EXTENT_LEN_TYPE;
		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args,
					0, 0, total - moved, &ext);
		if (ret < 0)
			break;

		args.root = dst;
		args.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
		ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args, ext.start,
					 ext.len, ext.map, ext.flags);
		if (ret < 0) {
			args.root = src;
			args.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
			err = scoutfs_ext_insert(sb, &alloc_ext_ops, &args,
						 ext.start, ext.len, ext.map,
						 ext.flags);
			BUG_ON(err); /* inconsistent */
			break;
		}

		moved += ext.len;
		scoutfs_inc_counter(sb, alloc_moved_extent);
	}

	scoutfs_inc_counter(sb, alloc_move);
	trace_scoutfs_alloc_move(sb, total, moved, ret);

	return ret;
}

/*
 * We only trim one block, instead of looping trimming all, because the
 * caller is assuming that we do a fixed amount of work when they check
 * that their allocator has enough remaining free blocks for us.
 */
static int trim_empty_first_block(struct super_block *sb,
				  struct scoutfs_alloc *alloc,
				  struct scoutfs_block_writer *wri,
				  struct scoutfs_alloc_list_head *lhead)
{
	struct scoutfs_alloc_list_block *one = NULL;
	struct scoutfs_alloc_list_block *two = NULL;
	struct scoutfs_block *one_bl = NULL;
	struct scoutfs_block *two_bl = NULL;
	int ret;

	if (WARN_ON_ONCE(lhead->ref.blkno == 0) ||
	    WARN_ON_ONCE(lhead->first_nr != 0))
		return 0;

	ret = read_list_block(sb, &lhead->ref, &one_bl);
	if (ret < 0)
		goto out;
	one = one_bl->data;

	if (one->next.blkno) {
		ret = read_list_block(sb, &one->next, &two_bl);
		if (ret < 0)
			goto out;
		two = two_bl->data;
	}

	ret = scoutfs_free_meta(sb, alloc, wri, le64_to_cpu(lhead->ref.blkno));
	if (ret < 0)
		goto out;

	lhead->ref = one->next;
	lhead->first_nr = two ? two->nr : 0;
	ret = 0;
out:
	scoutfs_block_put(sb, one_bl);
	scoutfs_block_put(sb, two_bl);
	return ret;
}

/*
 * True if the allocator has enough free blocks to cow (alloc and free)
 * a list block and all the btree blocks that store extent items.
 *
 * At most, an extent operation can dirty down three paths of the tree
 * to modify a blkno item and two distant len items.  We can grow and
 * split the root, and then those three paths could share blocks but each
 * modify two leaf blocks.
 */
static bool list_can_cow(struct super_block *sb, struct scoutfs_alloc *alloc,
			 struct scoutfs_alloc_root *root)
{
	u32 most = 1 + (1 + 1 + (3 * (1 - root->root.height + 1)));

	if (le32_to_cpu(alloc->avail.first_nr) < most) {
		scoutfs_inc_counter(sb, alloc_list_avail_lo);
		return false;
	}

	if (list_block_space(alloc->freed.first_nr) < most) {
		scoutfs_inc_counter(sb, alloc_list_freed_hi);
		return false;
	}

	return true;
}

static bool lhead_in_alloc(struct scoutfs_alloc *alloc,
			   struct scoutfs_alloc_list_head *lhead)
{
	return lhead == &alloc->avail || lhead == &alloc->freed;
}

/*
 * Move free blocks from extent items in the root into only the first
 * block in the list towards the target if it's fallen below the lo
 * threshold.  This can return success without necessarily moving as
 * much as was requested if its meta allocator runs low, the caller is
 * expected to check the counts and act accordingly.
 *
 * -ENOSPC is returned if the root runs out of extents before the list
 * reaches the target.
 */
int scoutfs_alloc_fill_list(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_alloc_list_head *lhead,
			    struct scoutfs_alloc_root *root,
			    u64 lo, u64 target)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.type = SCOUTFS_FREE_EXTENT_LEN_TYPE,
	};
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_extent ext;
	int ret = 0;
	int i;

	if (WARN_ON_ONCE(target < lo) ||
	    WARN_ON_ONCE(lo > SCOUTFS_ALLOC_LIST_MAX_BLOCKS) ||
	    WARN_ON_ONCE(target > SCOUTFS_ALLOC_LIST_MAX_BLOCKS) ||
	    WARN_ON_ONCE(lhead_in_alloc(alloc, lhead)))
		return -EINVAL;

	if (le32_to_cpu(lhead->first_nr) >= lo)
		return 0;

	ret = dirty_list_block(sb, alloc, wri, &lhead->ref, 0, NULL, &bl);
	if (ret < 0)
		goto out;
	lblk = bl->data;

	while (le32_to_cpu(lblk->nr) < target &&
	       list_can_cow(sb, alloc, root)) {

		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args, 0, 0,
					target - le32_to_cpu(lblk->nr), &ext);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = -ENOSPC;
			break;
		}

		for (i = 0; i < ext.len; i++)
			list_block_add(lhead, lblk, ext.start + i);
	}

out:
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * Move blknos from all the blocks in the list into extents in the root,
 * removing empty blocks as we go.  This can return success and leave blocks
 * on the list if its metadata alloc runs out of space.
 */
int scoutfs_alloc_empty_list(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_alloc_root *root,
			     struct scoutfs_alloc_list_head *lhead)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE,
	};
	struct scoutfs_alloc_list_block *lblk = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_extent ext;
	int ret = 0;

	if (WARN_ON_ONCE(lhead_in_alloc(alloc, lhead)))
		return -EINVAL;

	while (lhead->ref.blkno && list_can_cow(sb, alloc, args.root)) {

		if (lhead->first_nr == 0) {
			ret = trim_empty_first_block(sb, alloc, wri, lhead);
			if (ret < 0)
				break;

			scoutfs_block_put(sb, bl);
			bl = NULL;
			continue;
		}

		if (bl == NULL) {
			ret = dirty_list_block(sb, alloc, wri, &lhead->ref,
					       0, NULL, &bl);
			if (ret < 0)
				break;
			lblk = bl->data;

			/* sort to encourage forming extents */
			list_block_sort(lblk);
		}

		/* combine free blknos into extents and insert them */
		ext.start = list_block_peek(lblk, 0);
		ext.len = 1;
		while ((le32_to_cpu(lblk->nr) > ext.len) &&
		       (list_block_peek(lblk, ext.len) == ext.start + ext.len))
			ext.len++;

		ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args,
					 ext.start, ext.len, 0, 0);
		if (ret < 0)
			break;

		list_block_remove(lhead, lblk, ext.len);
	}

	scoutfs_block_put(sb, bl);

	return ret;
}

/*
 * Insert the source list at the head of the destination list, leaving
 * the source empty.
 *
 * This looks bad because the lists are singly-linked and we have to cow
 * the entire src lsit to update its tail block next ref to the start of
 * the dst list.
 *
 * In practice, this isn't a problem because the server only calls this
 * with small lists that it's going to use soon.
 */
int scoutfs_alloc_splice_list(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_alloc_list_head *dst,
			      struct scoutfs_alloc_list_head *src)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_alloc_list_ref *ref;
	struct scoutfs_block *prev = NULL;
	struct scoutfs_block *bl = NULL;
	int ret = 0;

	if (WARN_ON_ONCE(lhead_in_alloc(alloc, dst)) ||
	    WARN_ON_ONCE(lhead_in_alloc(alloc, src)))
		return -EINVAL;

	if (src->ref.blkno == 0)
		return 0;

	ref = &src->ref;
	while (ref->blkno) {
		ret = dirty_list_block(sb, alloc, wri, ref, 0, NULL, &bl);
		if (ret < 0)
			goto out;

		lblk = bl->data;
		ref = &lblk->next;

		scoutfs_block_put(sb, prev);
		prev = bl;
		bl = NULL;
	}

	*ref = dst->ref;
	dst->ref = src->ref;
	dst->first_nr = src->first_nr;
	le64_add_cpu(&dst->total_nr, le64_to_cpu(src->total_nr));

	memset(src, 0, sizeof(struct scoutfs_alloc_list_head));
	ret = 0;
out:
	scoutfs_block_put(sb, prev);
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * Returns true if we're running low on avail blocks or running out of
 * space for freed blocks.
 *
 * On the avail side, we're avoiding spurious enospc as our avail block
 * runs low.  If we commit it can be refilled by the server.
 *
 * On the freed side, we're avoiding getting errors in frees where they
 * can't be recovered from.  This is mostly in freeing cowed blocks in
 * the data allocator btree which is related to its height.
 *
 * And both of these need to be mindful of multiple tasks entering the
 * transaction.
 */
bool scoutfs_alloc_meta_lo_thresh(struct super_block *sb,
				  struct scoutfs_alloc *alloc)
{
	bool lo;

	spin_lock(&alloc->lock);
	lo = le32_to_cpu(alloc->avail.first_nr) < 8 ||
	     list_block_space(alloc->freed.first_nr) < 8;
	spin_unlock(&alloc->lock);

	return lo;
}

/*
 * Call the callers callback for every persistent allocator structure
 * we can find.
 */
int scoutfs_alloc_foreach(struct super_block *sb,
			  scoutfs_alloc_foreach_cb_t cb, void *arg)
{
	struct scoutfs_btree_ref stale_refs[2] = {{0,}};
	struct scoutfs_btree_ref refs[2] = {{0,}};
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_srch_compact_input *scin;
	struct scoutfs_log_trees_val ltv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	scin = kmalloc(sizeof(struct scoutfs_srch_compact_input), GFP_NOFS);
	if (!super || !scin) {
		ret = -ENOMEM;
		goto out;
	}

retry:
	ret = scoutfs_read_super(sb, super);
	if (ret < 0)
		goto out;

	refs[0] = super->logs_root.ref;
	refs[1] = super->srch_root.ref;

	/* all the server allocators */
	ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, true, true,
		 le64_to_cpu(super->meta_alloc[0].total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, true, true,
		 le64_to_cpu(super->meta_alloc[1].total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, false, true,
		 le64_to_cpu(super->data_alloc.total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, true,
		 le64_to_cpu(super->server_meta_avail[0].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, true,
		 le64_to_cpu(super->server_meta_avail[1].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, false,
		 le64_to_cpu(super->server_meta_freed[0].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, false,
		 le64_to_cpu(super->server_meta_freed[1].total_nr));
	if (ret < 0)
		goto out;

	/* mount fs transaction allocators */
	scoutfs_key_init_log_trees(&key, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret < 0)
			goto out;

		if (iref.val_len == sizeof(ltv)) {
			key = *iref.key;
			memcpy(&ltv, iref.val, sizeof(ltv));
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), true, true,
			 le64_to_cpu(ltv.meta_avail.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), true, false,
			 le64_to_cpu(ltv.meta_freed.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), false, true,
			 le64_to_cpu(ltv.data_avail.total_len)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), false, false,
			 le64_to_cpu(ltv.data_freed.total_len));
		if (ret < 0)
			goto out;

		scoutfs_key_inc(&key);
	}

	/* srch compaction allocators */
	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_SRCH_ZONE;
	key.sk_type = SCOUTFS_SRCH_BUSY_TYPE;

	for (;;) {
		/* _BUSY_ is last type, _next won't see other types */
		ret = scoutfs_btree_next(sb, &super->srch_root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0) {
			if (iref.val_len == sizeof(scin)) {
				key = *iref.key;
				memcpy(scin, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_SRCH,
			 le64_to_cpu(scin->id), true, true,
			 le64_to_cpu(scin->meta_avail.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SRCH,
			 le64_to_cpu(scin->id), true, false,
			 le64_to_cpu(scin->meta_freed.total_nr));
		if (ret < 0)
			goto out;

		scoutfs_key_inc(&key);
	}

	ret = 0;
out:
	if (ret == -ESTALE) {
		if (memcmp(&stale_refs, &refs, sizeof(refs)) == 0) {
			ret = -EIO;
		} else {
			BUILD_BUG_ON(sizeof(stale_refs) != sizeof(refs));
			memcpy(stale_refs, refs, sizeof(stale_refs));
			goto retry;
		}
	}

	kfree(super);
	kfree(scin);
	return ret;
}
