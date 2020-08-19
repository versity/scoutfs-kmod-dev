/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
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
#include <linux/mutex.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "lock.h"
#include "btree.h"
#include "client.h"
#include "radix.h"
#include "block.h"
#include "forest.h"
#include "hash.h"
#include "srch.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * scoutfs items are stored in a forest of btrees.  Each mount writes
 * items into its own relatively small log btree.  Each mount can also
 * have a few finalized log btrees sitting around that it is no longer
 * writing to.  Finally a much larger core fs btree is the final home
 * for metadata.
 *
 * The log btrees are modified by multiple transactions over time so
 * there is no consistent ordering relationship between the items in
 * different btrees.  Each item in a log btree stores a version number
 * for the item.  Readers check log btrees for the most recent version
 * that it should use.
 *
 * The item cache reads items in bulk from stable btrees, and writes a
 * transaction's worth of dirty items into the item log btree.
 *
 * Log btrees are typically very sparse.  It would be wasteful for
 * readers to read every log btree looking for an item.  Each log btree
 * contains a bloom filter keyed on the starting key of locks.  This
 * lets lock holders quickly eliminate log trees that cannot contain
 * keys protected by their lock.
 */

struct forest_info {
	struct mutex mutex;
	struct scoutfs_radix_allocator *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_log_trees our_log;

	struct mutex srch_mutex;
	struct scoutfs_srch_file srch_file;
	struct scoutfs_block *srch_bl;
};

#define DECLARE_FOREST_INFO(sb, name) \
	struct forest_info *name = SCOUTFS_SB(sb)->forest_info

struct forest_refs {
	struct scoutfs_btree_ref fs_ref;
	struct scoutfs_btree_ref logs_ref;
} __packed;

/* initialize some refs that initially aren't equal */
#define DECLARE_STALE_TRACKING_SUPER_REFS(a, b)		\
	struct forest_refs a = {{cpu_to_le64(0),}};	\
	struct forest_refs b = {{cpu_to_le64(1),}}

struct forest_bloom_nrs {
	unsigned int nrs[SCOUTFS_FOREST_BLOOM_NRS];
};

static void calc_bloom_nrs(struct forest_bloom_nrs *bloom,
			    struct scoutfs_key *key)
{
	u64 hash;
	int i;

	BUILD_BUG_ON((SCOUTFS_FOREST_BLOOM_FUNC_BITS *
		      SCOUTFS_FOREST_BLOOM_NRS) > 64);

	hash = scoutfs_hash64(key, sizeof(struct scoutfs_key));

	for (i = 0; i < ARRAY_SIZE(bloom->nrs); i++) {
		bloom->nrs[i] = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}
}

static struct scoutfs_block *read_bloom_ref(struct super_block *sb,
					    struct scoutfs_btree_ref *ref)
{
	struct scoutfs_block *bl;

	bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
	if (IS_ERR(bl))
		return bl;

	if (!scoutfs_block_consistent_ref(sb, bl, ref->seq, ref->blkno,
					  SCOUTFS_BLOCK_MAGIC_BLOOM)) {
		scoutfs_block_invalidate(sb, bl);
		scoutfs_block_put(sb, bl);
		return ERR_PTR(-ESTALE);
	}

	return bl;
}

/*
 * This is an unlocked iteration across all the btrees to find a hint at
 * the next key that the caller could read.  It's used to find out what
 * next key range to lock, presuming you're allowed to only see items
 * that have been synced.  We ask the server for the current roots to
 * check.
 *
 * We don't bother skipping deletion items here.  The caller will safely
 * skip over them when really reading from their locked region and will
 * call again after them to find the next hint.
 *
 * We're reading from stable persistent trees so we don't need to lock
 * against writers, their writes are cow into free blocks.
 */
int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_refs, refs);
	struct scoutfs_net_roots roots;
	struct scoutfs_btree_root item_root;
	struct scoutfs_log_trees_val *ltv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key found;
	struct scoutfs_key ltk;
	bool checked_fs;
	bool have_next;
	int ret;

	scoutfs_inc_counter(sb, forest_roots_next_hint);

retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	trace_scoutfs_forest_using_roots(sb, &roots.fs_root, &roots.logs_root);
	refs.fs_ref = roots.fs_root.ref;
	refs.logs_ref = roots.logs_root.ref;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	checked_fs = false;
	have_next = false;

	for (;;) {
		if (!checked_fs) {
			checked_fs = true;
			item_root = roots.fs_root;
		} else {
			ret = scoutfs_btree_next(sb, &roots.logs_root, &ltk,
						 &iref);
			if (ret == -ENOENT) {
				if (have_next)
					ret = 0;
				break;
			}
			if (ret == -ESTALE)
				break;
			if (ret < 0)
				goto out;

			if (iref.val_len == sizeof(*ltv)) {
				ltk = *iref.key;
				scoutfs_key_inc(&ltk);
				ltv = iref.val;
				item_root = ltv->item_root;
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
			if (ret < 0)
				goto out;

			if (item_root.ref.blkno == 0)
				continue;
		}

		ret = scoutfs_btree_next(sb, &item_root, key, &iref);
		if (ret == -ENOENT)
			continue;
		if (ret == -ESTALE)
			break;
		if (ret < 0)
			goto out;

		found = *iref.key;
		scoutfs_btree_put_iref(&iref);

		if (!have_next || scoutfs_key_compare(&found, next) < 0) {
			have_next = true;
			*next = found;
		}
	}

	if (ret == -ESTALE) {
		if (memcmp(&prev_refs, &refs, sizeof(refs)) == 0)
			return -EIO;
		prev_refs = refs;
		goto retry;
	}
out:

	return ret;
}

struct forest_read_items_data {
	bool is_fs;
	scoutfs_forest_item_cb cb;
	void *cb_arg;
};

static int forest_read_items(struct super_block *sb, struct scoutfs_key *key,
			     void *val, int val_len, void *arg)
{
	struct forest_read_items_data *rid = arg;
	struct scoutfs_log_item_value _liv = {0,};
	struct scoutfs_log_item_value *liv = &_liv;

	if (!rid->is_fs) {
		liv = val;
		val += sizeof(struct scoutfs_log_item_value);
		val_len -= sizeof(struct scoutfs_log_item_value);
	}

	return rid->cb(sb, key, liv, val, val_len, rid->cb_arg);
}

/*
 * For each forest btree whose bloom block indicates that the lock might
 * have items stored, call the caller's callback for every item in the
 * leaf block in each tree which contains the key.
 *
 * The btree iter calls clamp the caller's range to the tightest range
 * that covers all the blocks.  Any keys outside of this range can't be
 * trusted because we didn't visit all the trees to check their items.
 *
 * If we hit stale blocks and retry we can call the callback for
 * duplicate items.  This is harmless because the items are stable while
 * the caller holds their cluster lock and the caller has to filter out
 * item versions anyway.
 */
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_lock *lock,
			      struct scoutfs_key *key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_refs, refs);
	struct forest_read_items_data rid = {
		.cb = cb,
		.cb_arg = arg,
	};
	struct scoutfs_log_trees_val ltv;
	struct scoutfs_net_roots roots;
	struct scoutfs_bloom_block *bb;
	struct forest_bloom_nrs bloom;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_block *bl;
	struct scoutfs_key ltk;
	int ret;
	int i;

	scoutfs_inc_counter(sb, forest_read_items);
	calc_bloom_nrs(&bloom, &lock->start);

	roots = lock->roots;
retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	trace_scoutfs_forest_using_roots(sb, &roots.fs_root, &roots.logs_root);
	refs.fs_ref = roots.fs_root.ref;
	refs.logs_ref = roots.logs_root.ref;

	*start = lock->start;
	*end = lock->end;

	/* start with fs root items */
	rid.is_fs = true;
	ret = scoutfs_btree_read_items(sb, &roots.fs_root, key, start, end,
				       forest_read_items, &rid);
	if (ret < 0)
		goto out;
	rid.is_fs = false;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	for (;; scoutfs_key_inc(&ltk)) {
		ret = scoutfs_btree_next(sb, &roots.logs_root, &ltk, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(ltv)) {
				ltk = *iref.key;
				memcpy(&ltv, iref.val, sizeof(ltv));
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				break;
			goto out; /* including stale */
		}

		if (ltv.bloom_ref.blkno == 0)
			continue;

		bl = read_bloom_ref(sb, &ltv.bloom_ref);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}
		bb = bl->data;

		for (i = 0; i < ARRAY_SIZE(bloom.nrs); i++) {
			if (!test_bit_le(bloom.nrs[i], bb->bits))
				break;
		}

		scoutfs_block_put(sb, bl);

		/* one of the bloom bits wasn't set */
		if (i != ARRAY_SIZE(bloom.nrs)) {
			scoutfs_inc_counter(sb, forest_bloom_fail);
			continue;
		}

		scoutfs_inc_counter(sb, forest_bloom_pass);

		ret = scoutfs_btree_read_items(sb, &ltv.item_root, key, start,
					       end, forest_read_items, &rid);
		if (ret < 0)
			goto out;
	}

	ret = 0;
out:
	if (ret == -ESTALE) {
		if (memcmp(&prev_refs, &refs, sizeof(refs)) == 0) {
			ret = -EIO;
			goto out;
		}
		prev_refs = refs;

		ret = scoutfs_client_get_roots(sb, &roots);
		if (ret)
			goto out;
		goto retry;
	}

	return ret;
}

/*
 * Make sure that the bloom bits for the lock's start key are all set in
 * the current log's bloom block.  We record the nr of our log tree in
 * the lock so that we only try to cow and set the bits once per tree
 * across multiple commits as long as the lock isn't purged.
 *
 * This is using a coarse mutex to serialize cowing the block.  It could
 * be much finer grained, but it's infrequent.  We'll keep an eye on if
 * it gets expensive enough to warrant fixing.
 */
int scoutfs_forest_set_bloom_bits(struct super_block *sb,
				  struct scoutfs_lock *lock)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_block *new_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_bloom_block *bb;
	struct scoutfs_btree_ref *ref;
	struct forest_bloom_nrs bloom;
	int nr_set = 0;
	u64 blkno;
	u64 nr;
	int ret;
	int err;
	int i;

	nr = le64_to_cpu(finf->our_log.nr);

	/* our rid is constant */
	if (atomic64_read(&lock->forest_bloom_nr) == nr) {
		ret = 0;
		goto out;
	}

	mutex_lock(&finf->mutex);

	scoutfs_inc_counter(sb, forest_set_bloom_bits);
	calc_bloom_nrs(&bloom, &lock->start);

	ref = &finf->our_log.bloom_ref;

	if (ref->blkno) {
		bl = read_bloom_ref(sb, ref);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto unlock;
		}
		bb = bl->data;
	}

	if (!ref->blkno || !scoutfs_block_writer_is_dirty(sb, bl)) {

		ret = scoutfs_radix_alloc(sb, finf->alloc, finf->wri, &blkno);
		if (ret < 0)
			goto unlock;

		new_bl = scoutfs_block_create(sb, blkno);
		if (IS_ERR(new_bl)) {
			err = scoutfs_radix_free(sb, finf->alloc, finf->wri,
						 blkno);
			BUG_ON(err); /* could have dirtied */
			ret = PTR_ERR(new_bl);
			goto unlock;
		}

		if (bl) {
			err = scoutfs_radix_free(sb, finf->alloc, finf->wri,
						  le64_to_cpu(ref->blkno));
			BUG_ON(err); /* could have dirtied */
			memcpy(new_bl->data, bl->data, SCOUTFS_BLOCK_LG_SIZE);
		} else {
			memset(new_bl->data, 0, SCOUTFS_BLOCK_LG_SIZE);
		}

		scoutfs_block_writer_mark_dirty(sb, finf->wri, new_bl);

		scoutfs_block_put(sb, bl);
		bl = new_bl;
		bb = bl->data;
		new_bl = NULL;

		bb->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BLOOM);
		bb->hdr.fsid = super->hdr.fsid;
		bb->hdr.blkno = cpu_to_le64(blkno);
		prandom_bytes(&bb->hdr.seq, sizeof(bb->hdr.seq));
		ref->blkno = bb->hdr.blkno;
		ref->seq = bb->hdr.seq;
	}

	for (i = 0; i < ARRAY_SIZE(bloom.nrs); i++) {
		if (!test_and_set_bit_le(bloom.nrs[i], bb->bits)) {
			le64_add_cpu(&bb->total_set, 1);
			nr_set++;
		}
	}

	trace_scoutfs_forest_bloom_set(sb, &lock->start,
				le64_to_cpu(finf->our_log.rid),
				le64_to_cpu(finf->our_log.nr),
				le64_to_cpu(finf->our_log.bloom_ref.blkno),
				le64_to_cpu(finf->our_log.bloom_ref.seq),
				nr_set);

	atomic64_set(&lock->forest_bloom_nr,  nr);
	ret = 0;
unlock:
	mutex_unlock(&finf->mutex);
out:
	scoutfs_block_put(sb, bl);
	return ret;
}

int scoutfs_forest_insert_list(struct super_block *sb,
			       struct scoutfs_btree_item_list *lst)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_btree_insert_list(sb, finf->alloc, finf->wri,
					 &finf->our_log.item_root, lst);
}

/*
 * Add a srch entry to the current transaction's log file.  It will be
 * committed in a transaction along with the dirty btree blocks that
 * hold dirty items.  The srch entries aren't governed by lock
 * consistency.
 *
 * We lock here because of the shared file and block reference.
 * Typically these calls are a quick appending to the end of the block,
 * but they will allocate or cow blocks every few thousand calls.
 */
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id)
{
	DECLARE_FOREST_INFO(sb, finf);
	int ret;

	mutex_lock(&finf->srch_mutex);
	ret = scoutfs_srch_add(sb, finf->alloc, finf->wri, &finf->srch_file,
			       &finf->srch_bl, hash, ino, id);
	mutex_unlock(&finf->srch_mutex);
	return ret;
}

/*
 * This is called from transactions as a new transaction opens and is
 * serialized with all writers.
 */
void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt)
{
	DECLARE_FOREST_INFO(sb, finf);

	mutex_lock(&finf->mutex);

	finf->alloc = alloc;
	finf->wri = wri;

	/* the lt allocator fields have been used by the caller */
	memset(&finf->our_log, 0, sizeof(finf->our_log));
	finf->our_log.item_root = lt->item_root;
	finf->our_log.bloom_ref = lt->bloom_ref;
	finf->our_log.rid = lt->rid;
	finf->our_log.nr = lt->nr;
	finf->srch_file = lt->srch_file;
	WARN_ON_ONCE(finf->srch_bl); /* commiting should have put the block */
	finf->srch_bl = NULL;

	trace_scoutfs_forest_init_our_log(sb, le64_to_cpu(lt->rid),
					  le64_to_cpu(lt->nr),
					  le64_to_cpu(lt->item_root.ref.blkno),
					  le64_to_cpu(lt->item_root.ref.seq));

	mutex_unlock(&finf->mutex);
}

/*
 * This is called during transaction commit which excludes forest writer
 * calls.  The caller has already written all the dirty blocks that the
 * forest roots reference.  They're getting the roots to send to the server
 * for the commit.
 */
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt)
{
	DECLARE_FOREST_INFO(sb, finf);

	lt->item_root = finf->our_log.item_root;
	lt->bloom_ref = finf->our_log.bloom_ref;
	lt->srch_file = finf->srch_file;

	scoutfs_block_put(sb, finf->srch_bl);
	finf->srch_bl = NULL;

	trace_scoutfs_forest_prepare_commit(sb, &lt->item_root.ref,
					    &lt->bloom_ref);
}

int scoutfs_forest_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf;
	int ret;

	finf = kzalloc(sizeof(struct forest_info), GFP_KERNEL);
	if (!finf) {
		ret = -ENOMEM;
		goto out;
	}

	/* the finf fields will be setup as we open a transaction */
	mutex_init(&finf->mutex);
	mutex_init(&finf->srch_mutex);

	sbi->forest_info = finf;
	ret = 0;
out:
	if (ret)
		scoutfs_forest_destroy(sb);

	return 0;
}

void scoutfs_forest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf = SCOUTFS_SB(sb)->forest_info;

	if (finf) {
		scoutfs_block_put(sb, finf->srch_bl);
		kfree(finf);
		sbi->forest_info = NULL;
	}
}
