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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "seg.h"
#include "item.h"
#include "btree.h"
#include "cmp.h"
#include "compact.h"
#include "manifest.h"
#include "trans.h"
#include "counters.h"
#include "net.h"
#include "scoutfs_trace.h"

/*
 * Manifest entries are stored in the cow btrees in the persistently
 * allocated ring of blocks in the shared device.  This lets clients
 * read consistent old versions of the manifest when it's safe to do so.
 *
 * Manifest entries are sorted first by level then by their first key.
 * This enables the primary searches based on key value for looking up
 * items in segments via the manifest.
 */

struct manifest {
	struct rw_semaphore rwsem;
	u8 nr_levels;

	/* calculated on mount, const thereafter */
	u64 level_limits[SCOUTFS_MANIFEST_MAX_LEVEL + 1];

	unsigned long flags;

	struct scoutfs_key_buf *compact_keys[SCOUTFS_MANIFEST_MAX_LEVEL + 1];
};

#define MANI_FLAG_LEVEL0_FULL (1 << 0)

#define DECLARE_MANIFEST(sb, name) \
	struct manifest *name = SCOUTFS_SB(sb)->manifest

/*
 * A reader uses references to segments copied from a walk of the
 * manifest.  The references are a point in time sample of the manifest.
 * The manifest and segments can change while the reader uses their
 * references.  Locking ensures that the items they're reading will be
 * stable while the manifest and segments change, and the segment
 * allocator gives readers time to use immutable stale segments before
 * their reallocated and reused.
 */
struct manifest_ref {
	struct list_head entry;

	u64 segno;
	u64 seq;
	struct scoutfs_segment *seg;
	int found_ctr;
	int off;
	u8 level;

	struct scoutfs_key_buf *first;
	struct scoutfs_key_buf *last;
};

/*
 * Change the level count under the manifest lock.  We then maintain a
 * bit that can be tested outside the lock to determine if the caller
 * should wait for level 0 segments to drain.
 */
static void add_level_count(struct super_block *sb, int level, s64 val)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	__le64 count;
	int full;

	le64_add_cpu(&super->manifest.level_counts[level], val);

	if (level == 0) {
		count = super->manifest.level_counts[level];
		full = test_bit(MANI_FLAG_LEVEL0_FULL, &mani->flags);
		if (count && !full)
			set_bit(MANI_FLAG_LEVEL0_FULL, &mani->flags);
		else if (!count && full)
			clear_bit(MANI_FLAG_LEVEL0_FULL, &mani->flags);
	}
}

/*
 * Return whether or not level 0 segments are full.  It's safe to use
 * this as a wait_event condition because it doesn't block.
 *
 * Callers rely on on the spin locks in wait queues to synchronize
 * testing this as a sleeping condition with addition to the wait queue
 * and waking of the waitqueue.
 */
bool scoutfs_manifest_level0_full(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);

	return test_bit(MANI_FLAG_LEVEL0_FULL, &mani->flags);
}

void scoutfs_manifest_init_entry(struct scoutfs_manifest_entry *ment,
				 u64 level, u64 segno, u64 seq,
				 struct scoutfs_key_buf *first,
				 struct scoutfs_key_buf *last)
{
	ment->level = level;
	ment->segno = segno;
	ment->seq = seq;

	if (first)
		scoutfs_key_clone(&ment->first, first);
	else
		scoutfs_key_init(&ment->first, NULL, 0);

	if (last)
		scoutfs_key_clone(&ment->last, last);
	else
		scoutfs_key_init(&ment->last, NULL, 0);
}

/*
 * level 0 segments have the extra seq up in the btree key.
 */
static struct scoutfs_manifest_btree_key *
alloc_btree_key_val_lens(unsigned first_len, unsigned last_len)
{
	return kmalloc(sizeof(struct scoutfs_manifest_btree_key) +
		       sizeof(u64) +
		       sizeof(struct scoutfs_manifest_btree_val) +
		       first_len + last_len, GFP_NOFS);
}

/*
 * Initialize the btree key and value for a manifest entry in one contiguous
 * allocation.
 */
static struct scoutfs_manifest_btree_key *
alloc_btree_key_val(struct scoutfs_manifest_entry *ment, unsigned *mkey_len,
		    struct scoutfs_manifest_btree_val **mval_ret,
		    unsigned *mval_len_ret)
{
	struct scoutfs_manifest_btree_key *mkey;
	struct scoutfs_manifest_btree_val *mval;
	struct scoutfs_key_buf b_first;
	struct scoutfs_key_buf b_last;
	unsigned bkey_len;
	unsigned mval_len;
	__be64 seq;

	mkey = alloc_btree_key_val_lens(ment->first.key_len, ment->last.key_len);
	if (!mkey)
		return NULL;

	if (ment->level == 0) {
		seq = cpu_to_be64(ment->seq);
		bkey_len = sizeof(seq);
		memcpy(mkey->bkey, &seq, bkey_len);
	} else {
		bkey_len = ment->first.key_len;
	}

	*mkey_len = offsetof(struct scoutfs_manifest_btree_key, bkey[bkey_len]);
	mval = (void *)mkey + *mkey_len;

	if (ment->level == 0) {
		scoutfs_key_init(&b_first, mval->keys, ment->first.key_len);
		scoutfs_key_init(&b_last, mval->keys + ment->first.key_len,
				 ment->last.key_len);
		mval_len = sizeof(struct scoutfs_manifest_btree_val) +
			   ment->first.key_len + ment->last.key_len;
	} else {
		scoutfs_key_init(&b_first, mkey->bkey, ment->first.key_len);
		scoutfs_key_init(&b_last, mval->keys, ment->last.key_len);
		mval_len = sizeof(struct scoutfs_manifest_btree_val) +
			   ment->last.key_len;
	}

	mkey->level = ment->level;
	mval->segno = cpu_to_le64(ment->segno);
	mval->seq = cpu_to_le64(ment->seq);
	mval->first_key_len = cpu_to_le16(ment->first.key_len);
	mval->last_key_len = cpu_to_le16(ment->last.key_len);

	scoutfs_key_copy(&b_first, &ment->first);
	scoutfs_key_copy(&b_last, &ment->last);

	if (mval_ret) {
		*mval_ret = mval;
		*mval_len_ret = mval_len;
	}
	return mkey;
}

/* initialize a native manifest entry to point to the btree key and value */
static void init_ment_iref(struct scoutfs_manifest_entry *ment,
			   struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_manifest_btree_key *mkey = iref->key;
	struct scoutfs_manifest_btree_val *mval = iref->val;

	ment->level = mkey->level;
	ment->segno = le64_to_cpu(mval->segno);
	ment->seq = le64_to_cpu(mval->seq);

	if (ment->level == 0) {
		scoutfs_key_init(&ment->first, mval->keys,
				 le16_to_cpu(mval->first_key_len));
		scoutfs_key_init(&ment->last, mval->keys +
				 le16_to_cpu(mval->first_key_len),
				 le16_to_cpu(mval->last_key_len));
	} else {
		scoutfs_key_init(&ment->first, mkey->bkey,
				 le16_to_cpu(mval->first_key_len));
		scoutfs_key_init(&ment->last, mval->keys,
				 le16_to_cpu(mval->last_key_len));
	}
}

/*
 * Fill the callers max-size btree key with the given values and return
 * its length.
 */
static unsigned init_btree_key(struct scoutfs_manifest_btree_key *mkey,
			       u8 level, u64 seq, struct scoutfs_key_buf *first)
{
	struct scoutfs_key_buf b_first;
	unsigned bkey_len;
	__be64 bseq;

	mkey->level = level;

	if (level == 0) {
		bseq = cpu_to_be64(seq);
		bkey_len = sizeof(bseq);
		memcpy(mkey->bkey, &bseq, bkey_len);
	} else if (first) {
		scoutfs_key_init(&b_first, mkey->bkey, first->key_len);
		scoutfs_key_copy(&b_first, first);
		bkey_len = first->key_len;
	} else {
		bkey_len = 0;
	}

	return offsetof(struct scoutfs_manifest_btree_key, bkey[bkey_len]);
}

/*
 * Insert a new manifest entry in the ring.  The ring allocates a new
 * node for us and we fill it.
 *
 * This must be called with the manifest lock held.
 */
int scoutfs_manifest_add(struct super_block *sb,
			 struct scoutfs_manifest_entry *ment)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_manifest_btree_key *mkey;
	struct scoutfs_manifest_btree_val *mval;
	unsigned mkey_len;
	unsigned mval_len;
	int ret;

	lockdep_assert_held(&mani->rwsem);

	mkey = alloc_btree_key_val(ment, &mkey_len, &mval, &mval_len);
	if (!mkey)
		return -ENOMEM;

	trace_scoutfs_manifest_add(sb, ment->level, ment->segno, ment->seq,
				   &ment->first, &ment->last);

	ret = scoutfs_btree_insert(sb, &super->manifest.root, mkey, mkey_len,
				   mval, mval_len);
	if (ret == 0) {
		mani->nr_levels = max_t(u8, mani->nr_levels, ment->level + 1);
		add_level_count(sb, ment->level, 1);
	}

	kfree(mkey);
	return ret;
}

/*
 * This must be called with the manifest lock held.
 *
 * When this is called from the network we can take the keys directly as
 * they were sent from the clients.
 */
int scoutfs_manifest_del(struct super_block *sb,
			 struct scoutfs_manifest_entry *ment)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_manifest_btree_key *mkey;
	unsigned mkey_len;
	int ret;

	trace_scoutfs_manifest_delete(sb, ment->level, ment->segno, ment->seq,
				      &ment->first, &ment->last);

	lockdep_assert_held(&mani->rwsem);

	mkey = alloc_btree_key_val(ment, &mkey_len, NULL, NULL);
	if (!mkey)
		return -ENOMEM;

	ret = scoutfs_btree_delete(sb, &super->manifest.root, mkey, mkey_len);
	if (ret == 0)
		add_level_count(sb, ment->level, -1ULL);

	kfree(mkey);
	return ret;
}

/*
 * XXX This feels pretty gross, but it's a simple way to give compaction
 * atomic updates.  It'll go away once compactions go to the trouble of
 * communicating their atomic results in a message instead of a series
 * of function calls.
 */
int scoutfs_manifest_lock(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);

	down_write(&mani->rwsem);

	return 0;
}

int scoutfs_manifest_unlock(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);

	up_write(&mani->rwsem);

	return 0;
}

static void free_ref(struct super_block *sb, struct manifest_ref *ref)
{
	if (!IS_ERR_OR_NULL(ref)) {
		WARN_ON_ONCE(!list_empty(&ref->entry));
		scoutfs_seg_put(ref->seg);
		scoutfs_key_free(sb, ref->first);
		scoutfs_key_free(sb, ref->last);
		kfree(ref);
	}
}

/*
 * Allocate a reading manifest ref so that we can work with segments
 * described by the callers manifest entry.
 */
static int alloc_manifest_ref(struct super_block *sb, struct list_head *ref_list,
			      struct scoutfs_manifest_entry *ment)
{
	struct manifest_ref *ref;

	ref = kzalloc(sizeof(struct manifest_ref), GFP_NOFS);
	if (ref) {
		ref->first = scoutfs_key_dup(sb, &ment->first);
		ref->last = scoutfs_key_dup(sb, &ment->last);
	}
	if (!ref || !ref->first || !ref->last) {
		free_ref(sb, ref);
		return -ENOMEM;
	}

	ref->level = ment->level;
	ref->segno = ment->segno;
	ref->seq = ment->seq;

	list_add_tail(&ref->entry, ref_list);

	return 0;
}

/*
 * Return the previous entry if it's in the right level and it overlaps
 * with the start key by having a last key that's >=.  If no such entry
 * exists it just returns the next entry after the key and doesn't test
 * it at all.  If this returns 0 then the caller has to put the iref.
 */
static int btree_prev_overlap_or_next(struct super_block *sb,
				      struct scoutfs_btree_root *root,
				      void *key, unsigned key_len,
				      struct scoutfs_key_buf *start, u8 level,
				      struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_manifest_entry ment;
	int ret;

	ret = scoutfs_btree_prev(sb, root, key, key_len, iref);
	if (ret < 0 && ret != -ENOENT)
		return ret;

	if (ret == 0) {
		init_ment_iref(&ment, iref);
		if (ment.level != level ||
		    scoutfs_key_compare(&ment.last, start) < 0)
			ret = -ENOENT;
	}
	if (ret == -ENOENT) {
		scoutfs_btree_put_iref(iref);
		ret = scoutfs_btree_next(sb, root, key, key_len, iref);
	}

	return ret;
}

/*
 * starting with the caller's key.  The entries will be ordered by the
 * order that they should be read: level 0 from newest to oldest then
 * increasing higher order levels.
 *
 * We have to get all the level 0 segments that intersect with the range
 * of items that we want to search because the level 0 segments can
 * arbitrarily overlap with each other.
 *
 * We only need to search for the starting key in all the higher levels.
 * They do not overlap so we can iterate through the key space in each
 * segment starting with the key.  In each level we need the first
 * existing segment that intersects with the range, even if it doesn't
 * contain the key.  The key might fall between segments at that level.
 *
 * This is walking stable btree roots.  The blocks won't be changed as
 * long as we read valid blocks.  They can be overwritten in which case
 * we'll return -ESTALE and the caller can retry with a newer root or
 * return hard errors.
 */
static int get_manifest_refs(struct super_block *sb,
			     struct scoutfs_btree_root *root,
			     struct scoutfs_key_buf *key,
			     struct scoutfs_key_buf *end,
			     struct list_head *ref_list)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_manifest_btree_key *mkey;
	struct scoutfs_manifest_entry ment;
	SCOUTFS_BTREE_ITEM_REF(iref);
	SCOUTFS_BTREE_ITEM_REF(prev);
	unsigned mkey_len;
	int ret;
	int i;

	scoutfs_manifest_init_entry(&ment, 0, 0, 0, key, NULL);
	mkey = alloc_btree_key_val(&ment, &mkey_len, NULL, NULL);
	if (!mkey)
		return -ENOMEM;

	/* get level 0 segments that overlap with the missing range */
	mkey_len = init_btree_key(mkey, 0, ~0ULL, NULL);
	ret = scoutfs_btree_prev(sb, &super->manifest.root,
				 mkey, mkey_len, &iref);
	while (ret == 0) {
		init_ment_iref(&ment, &iref);

		if (scoutfs_key_compare_ranges(key, end, &ment.first,
					       &ment.last) == 0) {
			ret = alloc_manifest_ref(sb, ref_list, &ment);
			if (ret)
				goto out;
		}

		swap(prev, iref);
		ret = scoutfs_btree_before(sb, &super->manifest.root,
					   prev.key, prev.key_len, &iref);
		scoutfs_btree_put_iref(&prev);
	}
	if (ret != -ENOENT)
		goto out;

	/*
	 * XXX Today we need to read the next segment if our starting key
	 * falls between segments.  That won't be the case once we tie
	 * cached items to their locks.
	 */
	mkey_len = init_btree_key(mkey, 1, 0, key);
	for (i = 1; i < mani->nr_levels; i++) {
		mkey->level = i;

		/* XXX should use level counts to skip searches */

		scoutfs_btree_put_iref(&iref);
		ret = btree_prev_overlap_or_next(sb, &super->manifest.root,
						 mkey, mkey_len, key, i,
						 &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			goto out;
		}

		init_ment_iref(&ment, &iref);

		if (ment.level != i)
			continue;

		ret = alloc_manifest_ref(sb, ref_list, &ment);
		if (ret)
			goto out;
	}
	ret = 0;

out:
	scoutfs_btree_put_iref(&iref);
	scoutfs_btree_put_iref(&prev);
	kfree(mkey);
	BUG_ON(ret == -ESTALE); /* XXX caller needs to retry or return error */
	return ret;
}

/*
 * The caller found a hole in the item cache that they'd like populated.
 *
 * We search the manifest for all the segments we'll need to iterate
 * from the key to the end key.  If the end key is null then we'll read
 * as many items as the intersecting segments contain.
 *
 * If next_key is provided then the segments are only walked to find the
 * next key after the search key.  If none is found -ENOENT is returned.
 *
 * As we insert the batch of items we give the item cache the range of
 * keys that contain these items.  This lets the cache return negative
 * cache lookups for missing items within the range.
 *
 * Returns 0 if we inserted items with a range covering the starting
 * key.  The caller should be able to make progress.
 *
 * Returns -errno if we failed to make any change in the cache.
 *
 * This is asking the seg code to read each entire segment.  The seg
 * code could give it it helpers to submit and wait on blocks within the
 * segment so that we don't have wild bandwidth amplification for cold
 * random reads.
 *
 * The segments are immutable at this point so we can use their contents
 * as long as we hold refs.
 */
static int read_items(struct super_block *sb, struct scoutfs_key_buf *key,
		      struct scoutfs_key_buf *end,
		      struct scoutfs_key_buf *next_key)
{
	struct scoutfs_key_buf item_key;
	struct scoutfs_key_buf found_key;
	struct scoutfs_key_buf batch_end;
	struct scoutfs_key_buf seg_end;
	struct scoutfs_btree_root root;
	struct scoutfs_inode_key junk;
	SCOUTFS_DECLARE_KVEC(item_val);
	SCOUTFS_DECLARE_KVEC(found_val);
	struct scoutfs_segment *seg;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	LIST_HEAD(ref_list);
	LIST_HEAD(batch);
	u8 found_flags = 0;
	u8 item_flags;
	int found_ctr;
	bool found;
	bool added;
	int ret = 0;
	int err;
	int cmp;

	if (end) {
		scoutfs_key_clone(&seg_end, end);
	} else {
		scoutfs_key_init(&seg_end, &junk, sizeof(junk));
		scoutfs_key_set_max(&seg_end);
	}

	trace_scoutfs_read_items(sb, key, &seg_end);


	/*
	 * Ask the manifest server which manifest root to read from.  Lock
	 * holding callers will be responsible for this in the future.  They'll
	 * either get a manifest ref in the lvb of their lock or they'll
	 * ask the server the first time the system sees the lock.
	 */
	ret = scoutfs_net_get_manifest_root(sb, &root);
	if (ret)
		goto out;

	/* get refs on all the segments */
	ret = get_manifest_refs(sb, &root, key, &seg_end, &ref_list);
	if (ret)
		goto out;

	/* submit reads for all the segments */
	list_for_each_entry(ref, &ref_list, entry) {

		trace_scoutfs_read_item_segment(sb, ref->level,  ref->segno,
						ref->seq, ref->first, ref->last);

		seg = scoutfs_seg_submit_read(sb, ref->segno);
		if (IS_ERR(seg)) {
			ret = PTR_ERR(seg);
			break;
		}

		ref->seg = seg;
	}

	/* always wait for submitted segments */
	list_for_each_entry(ref, &ref_list, entry) {
		if (!ref->seg)
			break;

		err = scoutfs_seg_wait(sb, ref->seg);
		if (err && !ret)
			ret = err;
	}
	if (ret)
		goto out;

	/* start from the next item from the key in each segment */
	list_for_each_entry(ref, &ref_list, entry)
		ref->off = scoutfs_seg_find_off(ref->seg, key);

	/*
	 * Find the limit of the range we can safely walk.  We have all
	 * the level 0 segments that intersect with the caller's range.
	 * But we only have the level > 0 segments that intersected with
	 * the starting key.  We have to stop at the nearest end of
	 * those segments because other segments might overlap after
	 * that.
	 */
	list_for_each_entry(ref, &ref_list, entry) {
		if (ref->level > 0 &&
		    scoutfs_key_compare(ref->last, &seg_end) < 0) {
			scoutfs_key_clone(&seg_end, ref->last);
		}
	}

	found_ctr = 0;

	added = false;
	for (;;) {
		found = false;
		found_ctr++;

		/* find the next least key from the off in each segment */
		list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
			if (ref->off < 0)
				continue;

			/*
			 * Check the next item in the segment.  We're
			 * done with the segment if there are no more
			 * items or if the next item is past the keys
			 * that our segments can see.
			 */
			ret = scoutfs_seg_item_ptrs(ref->seg, ref->off,
						    &item_key, item_val,
						    &item_flags);
			if (ret < 0 ||
			    scoutfs_key_compare(&item_key, &seg_end) > 0) {
				ref->off = -1;
				continue;
			}

			/* see if it's the new least item */
			if (found) {
				cmp = scoutfs_key_compare(&item_key,
							  &found_key);
				if (cmp >= 0) {
					if (cmp == 0)
						ref->found_ctr = found_ctr;
					continue;
				}
			}

			/* remember new least key */
			scoutfs_key_clone(&found_key, &item_key);
			scoutfs_kvec_clone(found_val, item_val);
			found_flags = item_flags;
			ref->found_ctr = ++found_ctr;
			found = true;
		}

		if (next_key) {
			if (found) {
				scoutfs_key_copy(next_key, &found_key);
				ret = 0;
			} else {
				ret = -ENOENT;
			}
			break;
		}

		/* ran out of keys in segs, range extends to seg end */
		if (!found) {
			scoutfs_key_clone(&batch_end, &seg_end);
			ret = 0;
			break;
		}

		/*
		 * Add the next found item to the batch if it's not a
		 * deletion item.  We still need to use their key to
		 * remember the end of the batch for negative caching.
		 *
		 * If we fail to add an item we're done.  If we already
		 * have items it's not a failure and the end of the
		 * cached range is the last successfully added item.
		 */
		if (!(found_flags & SCOUTFS_ITEM_FLAG_DELETION)) {
			ret = scoutfs_item_add_batch(sb, &batch, &found_key,
						     found_val);
			if (ret) {
				if (added)
					ret = 0;
				break;
			}
			added = true;
		}

		/* the last successful key determines range end until run out */
		scoutfs_key_clone(&batch_end, &found_key);

		/* if we just saw the end key then we're done */
		if (scoutfs_key_compare(&found_key, &seg_end) == 0) {
			ret = 0;
			break;
		}

		/* advance all the positions that had the found key */
		list_for_each_entry(ref, &ref_list, entry) {
			if (ref->found_ctr == found_ctr)
				ref->off = scoutfs_seg_next_off(ref->seg,
								ref->off);
		}

		ret = 0;
	}

	if (next_key || ret)
		scoutfs_item_free_batch(sb, &batch);
	else
		ret = scoutfs_item_insert_batch(sb, &batch, key, &batch_end);
out:
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		list_del_init(&ref->entry);
		free_ref(sb, ref);
	}

	return ret;
}

int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key_buf *key,
				struct scoutfs_key_buf *end)
{
	return read_items(sb, key, end, NULL);
}

int scoutfs_manifest_next_key(struct super_block *sb,
			      struct scoutfs_key_buf *key,
			      struct scoutfs_key_buf *next_key)
{
	return read_items(sb, key, NULL, next_key);
}

/*
 * Give the caller the segments that will be involved in the next
 * compaction.
 *
 * For now we have a simple candidate search.  We only initiate
 * compaction when a level has exceeded its exponentially increasing
 * limit on the number of segments.  Once we have a level we use keys at
 * each level to chose the next segment.  This results in a pattern
 * where clock hands sweep through each level.  The hands wrap much
 * faster on the higher levels.
 *
 * We add all the segments to the compaction caller's data and let it do
 * its thing.  It'll allocate and free segments and update the manifest.
 *
 * Returns the number of input segments or -errno.
 *
 * XXX this will get a lot more clever:
 *  - ensuring concurrent compactions don't overlap
 *  - prioritize segments with deletion or incremental records
 *  - prioritize partial segments
 *  - maybe compact segments by age in a given level
 */
int scoutfs_manifest_next_compact(struct super_block *sb, void *data)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_manifest_entry ment;
	struct scoutfs_manifest_entry over;
	struct scoutfs_manifest_btree_key *mkey = NULL;
	SCOUTFS_BTREE_ITEM_REF(iref);
	SCOUTFS_BTREE_ITEM_REF(over_iref);
	SCOUTFS_BTREE_ITEM_REF(prev);
	unsigned mkey_len;
	bool sticky;
	int level;
	int ret;
	int nr = 0;
	int i;

	down_write(&mani->rwsem);

	for (level = mani->nr_levels - 1; level >= 0; level--) {
		if (le64_to_cpu(super->manifest.level_counts[level]) >
	            mani->level_limits[level])
			break;
	}

	trace_printk("level %d\n", level);

	if (level < 0) {
		ret = 0;
		goto out;
	}

	/* alloc a full size mkey, fill it with whatever search key */

	mkey = alloc_btree_key_val_lens(SCOUTFS_MAX_KEY_SIZE, 0);
	if (!mkey) {
		ret = -ENOMEM;
		goto out;
	}

	/* find the oldest level 0 or the next higher order level by key */
	if (level == 0) {
		/* find the oldest level 0 */
		mkey_len = init_btree_key(mkey, 0, 0, NULL);
		ret = scoutfs_btree_next(sb, &super->manifest.root,
					 mkey, mkey_len, &iref);
	} else {
		/* find the next segment after the compaction at this level */
		mkey_len = init_btree_key(mkey, level, 0,
					  mani->compact_keys[level]);

		ret = scoutfs_btree_next(sb, &super->manifest.root,
					 mkey, mkey_len, &iref);
		if (ret == 0) {
			init_ment_iref(&ment, &iref);
			if (ment.level != level)
				ret = -ENOENT;
		}
		if (ret == -ENOENT) {
			/* .. possibly wrapping to the first key in level */
			mkey_len = init_btree_key(mkey, level, 0, NULL);
			scoutfs_btree_put_iref(&iref);
			ret = scoutfs_btree_next(sb, &super->manifest.root,
						 mkey, mkey_len, &iref);
		}
	}
	if (ret == 0) {
		init_ment_iref(&ment, &iref);
		if (ment.level != level)
			goto out;
	}
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	/* add the upper input segment */
	ret = scoutfs_compact_add(sb, data, &ment);
	if (ret)
		goto out;
	nr++;

	/* and add a fanout's worth of lower overlapping segments */
	mkey_len = init_btree_key(mkey, level + 1, 0, &ment.first);
	ret = btree_prev_overlap_or_next(sb, &super->manifest.root,
					 mkey, mkey_len,
					 &ment.first, level + 1, &over_iref);
	sticky = false;
	for (i = 0; ret == 0 && i < SCOUTFS_MANIFEST_FANOUT + 1; i++) {
		init_ment_iref(&over, &over_iref);
		if (over.level != level + 1)
			break;

		if (scoutfs_key_compare_ranges(&ment.first, &ment.last,
					       &over.first, &over.last) != 0)
			break;

		/* upper level has to stay around when more than fanout */
		if (i == SCOUTFS_MANIFEST_FANOUT) {
			sticky = true;
			break;
		}

		ret = scoutfs_compact_add(sb, data, &over);
		if (ret)
			goto out;
		nr++;

		swap(prev, over_iref);
		ret = scoutfs_btree_after(sb, &super->manifest.root,
					  prev.key, prev.key_len, &over_iref);
		scoutfs_btree_put_iref(&prev);
	}
	if (ret < 0 && ret != -ENOENT)
		goto out;

	scoutfs_compact_describe(sb, data, level, mani->nr_levels - 1, sticky);

	/* record the next key to start from */
	scoutfs_key_copy(mani->compact_keys[level], &ment.last);
	scoutfs_key_inc(mani->compact_keys[level]);

	ret = 0;
out:
	up_write(&mani->rwsem);

	kfree(mkey);
	scoutfs_btree_put_iref(&iref);
	scoutfs_btree_put_iref(&over_iref);
	scoutfs_btree_put_iref(&prev);

	return ret ?: nr;
}

int scoutfs_manifest_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct manifest *mani;
	int i;

	mani = kzalloc(sizeof(struct manifest), GFP_KERNEL);
	if (!mani)
		return -ENOMEM;

	init_rwsem(&mani->rwsem);

	for (i = 0; i < ARRAY_SIZE(mani->compact_keys); i++) {
		mani->compact_keys[i] = scoutfs_key_alloc(sb,
							  SCOUTFS_MAX_KEY_SIZE);
		if (!mani->compact_keys[i]) {
			while (--i >= 0)
				scoutfs_key_free(sb, mani->compact_keys[i]);
			kfree(mani);
			return -ENOMEM;
		}

		scoutfs_key_set_min(mani->compact_keys[i]);
	}

	for (i = ARRAY_SIZE(super->manifest.level_counts) - 1; i >= 0; i--) {
		if (super->manifest.level_counts[i]) {
			mani->nr_levels = i + 1;
			break;
		}
	}

	/* always trigger a compaction if there's a single l0 segment? */
	mani->level_limits[0] = 0;
	mani->level_limits[1] = SCOUTFS_MANIFEST_FANOUT;
	for (i = 2; i < ARRAY_SIZE(mani->level_limits); i++) {
		mani->level_limits[i] = mani->level_limits[i - 1] *
					SCOUTFS_MANIFEST_FANOUT;
	}

	sbi->manifest = mani;

	return 0;
}

void scoutfs_manifest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct manifest *mani = sbi->manifest;
	int i;

	if (mani) {
		for (i = 0; i < ARRAY_SIZE(mani->compact_keys); i++)
			scoutfs_key_free(sb, mani->compact_keys[i]);
		kfree(mani);
		sbi->manifest = NULL;
	}
}
