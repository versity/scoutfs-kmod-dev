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
#include <linux/list_sort.h>

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
#include "triggers.h"
#include "client.h"
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

	struct scoutfs_key compact_keys[SCOUTFS_MANIFEST_MAX_LEVEL + 1];
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
	bool retried;

	struct scoutfs_key first;
	struct scoutfs_key last;
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
				 struct scoutfs_key *first,
				 struct scoutfs_key *last)
{
	ment->level = level;
	ment->segno = segno;
	ment->seq = seq;
	scoutfs_key_copy_or_zeros(&ment->first, first);
	scoutfs_key_copy_or_zeros(&ment->last, last);
}

static void init_btree_key(struct scoutfs_manifest_btree_key *mkey,
			   u8 level, u64 seq, struct scoutfs_key *first)
{
	mkey->level = level;
	scoutfs_key_to_be(&mkey->first_key, first);
	mkey->seq = cpu_to_be64(seq);
}

static void init_btree_val(struct scoutfs_manifest_btree_val *mval,
			   u64 segno, struct scoutfs_key *last)
{
	mval->segno = cpu_to_le64(segno);
	mval->last_key = *last;
}

/* initialize a native manifest entry to point to the btree key and value */
static void init_ment_iref(struct scoutfs_manifest_entry *ment,
			   struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_manifest_btree_key *mkey = iref->key;
	struct scoutfs_manifest_btree_val *mval = iref->val;

	ment->level = mkey->level;
	scoutfs_key_from_be(&ment->first, &mkey->first_key);
	ment->seq = be64_to_cpu(mkey->seq);
	ment->segno = le64_to_cpu(mval->segno);
	ment->last = mval->last_key;
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
	struct scoutfs_manifest_btree_key mkey;
	struct scoutfs_manifest_btree_val mval;
	int ret;

	lockdep_assert_held(&mani->rwsem);

	init_btree_key(&mkey, ment->level, ment->seq, &ment->first);
	init_btree_val(&mval, ment->segno, &ment->last);

	trace_scoutfs_manifest_add(sb, ment->level, ment->segno, ment->seq,
				   &ment->first, &ment->last);

	ret = scoutfs_btree_insert(sb, &super->manifest.root,
				   &mkey, sizeof(mkey), &mval, sizeof(mval));
	if (ret == 0) {
		mani->nr_levels = max_t(u8, mani->nr_levels, ment->level + 1);
		add_level_count(sb, ment->level, 1);
	}

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
	struct scoutfs_manifest_btree_key mkey;
	int ret;

	trace_scoutfs_manifest_delete(sb, ment->level, ment->segno, ment->seq,
				      &ment->first, &ment->last);

	lockdep_assert_held(&mani->rwsem);

	init_btree_key(&mkey, ment->level, ment->seq, &ment->first);

	ret = scoutfs_btree_delete(sb, &super->manifest.root,
				   &mkey, sizeof(mkey));
	if (ret == 0)
		add_level_count(sb, ment->level, -1ULL);

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
	if (!ref)
		return -ENOMEM;

	ref->first = ment->first;
	ref->last = ment->last;
	ref->level = ment->level;
	ref->segno = ment->segno;
	ref->seq = ment->seq;

	list_add_tail(&ref->entry, ref_list);

	return 0;
}

/*
 * Give the caller the next entry that overlaps with the given key at th
 * egiven level.  We first check the previous entry before the key to
 * see if it overlaps.  If it does then we return it.  If it doesn't
 * then we return the raw next entry after the key.  The caller has to
 * test it.
 *
 * If a start key is provided then the caller is working with cache
 * ranges.  If we find a previous entry that doesn't contain the key
 * then we see if we should shrink the range to make sure that it
 * doesn't include this segment whose items we're not using.
 *
 * Returns 0 with the iref pointing to the btree item with the entry,
 * callers has to put the iref when they're done.
 */
static int btree_prev_overlap_or_next(struct super_block *sb,
				      struct scoutfs_btree_root *root,
				      void *bkey, unsigned bkey_len,
				      struct scoutfs_key *key,
				      struct scoutfs_key *start, u8 level,
				      struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_manifest_entry ment;
	int ret;

	ret = scoutfs_btree_prev(sb, root, bkey, bkey_len, iref);
	if (ret < 0 && ret != -ENOENT)
		return ret;

	if (ret == 0) {
		init_ment_iref(&ment, iref);

		/* shrink range so it doesn't cover skipped prev */
		if (start && ment.level == level &&
		    scoutfs_key_compare(&ment.last, key) < 0 &&
		    scoutfs_key_compare(&ment.last, start) >= 0) {
			*start = ment.last;
			scoutfs_key_inc(start);
		}

		/* skip prev that doesn't contain the key */
		if (ment.level != level ||
		    scoutfs_key_compare(&ment.last, key) < 0)
			ret = -ENOENT;
	}
	if (ret == -ENOENT) {
		scoutfs_btree_put_iref(iref);
		ret = scoutfs_btree_next(sb, root, bkey, bkey_len, iref);
	}

	return ret;
}

/*
 * Get references to all the level 0 segments whose item ranges
 * intersect with the callers range.  The entries are sorted by their
 * first key so we can stop searching once our end key can only keep
 * being less than the increasing start key.
 *
 * This can return -ESTALE if it reads through stale btree blocks.
 */
static int get_zero_refs(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *start,
			 struct scoutfs_key *end,
			 struct list_head *ref_list)
{
	struct scoutfs_manifest_btree_key mkey;
	struct scoutfs_manifest_entry ment;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key zeros;
	int cmp;
	int ret;

	scoutfs_key_set_zeros(&zeros);
	init_btree_key(&mkey, 0, 0, &zeros);

	for (;;) {
		ret = scoutfs_btree_next(sb, root, &mkey, sizeof(mkey), &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		init_ment_iref(&ment, &iref);
		scoutfs_btree_put_iref(&iref);

		/* done if we went past level 0 */
		if (ment.level > 0) {
			ret = 0;
			break;
		}

		cmp = scoutfs_key_compare_ranges(start, end, &ment.first,
					         &ment.last);
		/* done if all the ments will be greater */
		if (cmp < 0) {
			ret = 0;
			break;
		}

		if (cmp == 0) {
			ret = alloc_manifest_ref(sb, ref_list, &ment);
			if (ret)
				break;
		}

		scoutfs_key_inc(&ment.first);
		init_btree_key(&mkey, ment.level, ment.seq, &ment.first);
	}

	return ret;
}

/*
 * Get references to all segments in non-zero levels that contain the
 * caller's key.   The item ranges of segments at each non-zero level
 * don't overlap so we can iterate through the key space in each segment
 * starting with the search key.  In each level we need the first
 * existing segment that intersects with the range, even if it doesn't
 * contain the key.  The key might fall between segments at that level.
 *
 * The caller can provide the range of items that they're going to
 * consider authoritative for the range of segments that we give them.
 * We have to shrink this range if we give them segments that don't
 * cover the range.  This includes implicitly negative cached space
 * that's created by using the segment after the hole between segments.
 * If a segment is entirely outside of the caller's range then we can't
 * trust its contents.
 *
 * This can return -ESTALE if it reads through stale btree blocks.
 */
static int get_nonzero_refs(struct super_block *sb,
			    struct scoutfs_btree_root *root,
			    struct scoutfs_key *key,
			    struct scoutfs_key *start,
			    struct scoutfs_key *end,
			    struct list_head *ref_list)
{
	struct scoutfs_manifest_btree_key mkey;
	struct scoutfs_manifest_entry ment;
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret;
	int i;

	if (WARN_ON_ONCE(!!start != !!end) ||
	    WARN_ON_ONCE(start && scoutfs_key_compare(start, end) > 0))
		return -EINVAL;

	for (i = 1; ; i++) {
		init_btree_key(&mkey, i, 0, key);

		ret = btree_prev_overlap_or_next(sb, root, &mkey, sizeof(mkey),
						 key, start, i, &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		init_ment_iref(&ment, &iref);
		scoutfs_btree_put_iref(&iref);

		if (ment.level != i ||
		    (end && scoutfs_key_compare(&ment.first, end) > 0))
			continue;

		ret = alloc_manifest_ref(sb, ref_list, &ment);
		if (ret)
			break;

		if (start && scoutfs_key_compare(&ment.first, start) > 0 &&
		    scoutfs_key_compare(&ment.first, key) <= 0)
			*start = ment.first;

		if (end && scoutfs_key_compare(&ment.last, end) < 0 &&
		    scoutfs_key_compare(&ment.last, key) >= 0)
			*end = ment.last;
	}

	return ret;
}

/*
 * If we saw persistent stale blocks or segment reads while walking the
 * manifest then we might be trying to read through an old stale root
 * that has been overwritten.  We can ask for a new root and try again.
 * If we don't get a new root and the errors persist then the we've hit
 * corruption.
 */
static int handle_stale_btree(struct super_block *sb,
			      struct scoutfs_btree_root *root,
			      __le64 last_root_seq, int ret)
{
	bool force_hard = scoutfs_trigger(sb, HARD_STALE_ERROR);

	if (ret == -ESTALE || force_hard) {
		if ((last_root_seq != root->ref.seq) && !force_hard)
			return -EAGAIN;

		scoutfs_inc_counter(sb, manifest_hard_stale_error);
		return -EIO;
	}

	return ret;
}

static int cmp_ment_ref_segno(void *priv, struct list_head *A,
			      struct list_head *B)
{
	struct manifest_ref *a = list_entry(A, struct manifest_ref, entry);
	struct manifest_ref *b = list_entry(B, struct manifest_ref, entry);

	return scoutfs_cmp_u64s(a->segno, b->segno);
}

/*
 * Sort by from most to least recent item contents.. from lowest to higest
 * level and from highest to loweset seq in level 0.
 */
static int cmp_ment_ref_level_seq(void *priv, struct list_head *A,
				  struct list_head *B)
{
	struct manifest_ref *a = list_entry(A, struct manifest_ref, entry);
	struct manifest_ref *b = list_entry(B, struct manifest_ref, entry);

	if (a->level == 0 && b->level == 0)
		return -scoutfs_cmp_u64s(a->seq, b->seq);

	return a->level < b->level ? -1 : a->level > b->level ? 1 : 0;
}

/*
 * The caller found a hole in the item cache that they'd like populated.
 * We can only trust items in the segments within their range (they hold
 * a lock) and they're going to keep calling ("He'll keep calling me,
 * he'll keep calling me") until we insert a range into the cache that
 * contains the search key.
 *
 * We search the manifest for all the non-zero segments that contain the
 * key.  We adjust the search range if the segments don't cover the
 * whole locked range.  We have to be careful not to shrink the range
 * past the key, it could be outside the segments and we still want to
 * negatively cache it.  Once we have the search range we get the level
 * zero segments that overlap.
 *
 * Once we have the segments we iterate over them and allocate the items
 * to insert into the cache.  We find the next item in each segment,
 * ignore deletion items, prefer more recent segments, and advance past
 * the items that we used.
 *
 * Returns 0 if we successfully inserted items.
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
int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key *key,
				struct scoutfs_key *start,
				struct scoutfs_key *end)
{
	struct scoutfs_key item_key;
	struct scoutfs_key found_key;
	struct scoutfs_key batch_end;
	struct scoutfs_key seg_start;
	struct scoutfs_key seg_end;
	struct scoutfs_btree_root root;
	struct scoutfs_segment *seg;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	__le64 last_root_seq;
	struct kvec found_val;
	struct kvec item_val;
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

	/*
	 * Ask the manifest server which manifest root to read from.  Lock
	 * holding callers will be responsible for this in the future.  They'll
	 * either get a manifest ref in the lvb of their lock or they'll
	 * ask the server the first time the system sees the lock.
	 */
	last_root_seq = 0;
retry_stale:

	seg_start = *start;
	seg_end = *end;

	ret = scoutfs_client_get_manifest_root(sb, &root);
	if (ret)
		goto out;

	/* get non-zero segments that intersect with the key, shrinks range */
	ret = get_nonzero_refs(sb, &root, key, &seg_start, &seg_end, &ref_list);
	if (ret)
		goto out;

	trace_scoutfs_read_item_keys(sb, key, start, end, &seg_start, &seg_end);

	/* then get level 0s that intersect with our search range */
	ret = get_zero_refs(sb, &root, &seg_start, &seg_end, &ref_list);
	if (ret)
		goto out;

	/* sort by segment to issue advancing reads */
	list_sort(NULL, &ref_list, cmp_ment_ref_segno);

resubmit:
	/* submit reads for all the segments */
	list_for_each_entry(ref, &ref_list, entry) {
		/* don't resubmit if we've read */
		if (ref->seg)
			continue;

		trace_scoutfs_read_item_segment(sb, ref->level, ref->segno,
						ref->seq, &ref->first,
						&ref->last);

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
			continue;

		err = scoutfs_seg_wait(sb, ref->seg, ref->segno, ref->seq);
		if (err == -ESTALE && !ref->retried) {
			ref->retried = true;
			err = 0;
			scoutfs_seg_put(ref->seg);
			ref->seg = NULL;
			goto resubmit;
		}
		if (err && !ret)
			ret = err;
	}
	if (ret)
		goto out;

	/* now sort refs by item age */
	list_sort(NULL, &ref_list, cmp_ment_ref_level_seq);

	/* walk items from the start of our range */
	list_for_each_entry(ref, &ref_list, entry)
		ref->off = scoutfs_seg_find_off(ref->seg, &seg_start);

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
			ret = scoutfs_seg_get_item(ref->seg, ref->off,
						   &item_key, &item_val,
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
			found_key = item_key;
			found_val = item_val;
			found_flags = item_flags;
			ref->found_ctr = ++found_ctr;
			found = true;
		}

		/* ran out of keys in segs, range extends to seg end */
		if (!found) {
			batch_end = seg_end;
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
						     &found_val);
			if (ret) {
				if (added)
					ret = 0;
				break;
			}
			added = true;
		}

		/* the last successful key determines range end until run out */
		batch_end = found_key;

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

	if (ret < 0) {
		scoutfs_item_free_batch(sb, &batch);
	} else {
		if (scoutfs_key_compare(key, &batch_end) > 0)
			scoutfs_inc_counter(sb, manifest_read_excluded_key);
		ret = scoutfs_item_insert_batch(sb, &batch, &seg_start,
						&batch_end);
	}
out:
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		list_del_init(&ref->entry);
		free_ref(sb, ref);
	}

	ret = handle_stale_btree(sb, &root, last_root_seq, ret);
	if (ret == -EAGAIN) {
		last_root_seq = root.ref.seq;
		goto retry_stale;
	}

	return ret;
}

/*
 * Give the caller a hint to the next key that they'll find after their
 * search key.
 *
 * We read the segments that intersect the key and return either the
 * next item we see or the nearest segment limit.
 *
 * This is a hint because we can return deleted items or the next
 * nearest segment limit can be well before the next items in the next
 * segments.  The caller needs to very carefully iterate using the next
 * key we return.
 *
 * Returns 0 if it set next_key and -ENOENT if the key was after all the
 * segments in the manifest.
 */
int scoutfs_manifest_next_key(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_key *next_key)
{
	struct scoutfs_key item_key;
	struct scoutfs_btree_root root;
	struct scoutfs_segment *seg;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	__le64 last_root_seq;
	LIST_HEAD(ref_list);
	bool found;
	int ret;
	int err;

	last_root_seq = 0;
retry_stale:
	ret = scoutfs_client_get_manifest_root(sb, &root);
	if (ret)
		goto out;

	ret = get_zero_refs(sb, &root, key, key, &ref_list) ?:
	      get_nonzero_refs(sb, &root, key, NULL, NULL, &ref_list);
	if (ret)
		goto out;

	if (list_empty(&ref_list)) {
		ret = -ENOENT;
		goto out;
	}

	list_sort(NULL, &ref_list, cmp_ment_ref_segno);

	list_for_each_entry(ref, &ref_list, entry) {
		seg = scoutfs_seg_submit_read(sb, ref->segno);
		if (IS_ERR(seg)) {
			ret = PTR_ERR(seg);
			break;
		}

		ref->seg = seg;
	}

	list_for_each_entry(ref, &ref_list, entry) {
		if (!ref->seg)
			break;

		err = scoutfs_seg_wait(sb, ref->seg, ref->segno, ref->seq);
		if (err && !ret)
			ret = err;
	}
	if (ret)
		goto out;

	list_sort(NULL, &ref_list, cmp_ment_ref_level_seq);

	/* default to returning the nearest segment limit and find offsets */
	found = false;
	list_for_each_entry(ref, &ref_list, entry) {
		if (ref->level > 0 &&
		    (!found ||
		     scoutfs_key_compare(&ref->last, next_key) < 0)) {
			*next_key = ref->last;
			found = true;
		}

		ref->off = scoutfs_seg_find_off(ref->seg, key);
	}

	/* return the nearest item in the segments */
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		if (ref->off < 0)
			continue;

		ret = scoutfs_seg_get_item(ref->seg, ref->off, &item_key,
					   NULL, NULL);
		if (ret < 0)
			continue;

		if (!found || scoutfs_key_compare(&item_key, next_key) < 0) {
			*next_key = item_key;
			found = true;
		}
	}

	ret = 0;
out:
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		list_del_init(&ref->entry);
		free_ref(sb, ref);
	}

	ret = handle_stale_btree(sb, &root, last_root_seq, ret);
	if (ret == -EAGAIN) {
		last_root_seq = root.ref.seq;
		goto retry_stale;
	}

	return ret;
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
	struct scoutfs_manifest_btree_key mkey;
	struct scoutfs_manifest_entry next;
	struct scoutfs_manifest_entry ment;
	struct scoutfs_manifest_entry over;
	SCOUTFS_BTREE_ITEM_REF(iref);
	SCOUTFS_BTREE_ITEM_REF(over_iref);
	SCOUTFS_BTREE_ITEM_REF(prev);
	struct scoutfs_key zeros;
	bool wrapped;
	bool sticky;
	int level;
	int ret;
	int nr = 0;
	int i;

	scoutfs_key_set_zeros(&zeros);

	down_write(&mani->rwsem);

	for (level = mani->nr_levels - 1; level >= 0; level--) {
		if (le64_to_cpu(super->manifest.level_counts[level]) >
	            mani->level_limits[level])
			break;
	}

	trace_scoutfs_manifest_next_compact(sb, level);

	if (level < 0) {
		ret = 0;
		goto out;
	}

	/* fill ment and ret == 0 if we find an entry at the level */
	if (level == 0) {

		/* find the oldest level 0 */
		init_btree_key(&mkey, 0, 0, &zeros);
		ment.seq = U64_MAX;

		for (;;) {
			ret = scoutfs_btree_next(sb, &super->manifest.root,
						 &mkey, sizeof(mkey), &iref);
			if (ret < 0) {
				if (ret == -ENOENT && ment.seq != U64_MAX)
					ret = 0;
				break;
			}

			init_ment_iref(&next, &iref);
			scoutfs_btree_put_iref(&iref);

			if (next.level > 0) {
				if (ment.seq == U64_MAX)
					ret = -ENOENT;
				break;
			}

			if (next.seq < ment.seq)
				ment = next;

			scoutfs_key_inc(&next.first);
			init_btree_key(&mkey, next.level, next.seq,
				       &next.first);
		}

	} else {
		/* find the next segment after the compaction at this level */
		init_btree_key(&mkey, level, 0, &mani->compact_keys[level]);
		wrapped = false;
again:
		ret = scoutfs_btree_next(sb, &super->manifest.root,
					 &mkey, sizeof(mkey), &iref);
		if (ret == 0) {
			init_ment_iref(&ment, &iref);
			scoutfs_btree_put_iref(&iref);
			if (ment.level != level)
				ret = -ENOENT;
		}
		/* try again if we wrapped */
		if (ret == -ENOENT && !wrapped) {
			init_btree_key(&mkey, level, 0, &zeros);
			wrapped = true;
			goto again;
		}
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
	init_btree_key(&mkey, level + 1, 0, &ment.first);
	ret = btree_prev_overlap_or_next(sb, &super->manifest.root,
					 &mkey, sizeof(mkey), &ment.first,
					 NULL, level + 1, &over_iref);
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
	mani->compact_keys[level] = ment.last;
	scoutfs_key_inc(&mani->compact_keys[level]);

	ret = 0;
out:
	up_write(&mani->rwsem);

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

	for (i = 0; i < ARRAY_SIZE(mani->compact_keys); i++)
		scoutfs_key_set_zeros(&mani->compact_keys[i]);

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

	if (mani) {
		kfree(mani);
		sbi->manifest = NULL;
	}
}
