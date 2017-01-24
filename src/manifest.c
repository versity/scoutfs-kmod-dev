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
#include "treap.h"
#include "cmp.h"
#include "compact.h"
#include "manifest.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * Manifest entries are stored as treap nodes in the ring.
 *
 * They're sorted first by level then by their first key.  This enables
 * the primary searches based on key value for looking up items in
 * segments via the manifest.
 *
 * The treap also supports augmented searches.  We get callbacks as the
 * tree structure which lets us maintain data in nodes that describe
 * subtrees to accelerate searches.  We will record the max sequence
 * numbers in subtrees for all the seq queries.  We'll probably also
 * have bits that direct us towards segments that contain deletion items
 * for prioritized compaction.
 */

struct manifest {
	struct rw_semaphore rwsem;
	seqcount_t seqcount;
	struct scoutfs_treap *treap;
	u8 nr_levels;

	/* calculated on mount, const thereafter */
	u64 level_limits[SCOUTFS_MANIFEST_MAX_LEVEL + 1];

	struct scoutfs_key_buf *compact_keys[SCOUTFS_MANIFEST_MAX_LEVEL + 1];
};

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
	int pos;
	u8 level;

	struct scoutfs_key_buf *first;
	struct scoutfs_key_buf *last;
};

struct manifest_fill_args {
	struct scoutfs_manifest_entry ment;
	struct scoutfs_key_buf *first;
	struct scoutfs_key_buf *last;
};

/*
 * Seq is only specified for operations that differentiate between
 * segments with identical items by their sequence number.
 */
struct manifest_search_key {
	u64 seq;
	struct scoutfs_key_buf *key;
	u8 level;
};

static void init_ment_keys(struct scoutfs_manifest_entry *ment,
			   struct scoutfs_key_buf *first,
			   struct scoutfs_key_buf *last)
{
	if (first)
		scoutfs_key_init(first, ment->keys,
				 le16_to_cpu(ment->first_key_len));
	if (last)
		scoutfs_key_init(last, ment->keys +
				 le16_to_cpu(ment->first_key_len),
				 le16_to_cpu(ment->last_key_len));
}

static bool cmp_range_ment(struct scoutfs_key_buf *key,
			   struct scoutfs_key_buf *end,
			   struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;

	init_ment_keys(ment, &first, &last);

	return scoutfs_key_compare_ranges(key, end, &first, &last);
}

static u64 get_level_count(struct manifest *mani,
			   struct scoutfs_super_block *super, u8 level)
{
	unsigned int sc;
	u64 count;

	do {
		sc = read_seqcount_begin(&mani->seqcount);
		count = le64_to_cpu(super->manifest.level_counts[level]);
	} while (read_seqcount_retry(&mani->seqcount, sc));

	return count;
}

static bool past_limit(struct manifest *mani, u8 level, u64 count)
{
	return count > mani->level_limits[level];
}

static bool level_full(struct manifest *mani,
		       struct scoutfs_super_block *super, u8 level)
{
	return past_limit(mani, level, get_level_count(mani, super, level));
}

static void add_level_count(struct super_block *sb, struct manifest *mani,
			    struct scoutfs_super_block *super, u8 level,
			    s64 val)
{
	bool was_full;
	bool now_full;
	u64 count;

	write_seqcount_begin(&mani->seqcount);

	count = le64_to_cpu(super->manifest.level_counts[level]);
	was_full = past_limit(mani, level, count);

	count += val;
	now_full = past_limit(mani, level, count);
	super->manifest.level_counts[level] = cpu_to_le64(count);

	write_seqcount_end(&mani->seqcount);

	if (was_full && !now_full)
		scoutfs_trans_wake_holders(sb);

	if (now_full)
		scoutfs_compact_kick(sb);
}

/*
 * Insert a new manifest entry in the treap.  The treap allocates a new
 * node for us and we fill it.
 *
 * This must be called with the manifest lock held.
 */
int scoutfs_manifest_add(struct super_block *sb,
			 struct scoutfs_key_buf *first,
			 struct scoutfs_key_buf *last, u64 segno, u64 seq,
			 u8 level)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_manifest_entry *ment;
	struct manifest_fill_args args;
	struct manifest_search_key skey;
	unsigned key_bytes;
	unsigned bytes;
	int ret;

//	trace_scoutfs_manifest_add(sb, first, last, segno, seq, level);

	key_bytes = first->key_len + last->key_len;
	bytes = offsetof(struct scoutfs_manifest_entry, keys[key_bytes]);

	args.ment.segno = cpu_to_le64(segno);
	args.ment.seq = cpu_to_le64(seq);
	args.ment.first_key_len = cpu_to_le16(first->key_len);
	args.ment.last_key_len = cpu_to_le16(last->key_len);
	args.ment.level = level;

	args.first = first;
	args.last = last;

	skey.key = first;
	skey.level = level;
	skey.seq = seq;

	ment = scoutfs_treap_insert(mani->treap, &skey, bytes, &args);
	if (IS_ERR(ment)) {
		ret = PTR_ERR(ment);
	} else {
		mani->nr_levels = max_t(u8, mani->nr_levels, level + 1);
		add_level_count(sb, mani, super, level, 1);
		ret = 0;
	}

	return ret;
}

/*
 * This must be called with the manifest lock held.
 */
int scoutfs_manifest_dirty(struct super_block *sb,
			   struct scoutfs_key_buf *first, u64 seq, u8 level)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_manifest_entry *ment;
	struct manifest_search_key skey;

	skey.key = first;
	skey.level = level;
	skey.seq = seq;

	ment = scoutfs_treap_lookup_dirty(mani->treap, &skey);
	if (IS_ERR(ment))
		return PTR_ERR(ment);
	if (!ment)
		return -ENOENT;
	return 0;
}

/*
 * This must be called with the manifest lock held.
 */
int scoutfs_manifest_del(struct super_block *sb, struct scoutfs_key_buf *first,
			 u64 seq, u8 level)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct manifest_search_key skey;
	int ret;

	skey.key = first;
	skey.level = level;
	skey.seq = seq;

	ret = scoutfs_treap_delete(mani->treap, &skey);
	if (ret == 0)
		add_level_count(sb, mani, super, level, -1ULL);

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

static int alloc_add_ref(struct super_block *sb, struct list_head *list,
			 struct scoutfs_manifest_entry *ment)
{
	struct scoutfs_key_buf ment_first;
	struct scoutfs_key_buf ment_last;
	struct manifest_ref *ref;

	init_ment_keys(ment, &ment_first, &ment_last);

	ref = kzalloc(sizeof(struct manifest_ref), GFP_NOFS);
	if (ref) {
		ref->first = scoutfs_key_dup(sb, &ment_first);
		ref->last = scoutfs_key_dup(sb, &ment_last);
	}
	if (!ref || !ref->first || !ref->last) {
		free_ref(sb, ref);
		return -ENOMEM;
	}

	ref->segno = le64_to_cpu(ment->segno);
	ref->seq = le64_to_cpu(ment->seq);
	ref->level = ment->level;

	list_add_tail(&ref->entry, list);

	return 0;
}

/*
 * Get refs on all the segments in the manifest that we'll need to
 * search to populate the cache with the given range.
 *
 * We have to get all the level 0 segments that intersect with the range
 * of items that we want to search because the level 0 segments can
 * arbitrarily overlap with each other.
 *
 * We only need to search for the starting key in all the higher levels.
 * They do not overlap so we can iterate through the key space in each
 * segment starting with the key.
 */
static int get_range_refs(struct super_block *sb, struct manifest *mani,
			  struct scoutfs_key_buf *key,
			  struct scoutfs_key_buf *end,
			  struct list_head *ref_list)
{
	struct scoutfs_manifest_entry *ment;
	struct manifest_search_key skey;
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	int ret;
	int i;

	down_write(&mani->rwsem);

	/* get level 0 segments that overlap with the missing range */
	skey.level = 0;
	skey.seq = ~0ULL;
	ment = scoutfs_treap_lookup_prev(mani->treap, &skey);
	while (!IS_ERR_OR_NULL(ment)) {
		if (cmp_range_ment(key, end, ment) == 0) {
			ret = alloc_add_ref(sb, ref_list, ment);
			if (ret)
				goto out;
		}

		ment = scoutfs_treap_prev(mani->treap, ment);
	}
	if (IS_ERR(ment)) {
		ret = PTR_ERR(ment);
		goto out;
	}

	/* get higher level segments that overlap with the starting key */
	for (i = 1; i < mani->nr_levels; i++) {
		skey.key = key;
		skey.level = i;
		skey.seq = 0;

		/* XXX should use level counts to skip searches */

		ment = scoutfs_treap_lookup(mani->treap, &skey);
		if (IS_ERR(ment)) {
			ret = PTR_ERR(ment);
			goto out;
		}

		if (ment) {
			init_ment_keys(ment, &first, &last);
			ret = alloc_add_ref(sb, ref_list, ment);
			if (ret)
				goto out;
		}
	}

	ret = 0;

out:
	up_write(&mani->rwsem);

	if (ret) {
		list_for_each_entry_safe(ref, tmp, ref_list, entry) {
			list_del_init(&ref->entry);
			free_ref(sb, ref);
		}
	}

	trace_printk("ret %d\n", ret);
	return ret;
}

/*
 * The caller found a hole in the item cache that they'd like populated.
 *
 * We search the manifest for all the segments we'll need to iterate
 * from the key to the end key.  We walk the segments and insert as many
 * items as we can from the segments, trying to amortize the per-item
 * cost of segment searching.
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
#define MAX_ITEMS_READ 32

int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key_buf *key,
				struct scoutfs_key_buf *end)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_key_buf item_key;
	struct scoutfs_key_buf found_key;
	struct scoutfs_key_buf batch_end;
	struct scoutfs_key_buf seg_end;
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
	int ret = 0;
	int err;
	int cmp;
	int n;

	trace_printk("reading items\n");

	/* get refs on all the segments */
	ret = get_range_refs(sb, mani, key, end, &ref_list);
	if (ret)
		return ret;

	/* submit reads for all the segments */
	list_for_each_entry(ref, &ref_list, entry) {
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
		ref->pos = scoutfs_seg_find_pos(ref->seg, key);

	/*
	 * Find the greatest range we can cover if we walk all the
	 * segments.  We only have level 0 segments for the missing
	 * range so that's the greatest.  Then we shrink the range by
	 * the limit of each higher level segment that intersected with
	 * our starting key.
	 */
	scoutfs_key_clone(&seg_end, end);
	list_for_each_entry(ref, &ref_list, entry) {
		if (ref->level > 0 &&
		    scoutfs_key_compare(ref->last, &seg_end) < 0) {
			scoutfs_key_clone(&seg_end, ref->last);
		}
	}

	found_ctr = 0;

	for (n = 0; n < MAX_ITEMS_READ; n++) {

		found = false;
		found_ctr++;

		/* find the next least key from the pos in each segment */
		list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
			if (ref->pos == -1)
				continue;

			/*
			 * Check the next item in the segment.  We're
			 * done with the segment if there are no more
			 * items or if the next item is past the
			 * caller's end.
			 */
			ret = scoutfs_seg_item_ptrs(ref->seg, ref->pos,
						    &item_key, item_val,
						    &item_flags);
			if (ret < 0 || scoutfs_key_compare(&item_key, end) > 0){
				ref->pos = -1;
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
				if (n > 0)
					ret = 0;
				break;
			}
		}

		/* the last successful key determines range end until run out */
		scoutfs_key_clone(&batch_end, &found_key);

		/* if we just saw the end key then we're done */
		if (scoutfs_key_compare(&found_key, end) == 0) {
			ret = 0;
			break;
		}

		/* advance all the positions that had the found key */
		list_for_each_entry(ref, &ref_list, entry) {
			if (ref->found_ctr == found_ctr)
				ref->pos++;
		}

		ret = 0;
	}

	if (ret)
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

int scoutfs_manifest_has_dirty(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);
	int ret;

	down_write(&mani->rwsem);
	ret = scoutfs_treap_has_dirty(mani->treap);
	up_write(&mani->rwsem);

	return ret;
}

/*
 * Append the dirty manifest entries to the end of the ring.
 *
 * This returns 0 but can't fail.
 */
int scoutfs_manifest_dirty_ring(struct super_block *sb)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	down_write(&mani->rwsem);
	scoutfs_treap_dirty_ring(mani->treap, &super->manifest.root);
	up_write(&mani->rwsem);

	return 0;
}

u64 scoutfs_manifest_level_count(struct super_block *sb, u8 level)
{
	DECLARE_MANIFEST(sb, mani);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;

	return get_level_count(mani, super, level);
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
 * Returns 0 or -errno.  The caller will see if any segments were added.
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
	struct scoutfs_manifest_entry *ment;
	struct scoutfs_manifest_entry *over;
	struct manifest_search_key skey;
	struct scoutfs_key_buf ment_first;
	struct scoutfs_key_buf ment_last;
	struct scoutfs_key_buf over_first;
	struct scoutfs_key_buf over_last;
	int level;
	int ret;
	int i;

	down_write(&mani->rwsem);

	for (level = mani->nr_levels - 1; level >= 0; level--) {
		if (level_full(mani, super, level))
			break;
	}

	trace_printk("level %d\n", level);

	if (level < 0) {
		ret = 0;
		goto out;
	}

	scoutfs_compact_describe(sb, data, level, mani->nr_levels - 1);

	/* find the oldest level 0 or the next higher order level by key */
	if (level == 0) {
		ment = scoutfs_treap_first(mani->treap);
		if (!IS_ERR_OR_NULL(ment) && ment->level)
			ment = NULL;
	} else {
		skey.key = mani->compact_keys[level];
		skey.level = level;
		skey.seq = 0;
		ment = scoutfs_treap_lookup_next(mani->treap, &skey);
		if (ment == NULL || ment->level != level) {
			scoutfs_key_set_min(skey.key);
			ment = scoutfs_treap_lookup_next(mani->treap, &skey);
		}
	}
	if (IS_ERR(ment)) {
		ret = PTR_ERR(ment);
		goto out;
	}
	if (ment == NULL || ment->level != level) {
		/* XXX shouldn't be possible */
		ret = 0;
		goto out;
	}

	init_ment_keys(ment, &ment_first, &ment_last);

	/* add the upper input segment */
	ret = scoutfs_compact_add(sb, data, &ment_first, &ment_last,
				  le64_to_cpu(ment->segno),
				  le64_to_cpu(ment->seq), level);
	if (ret)
		goto out;

	/* start with the first overlapping at the next level */
	skey.key = &ment_first;
	skey.level = level + 1;
	skey.seq = 0;
	over = scoutfs_treap_lookup_next(mani->treap, &skey);

	/* and add a fanout's worth of lower overlapping segments */
	for (i = 0; i < SCOUTFS_MANIFEST_FANOUT; i++) {
		if (IS_ERR(over)) {
			ret = PTR_ERR(over);
			goto out;
		}
		if (!over || over->level != (ment->level + 1))
			break;

		init_ment_keys(over, &over_first, &over_last);

		if (scoutfs_key_compare_ranges(&ment_first, &ment_last,
					       &over_first, &over_last) != 0)
			break;

		ret = scoutfs_compact_add(sb, data, &over_first, &over_last,
					  le64_to_cpu(over->segno),
					  le64_to_cpu(over->seq), level + 1);
		if (ret)
			goto out;

		over = scoutfs_treap_next(mani->treap, over);
	}

	/* record the next key to start from */
	scoutfs_key_copy(mani->compact_keys[level], &ment_last);
	scoutfs_key_inc(mani->compact_keys[level]);

	ret = 0;
out:
	up_write(&mani->rwsem);
	return ret;
}

/*
 * Manifest entries for all levels are stored in a single treap.
 *
 * First they're sorted by their level.
 *
 * Level 0 segments can contain any items which overlap so they are
 * sorted by their sequence number.  Compaction can find the first node
 * and reading walks backwards through level 0 to get them from newest
 * to oldest to resolve matching items.
 *
 * Higher level segments don't overlap.  They are sorted by their first
 * key.
 *
 * Searching comparisons are different than insertion and deletion
 * comparisons for higher level segments.  Searches want to find the
 * segment that intersects with a given key.  Insertions and deletions
 * want to operate on the segment with a specific first key and sequence
 * number.  We tell the difference by the presence of a sequence number.
 * A segment will never have a seq of 0.
 */
static int manifest_treap_compare(void *key, void *data)
{
	struct manifest_search_key *skey = key;
	struct scoutfs_manifest_entry *ment = data;
	struct scoutfs_key_buf first;
	struct scoutfs_key_buf last;
	int cmp;

	if (skey->level < ment->level) {
		cmp = -1;
		goto out;
	}
	if (skey->level > ment->level) {
		cmp = 1;
		goto out;
	}

	if (skey->level == 0) {
		cmp = scoutfs_cmp_u64s(skey->seq, le64_to_cpu(ment->seq));
		goto out;
	}

	init_ment_keys(ment, &first, &last);

	if (skey->seq == 0) {
		cmp = scoutfs_key_compare_ranges(skey->key, skey->key,
					         &first, &last);
	} else {
		cmp = scoutfs_key_compare(skey->key, &first) ?:
		      scoutfs_cmp_u64s(skey->seq, le64_to_cpu(ment->seq));
	}

out:
	return cmp;
}

static void manifest_treap_fill(void *data, void *arg)
{
	struct scoutfs_manifest_entry *ment = data;
	struct manifest_fill_args *args = arg;
	struct scoutfs_key_buf ment_first;
	struct scoutfs_key_buf ment_last;

	*ment = args->ment;

	init_ment_keys(ment, &ment_first, &ment_last);
	scoutfs_key_copy(&ment_first, args->first);
	scoutfs_key_copy(&ment_last, args->last);
}

static struct scoutfs_treap_ops manifest_treap_ops = {
	.compare = manifest_treap_compare,
	.fill = manifest_treap_fill,
	/* update aug when we track left and right max seq */
};


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
	seqcount_init(&mani->seqcount);

	mani->treap = scoutfs_treap_alloc(sb, &manifest_treap_ops,
					  &super->manifest.root);
	if (!mani->treap) {
		kfree(mani);
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(mani->compact_keys); i++) {
		mani->compact_keys[i] = scoutfs_key_alloc(sb,
							  SCOUTFS_MAX_KEY_SIZE);
		if (!mani->compact_keys[i]) {
			while (--i >= 0)
				scoutfs_key_free(sb, mani->compact_keys[i]);
			scoutfs_treap_free(mani->treap);
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
		scoutfs_treap_free(mani->treap);
		for (i = 0; i < ARRAY_SIZE(mani->compact_keys); i++)
			scoutfs_key_free(sb, mani->compact_keys[i]);
		kfree(mani);
	}
}
