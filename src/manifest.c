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
#include "treap.h"
#include "cmp.h"
#include "manifest.h"
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
	struct scoutfs_treap *treap;
	u8 nr_levels;
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
	u16 first_key_len;
	u16 last_key_len;
	u8 level;
	u8 keys[0];
};

struct manifest_fill_args {
	struct scoutfs_manifest_entry ment;
	struct kvec *first;
	struct kvec *last;
};

struct manifest_search_key {
	u64 seq;
	struct kvec *key;
	u8 level;
};

static void init_ment_keys(struct scoutfs_manifest_entry *ment,
			   struct kvec *first, struct kvec *last)
{
	if (first)
		scoutfs_kvec_init(first, ment->keys,
				  le16_to_cpu(ment->first_key_len));
	if (last)
		scoutfs_kvec_init(last, ment->keys +
				  le16_to_cpu(ment->first_key_len),
				  le16_to_cpu(ment->last_key_len));
}

static void init_ref_keys(struct manifest_ref *ref, struct kvec *first,
			  struct kvec *last)
{
	if (first)
		scoutfs_kvec_init(first, ref->keys, ref->first_key_len);
	if (last)
		scoutfs_kvec_init(last, ref->keys + ref->first_key_len,
				  ref->last_key_len);
}

static bool cmp_range_ment(struct kvec *key, struct kvec *end,
			   struct scoutfs_manifest_entry *ment)
{
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);

	init_ment_keys(ment, first, last);

	return scoutfs_kvec_cmp_overlap(key, end, first, last);
}

/*
 * Insert a new manifest entry in the treap.  The treap allocates a new
 * node for us and we fill it.
 */
int scoutfs_manifest_add(struct super_block *sb, struct kvec *first,
			 struct kvec *last, u64 segno, u64 seq, u8 level)
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

	trace_scoutfs_manifest_add(sb, first, last, segno, seq, level);

	key_bytes = scoutfs_kvec_length(first) + scoutfs_kvec_length(last);
	bytes = offsetof(struct scoutfs_manifest_entry, keys[key_bytes]);

	args.ment.segno = cpu_to_le64(segno);
	args.ment.seq = cpu_to_le64(seq);
	args.ment.first_key_len = cpu_to_le16(scoutfs_kvec_length(first));
	args.ment.last_key_len = cpu_to_le16(scoutfs_kvec_length(last));
	args.ment.level = level;

	args.first = first;
	args.last = last;

	skey.key = first;
	skey.level = level;
	skey.seq = seq;

	down_write(&mani->rwsem);

	ment = scoutfs_treap_insert(mani->treap, &skey, bytes, &args);
	if (IS_ERR(ment)) {
		ret = PTR_ERR(ment);
	} else {
		mani->nr_levels = max_t(u8, mani->nr_levels, level + 1);
		le64_add_cpu(&super->manifest.level_counts[level], 1);
		ret = 0;
	}

	up_write(&mani->rwsem);

	return ret;
}

static int alloc_add_ref(struct list_head *list,
			 struct scoutfs_manifest_entry *ment)
{
	SCOUTFS_DECLARE_KVEC(ment_first);
	SCOUTFS_DECLARE_KVEC(ment_last);
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);
	struct manifest_ref *ref;
	unsigned bytes;

	init_ment_keys(ment, ment_first, ment_last);

	bytes = scoutfs_kvec_length(ment_first) +
		scoutfs_kvec_length(ment_first);

	ref = kmalloc(offsetof(struct manifest_ref, keys[bytes]), GFP_NOFS);
	if (!ref)
		return -ENOMEM;

	memset(ref, 0, offsetof(struct manifest_ref, keys));

	ref->segno = le64_to_cpu(ment->segno);
	ref->seq = le64_to_cpu(ment->seq);
	ref->level = ment->level;
	ref->first_key_len = le16_to_cpu(ment->first_key_len);
	ref->last_key_len = le16_to_cpu(ment->last_key_len);

	init_ref_keys(ref, first, last);
	scoutfs_kvec_memcpy(first, ment_first);
	scoutfs_kvec_memcpy(last, ment_last);

	list_add_tail(&ref->entry, list);

	return 0;

}

/* sort level 0 segments of the list from greatest to least seq */
static int cmp_ref_list_seqs(void *priv, struct list_head *A,
			     struct list_head *B)
{
	struct manifest_ref *a = list_entry(A, struct manifest_ref, entry);
	struct manifest_ref *b = list_entry(B, struct manifest_ref, entry);

	return -scoutfs_cmp_u64s(a->seq, b->seq);
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
			  struct kvec *key, struct kvec *end,
			  struct list_head *ref_list)
{
	struct scoutfs_manifest_entry *ment;
	struct manifest_search_key skey;
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	int cmp;
	int ret;
	int i;

	down_write(&mani->rwsem);

	/* get level 0 segments that overlap with the missing range */
	ment = scoutfs_treap_first(mani->treap);
	while (!IS_ERR_OR_NULL(ment)) {
		if (ment->level > 0)
			break;

		cmp = cmp_range_ment(key, end, ment);
		if (cmp < 0)
			break;

		if (cmp == 0) {
			ret = alloc_add_ref(ref_list, ment);
			if (ret)
				goto out;
		}

		ment = scoutfs_treap_next(mani->treap, ment);
	}
	if (IS_ERR(ment)) {
		ret = PTR_ERR(ment);
		goto out;
	}

	/* level0s are sorted by key, reverse sort by seq */
	list_sort(NULL, ref_list, cmp_ref_list_seqs);

	/* get higher level segments that overlap with the starting key */
	for (i = 1; i < mani->nr_levels; i++) {
		skey.key = key;
		skey.level = i;

		/* XXX should use level counts to skip searches */

		ment = scoutfs_treap_lookup(mani->treap, &skey);
		if (IS_ERR(ment)) {
			ret = PTR_ERR(ment);
			goto out;
		}

		if (ment) {
			init_ment_keys(ment, first, last);
			ret = alloc_add_ref(ref_list, ment);
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
			kfree(ref);
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

int scoutfs_manifest_read_items(struct super_block *sb, struct kvec *key,
				struct kvec *end)
{
	DECLARE_MANIFEST(sb, mani);
	SCOUTFS_DECLARE_KVEC(item_key);
	SCOUTFS_DECLARE_KVEC(item_val);
	SCOUTFS_DECLARE_KVEC(found_key);
	SCOUTFS_DECLARE_KVEC(found_val);
	SCOUTFS_DECLARE_KVEC(batch_end);
	SCOUTFS_DECLARE_KVEC(seg_end);
	struct scoutfs_segment *seg;
	struct manifest_ref *ref;
	struct manifest_ref *tmp;
	LIST_HEAD(ref_list);
	LIST_HEAD(batch);
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

	/* wait for submitted segments and search for starting pos */
	list_for_each_entry(ref, &ref_list, entry) {
		if (!ref->seg)
			break;

		err = scoutfs_seg_wait(sb, ref->seg);
		if (err && !ret)
			ret = err;

		if (ret == 0)
			ref->pos = scoutfs_seg_find_pos(ref->seg, key);
	}
	if (ret)
		goto out;

	scoutfs_kvec_init_null(batch_end);
	scoutfs_kvec_init_null(seg_end);
	found_ctr = 0;

	for (n = 0; n < MAX_ITEMS_READ; n++) {

		found = false;
		found_ctr++;

		/* find the next least key from the pos in each segment */
		list_for_each_entry_safe(ref, tmp, &ref_list, entry) {

			/*
			 * Check the next item in the segment.  We're
			 * done with the segment if there are no more
			 * items or if the next item is past the
			 * caller's end.  We record either the caller's
			 * end or the segment end if it's a l1+ segment for
			 * use as the batch end if we don't see more items.
			 */
			ret = scoutfs_seg_item_kvecs(ref->seg, ref->pos,
					             item_key, item_val);
			if (ret < 0)  {
				if (ref->level > 0) {
					init_ref_keys(ref, NULL, item_key);
					scoutfs_kvec_clone_less(seg_end,
								item_key);
				}
			} else if (scoutfs_kvec_memcmp(item_key, end) > 0) {
				scoutfs_kvec_clone_less(seg_end, end);
				ret = -ENOENT;
			}
			if (ret < 0) {
				list_del_init(&ref->entry);
				scoutfs_seg_put(ref->seg);
				kfree(ref);
				continue;
			}

			/* see if it's the new least item */
			if (found) {
				cmp = scoutfs_kvec_memcmp(item_key, found_key);
				if (cmp >= 0) {
					if (cmp == 0)
						ref->found_ctr = found_ctr;
					continue;
				}
			}

			/* remember new least key */
			scoutfs_kvec_clone(found_key, item_key);
			scoutfs_kvec_clone(found_val, item_val);
			ref->found_ctr = ++found_ctr;
			found = true;
		}

		/* ran out of keys in segs, range extends to seg end */
		if (!found) {
			scoutfs_kvec_clone(batch_end, seg_end);
			ret = 0;
			break;
		}

		/*
		 * If we fail to add an item we're done.  If we already
		 * have items it's not a failure and the end of the cached
		 * range is the last successfully added item.
		 */
		ret = scoutfs_item_add_batch(sb, &batch, found_key, found_val);
		if (ret) {
			if (n > 0)
				ret = 0;
			break;
		}

		/* the last successful key determines the range */
		scoutfs_kvec_clone(batch_end, found_key);

		/* if we just saw the end key then we're done */
		if (scoutfs_kvec_memcmp(found_key, end) == 0) {
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
		scoutfs_item_free_batch(&batch);
	else
		ret = scoutfs_item_insert_batch(sb, &batch, key, batch_end);
out:
	list_for_each_entry_safe(ref, tmp, &ref_list, entry) {
		list_del_init(&ref->entry);
		scoutfs_seg_put(ref->seg);
		kfree(ref);
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
	scoutfs_treap_dirty_ring(mani->treap);
	scoutfs_treap_update_root(&super->manifest.root, mani->treap);
	up_write(&mani->rwsem);

	return 0;
}

/*
 * Manifest entries are first sorted by their level.
 *
 * Level 0 segments can arbitrarily overlap.  Their manifest entries are
 * sorted by their first key so that searches can iterate over the
 * entries until first shows that no more segments can overlap.  We then
 * sort by the sequence so that we can manage entries that have
 * identical keys.
 *
 * Higher level segments don't overlap.  There will never be manifest
 * entries with the same key at a given level.
 */
static int manifest_treap_compare(void *key, void *data)
{
	struct manifest_search_key *skey = key;
	struct scoutfs_manifest_entry *ment = data;
	SCOUTFS_DECLARE_KVEC(first);
	SCOUTFS_DECLARE_KVEC(last);

	if (skey->level < ment->level)
		return -1;
	if (skey->level > ment->level)
		return 1;

	init_ment_keys(ment, first, NULL);

	if (skey->level == 0)
		return scoutfs_kvec_memcmp(skey->key, first) ?:
		       scoutfs_cmp_u64s(skey->seq, le64_to_cpu(ment->seq));

	init_ment_keys(ment, NULL, last);

	return scoutfs_kvec_cmp_overlap(skey->key, skey->key, first, last);
}

static void manifest_treap_fill(void *data, void *arg)
{
	struct scoutfs_manifest_entry *ment = data;
	struct manifest_fill_args *args = arg;
	SCOUTFS_DECLARE_KVEC(ment_first);
	SCOUTFS_DECLARE_KVEC(ment_last);

	*ment = args->ment;

	init_ment_keys(ment, ment_first, ment_last);
	scoutfs_kvec_memcpy(ment_first, args->first);
	scoutfs_kvec_memcpy(ment_last, args->last);
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
	mani->treap = scoutfs_treap_alloc(sb, &manifest_treap_ops,
					  &super->manifest.root);
	if (!mani->treap) {
		kfree(mani);
		return -ENOMEM;
	}

	for (i = ARRAY_SIZE(super->manifest.level_counts) - 1; i >= 0; i--) {
		if (super->manifest.level_counts[i]) {
			mani->nr_levels = i + 1;
			break;
		}
	}

	sbi->manifest = mani;

	return 0;
}

void scoutfs_manifest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct manifest *mani = sbi->manifest;

	if (mani) {
		scoutfs_treap_free(mani->treap);
		kfree(mani);
	}
}
