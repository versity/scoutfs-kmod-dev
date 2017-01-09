/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>

#include "super.h"
#include "format.h"
#include "kvec.h"
#include "seg.h"
#include "bio.h"
#include "cmp.h"
#include "compact.h"
#include "manifest.h"
#include "scoutfs_trace.h"

/*
 * Compaction is what maintains the exponentially increasing number of
 * segments in each level of the lsm tree and is what merges duplicate
 * and deletion keys.
 *
 * When the manifest is modified in a way that requires compaction it
 * kicks the compaction thread.  The compaction thread calls into the
 * manifest to find the segments that need to be compaction.
 *
 * The compaction operation itself always involves a single "upper"
 * segment at a given level and a limited number of "lower" segments at
 * the next higher level whose key range intersects with the upper
 * segment.
 *
 * Compaction proceeds by iterating over the items in the upper segment
 * and items in each of the lower segments in sort order.  The items
 * from the two input segments are copied into new output segments in
 * sorted order.  Item space is reclaimed as duplicate or deletion items
 * are removed.
 *
 * Once the compaction is completed the manifest is updated to remove
 * the input segments and add the output segments.  Here segment space
 * is reclaimed when the input items fit in fewer output segments.
 *
 * XXX today we only know how to skip duplicate individual items.  We'll
 * need to know how to skip lower based on upper range deletion items
 * and to combine incremental update items.
 */

struct compact_info {
	struct super_block *sb;
	struct workqueue_struct *workq;
	struct work_struct work;
};

#define DECLARE_COMPACT_INFO(sb, name) \
	struct compact_info *name = SCOUTFS_SB(sb)->compact_info

struct compact_seg {
	struct list_head entry;

	u64 segno;
	u64 seq;
	u8 level;
	SCOUTFS_DECLARE_KVEC(first);
	struct scoutfs_segment *seg;
	int pos;
	int saved_pos;
};

/*
 * A compaction request.  It's filled up in scoutfs_compact_add() as
 * the manifest is wlaked and it finds segments involved in the compaction.
 */
struct compact_cursor {
	struct list_head csegs;

	u8 lower_level;

	struct compact_seg *upper;
	struct compact_seg *saved_upper;
	struct compact_seg *lower;
	struct compact_seg *saved_lower;
};

static void save_pos(struct compact_cursor *curs)
{
	struct compact_seg *cseg;

	list_for_each_entry(cseg, &curs->csegs, entry)
		cseg->saved_pos = cseg->pos;

	curs->saved_upper = curs->upper;
	curs->saved_lower = curs->lower;
}

static void restore_pos(struct compact_cursor *curs)
{
	struct compact_seg *cseg;

	list_for_each_entry(cseg, &curs->csegs, entry)
		cseg->pos = cseg->saved_pos;

	curs->upper = curs->saved_upper;
	curs->lower = curs->saved_lower;
}

/*
 * There's some common patterns with scoutfs_manifest_read_items().. may
 * want some sharing if it's clean.
 */
static int read_segments(struct super_block *sb, struct compact_cursor *curs)
{
	struct scoutfs_segment *seg;
	struct compact_seg *cseg;
	int ret = 0;
	int err;

	list_for_each_entry(cseg, &curs->csegs, entry) {
		seg = scoutfs_seg_submit_read(sb, cseg->segno);
		if (IS_ERR(seg)) {
			ret = PTR_ERR(seg);
			break;
		}

		cseg->seg = seg;
	}

	list_for_each_entry(cseg, &curs->csegs, entry) {
		if (!cseg->seg)
			break;

		err = scoutfs_seg_wait(sb, cseg->seg);
		if (err && !ret)
			ret = err;

		/* XXX verify segs */
	}

	return ret;
}

/*
 * This is synchronous for now.  We're just ensuring that the segments
 * are stable on disk so that the references to them in the dirty manifest
 * are safe without having to associate dirty segments and manifest entries.
 */
static int write_segments(struct super_block *sb, struct list_head *results)
{
	struct scoutfs_bio_completion comp;
	struct compact_seg *cseg;
	int ret = 0;
	int err;

	scoutfs_bio_init_comp(&comp);

	list_for_each_entry(cseg, results, entry) {
		ret = scoutfs_seg_submit_write(sb, cseg->seg, &comp);
		if (ret)
			break;
	}

	err = scoutfs_bio_wait_comp(sb, &comp);
	if (err && !ret)
		ret = err;

	return ret;
}

static struct compact_seg *next_spos(struct compact_cursor *curs,
				     struct compact_seg *cseg)
{
	if (cseg->entry.next == &curs->csegs)
		return NULL;

	return list_next_entry(cseg, entry);
}

/*
 * Point the caller's key and value kvecs at the next item that should
 * be copied from the segment's position in the upper and lower
 * segments.  We use the item that has the lowest key or the upper if
 * they're the same.  We advance the cursor past the item that is
 * returned.
 *
 * XXX this will get fancier as we get range deletion items and incremental
 * update items.
 */
static bool next_item(struct compact_cursor *curs,
		      struct kvec *item_key, struct kvec *item_val)
{
	struct compact_seg *upper = curs->upper;
	struct compact_seg *lower = curs->lower;
	SCOUTFS_DECLARE_KVEC(lower_key);
	SCOUTFS_DECLARE_KVEC(lower_val);
	bool found = false;
	int cmp;
	int ret;

	if (upper) {
		ret = scoutfs_seg_item_kvecs(upper->seg, upper->pos,
					     item_key, item_val);
		if (ret < 0)
			upper = NULL;
	}

	while (lower) {
		ret = scoutfs_seg_item_kvecs(lower->seg, lower->pos,
					     lower_key, lower_val);
		if (ret == 0)
			break;
		lower = next_spos(curs, lower);
	}

	/* we're done if all are empty */
	if (!upper && !lower) {
		found = false;
		goto out;
	}

	/*
	 * < 0: return upper, advance upper
	 * == 0: return upper, advance both
	 * > 0: return lower, advance lower
	 */
	if (upper && lower)
		cmp = scoutfs_kvec_memcmp(item_key, lower_key);
	else if (upper)
		cmp = -1;
	else
		cmp = 1;

	if (cmp > 0) {
		scoutfs_kvec_clone(item_key, lower_key);
		scoutfs_kvec_clone(item_val, lower_val);
	}

	if (cmp <= 0)
		upper->pos++;
	if (cmp >= 0)
		lower->pos++;

	found = true;
out:
	curs->upper = upper;
	curs->lower = lower;

	return found;
}

/*
 * Figure out how many items and bytes of keys we're going to try and
 * compact into the next segment.
 */
static void count_items(struct super_block *sb, struct compact_cursor *curs,
			u32 *nr_items, u32 *key_bytes)
{
	SCOUTFS_DECLARE_KVEC(item_key);
	SCOUTFS_DECLARE_KVEC(item_val);
	u32 total;

	*nr_items = 0;
	*key_bytes = 0;
	total = sizeof(struct scoutfs_segment_block);

	while (next_item(curs, item_key, item_val)) {

		total += sizeof(struct scoutfs_segment_item) +
			 scoutfs_kvec_length(item_key) +
			 scoutfs_kvec_length(item_val);

		if (total > SCOUTFS_SEGMENT_SIZE)
			break;

		(*nr_items)++;
		(*key_bytes) += scoutfs_kvec_length(item_key);
	}
}

static void compact_items(struct super_block *sb, struct compact_cursor *curs,
			  struct scoutfs_segment *seg, u32 nr_items,
			  u32 key_bytes)
{
	SCOUTFS_DECLARE_KVEC(item_key);
	SCOUTFS_DECLARE_KVEC(item_val);

	next_item(curs, item_key, item_val);
	scoutfs_seg_first_item(sb, seg, item_key, item_val,
			       nr_items, key_bytes);

	while (--nr_items && next_item(curs, item_key, item_val))
		scoutfs_seg_append_item(sb, seg, item_key, item_val);
}

static int compact_segments(struct super_block *sb,
			    struct compact_cursor *curs,
			    struct list_head *results)
{
	struct scoutfs_segment *seg;
	struct compact_seg *cseg;
	u32 key_bytes;
	u32 nr_items;
	int ret;

	for (;;) {

		save_pos(curs);
		count_items(sb, curs, &nr_items, &key_bytes);
		restore_pos(curs);

		if (nr_items == 0) {
			ret = 0;
			break;
		}

		cseg = kzalloc(sizeof(struct compact_seg), GFP_NOFS);
		if (!cseg) {
			ret = -ENOMEM;
			break;
		}

		ret = scoutfs_seg_alloc(sb, &seg);
		if (ret) {
			kfree(cseg);
			break;
		}

		cseg->level = curs->lower_level;
		cseg->seg = seg;
		list_add_tail(&cseg->entry, results);

		compact_items(sb, curs, seg, nr_items, key_bytes);
	}

	return ret;
}

static void free_csegs(struct list_head *list)
{
	struct compact_seg *cseg;
	struct compact_seg *tmp;

	list_for_each_entry_safe(cseg, tmp, list, entry) {
		list_del_init(&cseg->entry);
		scoutfs_seg_put(cseg->seg);
		scoutfs_kvec_kfree(cseg->first);
		kfree(cseg);
	}
}

int scoutfs_compact_add(struct super_block *sb, void *data, struct kvec *first,
			u64 segno, u64 seq, u8 level)
{
	struct compact_cursor *curs = data;
	struct compact_seg *cseg;
	int ret;

	cseg = kzalloc(sizeof(struct compact_seg), GFP_NOFS);
	if (!cseg) {
		ret = -ENOMEM;
		goto out;
	}

	list_add_tail(&cseg->entry, &curs->csegs);

	ret = scoutfs_kvec_dup_flatten(cseg->first, first);
	if (ret)
		goto out;

	cseg->segno = segno;
	cseg->seq = seq;
	cseg->level = level;

	if (!curs->upper) {
		curs->upper = cseg;
	} else if (!curs->lower) {
		curs->lower = cseg;
		curs->lower_level = level;
	}

	ret = 0;
out:
	return ret;
}

/*
 * Atomically update the manifest.  We lock down the manifest so no one
 * can use it while we're mucking with it.  We can always delete dirty
 * treap nodes without failure.  So we first dirty the deletion nodes
 * before modifying anything.  Then we add and if any of those fail we
 * can delete the dirty previous additions.  Then we can delete the
 * dirty existing entries without failure.
 *
 * XXX does locking the manifest prevent commits?  I would think so?
 */
static int update_manifest(struct super_block *sb, struct compact_cursor *curs,
			   struct list_head *results)
{
	struct compact_seg *cseg;
	struct compact_seg *until;
	int ret = 0;
	int err;

	scoutfs_manifest_lock(sb);

	list_for_each_entry(cseg, &curs->csegs, entry) {
		ret = scoutfs_manifest_dirty(sb, cseg->first,
					     cseg->seq, cseg->level);
		if (ret)
			goto out;
	}

	list_for_each_entry(cseg, results, entry) {
		ret = scoutfs_seg_manifest_add(sb, cseg->seg, cseg->level);
		if (ret) {
			until = cseg;
			list_for_each_entry(cseg, results, entry) {
				if (cseg == until)
					break;
				err = scoutfs_seg_manifest_del(sb, cseg->seg,
							       cseg->level);
				BUG_ON(err);
			}
			goto out;
		}
	}

	list_for_each_entry(cseg, &curs->csegs, entry) {
		ret = scoutfs_manifest_del(sb, cseg->first,
					   cseg->seq, cseg->level);
		BUG_ON(ret);
	}

out:
	scoutfs_manifest_unlock(sb);

	return ret;
}

static int free_result_segnos(struct super_block *sb,
			      struct list_head *results)
{
	struct compact_seg *cseg;
	int ret = 0;
	int err;

	list_for_each_entry(cseg, results, entry) {
		/* XXX failure here would be an inconsistency */
		err = scoutfs_seg_free_segno(sb, cseg->seg);
		if (err && !ret)
			ret = err;
	}

	return ret;
}

static void scoutfs_compact_func(struct work_struct *work)
{
	struct compact_info *ci = container_of(work, struct compact_info, work);
	struct super_block *sb = ci->sb;
	struct compact_cursor curs = {{NULL,}};
	LIST_HEAD(results);
	int ret;

	INIT_LIST_HEAD(&curs.csegs);

	ret = scoutfs_manifest_next_compact(sb, (void *)&curs) ?:
	      read_segments(sb, &curs) ?:
	      compact_segments(sb, &curs, &results) ?:
	      write_segments(sb, &results) ?:
	      update_manifest(sb, &curs, &results);

	if (ret)
		free_result_segnos(sb, &results);

	free_csegs(&curs.csegs);
	free_csegs(&results);

	WARN_ON_ONCE(ret);
	trace_printk("ret %d\n", ret);
}

void scoutfs_compact_kick(struct super_block *sb)
{
	DECLARE_COMPACT_INFO(sb, ci);

	queue_work(ci->workq, &ci->work);
}

int scoutfs_compact_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct compact_info *ci;

	ci = kzalloc(sizeof(struct compact_info), GFP_KERNEL);
	if (!ci)
		return -ENOMEM;

	ci->sb = sb;
	INIT_WORK(&ci->work, scoutfs_compact_func);

	ci->workq = alloc_workqueue("scoutfs_compact", 0, 1);
	if (!ci->workq) {
		kfree(ci);
		return -ENOMEM;
	}

	sbi->compact_info = ci;

	return 0;
}

/*
 * The system should be idle, there should not be any more manifest
 * modification which would kick compaction.
 */
void scoutfs_compact_destroy(struct super_block *sb)
{
	DECLARE_COMPACT_INFO(sb, ci);

	if (ci->workq) {
		flush_work(&ci->work);
		destroy_workqueue(ci->workq);
	}
}
