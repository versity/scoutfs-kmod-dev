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
#include <linux/sort.h>

#include "super.h"
#include "format.h"
#include "seg.h"
#include "bio.h"
#include "cmp.h"
#include "compact.h"
#include "manifest.h"
#include "counters.h"
#include "server.h"
#include "scoutfs_trace.h"

/*
 * Compaction is what maintains the exponentially increasing number of
 * segments in each level of the lsm tree and is what merges duplicate
 * and deletion keys.
 *
 * The compaction operation itself always involves a single "upper"
 * segment at a given level and a limited number of "lower" segments at
 * the next higher level whose key range intersects with the upper
 * segment.
 *
 * Compaction proceeds by iterating over the items in the upper segment
 * and items in each of the lower segments in sort order.  The items
 * from the two input segments are copied into new output segments in
 * sorted order.  Space is reclaimed as duplicate or deletion items are
 * removed and fewer segments are written than were read.
 */

struct compact_seg {
	struct list_head entry;

	u64 segno;
	u64 seq;
	u8 level;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_segment *seg;
	int off;
	bool part_of_move;
};

struct compact_cursor {
	struct list_head csegs;

	/* buffer holds allocations and our returning them */
	u64 segnos[SCOUTFS_COMPACTION_MAX_OUTPUT];
	unsigned int nr_segnos;

	u8 lower_level;
	u8 last_level;

	struct compact_seg *upper;
	struct compact_seg *lower;

	bool sticky;
	struct compact_seg *last_lower;

	__le32 *links[SCOUTFS_MAX_SKIP_LINKS];
};

static void free_cseg(struct super_block *sb, struct compact_seg *cseg)
{
	WARN_ON_ONCE(!list_empty(&cseg->entry));

	scoutfs_seg_put(cseg->seg);
	kfree(cseg);
}

static struct compact_seg *alloc_cseg(struct super_block *sb,
				      struct scoutfs_key *first,
				      struct scoutfs_key *last)
{
	struct compact_seg *cseg;

	cseg = kzalloc(sizeof(struct compact_seg), GFP_NOFS);
	if (cseg) {
		INIT_LIST_HEAD(&cseg->entry);
		cseg->first = *first;
		cseg->last = *last;
	}

	return cseg;
}

static void free_cseg_list(struct super_block *sb, struct list_head *list)
{
	struct compact_seg *cseg;
	struct compact_seg *tmp;

	list_for_each_entry_safe(cseg, tmp, list, entry) {
		list_del_init(&cseg->entry);
		free_cseg(sb, cseg);
	}
}

static int read_segment(struct super_block *sb, struct compact_seg *cseg)
{
	struct scoutfs_segment *seg;
	int ret;

	if (cseg == NULL || cseg->seg)
		return 0;

	seg = scoutfs_seg_submit_read(sb, cseg->segno);
	if (IS_ERR(seg)) {
		ret = PTR_ERR(seg);
	} else {
		cseg->seg = seg;
		scoutfs_inc_counter(sb, compact_segment_read);
		ret = scoutfs_seg_wait(sb, cseg->seg, cseg->segno, cseg->seq);
	}

	/* XXX verify read segment metadata */

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
 * be copied from the upper or lower segments.  We use the item that has
 * the lowest key or the upper if they're the same.  We advance the
 * cursor past the item that is returned.
 *
 * XXX this will get fancier as we get range deletion items and
 * incremental update items.
 */
static int next_item(struct super_block *sb, struct compact_cursor *curs,
		     struct scoutfs_key *item_key, struct kvec *item_val,
		     u8 *item_flags)
{
	struct compact_seg *upper = curs->upper;
	struct compact_seg *lower = curs->lower;
	struct scoutfs_key lower_key;
	struct kvec lower_val;
	u8 lower_flags;
	int cmp;
	int ret;

retry:
	if (upper) {
		ret = scoutfs_seg_get_item(upper->seg, upper->off,
					   item_key, item_val, item_flags);
		if (ret < 0)
			upper = NULL;
	}

	while (lower) {
		ret = read_segment(sb, lower);
		if (ret)
			goto out;

		ret = scoutfs_seg_get_item(lower->seg, lower->off,
					   &lower_key, &lower_val,
					   &lower_flags);
		if (ret == 0)
			break;
		lower = next_spos(curs, lower);
	}

	/* we're done if all are empty */
	if (!upper && !lower) {
		ret = 0;
		goto out;
	}

	/*
	 * < 0: return upper, advance upper
	 * == 0: return upper, advance both
	 * > 0: return lower, advance lower
	 */
	if (upper && lower)
		cmp = scoutfs_key_compare(item_key, &lower_key);
	else if (upper)
		cmp = -1;
	else
		cmp = 1;

	if (cmp > 0) {
		*item_key = lower_key;
		*item_val = lower_val;
		*item_flags = lower_flags;
	}

	/*
	 * If we have a sticky compaction then we can't mix items from
	 * the upper level past the last lower key into the lower level.
	 * The caller will notice when they're emptying the final upper
	 * level in a sticky merge and leave it at the upper level.
	 */
	if (curs->sticky && curs->lower &&
	    (!lower || lower == curs->last_lower) &&
	    scoutfs_key_compare(item_key, &curs->last_lower->last) > 0) {
		ret = 0;
		goto out;
	}

	if (cmp <= 0)
		upper->off = scoutfs_seg_next_off(upper->seg, upper->off);
	if (cmp >= 0)
		lower->off = scoutfs_seg_next_off(lower->seg, lower->off);

	/*
	 * Deletion items make their way down all the levels, replacing
	 * all the duplicate items that they find.  When we're
	 * compacting to the last level we can remove them by retrying
	 * the search after we've advanced past them.
	 *
	 * If we're filling the remaining items in a sticky merge into
	 * the upper level then we have to preserve the deletion items.
	 */
	if ((curs->lower_level == curs->last_level) &&
	    (!curs->sticky || lower) &&
	    ((*item_flags) & SCOUTFS_ITEM_FLAG_DELETION))
		goto retry;

	ret = 1;
out:
	curs->upper = upper;
	curs->lower = lower;

	return ret;
}

static int compact_segments(struct super_block *sb,
			    struct compact_cursor *curs,
			    struct scoutfs_bio_completion *comp,
			    struct list_head *results)
{
	struct scoutfs_key item_key;
	struct scoutfs_segment *seg;
	struct compact_seg *cseg;
	struct compact_seg *upper;
	struct compact_seg *lower;
	unsigned next_segno = 0;
	bool append_filled = false;
	struct kvec item_val;
	int ret = 0;
	u8 flags;

	scoutfs_inc_counter(sb, compact_operations);
	if (curs->sticky)
		scoutfs_inc_counter(sb, compact_sticky_upper);

	while (curs->upper || curs->lower) {

		upper = curs->upper;
		lower = curs->lower;

		/*
		 * If we're at the start of the upper segment and
		 * there's no lower segment then we might as well just
		 * move the segment in the manifest.  We can't do this
		 * if we're moving to the last level because we might
		 * need to drop any deletion items.
		 *
		 * XXX We should have metadata in the manifest to tell
		 * us that there's no deletion items in the segment.
		 */
		if (upper && upper->off == 0 && !lower && !curs->sticky &&
		    ((upper->level + 1) < curs->last_level)) {

			/*
			 * XXX blah!  these csegs are getting
			 * ridiculous.  We should have a robust manifest
			 * entry iterator that reading and compacting
			 * can use.
			 */
			cseg = alloc_cseg(sb, &upper->first, &upper->last);
			if (!cseg) {
				ret = -ENOMEM;
				break;
			}

			cseg->segno = upper->segno;
			cseg->seq = upper->seq;
			cseg->level = upper->level + 1;
			cseg->seg = upper->seg;
			if (cseg->seg)
				scoutfs_seg_get(cseg->seg);
			list_add_tail(&cseg->entry, results);

			/* don't mess with its segno */
			upper->part_of_move = true;
			cseg->part_of_move = true;

			curs->upper = NULL;

			scoutfs_inc_counter(sb, compact_segment_moved);
			break;
		}

		/* we're going to need its next key */
		ret = read_segment(sb, upper);
		if (ret)
			break;

		/*
		 * XXX we could intelligently skip reading and merging
		 * lower segments here.  The lower segment won't change
		 * if: 
		 *  - the lower segment is entirely before the upper
		 *  - the lower segment is full
		 *
		 * We don't have the metadata to determine that it's
		 * full today so we want to read lower segments that don't
		 * overlap so that we can merge partial lowers with
		 * its neighbours.
		 */

		ret = read_segment(sb, lower);
		if (ret)
			break;

		if (!append_filled)
			ret = next_item(sb, curs, &item_key, &item_val, &flags);
		else
			ret = 1;
		if (ret <= 0)
			break;

		/* no cseg keys, manifest update uses seg item keys */
		cseg = kzalloc(sizeof(struct compact_seg), GFP_NOFS);
		if (!cseg) {
			ret = -ENOMEM;
			break;
		}

		/* didn't get enough segnos */
		if (next_segno >= curs->nr_segnos) {
			ret = -ENOSPC;
			break;
		}

		cseg->segno = curs->segnos[next_segno];
		curs->segnos[next_segno] = 0;
		next_segno++;

		/*
		 * Compaction can free all the remaining items resulting
		 * in an empty output segment.  We just free it in that
		 * case.
		 */
		ret = scoutfs_seg_alloc(sb, cseg->segno, &seg);
		if (ret < 0) {
			next_segno--;
			curs->segnos[next_segno] = cseg->segno;
			kfree(cseg);
			scoutfs_seg_put(seg);
			break;
		}

		/*
		 * The remaining upper items in a sticky merge have to
		 * be written into the upper level.
		 */
		if (curs->sticky && !lower) {
			cseg->level = curs->lower_level - 1;
			scoutfs_inc_counter(sb, compact_sticky_written);
		} else {
			cseg->level = curs->lower_level;
		}

		/* csegs will be claned up once they're on the list */
		cseg->seg = seg;
		list_add_tail(&cseg->entry, results);

		for (;;) {
			if (!scoutfs_seg_append_item(sb, seg, &item_key,
						     &item_val, flags,
						     curs->links)) {
				append_filled = true;
				ret = 0;
				break;
			}
			ret = next_item(sb, curs, &item_key, &item_val, &flags);
			if (ret <= 0) {
				append_filled = false;
				break;
			}
		}
		if (ret < 0)
			break;

		/* start a complete segment write now, we'll wait later */
		ret = scoutfs_seg_submit_write(sb, seg, comp);
		if (ret)
			break;

		scoutfs_inc_counter(sb, compact_segment_writes);
		scoutfs_add_counter(sb, compact_segment_write_bytes,
				    scoutfs_seg_total_bytes(seg));
	}

	return ret;
}

/*
 * We want all the non-zero segnos sorted at the front of the array
 * and the empty segnos all packed at the end.  This is easily done by
 * subtracting one from both then comparing as usual.  All relations hold
 * except that 0 becomes the greatest instead of the least.
 */
static int sort_cmp_segnos(const void *A, const void *B)
{
	const u64 a = *(const u64 *)A - 1;
	const u64 b = *(const u64 *)B - 1;

	return a < b ? -1 : a > b ? 1 : 0;
}

static void sort_swap_segnos(void *A, void *B, int size)
{
	u64 *a = A;
	u64 *b = B;

	swap(*a, *b);
}

static int verify_request(struct super_block *sb,
			  struct scoutfs_net_compact_request *req)
{
	int ret = -EINVAL;
	int nr_segnos;
	int nr_ents;
	int i;

	/* no unknown flags */
	if (req->flags & ~SCOUTFS_NET_COMPACT_FLAG_STICKY)
		goto out;

	/* find the number of segments and entries */
	for (i = 0; i < ARRAY_SIZE(req->segnos); i++) {
		if (req->segnos[i] == 0)
			break;
	}
	nr_segnos = i;

	for (i = 0; i < ARRAY_SIZE(req->ents); i++) {
		if (req->ents[i].segno == 0)
			break;
	}
	nr_ents = i;

	/* must have at least an upper */
	if (nr_ents == 0)
		goto out;

	sort(req->segnos, nr_segnos, sizeof(req->segnos[i]),
	     sort_cmp_segnos, sort_swap_segnos);

	/* segnos must be unique */
	for (i = 1; i < nr_segnos; i++) {
		if (req->segnos[i] == req->segnos[i - 1])
			goto out;
	}

	/* if we have a lower it must be under upper */
	if (nr_ents > 1 && (req->ents[1].level != req->ents[0].level + 1))
		goto out;

	/* make sure lower ents are on the same level */
	for (i = 2; i < nr_ents; i++) {
		if (req->ents[i].level != req->ents[i - 1].level)
			goto out;
	}

	for (i = 1; i < nr_ents; i++) {
		/* lowers must overlap with upper */
		if (scoutfs_key_compare_ranges(&req->ents[0].first,
					       &req->ents[0].last,
					       &req->ents[i].first,
					       &req->ents[i].last) != 0)
			goto out;

		/* lowers must be on the level below upper */
		if (req->ents[i].level != req->ents[0].level + 1)
			goto out;
	}

	/* last level must include lowest level */
	if (req->last_level < req->ents[nr_ents - 1].level)
		goto out;

	for (i = 2; i < nr_ents; i++) {
		/* lowers must be sorted by first key */
		if (scoutfs_key_compare(&req->ents[i].first,
					&req->ents[i - 1].first) <= 0)
			goto out;

		/* lowers must not overlap with each other */
		if (scoutfs_key_compare_ranges(&req->ents[i].first,
					       &req->ents[i].last,
					       &req->ents[i - 1].first,
					       &req->ents[i - 1].last) == 0)
			goto out;
	}

	ret = 0;
out:
	if (WARN_ON_ONCE(ret < 0)) {
		scoutfs_inc_counter(sb, compact_invalid_request);
		printk("id %llu last_level %u flags 0x%x\n",
		       le64_to_cpu(req->id), req->last_level, req->flags);
		printk("segnos: ");
		for (i = 0; i < ARRAY_SIZE(req->segnos); i++)
			printk("%llu ", le64_to_cpu(req->segnos[i]));
		printk("\n");
		printk("entries: ");
		for (i = 0; i < ARRAY_SIZE(req->ents); i++) {
			printk("  [%u] segno %llu seq %llu level %u first "SK_FMT" last "SK_FMT"\n",
				i, le64_to_cpu(req->ents[i].segno),
				le64_to_cpu(req->ents[i].seq),
				req->ents[i].level,
				SK_ARG(&req->ents[i].first),
				SK_ARG(&req->ents[i].last));
		}
		printk("\n");
	}

	return ret;
}

/*
 * Translate the compaction request into our native structs that we use
 * to perform the compaction.  The caller has verified that the request
 * satisfies our constraints.
 *
 * If we return an error the caller will clean up a partially prepared
 * cursor.
 */
static int prepare_curs(struct super_block *sb, struct compact_cursor *curs,
			struct scoutfs_net_compact_request *req)
{
	struct scoutfs_manifest_entry ment;
	struct compact_seg *cseg;
	int ret = 0;
	int i;

	curs->lower_level = req->ents[0].level + 1;
	curs->last_level = req->last_level;
	curs->sticky = !!(req->flags & SCOUTFS_NET_COMPACT_FLAG_STICKY);

	for (i = 0; i < ARRAY_SIZE(req->segnos); i++) {
		if (req->segnos[i] == 0)
			break;
		curs->segnos[i] = le64_to_cpu(req->segnos[i]);
	}
	curs->nr_segnos = i;

	for (i = 0; i < ARRAY_SIZE(req->ents); i++) {
		if (req->ents[i].segno == 0)
			break;

		scoutfs_init_ment_from_net(&ment, &req->ents[i]);

		cseg = alloc_cseg(sb, &ment.first, &ment.last);
		if (!cseg) {
			ret = -ENOMEM;
			break;
		}

		list_add_tail(&cseg->entry, &curs->csegs);

		cseg->segno = ment.segno;
		cseg->seq = ment.seq;
		cseg->level = ment.level;

		if (!curs->upper)
			curs->upper = cseg;
		else if (!curs->lower)
			curs->lower = cseg;
		if (curs->lower)
			curs->last_lower = cseg;
	}

	return ret;
}

/*
 * Perform a compaction by translating the incoming request into our
 * working state, iterating over input segments and write output
 * segments, then generating the response that describes the output
 * segments.
 *
 * The server will either commit our response or cleanup the request if
 * we return an error that the caller sends in response.  The server
 * protects the input segments so they shouldn't be overwritten by other
 * compactions or allocations.  We shouldn't get stale segment reads.
 */
int scoutfs_compact(struct super_block *sb,
		    struct scoutfs_net_compact_request *req,
		    struct scoutfs_net_compact_response *resp)
{
	struct compact_cursor curs = {{NULL,}};
	struct scoutfs_manifest_entry ment;
	struct scoutfs_bio_completion comp;
	struct compact_seg *cseg;
	LIST_HEAD(results);
	int ret;
	int err;
	int nr;

	INIT_LIST_HEAD(&curs.csegs);
	scoutfs_bio_init_comp(&comp);

	ret = verify_request(sb, req) ?:
	      prepare_curs(sb, &curs, req);
	if (ret)
		goto out;

	/* trace compaction ranges */
	list_for_each_entry(cseg, &curs.csegs, entry) {
		trace_scoutfs_compact_input(sb, cseg->level, cseg->segno,
					    cseg->seq, &cseg->first,
					    &cseg->last);
	}

	ret = compact_segments(sb, &curs, &comp, &results);

	/* always wait for io completion */
	err = scoutfs_bio_wait_comp(sb, &comp);
	if (!ret && err)
		ret = err;
	if (ret)
		goto out;

	/* fill entries for written output segments */
	nr = 0;
	list_for_each_entry(cseg, &results, entry) {
		/* XXX moved upper segments won't have read the segment :P */
		if (cseg->seg)
			scoutfs_seg_init_ment(&ment, cseg->level, cseg->seg);
		else
			scoutfs_manifest_init_entry(&ment, cseg->level,
						    cseg->segno, cseg->seq,
						    &cseg->first, &cseg->last);

		trace_scoutfs_compact_output(sb, ment.level, ment.segno,
					    ment.seq, &ment.first,
					    &ment.last);

		scoutfs_init_ment_to_net(&resp->ents[nr++], &ment);
	}

	ret = 0;
out:
	/* server protects input segments, shouldn't be possible */
	if (WARN_ON_ONCE(ret == -ESTALE)) {
		scoutfs_inc_counter(sb, compact_stale_error);
		ret = -EIO;
	}

	free_cseg_list(sb, &curs.csegs);
	free_cseg_list(sb, &results);

	return ret;
}
