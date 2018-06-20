/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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

#include "extents.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "msg.h"

/*
 * These low level functions take on the fiddly details of extent
 * manipulation.  Callers handle serialization and storage and call in
 * here to add or remove extents.  This slices and dices the extents
 * while dodging all the fence posts.
 */

/* return the last logical position that is in the extent, inclusive */
static u64 extent_end(struct scoutfs_extent *ext)
{
	return ext->start + ext->len - 1;
}

/* returns true if the two extents overlap */
static bool extents_overlap(struct scoutfs_extent *a, struct scoutfs_extent *b)
{
	return extent_end(a) >= b->start && a->start <= extent_end(b);
}

/* Returns true if a is entirely within b */
static bool extent_within(struct scoutfs_extent *a, struct scoutfs_extent *b)
{
	return a->start >= b->start && extent_end(a) <= extent_end(b);
}

/*
 * Returns true if two extents can be merged because they're adjacent,
 * mapping is equally set or not, mappings are adjacent if they're set,
 * and all the rest of the fields match.
 */
static bool extents_can_merge(struct scoutfs_extent *a,
			      struct scoutfs_extent *b)
{
	if (a->start > b->start)
		swap(a, b);

	return (a->owner == b->owner) &&
	       ((a->start + a->len) == b->start) &&
	       (!!a->map == !!b->map) &&
	       (!a->map || ((a->map + a->len) == b->map)) &&
	       (a->type == b->type) &&
	       (a->flags == b->flags);
}

int scoutfs_extent_init(struct scoutfs_extent *ext, u8 type, u64 owner,
			u64 start, u64 len, u64 map, u8 flags)
{
	/* don't allow 0 len or len wrapping map or start */
	if ((start + len <= start) || (map + len <= map))
		return -EIO;

	ext->owner = owner;
	ext->start = start;
	ext->len = len;
	ext->map = map;
	ext->type = type;
	ext->flags = flags;

	return 0;
}

/*
 * Returns true if the two extents intersect and modifies a to be the
 * intersection of the two extents.  Callers only need to initialize a's
 * start and len when probing for an intersection and we'll copy the
 * rest from b.
 */
bool scoutfs_extent_intersection(struct scoutfs_extent *a,
				 struct scoutfs_extent *b)
{
	u64 new_start;
	u64 new_end;

	if (extents_overlap(a, b)) {
		new_end = min(extent_end(a), extent_end(b));
		new_start = max(a->start, b->start);

		a->owner = b->owner;
		a->start = new_start;
		a->len = new_end - new_start + 1;
		a->map = b->map ? (new_start - b->start) + b->map: 0;
		a->type = b->type;
		a->flags = b->flags;
		return true;
	}

	return false;
}

static int extent_insert(struct super_block *sb, scoutfs_extent_io_t iof,
			 struct scoutfs_extent *ins, void *data)
{
	scoutfs_inc_counter(sb, extent_insert);
	trace_scoutfs_extent_insert(sb, ins);
	return iof(sb, SEI_INSERT, ins, data);
}

static int extent_delete(struct super_block *sb, scoutfs_extent_io_t iof,
			 struct scoutfs_extent *del, void *data)
{
	scoutfs_inc_counter(sb, extent_delete);
	trace_scoutfs_extent_delete(sb, del);
	return iof(sb, SEI_DELETE, del, data);
}

/*
 * Find the next extent using the given extent as the starting search
 * position.  This just passes the extent through to the underlying key
 * building and searching routines.
 *
 * Callers have to be very careful when building the search extent.
 * Most extents are indexed by their final logical position and some
 * have all the metadata in the key.  So a typical pattern is to search
 * for an intersection by searching from a single block extent with the
 * rest of the fields set to zero.
 *
 * But some callers are searching indexes of free extents where both the
 * length and start are meaningful.
 *
 * The io function is responsible for ensuring that we return next
 * extents with the same type and owner as the given extent.
 */
int scoutfs_extent_next(struct super_block *sb, scoutfs_extent_io_t iof,
			struct scoutfs_extent *ext, void *data)
{
	int ret;

	scoutfs_inc_counter(sb, extent_next);
	trace_scoutfs_extent_next_input(sb, ext);
	ret = iof(sb, SEI_NEXT, ext, data);
	if (ret == 0)
		trace_scoutfs_extent_next_output(sb, ext);
	return ret;
}

int scoutfs_extent_prev(struct super_block *sb, scoutfs_extent_io_t iof,
			struct scoutfs_extent *ext, void *data)
{
	int ret;

	scoutfs_inc_counter(sb, extent_prev);
	trace_scoutfs_extent_prev_input(sb, ext);
	ret = iof(sb, SEI_PREV, ext, data);
	if (ret == 0)
		trace_scoutfs_extent_prev_output(sb, ext);
	return ret;
}

/*
 * Search for a next extent and see if we can merge it with the caller's
 * extent.  The caller has initialized next for us to search from.  If
 * we can merge then we update the callers extent, delete the old
 * extent, and return 1.  If we return an error or 0 then nothing will
 * have changed.
 */
static int try_merge_next(struct super_block *sb, scoutfs_extent_io_t iof,
			  struct scoutfs_extent *ext,
			  struct scoutfs_extent *next, void *data)
{
	int ret;

	ret = scoutfs_extent_next(sb, iof, next, data);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	if (extents_overlap(ext, next)) {
		ret = -EIO;
		goto out;
	}

	if (!extents_can_merge(ext, next)) {
		ret = 0;
		goto out;
	}

	if (next->start < ext->start) {
		ext->start = next->start;
		ext->map = next->map;
		ext->len += next->len;
	} else {
		ext->len += next->len;
	}

	ret = extent_delete(sb, iof, next, data);
	if (ret == 0)
		ret = 1;
out:
	return ret;
}

/*
 * Add a new extent.  It can not overlap with any existing extents.  It
 * may be merged with neighbouring extents.
 */
int scoutfs_extent_add(struct super_block *sb, scoutfs_extent_io_t iof,
		       struct scoutfs_extent *add, void *data)
{
	struct scoutfs_extent right;
	struct scoutfs_extent left;
	struct scoutfs_extent ext;
	bool ins_left = false;
	bool ins_right = false;
	int ret;

	scoutfs_inc_counter(sb, extent_add);
	trace_scoutfs_extent_add(sb, add);
	ext = *add;

	/* see if we are merging with and deleting a left neighbour */
	if (ext.start) {
		scoutfs_extent_init(&left, ext.type, ext.owner,
				    ext.start - 1, 1, 0, 0);
		ret = try_merge_next(sb, iof, &ext, &left, data);
		if (ret < 0)
			goto out;
		if (ret > 0)
			ins_left = true;
	}

	/* see if we are merging with and deleting a right neighbour */
	if (ext.start + ext.len <= SCOUTFS_BLOCK_MAX) {
		scoutfs_extent_init(&right, ext.type, ext.owner,
				    ext.start, 1, 0, 0);
		ret = try_merge_next(sb, iof, &ext, &right, data);
		if (ret < 0)
			goto out;
		if (ret > 0)
			ins_right = true;
	}

	/* finally insert our new (possibly merged) extent */
	ret = extent_insert(sb, iof, &ext, data);
out:
	scoutfs_extent_cleanup(ret < 0 && ins_right, extent_insert, sb, iof,
			       &right, data, SC_EXTENT_ADD_CLEANUP,
			       corrupt_extent_add_cleanup, add);
	scoutfs_extent_cleanup(ret < 0 && ins_left, extent_insert, sb, iof,
			       &left, data, SC_EXTENT_ADD_CLEANUP,
			       corrupt_extent_add_cleanup, add);
	return ret;
}


/*
 * Remove a region of an existing extent.  The region to remove must be
 * be fully within an existing extent.  This creates the items left
 * behind on either end of the removed region as appropriate.
 */
int scoutfs_extent_remove(struct super_block *sb, scoutfs_extent_io_t iof,
			  struct scoutfs_extent *rem, void *data)
{
	struct scoutfs_extent right;
	struct scoutfs_extent left;
	struct scoutfs_extent ext;
	bool ins_ext = false;
	bool del_left = false;
	int ret;

	scoutfs_inc_counter(sb, extent_remove);
	trace_scoutfs_extent_remove(sb, rem);

	scoutfs_extent_init(&ext, rem->type, rem->owner, rem->start, 1, 0, 0);
	ret = scoutfs_extent_next(sb, iof, &ext, data);
	if (ret < 0)
		goto out;

	/* make sure they're correct */
	if (!extent_within(rem, &ext)) {
		ret = -EIO;
		goto out;
	}

	ret = extent_delete(sb, iof, &ext, data);
	if (ret)
		goto out;
	ins_ext = true;

	if (rem->start != ext.start) {
		scoutfs_extent_init(&left, ext.type, ext.owner,
				    ext.start, rem->start - ext.start,
				    ext.map, ext.flags);
		ret = extent_insert(sb, iof, &left, data);
		if (ret)
			goto out;
		del_left = true;
	}

	if (extent_end(rem) != extent_end(&ext)) {
		scoutfs_extent_init(&right, ext.type, ext.owner,
				    rem->start + rem->len,
				    extent_end(&ext) - extent_end(rem),
				    ext.map ? rem->map + rem->len : 0,
				    ext.flags);
		ret = extent_insert(sb, iof, &right, data);
	}

out:
	scoutfs_extent_cleanup(ret < 0 && del_left, extent_delete, sb, iof,
			       &left, data, SC_EXTENT_REM_CLEANUP,
			       corrupt_extent_rem_cleanup, rem);
	scoutfs_extent_cleanup(ret < 0 && ins_ext, extent_insert, sb, iof,
			       &ext, data, SC_EXTENT_REM_CLEANUP,
			       corrupt_extent_rem_cleanup, rem);
	return ret;
}
