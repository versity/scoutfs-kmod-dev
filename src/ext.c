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
#include <linux/fs.h>

#include "ext.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * Extents are used to track free block regions and to map logical file
 * regions to device blocks.   Extents can be split and merged as
 * they're modified.  These helpers implement all the fiddly extent
 * manipulations.  Callers provide callbacks which implement the actual
 * storage of extents in either the item cache or btree items.
 */

static void ext_zero(struct scoutfs_extent *ext)
{
	memset(ext, 0, sizeof(struct scoutfs_extent));
}

static bool ext_overlap(struct scoutfs_extent *ext, u64 start, u64 len)
{
	u64 e_end = ext->start + ext->len - 1;
	u64 end = start + len - 1;

	return !(e_end < start || ext->start > end);
}

static bool ext_inside(u64 start, u64 len, struct scoutfs_extent *out)
{
	u64 in_end = start + len - 1;
	u64 out_end = out->start + out->len - 1;

	return out->start <= start && out_end >= in_end;
}

/* we only translate mappings when they exist */
static inline u64 ext_map_add(u64 map, u64 diff)
{
	return map ? map + diff : 0;
}

/*
 * Extents can merge if they're logically contiguous, both don't have
 * mappings or have mappings which are also contiguous, and have
 * matching flags.
 */
bool scoutfs_ext_can_merge(struct scoutfs_extent *left,
			   struct scoutfs_extent *right)
{
	return (left->start + left->len == right->start) &&
	       ((!left->map && !right->map) ||
		(left->map + left->len == right->map)) &&
	       (left->flags == right->flags);
}

/*
 * Split an existing extent in to left and right extents by removing
 * an interior range.  The split extents are all zeros if the range
 * extends to their end of the extent.
 */
static void ext_split(struct scoutfs_extent *ext, u64 start, u64 len,
		      struct scoutfs_extent *left,
		      struct scoutfs_extent *right)
{
	if (ext->start < start) {
		left->start = ext->start;
		left->len = start - ext->start;
		left->map = ext->map;
		left->flags = ext->flags;
	} else {
		ext_zero(left);
	}

	if (ext->start + ext->len > start + len) {
		right->start = start + len;
		right->len = ext->start + ext->len - right->start;
		right->map = ext_map_add(ext->map, right->start - ext->start);
		right->flags = ext->flags;
	} else {
		ext_zero(right);
	}
}

#define op_call(sb, ops, arg, which, args...)			\
({								\
	int _ret;						\
	_ret = ops->which(sb, arg, ##args);			\
	scoutfs_inc_counter(sb, ext_op_##which);		\
	trace_scoutfs_ext_op_##which(sb, ##args, _ret);		\
	_ret;							\
})

struct extent_changes {
	struct scoutfs_extent exts[4];
	bool ins[4];
	u8 nr;
};

static void add_change(struct extent_changes *chg,
		       struct scoutfs_extent *ext, bool ins)
{
	BUILD_BUG_ON(ARRAY_SIZE(chg->ins) != ARRAY_SIZE(chg->exts));

	if (ext->len) {
		BUG_ON(chg->nr == ARRAY_SIZE(chg->exts));
		chg->exts[chg->nr] = *ext;
		chg->ins[chg->nr] = !!ins;
		chg->nr++;
	}
}

static int apply_changes(struct super_block *sb, struct scoutfs_ext_ops *ops,
			 void *arg, struct extent_changes *chg)
{
	int ret = 0;
	int err;
	int i;

	for (i = 0; i < chg->nr; i++) {
		if (chg->ins[i])
			ret = op_call(sb, ops, arg, insert, chg->exts[i].start,
				      chg->exts[i].len, chg->exts[i].map,
				      chg->exts[i].flags);
		else
			ret = op_call(sb, ops, arg, remove, chg->exts[i].start,
				      chg->exts[i].len, chg->exts[i].map,
				      chg->exts[i].flags);
		if (ret < 0)
			break;
	}

	while (ret < 0 && --i >= 0) {
		if (chg->ins[i])
			err = op_call(sb, ops, arg, remove, chg->exts[i].start,
				      chg->exts[i].len, chg->exts[i].map,
				      chg->exts[i].flags);
		else
			err = op_call(sb, ops, arg, insert, chg->exts[i].start,
				      chg->exts[i].len, chg->exts[i].map,
				      chg->exts[i].flags);
		BUG_ON(err); /* inconsistent */
	}

	return ret;
}

int scoutfs_ext_next(struct super_block *sb, struct scoutfs_ext_ops *ops,
		     void *arg, u64 start, u64 len, struct scoutfs_extent *ext)
{
	int ret;

	ret = op_call(sb, ops, arg, next, start, len, ext);
	trace_scoutfs_ext_next(sb, start, len, ext, ret);
	return ret;
}

/*
 * Insert the given extent.  EINVAL is returned if there's already an existing
 * overlapping extent.  This can merge with its neighbours.
 */
int scoutfs_ext_insert(struct super_block *sb, struct scoutfs_ext_ops *ops,
		       void *arg, u64 start, u64 len, u64 map, u8 flags)
{
	struct extent_changes chg = { .nr = 0 };
	struct scoutfs_extent found;
	struct scoutfs_extent ins;
	int ret;

	ins.start = start;
	ins.len = len;
	ins.map = map;
	ins.flags = flags;

	/* find right neighbour and check for overlap */
	ret = op_call(sb, ops, arg, next, start, 1, &found);
	if (ret < 0 && ret != -ENOENT)
		goto out;

	/* inserting extent must not overlap */
	if (found.len && ext_overlap(&ins, found.start, found.len)) {
		ret = -EINVAL;
		goto out;
	}

	/* merge with right if we can */
	if (found.len && scoutfs_ext_can_merge(&ins, &found)) {
		ins.len += found.len;
		add_change(&chg, &found, false);
	}

	/* see if we can merge with a left neighbour */
	if (start > 0) {
		ret = op_call(sb, ops, arg, next, start - 1,  1, &found);
		if (ret < 0 && ret != -ENOENT)
			goto out;

		if (ret == 0 && scoutfs_ext_can_merge(&found, &ins)) {
			ins.start = found.start;
			ins.map = found.map;
			ins.len += found.len;
			add_change(&chg, &found, false);
		}
	}

	add_change(&chg, &ins, true);
	ret = apply_changes(sb, ops, arg, &chg);
out:
	trace_scoutfs_ext_insert(sb, start, len, map, flags, ret);
	return ret;
}

/*
 * Remove the given extent.  The extent to remove must be found entirely
 * in an existing extent.  If the existing extent is larger then we leave
 * behind the remaining extent.  The existing extent can be split.
 */
int scoutfs_ext_remove(struct super_block *sb, struct scoutfs_ext_ops *ops,
		       void *arg, u64 start, u64 len)
{
	struct extent_changes chg = { .nr = 0 };
	struct scoutfs_extent found;
	struct scoutfs_extent left;
	struct scoutfs_extent right;
	int ret;

	ret = op_call(sb, ops, arg, next, start, 1, &found);
	if (ret < 0)
		goto out;

	/* removed extent must be entirely within found */
	if (!ext_inside(start, len, &found)) {
		ret = -EINVAL;
		goto out;
	}

	ext_split(&found, start, len, &left, &right);

	add_change(&chg, &found, false);
	add_change(&chg, &left, true);
	add_change(&chg, &right, true);

	ret = apply_changes(sb, ops, arg, &chg);
out:
	trace_scoutfs_ext_remove(sb, start, len, 0, 0, ret);
	return ret;
}

/*
 * Find and remove the next extent, removing only a portion if the
 * extent is larger than the count.  Returns ENOENT if it didn't
 * find any extents.
 *
 * This does not search for merge candidates so it's safe to call with
 * extents indexed by length.
 */
int scoutfs_ext_alloc(struct super_block *sb, struct scoutfs_ext_ops *ops,
		      void *arg, u64 start, u64 len, u64 count,
		      struct scoutfs_extent *ext)
{
	struct extent_changes chg = { .nr = 0 };
	struct scoutfs_extent found;
	struct scoutfs_extent ins;
	int ret;

	ret = op_call(sb, ops, arg, next, start, len, &found);
	if (ret < 0)
		goto out;

	add_change(&chg, &found, false);

	if (found.len > count) {
		ins.start = found.start + count;
		ins.len = found.len - count;
		ins.map = ext_map_add(found.map, count);
		ins.flags = found.flags;

		add_change(&chg, &ins, true);
	}

	ret = apply_changes(sb, ops, arg, &chg);
out:
	if (ret == 0) {
		ext->start = found.start;
		ext->len = min(found.len, count);
		ext->map = found.map;
		ext->flags = found.flags;
	} else {
		ext_zero(ext);
	}

	trace_scoutfs_ext_alloc(sb, start, len, count, ext, ret);
	return ret;
}

/*
 * Set the map and flags for an extent region, with the magical property
 * that extents with map and flags set to 0 are removed.
 *
 * If we're modifying an existing extent then the modification must be
 * fully inside the existing extent.  The modification can leave edges
 * of the extent which need to be inserted.  If the modification extends
 * to the end of the existing extent then we need to check for adjacent
 * neighbouring extents which might now be able to be merged.
 *
 * Inserting a new extent is like the case of modifying the entire
 * existing extent.  We need to check neighbours of the inserted extent
 * to see if they can be merged.
 */
int scoutfs_ext_set(struct super_block *sb, struct scoutfs_ext_ops *ops,
		    void *arg, u64 start, u64 len, u64 map, u8 flags)
{
	struct extent_changes chg = { .nr = 0 };
	struct scoutfs_extent found;
	struct scoutfs_extent left;
	struct scoutfs_extent right;
	struct scoutfs_extent set;
	int ret;

	set.start = start;
	set.len = len;
	set.map = map;
	set.flags = flags;

	/* find extent to remove */
	ret = op_call(sb, ops, arg, next, start, 1, &found);
	if (ret < 0 && ret != -ENOENT)
		goto out;

	if (ret == 0 && ext_overlap(&found, start, len)) {
		/* set extent must be entirely within found */
		if (!ext_inside(start, len, &found)) {
			ret = -EINVAL;
			goto out;
		}

		add_change(&chg, &found, false);
		ext_split(&found, start, len, &left, &right);
	} else {
		ext_zero(&found);
		ext_zero(&left);
		ext_zero(&right);
	}

	if (left.len) {
		/* inserting split left, won't merge */
		add_change(&chg, &left, true);
	} else if (start > 0) {
		ret = op_call(sb, ops, arg, next, start - 1, 1, &left);
		if (ret < 0 && ret != -ENOENT)
			goto out;
		else if (ret == 0 && scoutfs_ext_can_merge(&left, &set)) {
			/* remove found left, merging */
			set.start = left.start;
			set.map = left.map;
			set.len += left.len;
			add_change(&chg, &left, false);
		}
	}

	if (right.len) {
		/* inserting split right, won't merge */
		add_change(&chg, &right, true);
	} else {
		ret = op_call(sb, ops, arg, next, start + len, 1, &right);
		if (ret < 0 && ret != -ENOENT)
			goto out;
		else if (ret == 0 && scoutfs_ext_can_merge(&set, &right)) {
			/* remove found right, merging */
			set.len += right.len;
			add_change(&chg, &right, false);
		}
	}

	if (set.flags || set.map)
		add_change(&chg, &set, true);

	ret = apply_changes(sb, ops, arg, &chg);
out:
	trace_scoutfs_ext_set(sb, start, len, map, flags, ret);
	return ret;
}
