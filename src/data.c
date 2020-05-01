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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/falloc.h>
#include <linux/writeback.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "data.h"
#include "kvec.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "forest.h"
#include "ioctl.h"
#include "btree.h"
#include "lock.h"
#include "file.h"
#include "msg.h"
#include "count.h"
#include "radix.h"

/*
 * Logical file blocks are mapped to device blocks with extents stored
 * in items.  Each extent item maps a fixed size logical region and can
 * contain multiple extent records.  Each extent record is packed to
 * minimize the space it uses.  The logical starting block is implicit
 * so sparse extents are stored to skip unmapped blocks, and the mapped
 * blkno is encoded as the difference from the previous extent and only
 * its set bytes are stored.
 *
 * To operate on the extents we load their item and unpack them into an
 * rbtree of full extent records in memory.  Once the memory extents are
 * modified they can be packed back into the item.  Typically there are
 * very few extents that cover the region.
 *
 * The client is given a radix allocator with trees for allocating
 * blocks and recording frees at the start of each transaction.
 */

struct data_info {
	struct super_block *sb;
	struct rw_semaphore alloc_rwsem;
	struct scoutfs_radix_allocator *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_radix_root data_avail;
	struct scoutfs_radix_root data_freed;
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

static void init_packed_extent_key(struct scoutfs_key *key, u64 ino,
				   u64 iblock, u8 part)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skpe_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_PACKED_EXTENT_TYPE,
		.skpe_base = cpu_to_le64(iblock >> SCOUTFS_PACKEXT_BASE_SHIFT),
		.skpe_part = part,
	};
}

/*
 * Packed extents are read from items and unpacked into this structure
 * in memory so they can be easily manipulated before being packed and
 * stored in items.
 */
struct unpacked_extents {
	u64 iblock;
	struct rb_root extents;
	__u8 existing_parts;
	bool changed;
};

struct unpacked_extent {
	struct rb_node node;
	u64 iblock;
	u64 count;
	u64 blkno;
	u8 flags;
};

static void init_traced_extent(struct scoutfs_traced_extent *te,
			       u64 iblock, u64 count, u64 blkno, u8 flags)
{
	te->iblock = iblock;
	te->count = count;
	te->blkno = blkno;
	te->flags = flags;
}

static void copy_traced_extent(struct scoutfs_traced_extent *te,
			       struct unpacked_extent *ext)
{
	te->iblock = ext->iblock;
	te->count = ext->count;
	te->blkno = ext->blkno;
	te->flags = ext->flags;
}

static u64 ext_last(struct unpacked_extent *ext)
{
	return ext->iblock + ext->count - 1;
}

/* The first possible iblock in an item that contains the given iblock */
static u64 first_iblock(u64 iblock)
{
	return iblock & SCOUTFS_PACKEXT_BASE_MASK;
}

/* The last possible iblock in an item that contains the given iblock */
static u64 last_iblock(u64 iblock)
{
	return iblock | ~SCOUTFS_PACKEXT_BASE_MASK;
}

/*
 * Extents can merge if they're logically contiguous, have block
 * mappings or not which also must be contiguous, and have matching
 * flags.
 *
 * We also require that a given extent's allocation be from only one
 * radix bitmap leaf block because the radix freeing functions only
 * operate on one leaf block.
 */
static bool extents_merge(struct unpacked_extent *left,
			  struct unpacked_extent *right)
{
	return (left->iblock + left->count == right->iblock) &&
	       ((!left->blkno && !right->blkno) ||
	        (left->blkno + left->count == right->blkno)) &&
	       (left->flags == right->flags) &&
	       (scoutfs_radix_bit_leaf_nr(left->blkno) ==
	        scoutfs_radix_bit_leaf_nr(right->blkno + right->count - 1));
}

static struct unpacked_extent *first_extent(struct unpacked_extents *unpe)
{
	return rb_entry_safe(rb_first(&unpe->extents),
			     struct unpacked_extent, node);
}

static struct unpacked_extent *last_extent(struct unpacked_extents *unpe)
{
	return rb_entry_safe(rb_last(&unpe->extents),
			     struct unpacked_extent, node);
}

static struct unpacked_extent *next_extent(struct unpacked_extent *ext)
{
	return rb_entry_safe(rb_next(&ext->node),
			     struct unpacked_extent, node);
}

static struct unpacked_extent *prev_extent(struct unpacked_extent *ext)
{
	return rb_entry_safe(rb_prev(&ext->node),
			     struct unpacked_extent, node);
}

/*
 * Find the first extent that intersects the requested range.  NULL is
 * returned if no extents intersect.
 */
static struct unpacked_extent *find_extent(struct unpacked_extents *unpe,
					   u64 iblock, u64 last)
{

	struct rb_node *node = unpe->extents.rb_node;
	struct unpacked_extent *ret = NULL;
	struct unpacked_extent *ext;

	if (iblock > last)
		return NULL;

	while (node) {
		ext = rb_entry(node, struct unpacked_extent, node);

		if (last < ext->iblock) {
			node = node->rb_left;
		} else if (iblock > ext_last(ext)) {
			node = node->rb_right;
		} else {
			ret = ext;
			node = node->rb_left;
		}
	}

	return ret;
}

static void track_blocks(struct unpacked_extent *ext, s64 delta,
			 s64 *on, s64 *off)
{
	if (ext->blkno && !(ext->flags & SEF_UNWRITTEN))
		*on += delta;
	else if (ext->flags & SEF_OFFLINE)
		*off += delta;
}

static void modify_and_track_count(struct unpacked_extent *ext, u64 count,
				   s64 *on, s64 *off)
{
	track_blocks(ext, count - ext->count, on, off);
	ext->count = count;
}

/*
 * Callers can temporarily insert extents with equal starting iblocks.
 * We're careful to insert those to the left so that caller's can find
 * these existing overlapping extents by iterating with next.
 */
static void insert_extent(struct unpacked_extents *unpe,
			  struct unpacked_extent *ins, s64 *on, s64 *off)
{
	struct rb_node **node = &unpe->extents.rb_node;
	struct rb_node *parent = NULL;
	struct unpacked_extent *ext;
	int cmp;

	while (*node) {
		parent = *node;
		ext = rb_entry(*node, struct unpacked_extent, node);

		cmp = scoutfs_cmp_u64s(ins->iblock, ext->iblock);
		if (cmp <= 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, &unpe->extents);

	track_blocks(ins, ins->count, on, off);
}

static void remove_extent(struct unpacked_extents *unpe,
			  struct unpacked_extent *ext, s64 *on, s64 *off)
{
	rb_erase(&ext->node, &unpe->extents);
	track_blocks(ext, -ext->count, on, off);
	kfree(ext);
}

static void free_unpacked_extents(struct unpacked_extents *unpe)
{
	struct unpacked_extent *ext;
	struct unpacked_extent *tmp;

	if (unpe) {
		rbtree_postorder_for_each_entry_safe(ext, tmp, &unpe->extents,
						     node) {
			kfree(ext);
		}
		kfree(unpe);
	}
}

static int unpack_extent(struct unpacked_extent *ext, u64 iblock,
			 struct scoutfs_packed_extent *pe, int size,
			 u64 prev_blkno)
{
	__le64 lediff;
	u64 blkno;
	u64 diff;

	if (size < sizeof(struct scoutfs_packed_extent) ||
	    size < (sizeof(struct scoutfs_packed_extent) + pe->diff_bytes))
		return 0;

	if (pe->diff_bytes) {
		lediff = 0;
		memcpy(&lediff, pe->le_blkno_diff, pe->diff_bytes);
		diff = le64_to_cpu(lediff);
		diff = (diff >> 1) ^ (-(diff & 1));
		blkno = prev_blkno + diff;
	} else {
		blkno = 0;
	}

	ext->iblock = iblock;
	ext->blkno = blkno;
	ext->count = le16_to_cpu(pe->count);
	ext->flags = pe->flags;

	return sizeof(struct scoutfs_packed_extent) + pe->diff_bytes;
}

static int load_unpacked_extents(struct super_block *sb, u64 ino,
				 u64 iblock, u64 last, bool empty_enoent,
				 struct unpacked_extents **unpe_ret,
				 struct scoutfs_lock *lock)
{
	struct unpacked_extents *unpe = NULL;
	struct scoutfs_packed_extent *pe;
	struct unpacked_extent *ext;
	struct scoutfs_key key;
	struct scoutfs_key end;
	struct rb_node *parent;
	struct rb_node **node;
	void *buf = NULL;
	struct kvec val;
	u64 prev_blkno;
	bool saw_final;
	int size;
	int ret;
	int p;

	*unpe_ret = NULL;

	unpe = kzalloc(sizeof(struct unpacked_extents), GFP_NOFS);
	if (!unpe) {
		ret = -ENOMEM;
		goto out;
	}

	unpe->extents = RB_ROOT;
	unpe->changed = true;
	/* updated later if _next gives us a greater key */
	unpe->iblock = first_iblock(iblock);

	buf = kmalloc(SCOUTFS_PACKEXT_MAX_BYTES, GFP_NOFS);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	if (last > iblock)
		init_packed_extent_key(&end, ino, last, 0);

	parent = NULL;
	node = &unpe->extents.rb_node;
	prev_blkno = 0;
	saw_final = false;

	for (p = 0; !saw_final; p++) {
		init_packed_extent_key(&key, ino, iblock, p);
		kvec_init(&val, buf, SCOUTFS_PACKEXT_MAX_BYTES);

		/* maybe search for next initial item, lookup more parts */
		if (p == 0 && last > iblock)
			ret = scoutfs_forest_next(sb, &key, &end, &val, lock);
		else
			ret = scoutfs_forest_lookup(sb, &key, &val, lock);
		if (ret < 0) {
			if (p == 0 && ret == -ENOENT && empty_enoent)
				ret = 0;
			goto out;
		}

		if (key.skpe_part != p) {
			ret = -EIO; /* corruption */
			goto out;
		}

		if (p == 0) {
			iblock = le64_to_cpu(key.skpe_base) <<
					SCOUTFS_PACKEXT_BASE_SHIFT;
			unpe->iblock = iblock;
		}
		pe = buf;
		size = ret;

		while (size > 0) {
			ext = kmalloc(sizeof(struct unpacked_extent), GFP_NOFS);
			if (!ext) {
				ret = -ENOMEM;
				goto out;
			}

			ret = unpack_extent(ext, iblock, pe, size, prev_blkno);
			if (ret == 0) { /* XXX corruption? */
				kfree(ext);
				ret = -EIO;
				goto out;
			}

			saw_final = pe->final;
			pe = (void *)pe + ret;
			size -= ret;

			/* sparse packed extents advance iblock */
			if (ext->flags == 0 && ext->blkno == 0) {
				iblock += ext->count;
				kfree(ext);
				ext = NULL;
				continue;
			}

			iblock += ext->count;
			prev_blkno = ext->blkno + ext->count - 1;

			/* building the rbtree from sorted nodes */
			rb_link_node(&ext->node, parent, node);
			rb_insert_color(&ext->node, &unpe->extents);
			parent = &ext->node;
			node = &ext->node.rb_right;

			if (saw_final)
				unpe->existing_parts = p + 1;
		}
	}

	ret = 0;
out:
	kfree(buf);
	if (ret < 0)
		free_unpacked_extents(unpe);
	else
		*unpe_ret = unpe;

	return ret;
}

static int pack_extent(struct scoutfs_packed_extent *pe, int size,
		       struct unpacked_extent *ext,
		       u64 prev_blkno, bool final)
{
	int diff_bytes;
	__le64 lediff;
	u64 diff;
	int bytes;
	int last;

	diff = ext->blkno - prev_blkno;
	diff = (diff << 1) ^ ((s64)diff >> 63); /* shift sign extend */
	lediff = cpu_to_le64(diff);
	last = fls64(diff);
	diff_bytes = (last + 7) >> 3;

	bytes = offsetof(struct scoutfs_packed_extent,
			 le_blkno_diff[diff_bytes]);
	if (size < bytes)
		return 0;

	pe->count = cpu_to_le16(ext->count);
	pe->diff_bytes = diff_bytes;
	pe->flags = ext->flags;
	pe->final = !!final;
	if (diff_bytes)
		memcpy(pe->le_blkno_diff, &lediff, diff_bytes);

	return bytes;
}

static int store_packed_extents(struct super_block *sb, u64 ino,
				struct unpacked_extents *unpe,
				struct scoutfs_lock *lock)
{
	struct scoutfs_packed_extent *pe;
	struct unpacked_extent *final;
	struct unpacked_extent *ext;
	struct scoutfs_key key;
	struct kvec val;
	void *buf = NULL;
	u64 prev_blkno;
	u64 iblock;
	int space;
	int size;
	int ret;
	int p;
	int i;

	if (!unpe->changed)
		return 0;

	if (RB_EMPTY_ROOT(&unpe->extents)) {
		for (p = 0; p < unpe->existing_parts; p++) {
			init_packed_extent_key(&key, ino, unpe->iblock, p);
			ret = scoutfs_forest_delete(sb, &key, lock);
			BUG_ON(ret); /* XXX inconsistent between parts */
		}
		unpe->existing_parts = 0;
		unpe->changed = false;
		return 0;
	}

	buf = kmalloc(SCOUTFS_PACKEXT_MAX_BYTES, GFP_NOFS);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	final = last_extent(unpe);
	prev_blkno = 0;

	pe = buf;
	space = SCOUTFS_PACKEXT_MAX_BYTES;
	size = 0;
	p = 0;
	iblock = unpe->iblock;

	ext = first_extent(unpe);
	while (ext) {
		/* encode sparse extent to advance iblock */
		if (ext->iblock > iblock && space >= sizeof(*pe)) {
			pe->count = cpu_to_le16(ext->iblock - iblock);
			pe->diff_bytes = 0;
			pe->flags = 0;
			pe->final = 0;
			pe++;
			space -= sizeof(*pe);
			size += sizeof(*pe);
			iblock = ext->iblock;
		}

		/* encode actual extent */
		if (ext->iblock == iblock &&
		    (ret = pack_extent(pe, space, ext, prev_blkno,
				       ext == final)) > 0) {
			pe = (void *)pe + ret;
			space -= ret;
			size += ret;
			iblock += ext->count;
			prev_blkno = ext->blkno + ext->count - 1;
			ext = next_extent(ext);
			if (ext)
				continue;
		}

		/* store full item or after packing final extent */
		init_packed_extent_key(&key, ino, unpe->iblock, p);
		kvec_init(&val, buf, size);
		if (p < unpe->existing_parts)
			ret = scoutfs_forest_update(sb, &key, &val, lock);
		else
			ret = scoutfs_forest_create(sb, &key, &val, lock);
		BUG_ON(ret); /* XXX inconsistent between parts */

		pe = buf;
		space = SCOUTFS_PACKEXT_MAX_BYTES;
		size = 0;
		p++;
	}

	/* delete any remaining previous part items */
	for (i = p; i < unpe->existing_parts; i++) {
		init_packed_extent_key(&key, ino, unpe->iblock, i);
		ret = scoutfs_forest_delete(sb, &key, lock);
		BUG_ON(ret); /* XXX inconsistent between parts */
	}

	/* the next store has to know our stored parts */
	unpe->existing_parts = p;
	unpe->changed = false;
	ret = 0;
out:
	kfree(buf);

	return ret;
}

/*
 * Set a logical extent mapping in the unpacked extents for a region of
 * a file.  The caller's extent is authoritative, any existing
 * overlapping extents are trimmed or removed.  The new extent can be
 * merged with remaining adjacent and compatible extents.
 *
 * If the caller provides an inode struct then we'll keep the inode
 * block counts in sync with flagged extents because updating the inode
 * counts won't fail.  The caller is expected to keep all other state
 * consistent with the extents (i_size, i_blocks, allocator bitmaps).
 */
static int set_extent(struct super_block *sb, struct inode *inode,
		      u64 ino, struct unpacked_extents *unpe,
		      u64 iblock, u64 blkno, u64 count, u8 flags)
{
	struct unpacked_extent *split;
	struct unpacked_extent *next;
	struct unpacked_extent *prev;
	struct unpacked_extent *ext;
	u64 offset;
	s64 on = 0;
	s64 off = 0;

	/* make sure the given extent fits entirely within one item */
	if (WARN_ON_ONCE(first_iblock(iblock) !=
			 first_iblock(iblock + count - 1)))
		return -EINVAL;

	ext = kmalloc(sizeof(struct unpacked_extent), GFP_NOFS);
	split = kmalloc(sizeof(struct unpacked_extent), GFP_NOFS);
	if (!ext || !split) {
		kfree(ext);
		kfree(split);
		return -ENOMEM;
	}

	unpe->changed = true;

	ext->iblock = iblock;
	ext->blkno = blkno;
	ext->count = count;
	ext->flags = flags;

	insert_extent(unpe, ext, &on, &off);

	prev = prev_extent(ext);

	/* splitting an existing extent? */
	if (prev && ext_last(prev) > ext_last(ext)) {
		split->iblock = ext_last(ext) + 1;
		split->count = ext_last(prev) - split->iblock + 1;
		split->blkno = prev->blkno ?
			       prev->blkno + prev->count - split->count : 0;
		split->flags = prev->flags;

		modify_and_track_count(prev, ext->iblock - prev->iblock,
				       &on, &off);

		insert_extent(unpe, split, &on, &off);
		next = split;
		split = NULL;
	} else {
		next = NULL;
	}

	/* trimming a prev extent? */
	if (prev && ext_last(prev) >= ext->iblock) {
		modify_and_track_count(prev, ext->iblock - prev->iblock,
				       &on, &off);
	}

	/* merging with a prev extent? */
	if (prev && extents_merge(prev, ext)) {
		ext->iblock = prev->iblock;
		ext->blkno = prev->blkno;
		modify_and_track_count(ext, ext->count + prev->count,
				       &on, &off);
		remove_extent(unpe, prev, &on, &off);
	}

	/* if didn't split find next, removing any totally within ours */
	if (!next) {
		while ((next = next_extent(ext)) &&
		       ext_last(next) <= ext_last(ext)) {
			remove_extent(unpe, next, &on, &off);
		}
	}

	/* trimming a next extent? */
	if (next && next->iblock <= ext_last(ext)) {
		offset = (ext_last(ext) + 1) - next->iblock;
		next->iblock += offset;
		next->blkno = next->blkno ?  next->blkno + offset : 0;
		modify_and_track_count(next, next->count - offset,
				       &on, &off);
	}

	/* merging with a next extent? */
	if (next && extents_merge(ext, next)) {
		modify_and_track_count(ext, ext->count + next->count,
				       &on, &off);
		remove_extent(unpe, next, &on, &off);
	}

	/* and finally remove our extent if it was only removing others */
	if (ext->blkno == 0 && ext->flags == 0)
		remove_extent(unpe, ext, &on, &off);

	if (inode)
		scoutfs_inode_add_onoff(inode, on, off);

	kfree(split);
	return 0;
}

/*
 * Find and remove or mark offline the block mappings that intersect
 * with the caller's range.  The caller is responsible for transactions
 * and locks.
 *
 * Returns:
 *  - -errno on errors
 *  - 0 if there are no more extents to stop iteration
 *  - +iblock of next logical block to truncate the next block from
 */
static s64 truncate_extents(struct super_block *sb, struct inode *inode,
			    u64 ino, u64 iblock, u64 last, bool offline,
			    struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct unpacked_extents *unpe = NULL;
	struct unpacked_extent *ext;
	struct scoutfs_traced_extent te;
	u64 offset;
	u64 blkno;
	u64 count;
	u8 flags;
	s64 ret;
	int err;

	ret = load_unpacked_extents(sb, ino, iblock, last, false, &unpe, lock);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	flags = offline ? SEF_OFFLINE : 0;

	ret = 0;
	ext = find_extent(unpe, iblock, last);
	while (ext && ext->iblock <= last) {

		/* nothing to do when already offline and unmapped */
		if ((offline && (ext->flags & SEF_OFFLINE)) && !ext->blkno) {
			ext = next_extent(ext);
			continue;
		}

		iblock = max(ext->iblock, iblock);
		offset = iblock - ext->iblock;
		blkno = ext->blkno + offset;
		count = min(ext->count - offset, last - iblock + 1);

		if (ext->blkno) {
			down_write(&datinf->alloc_rwsem);
			err = scoutfs_radix_free_data(sb, datinf->alloc,
						      datinf->wri,
						      &datinf->data_freed,
						      blkno, count);
			up_write(&datinf->alloc_rwsem);
			if (err < 0) {
				ret = err;
				break;
			}
		}

		init_traced_extent(&te, iblock, count, 0, flags);
		trace_scoutfs_data_extent_truncated(sb, ino, &te);

		err = set_extent(sb, inode, ino, unpe, iblock, 0, count, flags);
		BUG_ON(err);  /* inconsistent alloc and extents */

		/* modifying could have merged and deleted ext, search again */
		iblock += count;
		if (iblock > last)
			break;
		ext = find_extent(unpe, iblock, last);
	}

	err = store_packed_extents(sb, ino, unpe, lock);
	BUG_ON(err);  /* inconsistent alloc and extents */

	/* continue after the packed extent item if we exhausted extents */
	if (ret == 0)
		ret = unpe->iblock + SCOUTFS_PACKEXT_BLOCKS;
out:
	free_unpacked_extents(unpe);
	return ret;
}

/*
 * Free blocks inside the logical block range from 'iblock' to 'last',
 * inclusive.
 *
 * If 'offline' is given then blocks are freed an offline mapping is
 * left behind.  Only blocks that have been allocated can be marked
 * offline.
 *
 * If the inode is provided then we update its tracking of the online
 * and offline blocks.  If it's not provided then the inode is being
 * destroyed and isn't reachable, we don't need to update it.
 *
 * The caller is in charge of locking the inode and data, but we may
 * have to modify far more items than fit in a transaction so we're in
 * charge of batching updates into transactions.  If the inode is
 * provided then we're responsible for updating its item as we go.
 */
int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_item_count cnt = SIC_TRUNC_EXTENT(inode);
	LIST_HEAD(ind_locks);
	s64 ret = 0;

	WARN_ON_ONCE(inode && !mutex_is_locked(&inode->i_mutex));

	/* clamp last to the last possible block? */
	if (last > SCOUTFS_BLOCK_SM_MAX)
		last = SCOUTFS_BLOCK_SM_MAX;

	trace_scoutfs_data_truncate_items(sb, iblock, last, offline);

	if (WARN_ON_ONCE(last < iblock))
		return -EINVAL;

	while (iblock <= last) {
		if (inode)
			ret = scoutfs_inode_index_lock_hold(inode, &ind_locks,
							    true, cnt);
		else
			ret = scoutfs_hold_trans(sb, cnt);
		if (ret)
			break;

		if (inode)
			ret = scoutfs_dirty_inode_item(inode, lock);
		else
			ret = 0;

		if (ret == 0)
			ret = truncate_extents(sb, inode, ino, iblock, last,
					       offline, lock);

		if (inode)
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		scoutfs_release_trans(sb);
		if (inode)
			scoutfs_inode_index_unlock(sb, &ind_locks);

		if (ret <= 0)
			break;

		iblock = ret;
		ret = 0;
	}

	return ret;
}

/*
 * The caller is writing to a logical iblock that doesn't have an
 * allocated extent.
 *
 * We always allocate an extent starting at the logical iblock.  The
 * caller has searched for an extent containing iblock.  If it already
 * existed then it must be unallocated and offline.
 *
 * Preallocation is used if we're strictly contiguously extending
 * writes.  That is, if the logical block offset equals the number of
 * online blocks.  We try to preallocate the number of blocks existing
 * so that small files don't waste inordinate amounts of space and large
 * files will eventually see large extents.  This only works for
 * contiguous single stream writes or stages of files from the first
 * block.  It doesn't work for concurrent stages, releasing behind
 * staging, sparse files, multi-node writes, etc.  fallocate() is always
 * a better tool to use.
 *
 * We can mangle the extents so the caller is going to search for the
 * intersecting extent again if we succeed.
 */
static int alloc_block(struct super_block *sb, struct inode *inode,
		       struct unpacked_extents *unpe,
		       struct unpacked_extent *ext, u64 iblock,
		       struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_traced_extent te;
	u64 blkno = 0;
	u64 online;
	u64 offline;
	u64 last;
	u8 flags;
	int count;
	int ret;
	int err;

	/* can only allocate over existing unallocated offline extent */
	if (WARN_ON_ONCE(ext &&
			 !(iblock >= ext->iblock && iblock <= ext_last(ext) &&
			  ext->blkno == 0 && (ext->flags & SEF_OFFLINE))))
		return -EINVAL;

	down_write(&datinf->alloc_rwsem);

	scoutfs_inode_get_onoff(inode, &online, &offline);

	if (ext) {
		/* limit preallocation to remaining existing (offline) extent */
		count = ext->count - (iblock - ext->iblock);
		flags = ext->flags;
	} else {
		/* otherwise alloc to next extent or end of packed item */
		last = last_iblock(iblock);
		ext = find_extent(unpe, iblock, last);
		if (ext)
			count = ext->iblock - iblock;
		else
			count = last - iblock + 1;
		flags = 0;
	}

	/* only strictly contiguous extending writes will try to preallocate */
	if (iblock > 1 && iblock == online)
		count = min_t(u64, iblock, count);
	else
		count = 1;

	ret = scoutfs_radix_alloc_data(sb, datinf->alloc, datinf->wri,
				       &datinf->data_avail, count, &blkno,
				       &count);
	if (ret < 0)
		goto out;

	ret = set_extent(sb, inode, ino, unpe, iblock, blkno, 1, 0);
	if (ret < 0)
		goto out;

	init_traced_extent(&te, iblock, blkno, 1, 0);
	trace_scoutfs_data_alloc_block(sb, ino, &te);

	if (count > 1) {
		ret = set_extent(sb, inode, ino, unpe, iblock + 1,
				 blkno + 1, count - 1, flags | SEF_UNWRITTEN);
		if (ret < 0) {
			err = set_extent(sb, inode, ino, unpe, iblock, 0, 1,
					 flags);
			BUG_ON(err); /* couldn't restore original */
		}

		init_traced_extent(&te, iblock + 1, blkno + 1, count - 1,
				   flags | SEF_UNWRITTEN);
		trace_scoutfs_data_prealloc_unwritten(sb, ino, &te);
	}

	ret = store_packed_extents(sb, ino, unpe, lock);
	BUG_ON(ret); /* inconsistent previous extent state */

out:
	if (ret < 0 && blkno > 0) {
		err = scoutfs_radix_free_data(sb, datinf->alloc, datinf->wri,
					      &datinf->data_freed,
					      blkno, count);
		BUG_ON(err); /* leaked free blocks */
	}

	up_write(&datinf->alloc_rwsem);

	return ret;
}

/*
 * A caller is writing into an unwritten block.  This can also be called
 * for staging writes so we clear both the unwritten and offline flags.
 *
 * We don't have to wait for dirty block IO to complete before clearing
 * the unwritten flag in metadata because we have strict synchronization
 * between data and metadata.  All dirty data in the current transaction
 * is written before the metadata in the transaction that references it
 * is committed.
 */
static int convert_unwritten(struct super_block *sb, struct inode *inode,
			     struct unpacked_extents *unpe,
			     struct unpacked_extent *ext, u64 iblock,
			     struct scoutfs_lock *lock)
{
	struct scoutfs_traced_extent te;
	u64 blkno;
	u8 ext_fl;
	int err;
	int ret;

	blkno = ext->blkno + (iblock - ext->iblock);
	ext_fl = ext->flags;

	init_traced_extent(&te, iblock, 1, blkno, ext_fl);
	trace_scoutfs_data_convert_unwritten(sb, scoutfs_ino(inode), &te);

	ret = set_extent(sb, inode, scoutfs_ino(inode), unpe, iblock,
			 blkno, 1, ext_fl & ~(SEF_OFFLINE|SEF_UNWRITTEN));
	if (ret < 0)
		goto out;

	ret = store_packed_extents(sb, scoutfs_ino(inode), unpe, lock);
	if (ret < 0) {
		err = set_extent(sb, inode, scoutfs_ino(inode), unpe, iblock,
				 blkno, 1, ext_fl);
		BUG_ON(err); /* packed and unpacked inconsistent */
	}

out:
	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	const u64 ino = scoutfs_ino(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	struct unpacked_extents *unpe = NULL;
	struct unpacked_extent *ext = NULL;
	DECLARE_TRACED_EXTENT(te);
	u64 offset;
	int ret;

	WARN_ON_ONCE(create && !mutex_is_locked(&inode->i_mutex));

	/* make sure caller holds a cluster lock */
	lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!lock)) {
		ret = -EINVAL;
		goto out;
	}

	ret = load_unpacked_extents(sb, ino, iblock, iblock, true, &unpe, lock);
	if (ret < 0)
		goto out;

	ext = find_extent(unpe, iblock, iblock);

	/* non-staging callers should have waited on offline blocks */
	if (WARN_ON_ONCE(ext && (ext->flags & SEF_OFFLINE) && !si->staging)) {
		ret = -EIO;
		goto out;
	}

	/* convert unwritten to written */
	if (create && ext && (ext->flags & SEF_UNWRITTEN)) {
		ret = convert_unwritten(sb, inode, unpe, ext, iblock, lock);
		if (ret == 0) {
			set_buffer_new(bh);
			ext = find_extent(unpe, iblock, iblock);
		}
		goto out;
	}

	/* allocate and map blocks containing our logical block */
	if (create && (!ext || !ext->blkno)) {
		ret = alloc_block(sb, inode, unpe, ext, iblock, lock);
		if (ret == 0) {
			set_buffer_new(bh);
			ext = find_extent(unpe, iblock, iblock);
		}
	} else {
		ret = 0;
	}
out:
	/* map usable extent, else leave bh unmapped for sparse reads */
	if (ret == 0 && ext && ext->blkno && !(ext->flags & SEF_UNWRITTEN)) {
		offset = iblock - ext->iblock;
		map_bh(bh, inode->i_sb, ext->blkno + offset);
		bh->b_size = min_t(u64, bh->b_size,
			     (ext->count - offset) << SCOUTFS_BLOCK_SM_SHIFT);
	}

	if (ext)
		copy_traced_extent(&te, ext);

	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				&te, ret, bh->b_blocknr, bh->b_size);
	free_unpacked_extents(unpe);
	return ret;
}

/*
 * This is almost never used.  We can't block on a cluster lock while
 * holding the page lock because lock invalidation gets the page lock
 * while blocking locks.  If a non blocking lock attempt fails we unlock
 * the page and block acquiring the lock.  We unlocked the page so it
 * could have been truncated away, or whatever, so we return
 * AOP_TRUNCATED_PAGE to have the caller try again.
 *
 * A similar process happens if we try to read from an offline extent
 * that a caller hasn't already waited for.  Instead of blocking
 * acquiring the lock we block waiting for the offline extent.  The page
 * lock protects the page from release while we're checking and
 * reading the extent.
 *
 * We can return errors from locking and checking offline extents.  The
 * page is unlocked if we return an error.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	DECLARE_DATA_WAIT(dw);
	int flags;
	int ret;

	flags = SCOUTFS_LKF_REFRESH_INODE | SCOUTFS_LKF_NONBLOCK;
	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags, inode,
				 &inode_lock);
	if (ret < 0) {
		unlock_page(page);
		if (ret == -EAGAIN) {
			flags &= ~SCOUTFS_LKF_NONBLOCK;
			ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags,
						 inode, &inode_lock);
			if (ret == 0) {
				scoutfs_unlock(sb, inode_lock,
					       SCOUTFS_LOCK_READ);
				ret = AOP_TRUNCATED_PAGE;
			}
		}
		return ret;
	}

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, inode_lock)) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_CACHE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, &dw,
					      inode_lock);
		if (ret != 0) {
			unlock_page(page);
			scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
			scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
		}
		if (ret > 0) {
			ret = scoutfs_data_wait(inode, &dw);
			if (ret == 0)
				ret = AOP_TRUNCATED_PAGE;
		}
		if (ret != 0)
			return ret;
	}

	ret = mpage_readpage(page, scoutfs_get_block);

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);

	return ret;
}

/*
 * This is used for opportunistic read-ahead which can throw the pages
 * away if it needs to.  If the caller didn't deal with offline extents
 * then we drop those pages rather than trying to wait.  Whoever is
 * staging offline extents should be doing it in enormous chunks so that
 * read-ahead can ramp up within each staged region.  The check for
 * offline extents is cheap when the inode has no offline extents.
 */
static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	struct page *page;
	struct page *tmp;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		goto out;

	list_for_each_entry_safe(page, tmp, pages, lru) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_CACHE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, NULL,
					      inode_lock);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			list_del(&page->lru);
			page_cache_release(page);
			if (--nr_pages == 0) {
				ret = 0;
				goto out;
			}
		}
	}

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block);
out:
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	BUG_ON(!list_empty(pages));
	return ret;
}

static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, scoutfs_get_block, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, scoutfs_get_block);
}

/* fsdata allocated in write_begin and freed in write_end */
struct write_begin_data {
	struct list_head ind_locks;
	struct scoutfs_lock *lock;
};

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd;
	u64 ind_seq;
	int ret;

	trace_scoutfs_write_begin(sb, scoutfs_ino(inode), (__u64)pos, len);

	wbd = kmalloc(sizeof(struct write_begin_data), GFP_NOFS);
	if (!wbd)
		return -ENOMEM;

	INIT_LIST_HEAD(&wbd->ind_locks);
	*fsdata = wbd;

	wbd->lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!wbd->lock)) {
		ret = -EINVAL;
		goto out;
	}

	do {
		ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
		      scoutfs_inode_index_prepare(sb, &wbd->ind_locks, inode,
						  true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, &wbd->ind_locks,
							ind_seq,
							SIC_WRITE_BEGIN());
	} while (ret > 0);
	if (ret < 0)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode, wbd->lock);
	if (ret == 0)
		ret = block_write_begin(mapping, pos, len, flags, pagep,
					scoutfs_get_block);
	if (ret)
		scoutfs_release_trans(sb);
out:
	if (ret) {
		scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
		kfree(wbd);
	}
        return ret;
}

/* kinda like __filemap_fdatawrite_range! :P */
static int writepages_sync_none(struct address_space *mapping, loff_t start,
				loff_t end)
{
        struct writeback_control wbc = {
                .sync_mode = WB_SYNC_NONE,
                .nr_to_write = LONG_MAX,
                .range_start = start,
                .range_end = end,
        };

	return mapping->a_ops->writepages(mapping, &wbc);
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd = fsdata;
	int ret;

	trace_scoutfs_write_end(sb, scoutfs_ino(inode), page->index, (u64)pos,
				len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		if (!si->staging) {
			scoutfs_inode_set_data_seq(inode);
			scoutfs_inode_inc_data_version(inode);
		}

		scoutfs_update_inode_item(inode, wbd->lock, &wbd->ind_locks);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
	kfree(wbd);

	/*
	 * Currently transactions are kept very simple.  Only one is
	 * open at a time and commit excludes concurrent dirtying.  It
	 * writes out all dirty file data during commit.  This can lead
	 * to very long commit latencies with lots of dirty file data.
	 *
	 * This hack tries to minimize these writeback latencies while
	 * keeping concurrent large file strreaming writes from
	 * suffering too terribly.  Every N bytes we kick off background
	 * writbeack on the previous N bytes.  By the time transaction
	 * commit comes along it will find that dirty file blocks have
	 * already been written.
	 */
#define BACKGROUND_WRITEBACK_BYTES (16 * 1024 * 1024)
#define BACKGROUND_WRITEBACK_MASK (BACKGROUND_WRITEBACK_BYTES - 1)
	if (ret > 0 && ((pos + ret) & BACKGROUND_WRITEBACK_MASK) == 0)
		writepages_sync_none(mapping,
				     pos + ret - BACKGROUND_WRITEBACK_BYTES,
				     pos + ret - 1);

	return ret;
}

/*
 * Try to allocate unwritten extents for any unallocated regions of the
 * logical block extent from the caller.  We work one packed extent item
 * at a time.
 *
 * We return an error or the numbet of contiguous blocks starting at
 * iblock that were successfully processed.
 */
static int fallocate_extents(struct super_block *sb, struct inode *inode,
			     u64 iblock, u64 last, struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	const u64 ino = scoutfs_ino(inode);
	struct unpacked_extents *unpe = NULL;
	struct unpacked_extent *ext;
	u8 ext_fl;
	u64 blkno;
	int count;
	int done;
	int ret;
	int err;

	/* work with the extents in one item at a time */
	last = min(last, last_iblock(iblock));
	done = 0;

	ret = load_unpacked_extents(sb, ino, iblock, iblock, true, &unpe, lock);
	if (ret < 0)
		goto out;

	ext = find_extent(unpe, iblock, last);
	while (iblock <= last) {

		/* default to allocate to end of region */
		count = last - iblock + 1;
		ext_fl = 0;

		if (!ext) {
			/* no extent, default alloc from above */

		} else if (ext->iblock <= iblock && ext->blkno) {
			/* skip portion of allocated extent */
			count = min_t(u64, count,
				      ext->count - (iblock - ext->iblock));
			iblock += count;
			done += count;
			ext = next_extent(ext);
			continue;

		} else if (ext->iblock <= iblock && !ext->blkno) {
			/* alloc portion of unallocated extent */
			count = min_t(u64, count,
				      ext->count - (iblock - ext->iblock));
			ext_fl = ext->flags;

		} else if (iblock < ext->iblock) {
			/* alloc hole until next extent */
			count = min_t(u64, count, ext->iblock - iblock);
		}

		down_write(&datinf->alloc_rwsem);

		ret = scoutfs_radix_alloc_data(sb, datinf->alloc, datinf->wri,
					       &datinf->data_avail, count,
					       &blkno, &count);
		if (ret == 0) {
			ret = set_extent(sb, inode, ino, unpe, iblock, blkno,
					 count, ext_fl | SEF_UNWRITTEN);
			if (ret < 0) {
				err = scoutfs_radix_free_data(sb, datinf->alloc,
							datinf->wri,
							&datinf->data_avail,
							blkno, count);
				BUG_ON(err); /* inconsistent */
			}
		}

		up_write(&datinf->alloc_rwsem);

		if (ret < 0)
			break;

		iblock += count;
		done += count;
		ext = find_extent(unpe, iblock, last);
	}

	ret = store_packed_extents(sb, ino, unpe, lock);
	BUG_ON(ret); /* inconsistent with unpacked and alloc */

	if (ret == 0)
		ret = done;

out:
	free_unpacked_extents(unpe);

	return ret;
}

/*
 * Modify the extents that map the blocks that store the len byte region
 * starting at offset.
 *
 * The caller has only prevented freezing by entering a fs write
 * context.  We're responsible for all other locking and consistency.
 *
 * This can be used to preallocate files for staging.  We find existing
 * offline extents and allocate block for them and set unwritten.
 */
long scoutfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	LIST_HEAD(ind_locks);
	loff_t end;
	u64 iblock;
	u64 last;
	int ret;

	mutex_lock(&inode->i_mutex);

	/* XXX support more flags */
        if (mode & ~(FALLOC_FL_KEEP_SIZE)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* catch wrapping */
	if (offset + len < offset) {
		ret = -EINVAL;
		goto out;
	}

	if (len == 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto out;

	inode_dio_wait(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len > i_size_read(inode))) {
                ret = inode_newsize_ok(inode, offset + len);
                if (ret)
                        goto out;
        }

	iblock = offset >> SCOUTFS_BLOCK_SM_SHIFT;
	last = (offset + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	while(iblock <= last) {

		ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false,
						    SIC_FALLOCATE_ONE());
		if (ret)
			goto out;

		ret = fallocate_extents(sb, inode, iblock, last, lock);

		if (ret >= 0 && !(mode & FALLOC_FL_KEEP_SIZE)) {
			end = (iblock + ret) << SCOUTFS_BLOCK_SM_SHIFT;
			if (end > offset + len)
				end = offset + len;
			if (end > i_size_read(inode))
				i_size_write(inode, end);
		}
		if (ret >= 0)
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);

		if (ret <= 0)
			goto out;

		iblock += ret;
		ret = 0;
	}

out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	mutex_unlock(&inode->i_mutex);

	trace_scoutfs_data_fallocate(sb, ino, mode, offset, len, ret);
	return ret;
}

/*
 * A special case of initializing a single large offline extent.  This
 * chooses not to deal with any existing extents.  It can only be used
 * on regular files with no data extents.  It's used to restore a file
 * with an offline extent which can then trigger staging.
 *
 * The caller has taken care of locking.  We're creating many packed
 * extent items which may have to be written in multiple transactions.
 * We create exetnts from the front of the file and use the offline
 * block count to figure out where to continue from.
 */
int scoutfs_data_init_offline_extent(struct inode *inode, u64 size,
				     struct scoutfs_lock *lock)

{
	struct super_block *sb = inode->i_sb;
	struct unpacked_extents *unpe = NULL;
	u64 ino = scoutfs_ino(inode);
	LIST_HEAD(ind_locks);
	bool held = false;
	u64 blocks;
	u64 iblock;
	u64 count;
	u64 on;
	u64 off;
	int ret;

	blocks = DIV_ROUND_UP(size, SCOUTFS_BLOCK_SM_SIZE);

	scoutfs_inode_get_onoff(inode, &on, &off);
	iblock = off;

	while (iblock < blocks) {
		/* we're updating meta_seq with offline block count */
		ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false,
						    SIC_SETATTR_MORE());
		if (ret < 0)
			goto out;
		held = true;

		ret = scoutfs_dirty_inode_item(inode, lock);
		if (ret < 0)
			goto out;

		ret = load_unpacked_extents(sb, ino, iblock, iblock, true,
					    &unpe, lock);
		if (ret < 0)
			goto out;

		count = min(blocks - iblock, last_iblock(iblock) - iblock + 1);

		ret = set_extent(sb, inode, ino, unpe, iblock, 0, count,
				 SEF_OFFLINE);
		if (ret < 0)
			goto out;

		ret = store_packed_extents(sb, ino, unpe, lock);
		if (ret < 0)
			goto out;

		free_unpacked_extents(unpe);
		unpe = NULL;

		scoutfs_update_inode_item(inode, lock, &ind_locks);

		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);
		held = false;

		iblock += count;
	}

	ret = 0;
out:
	if (held) {
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);
	}
	free_unpacked_extents(unpe);
	return ret;
}

/*
 * This copies to userspace :/
 */
static int fill_extent(struct fiemap_extent_info *fieinfo,
		       struct unpacked_extent *ext, u32 fiemap_flags)
{
	u32 flags;

	if (ext->count == 0)
		return 0;

	flags = fiemap_flags;
	if (ext->flags & SEF_OFFLINE)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	else if (ext->flags & SEF_UNWRITTEN)
		flags |= FIEMAP_EXTENT_UNWRITTEN;

	return fiemap_fill_next_extent(fieinfo,
				       ext->iblock << SCOUTFS_BLOCK_SM_SHIFT,
				       ext->blkno << SCOUTFS_BLOCK_SM_SHIFT,
				       ext->count << SCOUTFS_BLOCK_SM_SHIFT,
				       flags);
}

/*
 * Return all the file's extents whose blocks overlap with the caller's
 * byte region.  We set _LAST on the last extent and _UNKNOWN on offline
 * extents.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	struct unpacked_extents *unpe = NULL;
	struct unpacked_extent *ext;
	struct unpacked_extent cur;
	struct scoutfs_traced_extent te;
	u32 last_flags;
	u64 iblock;
	u64 last;
	int ret;

	if (len == 0)
		return 0;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	/* XXX overkill? */
	mutex_lock(&inode->i_mutex);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lock);
	if (ret)
		goto out;

	/* use a dummy extent to track */
	memset(&cur, 0, sizeof(cur));
	last_flags = 0;

	iblock = start >> SCOUTFS_BLOCK_SM_SHIFT;
	last = (start + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	for (;;) {
		ret = load_unpacked_extents(sb, ino, iblock, last, false,
					    &unpe, lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			last_flags = FIEMAP_EXTENT_LAST;
			break;
		}

		for (ext = find_extent(unpe, iblock, last); ext;
		     ext = next_extent(ext)) {

			copy_traced_extent(&te, ext);
			trace_scoutfs_data_fiemap_extent(sb, ino, &te);

			if (ext->iblock > last) {
				/* not setting _LAST, it's for end of file */
				ret = 0;
				break;
			}

			if (extents_merge(&cur, ext)) {
				cur.count += ext->count;
				continue;
			}

			ret = fill_extent(fieinfo, &cur, 0);
			if (ret != 0)
				goto out;
			cur = *ext;
		}

		iblock = unpe->iblock + SCOUTFS_PACKEXT_BLOCKS;
		free_unpacked_extents(unpe);
		unpe = NULL;
	}

	if (cur.count)
		ret = fill_extent(fieinfo, &cur, last_flags);
out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	mutex_unlock(&inode->i_mutex);

	free_unpacked_extents(unpe);

	if (ret == 1)
		ret = 0;

	return ret;
}

/*
 * Insert a new waiter.  This supports multiple tasks waiting for the
 * same ino and iblock by also comparing waiters by their addresses.
 */
static void insert_offline_waiting(struct rb_root *root,
				   struct scoutfs_data_wait *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		cmp = scoutfs_cmp_u64s(ins->ino, dw->ino) ?:
		      scoutfs_cmp_u64s(ins->iblock, dw->iblock) ?:
		      scoutfs_cmp(ins, dw);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static struct scoutfs_data_wait *next_data_wait(struct rb_root *root, u64 ino,
						u64 iblock)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *next = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		/* go left when ino/iblock are equal to get first task */
		cmp = scoutfs_cmp_u64s(ino, dw->ino) ?:
		      scoutfs_cmp_u64s(iblock, dw->iblock);
		if (cmp <= 0) {
			node = &(*node)->rb_left;
			next = dw;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		}
	}

	return next;
}

static struct scoutfs_data_wait *dw_next(struct scoutfs_data_wait *dw)
{
	struct rb_node *node = rb_next(&dw->node);
	if (node)
		return container_of(node, struct scoutfs_data_wait, node);
	return NULL;
}

/*
 * Check if we should wait by looking for extents whose flags match.
 * Returns 0 if no extents were found or any error encountered.
 *
 * The caller must have locked the extents before calling, both across
 * mounts and within this mount.
 *
 * Returns 1 if any file extents in the caller's region matched.  If the
 * wait struct is provided then it is initialized to be woken when the
 * extents change after the caller unlocks after the check.  The caller
 * must come through _data_wait() to clean up the wait struct if we set
 * it up.
 */
int scoutfs_data_wait_check(struct inode *inode, loff_t pos, loff_t len,
			    u8 sef, u8 op, struct scoutfs_data_wait *dw,
			    struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	struct unpacked_extents *unpe = NULL;
	struct unpacked_extent *ext;
	DECLARE_TRACED_EXTENT(te);
	u64 iblock;
	u64 last_block;
	u64 on;
	u64 off;
	int ret = 0;

	if (WARN_ON_ONCE(sef & SEF_UNKNOWN) ||
	    WARN_ON_ONCE(op & SCOUTFS_IOC_DWO_UNKNOWN) ||
	    WARN_ON_ONCE(dw && !RB_EMPTY_NODE(&dw->node)) ||
	    WARN_ON_ONCE(pos + len < pos)) {
		ret = -EINVAL;
		goto out;
	}

	if ((sef & SEF_OFFLINE)) {
		scoutfs_inode_get_onoff(inode, &on, &off);
		if (off == 0) {
			ret = 0;
			goto out;
		}
	}

	iblock = pos >> SCOUTFS_BLOCK_SM_SHIFT;
	last_block = (pos + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	while(iblock <= last_block) {

		free_unpacked_extents(unpe);
		ret = load_unpacked_extents(sb, ino, iblock, last_block, false,
					    &unpe, lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			goto out;
		}

		for (ext = find_extent(unpe, iblock, last_block); ext;
		     ext = next_extent(ext)) {

			if (ext->iblock > last_block) {
				ret = 0;
				goto out;
			}

			if (sef & ext->flags) {
				if (dw) {
					dw->chg = atomic64_read(&wq->changed);
					dw->ino = ino;
					dw->iblock = max(iblock, ext->iblock);
					dw->op = op;

					spin_lock(&rt->lock);
					insert_offline_waiting(&rt->root, dw);
					spin_unlock(&rt->lock);
				}

				copy_traced_extent(&te, ext);
				ret = 1;
				goto out;
			}

		}

		iblock = unpe->iblock + SCOUTFS_PACKEXT_BLOCKS;
	}

out:
	trace_scoutfs_data_wait_check(sb, ino, pos, len, sef, op, &te, ret);

	free_unpacked_extents(unpe);

	return ret;
}

bool scoutfs_data_wait_found(struct scoutfs_data_wait *dw)
{
	return !RB_EMPTY_NODE(&dw->node);
}

int scoutfs_data_wait_check_iov(struct inode *inode, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos, u8 sef,
				u8 op, struct scoutfs_data_wait *dw,
				struct scoutfs_lock *lock)
{
	unsigned long i;
	int ret = 0;

	for (i = 0; i < nr_segs; i++) {
		if (iov[i].iov_len == 0)
			continue;

		ret = scoutfs_data_wait_check(inode, pos, iov[i].iov_len, sef,
					      op, dw, lock);
		if (ret != 0)
			break;

		pos += iov[i].iov_len;
	}

	return ret;
}

int scoutfs_data_wait(struct inode *inode, struct scoutfs_data_wait *dw)
{
	DECLARE_DATA_WAIT_ROOT(inode->i_sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	int ret;

	ret = wait_event_interruptible(wq->waitq,
					atomic64_read(&wq->changed) != dw->chg);

	spin_lock(&rt->lock);
	rb_erase(&dw->node, &rt->root);
	RB_CLEAR_NODE(&dw->node);
	if (!ret && dw->err)
		ret = dw->err;
	spin_unlock(&rt->lock);

	return ret;
}

void scoutfs_data_wait_changed(struct inode *inode)
{
	DECLARE_DATA_WAITQ(inode, wq);

	atomic64_inc(&wq->changed);
	wake_up(&wq->waitq);
}

long scoutfs_data_wait_err(struct inode *inode, u64 sblock, u64 eblock,
			   u64 op, long err)
{
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	struct scoutfs_data_wait *dw;
	long nr = 0;

	if (!err)
		return 0;

	spin_lock(&rt->lock);

	for (dw = next_data_wait(&rt->root, ino, sblock);
	     dw; dw = dw_next(dw)) {
		if (dw->ino != ino || dw->iblock > eblock)
			break;
		if ((dw->op & op) && !dw->err) {
			dw->err = err;
			nr++;
		}
	}

	spin_unlock(&rt->lock);
	if (nr)
		scoutfs_data_wait_changed(inode);
	return nr;
}

int scoutfs_data_waiting(struct super_block *sb, u64 ino, u64 iblock,
			 struct scoutfs_ioctl_data_waiting_entry *dwe,
			 unsigned int nr)
{
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	struct scoutfs_data_wait *dw;
	int ret = 0;

	spin_lock(&rt->lock);

	dw = next_data_wait(&rt->root, ino, iblock);
	while (dw && ret < nr) {

		dwe->ino = dw->ino;
		dwe->iblock = dw->iblock;
		dwe->op = dw->op;

		while ((dw = dw_next(dw)) &&
		       (dw->ino == dwe->ino && dw->iblock == dwe->iblock)) {
			dwe->op |= dw->op;
		}

		dwe++;
		ret++;
	}

	spin_unlock(&rt->lock);

	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
	.readpages		= scoutfs_readpages,
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= scoutfs_file_aio_read,
	.aio_write	= scoutfs_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= scoutfs_file_llseek,
	.fallocate	= scoutfs_fallocate,
};

void scoutfs_data_init_btrees(struct super_block *sb,
			      struct scoutfs_radix_allocator *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_log_trees *lt)
{
	DECLARE_DATA_INFO(sb, datinf);

	down_write(&datinf->alloc_rwsem);

	datinf->alloc = alloc;
	datinf->wri = wri;
	datinf->data_avail = lt->data_avail;
	datinf->data_freed = lt->data_freed;

	up_write(&datinf->alloc_rwsem);
}

void scoutfs_data_get_btrees(struct super_block *sb,
			     struct scoutfs_log_trees *lt)
{
	DECLARE_DATA_INFO(sb, datinf);

	down_read(&datinf->alloc_rwsem);

	lt->data_avail = datinf->data_avail;
	lt->data_freed = datinf->data_freed;

	up_read(&datinf->alloc_rwsem);
}

/*
 * This isn't serializing with allocators so it can be a bit racey.
 */
u64 scoutfs_data_alloc_free_bytes(struct super_block *sb)
{
	DECLARE_DATA_INFO(sb, datinf);

	return scoutfs_radix_root_free_blocks(sb, &datinf->data_avail) <<
		SCOUTFS_BLOCK_SM_SHIFT;
}

int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	datinf->sb = sb;
	init_rwsem(&datinf->alloc_rwsem);

	sbi->data_info = datinf;
	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		sbi->data_info = NULL;
		kfree(datinf);
	}
}
