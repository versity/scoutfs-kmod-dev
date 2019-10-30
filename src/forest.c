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
#include <linux/rwsem.h>
#include <linux/random.h>
#include <linux/crc32c.h>

#include "super.h"
#include "format.h"
#include "lock.h"
#include "btree.h"
#include "client.h"
#include "balloc.h"
#include "block.h"
#include "forest.h"
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
 * From a mount's perspective, the only btree whose blocks are actively
 * changing is the mount's own log btree in memory.  Every other btree
 * it reads is stable (but could be stale) on disk.  They don't need to
 * be locked, but we might have to retry reads if we hit blocks that
 * have been overwritten.
 *
 * Log btrees are typically very sparse.  It would be wasteful for
 * readers to read every log btree looking for an item.  Each log btree
 * contains a bloom filter keyed on the starting key of locks.  This
 * lets lock holders quickly eliminate log trees that cannot contain
 * keys protected by their lock and it caches the btrees to search in
 * the lock for the duration of its use. 
 */

/*
 * todo:
 * - when we adopt a new bloom root we'd need to reset bloom bits in locks
 * - add a bunch of counters so we can see bloom/tree ops/etc
 */

struct forest_info {
	struct rw_semaphore rwsem;
	struct scoutfs_balloc_allocator alloc;
	struct scoutfs_block_writer wri;
	struct scoutfs_log_trees our_log;
};

#define DECLARE_FOREST_INFO(sb, name) \
	struct forest_info *name = SCOUTFS_SB(sb)->forest_info

struct forest_root {
	struct list_head entry;
	struct scoutfs_btree_root item_root;
	u64 rid;
	u64 nr;
};

struct forest_super_refs {
	struct scoutfs_btree_ref fs_ref;
	struct scoutfs_btree_ref logs_ref;
} __packed;

struct forest_bloom_nrs {
	unsigned int nrs[SCOUTFS_FOREST_BLOOM_NRS];
};

/*
 * We have static forest_root entries for the fs and our log btrees so
 * that we can iterate over them along with all the discovered and
 * allocated log btrees.
 */
struct forest_lock_private {
	u64 last_refreshed;
	struct rw_semaphore rwsem;
	struct list_head roots;
	struct forest_root fs_root;
	struct forest_root our_log_root;
	unsigned long flags;
};

enum {
	LPRIV_FLAG_ALL_BLOOM_BITS = 0,
};

static inline void set_lpriv_flag(struct forest_lock_private *lpriv, int flag)
{
	set_bit(flag, &lpriv->flags);
}
static inline int test_lpriv_flag(struct forest_lock_private *lpriv, int flag)
{
	return test_bit(flag, &lpriv->flags);
}

static bool is_fs_root(struct forest_lock_private *lpriv,
		       struct forest_root *fr)
{
	return fr == &lpriv->fs_root;
}

static bool is_our_log_root(struct forest_lock_private *lpriv,
			    struct forest_root *fr)
{
	return fr == &lpriv->our_log_root;
}

static struct forest_lock_private *get_lock_private(struct scoutfs_lock *lock)
{
	struct forest_lock_private *lpriv = ACCESS_ONCE(lock->forest_private);

	if (lpriv == NULL) {
		lpriv = kzalloc(sizeof(struct forest_lock_private), GFP_NOFS);
		if (lpriv) {
			init_rwsem(&lpriv->rwsem);
			INIT_LIST_HEAD(&lpriv->roots);
			INIT_LIST_HEAD(&lpriv->fs_root.entry);
			INIT_LIST_HEAD(&lpriv->our_log_root.entry);

			if (cmpxchg(&lock->forest_private, NULL, lpriv) != NULL)
				kfree(lpriv);
			lpriv = lock->forest_private;
		}
	}

	return lpriv;
}

/*
 * We can tell if an item is currently dirty in our transaction's log
 * root if its lock is held for writing and the item's version matches
 * the lock's write version.
 */
static bool is_our_dirty_item(struct scoutfs_lock *lock,
			      struct forest_root *fr, u64 vers)
{
	struct forest_lock_private *lpriv = get_lock_private(lock);

	return is_our_log_root(lpriv, fr) &&
	       lock->mode == SCOUTFS_LOCK_WRITE &&
	       vers == lock->write_version;
}

static void clear_roots(struct forest_lock_private *lpriv)
{
	struct forest_root *fr;
	struct forest_root *tmp;

	list_for_each_entry_safe(fr, tmp, &lpriv->roots, entry) {
		list_del_init(&fr->entry);
		if (!is_fs_root(lpriv, fr) && !is_our_log_root(lpriv, fr))
			kfree(fr);
	}
}

/*
 * Make sure that our log btree will be at the head of the list of
 * btrees to read.  This can be racing with clearing the list to check
 * the bloom blocks again.  We want the addition of the log btree to
 * persist across clearing the lists so we set the rid/nr which causes
 * the root to be added to the list after the bloom blocks are checked.
 */
static void add_our_log_root(struct forest_info *finf,
			     struct forest_lock_private *lpriv)
{
	struct forest_root *fr = &lpriv->our_log_root;

	BUG_ON(!rwsem_is_locked(&lpriv->rwsem));

	if (fr->rid == 0) {
		fr->rid = le64_to_cpu(finf->our_log.rid);
		fr->nr = le64_to_cpu(finf->our_log.nr);
	}

	if (list_empty(&fr->entry))
		list_add(&fr->entry, &lpriv->roots);
}

/*
 * This is called by the locking code while it's excluding users of the
 * lock.
 */
void scoutfs_forest_clear_lock(struct super_block *sb,
			       struct scoutfs_lock *lock)
{
	struct forest_lock_private *lpriv = ACCESS_ONCE(lock->forest_private);

	if (lpriv) {
		clear_roots(lpriv);
		kfree(lpriv);
	}
}

/*
 * All the btrees we read are stable and read-only except for our log
 * btree which is being actively modified in memory by locked writers.
 * Once we lock it we need to get the current version of the root.
 */
static void read_lock_forest_root(struct forest_info *finf,
				  struct forest_lock_private *lpriv,
				  struct forest_root *fr)
{
	if (is_our_log_root(lpriv, fr)) {
		down_read(&finf->rwsem);
		fr->item_root = finf->our_log.item_root;
	}
}

static void read_unlock_forest_root(struct forest_info *finf,
				    struct forest_lock_private *lpriv,
				    struct forest_root *fr)
{
	if (is_our_log_root(lpriv, fr)) {
		up_read(&finf->rwsem);
	}
}

/*
 * XXX need something better.
 */
static void calc_bloom_nrs(struct forest_bloom_nrs *bloom,
			    struct scoutfs_key *key)
{
	u32 crc = ~0;
	int i;

	for (i = 0; i < ARRAY_SIZE(bloom->nrs); i++) {
		crc = crc32c(crc, key, sizeof(struct scoutfs_key));
		bloom->nrs[i] = crc % SCOUTFS_FOREST_BLOOM_BITS;
	}
}

/*
 * Empty the list of btrees currently stored in the lock and walk the
 * current fs image looking for btrees whose bloom filters indicate that
 * the btree may contain items covered by the lock.
 *
 * We ensure that the our log btree is always first and that the fs
 * btree is always last because those positions offer short-circuiting
 * optimizations.
 *
 * This doesn't deal with rereading stale blocks itself.. it returns
 * ESTALE to the caller who already has to deal with retrying stale
 * blocks from their btree reads.  We give them the super refs we read
 * so that they can identify persistent stale block errors that come
 * from corruption.
 *
 * Because we're starting all the reads from a stable read super this
 * will not see any dirty blocks we have in memory.  We don't have to
 * lock any of the btree reads.  It also won't find the currently dirty
 * version of our log btree.  Writers mark our static log btree in lpriv
 * to indicate that we should include our dirty log btree in reads.
 * We'll also naturally add it if we see a persistent version on disk
 * with all of the bloom bits set.
 */
static int refresh_bloom_roots(struct super_block *sb,
			       struct scoutfs_lock *lock,
			       struct forest_super_refs *srefs)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct forest_lock_private *lpriv = ACCESS_ONCE(lock->forest_private);
	struct scoutfs_log_trees_key ltk;
	struct scoutfs_log_trees_val ltv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct forest_bloom_nrs bloom;
	struct scoutfs_super_block super;
	struct forest_root *fr = NULL;
	struct scoutfs_bloom_block *bb;
	struct scoutfs_block *bl;
	int ret;
	int i;

	memset(srefs, 0, sizeof(*srefs));

	/* empty the list so no one iterates until someone's added */
	clear_roots(lpriv);

	ret = scoutfs_read_super(sb, &super);
	if (ret)
		goto out;

	srefs->fs_ref = super.fs_root.ref;
	srefs->logs_ref = super.logs_root.ref;

	calc_bloom_nrs(&bloom, &lock->start);

	memset(&ltk, 0, sizeof(ltk));
	for (;; be64_add_cpu(&ltk.nr, 1)) {

		ret = scoutfs_btree_next(sb, &super.logs_root,
					 &ltk, sizeof(ltk), &iref);
		if (ret == -ENOENT) {
			ret = 0;
			break;
		}
		if (ret < 0)
			goto out;

		if (iref.key_len == sizeof(struct scoutfs_log_trees_key) &&
		    iref.val_len == sizeof(struct scoutfs_log_trees_val)) {
			memcpy(&ltk, iref.key, iref.key_len);
			memcpy(&ltv, iref.val, iref.val_len);
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		if (ltv.bloom_ref.blkno == 0)
			continue;

		bl = scoutfs_block_read(sb, le64_to_cpu(ltv.bloom_ref.blkno));
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

		trace_scoutfs_forest_bloom_search(sb, &lock->start,
					be64_to_cpu(ltk.rid),
					be64_to_cpu(ltk.nr),
					le64_to_cpu(ltv.bloom_ref.blkno),
					le64_to_cpu(ltv.bloom_ref.seq),
					i);

		/* one of the bloom bits wasn't set */
		if (i != ARRAY_SIZE(bloom.nrs))
			continue;

		/* add our current log tree if we see its bloom */
		if (be64_to_cpu(ltk.rid) == le64_to_cpu(finf->our_log.rid) &&
		    be64_to_cpu(ltk.nr) == le64_to_cpu(finf->our_log.nr)) {
			add_our_log_root(finf, lpriv);
			continue;
		}

		/* all bloom bits set, add to the list */
		fr = kzalloc(sizeof(struct forest_root), GFP_NOFS);
		if (fr == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		fr->item_root = ltv.item_root;
		fr->rid = be64_to_cpu(ltk.rid);
		fr->nr = be64_to_cpu(ltk.nr);

		list_add_tail(&fr->entry, &lpriv->roots);

		trace_scoutfs_forest_add_root(sb, &lock->start, fr->rid,
				fr->nr, le64_to_cpu(fr->item_root.ref.blkno),
				le64_to_cpu(fr->item_root.ref.seq));
	}

	/* add our current log root if a locked writer added it */
	if (lpriv->our_log_root.rid != 0)
		add_our_log_root(finf, lpriv);

	/* always add the fs root at the tail */
	fr = &lpriv->fs_root;
	fr->item_root = super.fs_root;
	fr->rid = 0;
	fr->nr = 0;
	list_add_tail(&fr->entry, &lpriv->roots);

	lpriv->last_refreshed = lock->refresh_gen;

	ret = 0;

out:
	if (ret < 0)
		clear_roots(lpriv);
	return ret;
}

/* initialize some super refs that initially aren't equal */
#define DECLARE_STALE_TRACKING_SUPER_REFS(a, b)			\
	struct forest_super_refs a = {{cpu_to_le64(0),}};	\
	struct forest_super_refs b = {{cpu_to_le64(1),}}


/*
 * The caller saw stale blocks.  If they're seeing the same root refs
 * and are still getting stale then it's consistent corruption and we
 * return an error.  Otherwise we refresh the bloom roots and try again.
 * If this returns 0 then the caller is going to retry.  If *we* saw
 * stale blocks trying to refresh the bloom then we return 0 to have the
 * caller remember the root refs and try again.
 */
static int refresh_check_stale(struct super_block *sb,
			       struct scoutfs_lock *lock,
			       struct forest_super_refs *prev_srefs,
			       struct forest_super_refs *srefs)
{
	struct forest_lock_private *lpriv = ACCESS_ONCE(lock->forest_private);
	int ret;

	if (memcmp(prev_srefs, srefs, sizeof(*srefs)) == 0)
		return -EIO;
	*prev_srefs = *srefs;

	down_write(&lpriv->rwsem);
	ret = refresh_bloom_roots(sb, lock, srefs);
	up_write(&lpriv->rwsem);
	if (ret == -ESTALE)
		ret = 0;

	return ret;
}

/*
 * Iterate over all the roots that could contain items covered by the
 * caller's lock.  The caller starts iteration by passing in a NULL fr.
 * We return -ESTALE if the caller needs to refresh the bloom roots.  We
 * use the lock's refresh gen to find out when the lock was invalidated
 * and the contents of the trees could have changed.
 */
static int for_each_forest_root(struct scoutfs_lock *lock,
				struct forest_lock_private *lpriv,
				struct forest_root **fr)
{
	if (WARN_ON_ONCE(!rwsem_is_locked(&lpriv->rwsem)))
		return -EIO;

	if (list_empty(&lpriv->roots) ||
	    lock->refresh_gen != lpriv->last_refreshed)
		return -ESTALE;

	if (*fr == NULL)
		*fr = list_prepare_entry((*fr), &lpriv->roots, entry);

	list_for_each_entry_continue((*fr), &lpriv->roots, entry)
		return 0;

	*fr = NULL;
	return 0;
}

/*
 * We fake 1 as the version for the fs items.  The least valid log item
 * version is also 1, but we guarantee that we check the log trees first
 * so they'll always be found before the fs items.
 */
static u64 item_vers(struct forest_lock_private *lpriv,
		     struct forest_root *fr, void *val)
{
	struct scoutfs_log_item_value *liv;

	if (is_fs_root(lpriv, fr))
		return 1;

	liv = val;
	return le64_to_cpu(liv->vers);
}

static bool item_flags(struct forest_lock_private *lpriv,
			     struct forest_root *fr, void *val)
{
	struct scoutfs_log_item_value *liv;

	if (is_fs_root(lpriv, fr))
		return 0;

	liv = val;
	return liv->flags;
}

static bool item_is_deletion(struct forest_lock_private *lpriv,
			     struct forest_root *fr, void *val)
{
	return item_flags(lpriv, fr, val) & SCOUTFS_LOG_ITEM_FLAG_DELETION;
}

/* just a little helper to slim down all the call sites */
static int lock_safe(struct scoutfs_lock *lock, struct scoutfs_key *key,
		     int mode)
{
	if (WARN_ON_ONCE(!scoutfs_lock_protected(lock, key, mode)))
		return -EINVAL;
	else
		return 0;
}

/*
 * Copy the cached item's value into the caller's single value vector.
 * The number of bytes that fit in the vec and were copied is returned.
 * A null val returns 0.  Items in log trees have a value header that
 * needs to be skipped.
 */
static int copy_val(struct forest_lock_private *lpriv, struct forest_root *fr,
		    struct kvec *val, struct scoutfs_btree_item_ref *iref)
{
	void *val_start = iref->val;
	unsigned int val_len = iref->val_len;
	int ret;

	if (!is_fs_root(lpriv, fr)) {
		val_start += sizeof(struct scoutfs_log_item_value);
		val_len -= sizeof(struct scoutfs_log_item_value);
	}

	if (val) {
		ret = min_t(size_t, val_len, val->iov_len);
		memcpy(val->iov_base, val_start, ret);
	} else {
		ret = 0;
	}

	return ret;
}

int scoutfs_forest_lookup(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock)
{
	DECLARE_FOREST_INFO(sb, finf);
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_srefs, srefs);
	struct forest_lock_private *lpriv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key_be kbe;
	struct forest_root *fr;
	u64 found_vers;
	u64 vers;
	int ret;
	int err;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_READ)) < 0)
		goto out;

	lpriv = get_lock_private(lock);
	if (!lpriv) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_key_to_be(&kbe, key);

retry:
	down_read(&lpriv->rwsem);

	found_vers = 0;
	ret = -ENOENT;
	fr = NULL;

	while (!(err = for_each_forest_root(lock, lpriv, &fr)) && fr) {

		/* done if we found log items before fs root */
		if (found_vers > 0 && is_fs_root(lpriv, fr))
			break;

		read_lock_forest_root(finf, lpriv, fr);
		err = scoutfs_btree_lookup(sb, &fr->item_root,
					   &kbe, sizeof(kbe), &iref);
		if (err < 0)
			read_unlock_forest_root(finf, lpriv, fr);
		if (err == -ENOENT)
			continue;
		if (err < 0)
			break;

		vers = item_vers(lpriv, fr, iref.val);

		if (vers > found_vers) {
			found_vers = vers;

			if (item_is_deletion(lpriv, fr, iref.val))
				ret = -ENOENT;
			else
				ret = copy_val(lpriv, fr, val, &iref);
		}
		scoutfs_btree_put_iref(&iref);
		read_unlock_forest_root(finf, lpriv, fr);

		/* done if we have the most recent locked dirty version */
		if (is_our_dirty_item(lock, fr, vers))
			break;
	}

	up_read(&lpriv->rwsem);

	if (err == -ESTALE) {
		err = refresh_check_stale(sb, lock, &prev_srefs, &srefs);
		if (err == 0)
			goto retry;
		ret = err;
	}
out:
	return ret;
}

int scoutfs_forest_lookup_exact(struct super_block *sb,
				struct scoutfs_key *key, struct kvec *val,
				struct scoutfs_lock *lock)
{
	int ret;

	ret = scoutfs_forest_lookup(sb, key, val, lock);
	if (ret == val->iov_len)
		ret = 0;
	else if (ret >= 0)
		ret = -EIO;

	return ret;
}

static inline void forest_iter_set_max(struct scoutfs_key *key, bool forward)
{
	if (forward)
		scoutfs_key_set_ones(key);
	else
		scoutfs_key_set_zeros(key);
}

static inline void forest_iter_set_min(struct scoutfs_key *key, bool forward)
{
	return forest_iter_set_max(key, !forward);
}

static inline void forest_iter_key_advance(struct scoutfs_key *key, bool forward)
{
	if (forward)
		scoutfs_key_inc(key);
	else
		scoutfs_key_dec(key);
}

/* returns true if a is before b in the direction of iteration */
static inline bool forest_iter_key_before(struct scoutfs_key *a,
					  struct scoutfs_key *b, bool forward)
{
	int cmp = scoutfs_key_compare(a, b);

	return forward ? cmp < 0 : cmp > 0;
}

/* returns true if a is before or equal to b in the direction of iteration */
static inline bool forest_iter_key_within(struct scoutfs_key *a,
					  struct scoutfs_key *b, bool forward)
{
	int cmp = scoutfs_key_compare(a, b);

	return forward ? cmp <= 0 : cmp >= 0;
}

static inline int forest_iter_btree_search(struct super_block *sb,
					   struct scoutfs_btree_root *root,
					   void *key, unsigned key_len,
					   struct scoutfs_btree_item_ref *iref,
					   bool forward)
{
	if (forward)
		return scoutfs_btree_next(sb, root, key, key_len, iref);
	else
		return scoutfs_btree_prev(sb, root, key, key_len, iref);
}

struct forest_iter_pos {
	struct list_head entry;
	struct forest_root *fr;
	struct scoutfs_key pos;
};

/*
 * Iterate over items in all the roots looking for the next least
 * non-deletion item in the direction of iteration.  The roots can have
 * any mix of deletion items and item versions.  As we iterate we record
 * the non-deletion item we've seen with the earliest key and the
 * greatest version of that specific key.  We record iteration positions
 * in all btrees and we know we've finished once we've found a possible
 * item to return and all the btrees have checked up to that position.
 */
static int forest_iter(struct super_block *sb, struct scoutfs_key *key,
		       struct scoutfs_key *end, struct kvec *val,
		       struct scoutfs_lock *lock, bool fwd)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_srefs, srefs);
	struct forest_lock_private *lpriv;
	DECLARE_FOREST_INFO(sb, finf);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct forest_iter_pos *tmp;
	struct forest_iter_pos *ip;
	struct scoutfs_key_be kbe;
	struct scoutfs_key found;
	struct forest_root *fr;
	LIST_HEAD(list);
	int found_copied;
	u64 found_vers;
	u64 vers;
	int ret;

	scoutfs_key_set_zeros(&found);
	found_copied = 0;
	found_vers = 0;
	ret = 0;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_READ)) < 0)
		goto out;

	/* use the end key as the end key if it's closer to reduce compares */
	if (forest_iter_key_before(&lock->end, end, fwd))
		end = &lock->end;

	/* convenience to avoid searching if caller iterates past their end */
	if (!forest_iter_key_within(key, end, fwd)) {
		ret = -ENOENT;
		goto out;
	}

	lpriv = get_lock_private(lock);
	if (!lpriv) {
		ret = -ENOMEM;
		goto out;
	}

retry:
	down_read(&lpriv->rwsem);

	/* track iteration position in each btree */
	fr = NULL;
	while (!(ret = for_each_forest_root(lock, lpriv, &fr)) && fr) {
		ip = kmalloc(sizeof(struct forest_iter_pos), GFP_NOFS);
		if (!ip) {
			ret = -ENOMEM;
			goto unlock;
		}

		ip->fr = fr;
		forest_iter_set_min(&ip->pos, fwd);
		list_add_tail(&ip->entry, &list);
	}
	if (ret < 0)
		goto unlock;

	forest_iter_set_max(&found, fwd);
	found_vers = 0;
	found_copied = 0;

	/* check each tree until they've all searched up to found */
	while (!list_empty(&list)) {
		list_for_each_entry_safe(ip, tmp, &list, entry) {
			fr = ip->fr;

			trace_scoutfs_forest_iter_search(sb, fr->rid, fr->nr,
							 &ip->pos);

			/* remove once we can't contain any more items */
			if (!forest_iter_key_before(&ip->pos, &found, fwd) ||
			    !forest_iter_key_within(&ip->pos, end, fwd)) {
				list_del(&ip->entry);
				kfree(ip);
				continue;
			}

			/* iter pos key is only set after searching */
			if (forest_iter_key_before(&ip->pos, key, fwd))
				scoutfs_key_to_be(&kbe, key);
			else
				scoutfs_key_to_be(&kbe, &ip->pos);

			read_lock_forest_root(finf, lpriv, fr);
			ret = forest_iter_btree_search(sb, &fr->item_root,
						       &kbe, sizeof(kbe),
						       &iref, fwd);
			if (ret < 0)
				read_unlock_forest_root(finf, lpriv, fr);
			if (ret == -ENOENT) {
				forest_iter_set_max(&ip->pos, fwd);
				continue;
			}
			if (ret < 0)
				goto unlock;

			scoutfs_key_from_be(&ip->pos, iref.key);
			vers = item_vers(lpriv, fr, iref.val);

			trace_scoutfs_forest_iter_found(sb, fr->rid, fr->nr,
					vers,
					item_flags(lpriv, fr, iref.val),
					&ip->pos);

			/* record next earliest item and copy to caller */
			if (!item_is_deletion(lpriv, fr, iref.val) &&
			    forest_iter_key_within(&ip->pos, end, fwd) &&
			    (forest_iter_key_before(&ip->pos, &found, fwd) ||
			     (scoutfs_key_compare(&ip->pos, &found) == 0 &&
			      vers > found_vers))) {

				found = ip->pos;
				found_vers = vers;
				found_copied = copy_val(lpriv, fr, val, &iref);
			}
			scoutfs_btree_put_iref(&iref);
			read_unlock_forest_root(finf, lpriv, fr);

			forest_iter_key_advance(&ip->pos, fwd);
		}
	}

	ret = 0;
unlock:
	up_read(&lpriv->rwsem);

	list_for_each_entry_safe(ip, tmp, &list, entry) {
		list_del(&ip->entry);
		kfree(ip);
	}

	if (ret == -ESTALE) {
		ret = refresh_check_stale(sb, lock, &prev_srefs, &srefs);
		if (ret == 0)
			goto retry;
	}

out:
	trace_scoutfs_forest_iter_ret(sb, key, end, fwd, ret,
				      found_vers, found_copied, &found);
	if (ret == 0) {
		/* _next/_prev interfaces modify caller's key :/ */
		if (found_vers > 0) {
			*key = found;
			ret = found_copied;
		} else {
			ret = -ENOENT;
		}
	}

	return ret;
}

int scoutfs_forest_next(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_key *last, struct kvec *val,
			struct scoutfs_lock *lock)
{
	return forest_iter(sb, key, last, val, lock, true);
}

int scoutfs_forest_prev(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_key *first, struct kvec *val,
			struct scoutfs_lock *lock)
{
	return forest_iter(sb, key, first, val, lock, false);
}

/*
 * This is an unlocked iteration across all the btrees to find a hint at
 * the next key that the caller could read.  It's used to find out what
 * next key range to lock, presuming you're allowed to only see items
 * that have been synced.  We read the super every time to get the most
 * recent trees.
 *
 * We don't bother skipping deletion or reservation items here.  They're
 * unlikely.  The caller will iterate them over safely and call again to
 * find the next hint after them.
 *
 * We're reading from stable persistent trees so we don't need to lock
 * against writers, their writes are cow into free blocks.
 */
int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_srefs, srefs);
	struct scoutfs_super_block super;
	struct scoutfs_log_trees_key ltk;
	struct scoutfs_log_trees_val ltv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key_be kbe;
	struct scoutfs_key found;
	bool have_next;
	int ret;

retry:
	ret = scoutfs_read_super(sb, &super);
	if (ret)
		goto out;

	srefs.fs_ref = super.fs_root.ref;
	srefs.logs_ref = super.logs_root.ref;

	memset(&ltk, 0, sizeof(ltk));
	have_next = false;

	for (;; be64_add_cpu(&ltk.nr, 1)) {

		ret = scoutfs_btree_next(sb, &super.logs_root,
					 &ltk, sizeof(ltk), &iref);
		if (ret == -ENOENT) {
			if (have_next)
				ret = 0;
			break;
		}
		if (ret == -ESTALE)
			break;
		if (ret < 0)
			goto out;

		if (iref.key_len == sizeof(ltk) &&
		    iref.val_len == sizeof(ltv)) {
			memcpy(&ltk, iref.key, iref.key_len);
			memcpy(&ltv, iref.val, iref.val_len);
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		scoutfs_key_to_be(&kbe, key);
		ret = scoutfs_btree_next(sb, &ltv.item_root,
					 &kbe, sizeof(kbe), &iref);
		if (ret == -ENOENT)
			continue;
		if (ret == -ESTALE)
			break;
		if (ret < 0)
			goto out;

		if (iref.key_len == sizeof(kbe))
			scoutfs_key_from_be(&found, iref.key);
		else
			ret = -EIO;
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		if (!have_next || scoutfs_key_compare(&found, next) < 0) {
			have_next = true;
			*next = found;
		}
	}

	if (ret == -ESTALE) {
		if (memcmp(&prev_srefs, &srefs, sizeof(srefs)) == 0)
			return -EIO;
		prev_srefs = srefs;
		goto retry;
	}
out:

	return ret;
}


/*
 * Make sure that the bloom bits for the lock's start value are all set
 * in the bloom block.  We record the bits being set in the lock so that
 * we only dirty the bloom block once per lock acquisition per log
 * btree.
 *
 * If all the bloom bits weren't set then our log btree won't have been
 * found by the search for log btrees to read under the lock.  The
 * caller is about to insert an item into the log tree that future
 * readers must find so we make sure that the log root is added to the
 * lock's list of roots.
 *
 * This can be racing with itself and readers in any stages of checking
 * the forest trees and bloom blocks.
 */
static int set_lock_bloom_bits(struct super_block *sb,
			       struct scoutfs_lock *lock)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct forest_lock_private *lpriv;
	struct scoutfs_block *new_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_bloom_block *bb;
	struct scoutfs_btree_ref *ref;
	struct forest_bloom_nrs bloom;
	int nr_set = 0;
	u64 blkno;
	int ret;
	int err;
	int i;

	lpriv = get_lock_private(lock);
	if (!lpriv) {
		ret = -ENOMEM;
		goto out;
	}

	if (test_lpriv_flag(lpriv, LPRIV_FLAG_ALL_BLOOM_BITS)) {
		ret = 0;
		goto out;
	}

	calc_bloom_nrs(&bloom, &lock->start);

	down_write(&finf->rwsem);

	ref = &finf->our_log.bloom_ref;

	if (ref->blkno) {
		bl = scoutfs_block_read(sb, le64_to_cpu(ref->blkno));
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto unlock;
		}
		bb = bl->data;
	}

	if (!ref->blkno || !scoutfs_block_writer_is_dirty(sb, bl)) {

		ret = scoutfs_balloc_alloc(sb, &finf->alloc, &finf->wri,
					   &blkno);
		if (ret < 0)
			goto unlock;

		new_bl = scoutfs_block_create(sb, blkno);
		if (IS_ERR(new_bl)) {
			err = scoutfs_balloc_free(sb, &finf->alloc, &finf->wri,
						  blkno);
			BUG_ON(err); /* could have dirtied */
			ret = PTR_ERR(new_bl);
			goto unlock;
		}

		if (bl) {
			err = scoutfs_balloc_free(sb, &finf->alloc, &finf->wri,
						  le64_to_cpu(ref->blkno));
			BUG_ON(err); /* could have dirtied */
			memcpy(new_bl->data, bl->data, SCOUTFS_BLOCK_SIZE);
		} else {
			memset(new_bl->data, 0, SCOUTFS_BLOCK_SIZE);
		}

		scoutfs_block_writer_mark_dirty(sb, &finf->wri, new_bl);

		scoutfs_block_put(sb, bl);
		bl = new_bl;
		bb = bl->data;
		new_bl = NULL;

		bb->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BLOOM);
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

	ret = 0;
unlock:
	up_write(&finf->rwsem);

	if (ret == 0) {
		down_write(&lpriv->rwsem);
		add_our_log_root(finf, lpriv);
		up_write(&lpriv->rwsem);
		set_lpriv_flag(lpriv, LPRIV_FLAG_ALL_BLOOM_BITS);
	}

out:
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * The btree code takes a single value buffer.  When we're working with
 * the log btrees we want to add a log item value metadata header.  In
 * the interest of expedience we're just allocating a new contiguous
 * buffer that prepends the header.  We could make the btree ops take
 * vectored values or we could make all btree items have the metadata.
 */
static struct kvec *alloc_log_item_value(struct kvec *val, __u8 flags,
					 struct scoutfs_lock *lock)
{
	struct scoutfs_log_item_value *liv;
	struct kvec *kv;
	unsigned int val_len = val ? val->iov_len : 0;

	kv = kmalloc(sizeof(*kv) + sizeof(*liv) + val_len, GFP_NOFS);
	if (kv) {
		liv = (void *)kv + sizeof(*kv);

		kv->iov_base = liv;
		kv->iov_len = sizeof(*liv) + val_len;

		liv->vers = cpu_to_le64(lock->write_version);
		liv->flags = flags;
		if (val)
			memcpy(liv->data, val->iov_base, val->iov_len);
	}

	return kv;
}

/*
 * Create a new dirty item.  Can return -EEXIST if the item already
 * exists or will just force createion the caller's item, overwriting
 * any existing item.  We can be overwriting an existing deletion item
 * in our log root.
 */
static int forest_insert(struct super_block *sb, struct scoutfs_key *key,
			 struct kvec *val, struct scoutfs_lock *lock,
			 bool check_eexist, bool check_enoent)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_key_be kbe;
	struct kvec *iv = NULL;
	int ret;

	if (check_eexist || check_enoent) {
		ret = scoutfs_forest_lookup(sb, key, NULL, lock);
		if (ret == 0 && check_eexist) {
			ret = -EEXIST;
			goto out;
		}
		if (ret == -ENOENT) {
			if (check_enoent)
				goto out;
			ret = 0;
		}
		if (ret < 0)
			goto out;
	}

	ret = set_lock_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	iv = alloc_log_item_value(val, 0, lock);
	if (iv == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_key_to_be(&kbe, key);

	down_write(&finf->rwsem);
	ret = scoutfs_btree_force(sb, &finf->alloc, &finf->wri,
				  &finf->our_log.item_root, &kbe, sizeof(kbe),
				  iv->iov_base, iv->iov_len);
	up_write(&finf->rwsem);
	kfree(iv);
out:
	return ret;
}

/*
 * Insert an item, returning -EEXIST if it already exists.
 */
int scoutfs_forest_create(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock)
{
	int ret;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE)) < 0)
		return ret;

	return forest_insert(sb, key, val, lock, true, false);
}

/*
 * Insert an item, ignoring whether it exists or not.
 */
int scoutfs_forest_create_force(struct super_block *sb,
				struct scoutfs_key *key, struct kvec *val,
				struct scoutfs_lock *lock)
{
	int ret;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE_ONLY)) < 0)
		return ret;

	return forest_insert(sb, key, val, lock, false, false);
}

/*
 * Overwrite an existing item, possibly changing its value length,
 * returning -ENOENT if it didn't already exist.
 */
int scoutfs_forest_update(struct super_block *sb, struct scoutfs_key *key,
			  struct kvec *val, struct scoutfs_lock *lock)
{
	int ret;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE)) < 0)
		return ret;

	return forest_insert(sb, key, val, lock, false, true);
}

/* XXX not yet supported, idea is btree op that only uses dirty blocks */
int scoutfs_forest_delete_dirty(struct super_block *sb,
			        struct scoutfs_key *key)
{
	BUG();
	return 0;
}

static int forest_delete(struct super_block *sb, struct scoutfs_key *key,
			 struct scoutfs_lock *lock, bool check_enoent)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_log_item_value liv;
	struct scoutfs_key_be kbe;
	int ret;

	if (check_enoent) {
		ret = scoutfs_forest_lookup(sb, key, NULL, lock);
		if (ret < 0)
			goto out;
	}

	ret = set_lock_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	scoutfs_key_to_be(&kbe, key);
	liv.vers = cpu_to_le64(lock->write_version);
	liv.flags = SCOUTFS_LOG_ITEM_FLAG_DELETION;

	down_write(&finf->rwsem);
	ret = scoutfs_btree_force(sb, &finf->alloc, &finf->wri,
				  &finf->our_log.item_root,
				  &kbe, sizeof(kbe), &liv, sizeof(liv));
	up_write(&finf->rwsem);
out:
	return ret;
}

/*
 * Delete an item from the forest of btrees.  This interface returns
 * -ENOENT if the item doesn't exist (may already be deleted).  We have
 * to first read from the forest to see if it exists.  If we get -ENOENT
 * it might be because it exists in our log tree.  We force our deletion
 * item regardless of the current state of the item in our log tree.
 */
int scoutfs_forest_delete(struct super_block *sb, struct scoutfs_key *key,
			  struct scoutfs_lock *lock)
{
	int ret;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE)) < 0)
		return ret;

	return forest_delete(sb, key, lock, true);
}

/*
 * Like deletion, but we don't have to read the current item to return
 * -ENOENT.  We just force a deletion item.
 */
int scoutfs_forest_delete_force(struct super_block *sb,
				struct scoutfs_key *key,
				struct scoutfs_lock *lock)
{
	int ret;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE_ONLY)) < 0)
		return ret;

	return forest_delete(sb, key, lock, false);
}

/* XXX not supported, just for initial demo */
int scoutfs_forest_delete_save(struct super_block *sb,
			       struct scoutfs_key *key,
			       struct list_head *list,
			       struct scoutfs_lock *lock)
{
	int ret = scoutfs_forest_delete(sb, key, lock);
	BUG_ON(ret != 0);
	return ret;
}

/* XXX not supported, just for initial demo */
int scoutfs_forest_restore(struct super_block *sb, struct list_head *list,
			   struct scoutfs_lock *lock)
{
	BUG();
	return 0;
}

/* XXX not supported, just for initial demo */
void scoutfs_forest_free_batch(struct super_block *sb, struct list_head *list)
{
}


/*
 * This is called from transactions as a new transaction opens and is
 * serialized with all writers.  Get the tree roots that we'll need
 * for the transaction.
 */
int scoutfs_forest_get_log_trees(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_log_trees lt;
	int ret;

	ret = scoutfs_client_get_log_trees(sb, &lt);
	if (ret)
		goto out;

	down_write(&finf->rwsem);
	scoutfs_balloc_init(&finf->alloc, &lt.alloc_root, &lt.free_root);
	scoutfs_block_writer_init(sb, &finf->wri);
	finf->our_log = lt;
	up_write(&finf->rwsem);

	ret = 0;
out:
	return ret;
}

bool scoutfs_forest_has_dirty(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_block_writer_has_dirty(sb, &finf->wri);
}

unsigned long scoutfs_forest_dirty_bytes(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_block_writer_dirty_bytes(sb, &finf->wri);
}

int scoutfs_forest_write(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_block_writer_write(sb, &finf->wri);
}

/*
 * This is called during transaction commit which excludes forest writer
 * calls.  The caller has already written all the dirty blocks that the
 * forest roots reference.
 */
int scoutfs_forest_commit(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_log_trees lt = {
		.alloc_root = finf->alloc.alloc_root,
		.free_root = finf->alloc.free_root,
		.item_root = finf->our_log.item_root,
		.bloom_ref = finf->our_log.bloom_ref,
		.rid = finf->our_log.rid,
		.nr = finf->our_log.nr,
	};

	return scoutfs_client_commit_log_trees(sb, &lt);
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
	init_rwsem(&finf->rwsem);

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
		scoutfs_block_writer_forget_all(sb, &finf->wri);
		kfree(finf);
		sbi->forest_info = NULL;
	}
}
