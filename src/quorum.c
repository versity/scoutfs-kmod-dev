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
#include <linux/in.h>
#include <linux/crc32c.h>
#include <linux/sort.h>
#include <linux/buffer_head.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/hrtimer.h>
#include <linux/blkdev.h>

#include "format.h"
#include "msg.h"
#include "counters.h"
#include "quorum.h"
#include "server.h"
#include "net.h"
#include "scoutfs_trace.h"

/*
 * scoutfs mounts use a region of statically allocated blocks in the
 * shared metadata device to elect a leader mount who runs the server
 * that the rest of the mounts of the filesystem connect to.
 *
 * Mounts that should participate in the election are configured in an
 * array in the super block.  Their position in the array determines the
 * preallocated block that they'll be writing to.  Mounts that aren't
 * participating in the election only read the blocks to discover the
 * outcome of the election.
 *
 * During the election each participating mount reads all the quorum
 * blocks that all the mounts wrote, sees which are active and chooses
 * which to vote for, and writes a new version of their block that
 * includes their vote.  Mounts vote for the mount with the highest
 * priority in the config that is seen actively writing voting blocks
 * over time.
 *
 * Once a mount receives a majority of votes from its peers then it
 * writes its block with an indication that it has been elected.  Only
 * after reading that block, and seeing no other blocks that indicate
 * more recently elected leaders, will it consider itself elected and
 * try to fence any other previously elected leaders before starting the
 * server.  This ensures that racing elected leaders will always result
 * in fencing all but the most recent.
 *
 * XXX:
 *  - actually fence
 *  - add temporary priority for choosing a specific mount as a leader
 *  - add config rotation (write new config, reclaim stale slots)
 */

static void addr_to_sin(struct sockaddr_in *sin, struct scoutfs_inet_addr *addr)
{
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = cpu_to_be32(le32_to_cpu(addr->addr));
	sin->sin_port = cpu_to_be16(le16_to_cpu(addr->port));
}

/* active slots are sorted to the front for validation */
static int cmp_slot_active(const struct scoutfs_quorum_slot *a,
			   const struct scoutfs_quorum_slot *b)
{
	int a_active = !!(a->flags & SCOUTFS_QUORUM_SLOT_ACTIVE);
	int b_active = !!(b->flags & SCOUTFS_QUORUM_SLOT_ACTIVE);

	return b_active - a_active;
}

/* slot validation has ensured that the names are null terminated */
static int cmp_slot_names(const void *A, const void *B)
{
	const struct scoutfs_quorum_slot *a = A;
	const struct scoutfs_quorum_slot *b = B;

	return cmp_slot_active(a, b) ?:
	       strcmp(a->name, b->name);
}

static int cmp_slot_addrs(const void *A, const void *B)
{
	const struct scoutfs_quorum_slot *a = A;
	const struct scoutfs_quorum_slot *b = B;

	return cmp_slot_active(a, b) ?:
	       memcmp(&a->addr, &b->addr, sizeof(a->addr));
}

static void swap_slots(void *A, void *B, int size)
{
	struct scoutfs_quorum_slot *a = A;
	struct scoutfs_quorum_slot *b = B;

	swap(*a, *b);
}

/*
 * We'll set the callers our_slot to the slot that contains the their.
 * If the name isn't found then it'll be set to -1.
 */
static int read_quorum_config(struct super_block *sb,
			      struct scoutfs_super_block *super,
			      char *our_name, int *our_slot_ret,
			      int *nr_active_ret)
{
	struct scoutfs_quorum_slot *sorted = NULL;
	struct scoutfs_quorum_slot *slot;
	struct scoutfs_quorum_config *conf;
	struct sockaddr_in sin;
	int nr_active = 0;
	int our_slot = -1;
	int ret;
	int i;

	sorted = kcalloc(SCOUTFS_QUORUM_MAX_SLOTS, sizeof(sorted[0]), GFP_NOFS);
	if (sorted == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;
	conf = &super->quorum_config;

	ret = -EINVAL;

	if (conf->gen == 0) {
		scoutfs_err(sb, "invalid zero quorum config gen");
		goto out;
	}

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &conf->slots[i];

		if (slot->flags & SCOUTFS_QUORUM_SLOT_FLAGS_UNKNOWN) {
			scoutfs_err(sb, "quorum slot ind %u unknown flags 0x%02x",
				     i, slot->flags);
			goto out;
		}

		if ((slot->flags & SCOUTFS_QUORUM_SLOT_ACTIVE) &&
		     (slot->flags & SCOUTFS_QUORUM_SLOT_STALE)) {
			scoutfs_err(sb, "quorum slot ind %u is both active and stale",
				     i);
			goto out;
		}

		if (!(slot->flags & SCOUTFS_QUORUM_SLOT_ACTIVE))
			continue;

		nr_active++;

		if (slot->name[0] == '\0') {
			scoutfs_err(sb, "quorum slot ind %u name is null", i);
			goto out;
		}

		if (slot->name[SCOUTFS_UNIQUE_NAME_MAX_BYTES - 1] != '\0') {
			scoutfs_err(sb, "quorum slot ind %u name isn't null terminated",
				     i);
			goto out;
		}

		if (our_name && strcmp(our_name, slot->name) == 0)
			our_slot = i;

		addr_to_sin(&sin, &slot->addr);

		if (ipv4_is_multicast(sin.sin_addr.s_addr) ||
		    ipv4_is_lbcast(sin.sin_addr.s_addr) ||
		    ipv4_is_zeronet(sin.sin_addr.s_addr) ||
		    ipv4_is_local_multicast(sin.sin_addr.s_addr) ||
		    ntohs(sin.sin_port) == 0 ||
		    ntohs(sin.sin_port) == U16_MAX) {
			scoutfs_err(sb, "quorum slot ind %u has invalid addr %pIS:%u",
				     i, &sin, ntohs(sin.sin_port));
			goto out;
		}
	}

	if (nr_active == 0) {
		scoutfs_err(sb, "quorum config has no active slots");
		goto out;
	}

	if (nr_active > SCOUTFS_QUORUM_MAX_ACTIVE) {
		scoutfs_err(sb, "quorum config has %u active slots, can have at most %u ",
				nr_active, SCOUTFS_QUORUM_MAX_ACTIVE);
		goto out;
	}

	memcpy(sorted, conf->slots,
	       SCOUTFS_QUORUM_MAX_SLOTS * sizeof(sorted[0]));

	sort(sorted, SCOUTFS_QUORUM_MAX_SLOTS, sizeof(sorted[0]),
	     cmp_slot_names, swap_slots);

	for (i = 1; i < nr_active; i++) {
		if (strcmp(sorted[i].name, sorted[i - 1].name) == 0) {
			scoutfs_err(sb, "multiple quorum slots have the same name '%s'",
				     sorted[i].name);
			goto out;
		}
	}

	sort(sorted, SCOUTFS_QUORUM_MAX_SLOTS, sizeof(sorted[0]),
	     cmp_slot_addrs, swap_slots);

	for (i = 1; i < nr_active; i++) {
		if (memcmp(&sorted[i].addr, &sorted[i - 1].addr,
			   sizeof(sorted[i].addr)) == 0) {
			addr_to_sin(&sin, &sorted[i].addr);
			scoutfs_err(sb, "multiple quorum slots have the same address %pIS:%u",
				     &sin, ntohs(sin.sin_port));
			goto out;
		}
	}

	ret = 0;
	if (our_slot_ret)
		*our_slot_ret = our_slot;
	if (nr_active_ret)
		*nr_active_ret = nr_active;
out:
	if (ret)
		scoutfs_inc_counter(sb, quorum_read_invalid_config);
	kfree(sorted);
	return ret;
}

/*
 * The caller is about to read the current version of a set of quorum
 * blocks.  We invalidate all the quorum blocks in the cache and
 * populate the cache with all the blocks with one large contiguous
 * read.  The caller then uses simple sync bh methods to access
 * whichever blocks it needs.  I'm not a huge fan of the plug but I
 * couldn't get the individual readahead requests merged without it.
 */
static void readahead_quorum_blocks(struct super_block *sb)
{
	struct buffer_head *bh;
	struct blk_plug plug;
	int i;

	blk_start_plug(&plug);

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		bh = sb_getblk(sb, SCOUTFS_QUORUM_BLKNO + i);
		if (!bh)
			continue;

		lock_buffer(bh);
		clear_buffer_uptodate(bh);
		unlock_buffer(bh);

		ll_rw_block(READA | REQ_META | REQ_PRIO, 1, &bh);
		brelse(bh);
	}

	blk_finish_plug(&plug);
}

/*
 * Callers don't mind us clobbering the crc temporarily.
 */
static __le32 quorum_block_crc(struct scoutfs_quorum_block *blk)
{
	__le32 calc_crc;
	__le32 blk_crc;

	blk_crc = blk->crc;
	blk->crc = 0;
	calc_crc = cpu_to_le32(crc32c(~0, blk, sizeof(*blk)));
	blk->crc = blk_crc;

	return calc_crc;
}

static bool invalid_quorum_block(struct scoutfs_super_block *super,
				 struct buffer_head *bh,
				 struct scoutfs_quorum_block *blk)
{
	return quorum_block_crc(blk) != blk->crc ||
	       blk->fsid != super->hdr.fsid ||
	       le64_to_cpu(blk->blkno) != bh->b_blocknr ||
	       blk->vote_slot >= SCOUTFS_QUORUM_MAX_SLOTS ||
	       (blk->flags & SCOUTFS_QUORUM_BLOCK_FLAGS_UNKNOWN);
}

/*
 * Give the caller the most recently updated version of the quorum
 * block.  Returns 0 and fills the callers block struct on success.
 * Returns -ENOENT and zeros the caller's block if we couldn't read a
 * valid block.  We don't consider the config gen, that's up to the
 * caller.
 */
static int read_quorum_block(struct super_block *sb,
			     struct scoutfs_super_block *super, int slot,
			     struct scoutfs_quorum_block *blk_ret)
{
	struct scoutfs_quorum_block *blk;
	struct buffer_head *bh;
	int ret;

	/* code strongly assumes that slots and blocks are directly mapped */
	BUILD_BUG_ON(SCOUTFS_QUORUM_BLOCKS != SCOUTFS_QUORUM_MAX_SLOTS);

	ret = -ENOENT;

	bh = sb_bread(sb, SCOUTFS_QUORUM_BLKNO + slot);
	if (!bh) {
		scoutfs_inc_counter(sb, quorum_read_block_error);
		goto out;
	}
	blk = (void *)(bh->b_data);

	/* ignore unwritten blocks */
	if (blk->write_nr == 0)
		goto out;

	trace_scoutfs_quorum_read_block(sb, bh->b_blocknr, blk);

	if (invalid_quorum_block(super, bh, blk)) {
		scoutfs_inc_counter(sb, quorum_read_invalid_block);
		goto out;
	}

	*blk_ret = *blk;
	scoutfs_inc_counter(sb, quorum_read_block);
	ret = 0;
out:
	if (ret < 0)
		memset(blk_ret, 0, sizeof(struct scoutfs_quorum_block));
	brelse(bh);
	return ret;
}

/*
 * Iterate over config slots from the given index and return the first
 * slot that has any of the given flags set.
 */
static inline int first_slot_flags(struct scoutfs_quorum_config *conf,
				   int i, u8 flags)
{
	for (; i < ARRAY_SIZE(conf->slots); i++) {
		if (conf->slots[i].flags & flags)
			break;
	}
	return i;
}

/*
 * Execute the loop body with the read block for each slot that's
 * configured and active.  If we can't read the block for whatever
 * reason then the loop will execute with the blk struct zeroed.
 */
#define for_each_active_block(sb, super, conf, hists, hi, blk, slot, i)	\
	for (i = first_slot_flags(conf, 0, SCOUTFS_QUORUM_SLOT_ACTIVE);	\
	     (i < ARRAY_SIZE(conf->slots)) &&				\
		(slot = &conf->slots[i],				\
		 hi = &hists[i],					\
		 read_quorum_block(sb, super, i, blk), 1);		\
	     i = first_slot_flags(conf, i + 1, SCOUTFS_QUORUM_SLOT_ACTIVE))

/*
 * Iterate over every possible block, regardless of config.  A lot of these
 * will be zero.
 */
#define for_each_block(sb, super, i, blk)				\
	for (i = 0;							\
	     (i < SCOUTFS_QUORUM_BLOCKS) &&				\
		(read_quorum_block(sb, super, i, blk), 1);		\
	     i++)

/*
 * Synchronously write a single quorum block.  The caller has provided
 * the meaningful fields for the write.  We fill in the rest that are
 * consistent for every write and zero the rest of the block.
 */
static int write_quorum_block(struct super_block *sb, __le64 fsid,
			      __le64 config_gen, u8 our_slot, __le64 write_nr,
			      u64 elected_nr, u64 unmount_barrier,
			      u8 vote_slot, u8 flags)
{
	struct scoutfs_quorum_block *blk;
	struct buffer_head *bh;
	int ret;

	BUILD_BUG_ON(sizeof(struct scoutfs_quorum_block) > SCOUTFS_BLOCK_SIZE);

	if (WARN_ON_ONCE(our_slot >= SCOUTFS_QUORUM_MAX_SLOTS) ||
	    WARN_ON_ONCE(vote_slot >= SCOUTFS_QUORUM_MAX_SLOTS))
		return -EINVAL;

	bh = sb_getblk(sb, SCOUTFS_QUORUM_BLKNO + our_slot);
	if (bh == NULL) {
		ret = -EIO;
		goto out;
	}
	blk = (void *)bh->b_data;

	blk->fsid = fsid;
	blk->blkno = cpu_to_le64(bh->b_blocknr);
	blk->config_gen = config_gen;
	blk->write_nr = write_nr;
	blk->elected_nr = cpu_to_le64(elected_nr);
	blk->unmount_barrier = cpu_to_le64(unmount_barrier);
	blk->vote_slot = vote_slot;
	blk->flags = flags;

	blk->crc = quorum_block_crc(blk);

	lock_buffer(bh);
	set_buffer_mapped(bh);
	bh->b_end_io = end_buffer_write_sync;
	get_bh(bh);
	submit_bh(WRITE_SYNC | REQ_META | REQ_PRIO, bh);

	wait_on_buffer(bh);
	if (!buffer_uptodate(bh))
		ret = -EIO;
	else
		ret = 0;

	if (ret == 0) {
		trace_scoutfs_quorum_write_block(sb, bh->b_blocknr, blk);
		scoutfs_inc_counter(sb, quorum_write_block);
	}
out:
	if (ret)
		scoutfs_inc_counter(sb, quorum_write_block_error);
	brelse(bh);
	return ret;
}

/*
 * The caller read their quorum block which indicated that they were
 * elected.  We have to fence all other previously elected leaders so
 * that we're running the only instance of the server.
 *
 * Time can pass between all phases of this: reading that we're elected,
 * fencing, and writing the quorum block that clears the elected flag of
 * those we fenced.
 *
 * This is always safe because we either have exclusive access to the
 * device having fenced others or someone else would have fenced us
 * before they write.
 */
static int fence_other_elected(struct super_block *sb,
			       struct scoutfs_super_block *super,
			       int our_slot, u64 elected_nr)
{
	struct scoutfs_quorum_config *conf = &super->quorum_config;
	struct scoutfs_quorum_block blk;
	u8 flags;
	int ret;
	int i;

	for_each_block(sb, super, i, &blk) {
		if (i != our_slot &&
		    (blk.flags & SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED) &&
		    le64_to_cpu(blk.elected_nr) <= elected_nr) {
			scoutfs_err(sb, "would have fenced");
			scoutfs_inc_counter(sb, quorum_fenced);

			flags = blk.flags & ~SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED;

			ret = write_quorum_block(sb, super->hdr.fsid,
					conf->gen, i, blk.write_nr,
					le64_to_cpu(blk.elected_nr),
					le64_to_cpu(blk.unmount_barrier), i,
					flags);
			if (ret)
				break;
		}
	}

	return ret;
}

struct quorum_block_history {
	__le64 write_nr;
	u8 writing;
};

/*
 * The caller couldn't connect to a server.  Read the quorum blocks
 * until we see an elected leader and give their address to the caller.
 * If we're configured as part of the quorum then we participate in the
 * electing by writing our vote to our quorum block.
 *
 * Voting members read the blocks at regular intervals and update their
 * quorum block with their vote for the elected leader.  new leader.
 * When a mount receives enough votes it marks its vote in the block as
 * elected, fences other elected leaders, and returns to the caller who
 * starts up the server for others to connect to.
 *
 * The calling client may have never seen a server before, or could have
 * failed to connect to a valid server, or might have tried to connect
 * to a dead server.  They pass in an existing elected_nr if they want
 * us to ignore old servers and they pass in a timeout so that they can
 * return to retrying to connect to whatever address we find.
 *
 * When we return success we update the caller's elected info with the
 * most recent elected leader we found, which may well be long gone.  We
 * return -ENOENT if we didn't find any elected leaders.
 *
 * If we return success because we saw a larger unmount barrier we set
 * elected_nr to 0 and fill the unmount_barrier.
 */
int scoutfs_quorum_election(struct super_block *sb, char *our_name,
			    u64 old_elected_nr, ktime_t timeout_abs,
			    bool unmounting, u64 our_umb,
			    struct scoutfs_quorum_elected_info *qei)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_quorum_config *conf;
	struct scoutfs_quorum_slot *slot;
	struct scoutfs_quorum_block blk;
	struct quorum_block_history *hist;
	struct quorum_block_history *hi;
	ktime_t expires;
	ktime_t now;
	__le64 write_nr = 0;
	u64 elected_nr = 0;
	u64 unmount_barrier = 0;
	u8 flags = 0;
	int vote_streak = 0;
	int vote_slot;
	int our_slot;
	int vote_prio;
	int nr_active;
	int nr_votes;
	int majority;
	int ret;
	int i;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	hist = kcalloc(SCOUTFS_QUORUM_MAX_SLOTS, sizeof(hist[0]), GFP_NOFS);
	if (!super || !hist) {
		ret = -ENOMEM;
		goto out;
	}

	for (;;) {
		now = ktime_get();
		expires = ktime_add_ms(now, SCOUTFS_QUORUM_INTERVAL_MS);

		ret = read_quorum_config(sb, super, our_name, &our_slot,
					 &nr_active);
		if (ret)
			goto out;
		conf = &super->quorum_config;

		majority = scoutfs_quorum_majority(sb, conf);

		readahead_quorum_blocks(sb);

		/* default to voting for ourselves, but at min prio */
		vote_slot = our_slot;
		vote_prio = -1;
		memset(qei, 0, sizeof(*qei));

		for_each_active_block(sb, super, conf, hist, hi, &blk, slot, i){
			/* determine which mounts are writing */
			if (blk.config_gen == conf->gen &&
			    blk.write_nr != 0 &&
			    blk.write_nr != hi->write_nr)
				hi->writing = min(hi->writing + 1, 2);
			else
				hi->writing = 0;
			hi->write_nr = blk.write_nr;

			/* vote for first highest priority writing block */
			if (hi->writing >= 2 &&
			    slot->vote_priority > vote_prio) {
				vote_slot = i;
				vote_prio = slot->vote_priority;
			}

			/* find the most recently elected leader */
			if ((blk.config_gen == conf->gen) &&
			    (blk.flags & SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED) &&
			    (le64_to_cpu(blk.elected_nr) > qei->elected_nr)){
				addr_to_sin(&qei->sin, &slot->addr);
				qei->config_gen = blk.config_gen;
				qei->write_nr = blk.write_nr;
				qei->elected_nr = le64_to_cpu(blk.elected_nr);
				qei->unmount_barrier =
					le64_to_cpu(blk.unmount_barrier);
				qei->config_slot = i;
				qei->flags = blk.flags;
			}
		}

		/*
		 * After writing a block indicating that we were elected
		 * we make sure that we can read it and that we're still
		 * the most recent elected leader.  If we are then we
		 * try to fence.  If we can't read it, or we're not the
		 * most recent, or we couldn't fence, then we fall back
		 * to participating in the election.
		 */
		if (flags & SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED) {
			if (qei->write_nr == write_nr &&
			    qei->elected_nr == elected_nr &&
			    qei->config_slot == our_slot) {
				ret = fence_other_elected(sb, super, our_slot,
							  elected_nr);
				if (ret == 0) {
					qei->run_server = true;
					goto out;
				}

				memset(qei, 0, sizeof(*qei));
			}

			vote_streak = 0;
		}

		/* return if we found a new leader or ran out of time */
		if (qei->elected_nr > old_elected_nr ||
		     ktime_after(now, timeout_abs)) {
			if (qei->elected_nr > 0) {
				scoutfs_inc_counter(sb, quorum_found_leader);
				ret = 0;
			} else {
				scoutfs_inc_counter(sb, quorum_no_leader);
				ret = -ENOENT;
			}
			goto out;
		}

		/* wait for the next cycle if we're not in the voting config */
		if (our_slot < 0)
			continue;

		nr_votes = 0;
		write_nr = cpu_to_le64(1);
		elected_nr = 0;
		unmount_barrier = 0;
		flags = 0;

		for_each_active_block(sb, super, conf, hist, hi, &blk, slot, i){
			/* count our votes (maybe including from us) */
			if (hi->writing >= 2 && blk.vote_slot == our_slot)
				nr_votes++;

			/* can finish unmounting if members all left */
			if (unmounting &&
			    le64_to_cpu(blk.unmount_barrier) > our_umb) {
				qei->elected_nr = 0;
				qei->unmount_barrier =
					le64_to_cpu(blk.unmount_barrier);
				ret = 0;
				goto out;
			}

			/* sample existing fields for our write */
			if (i == our_slot) {
				write_nr = blk.write_nr;
				le64_add_cpu(&write_nr, 1);
			}
			elected_nr = max(elected_nr,
					 le64_to_cpu(blk.elected_nr));
			unmount_barrier = max(unmount_barrier,
					      le64_to_cpu(blk.unmount_barrier));
		}


		/* elected after sufficient cycles with a majority vote */
		if (nr_votes >= majority)
			vote_streak = min(vote_streak + 1, 2);
		else
			vote_streak = 0;

		if (vote_streak >= 2) {
			flags |= SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED;
			elected_nr++;
		}

		write_quorum_block(sb, super->hdr.fsid, conf->gen, our_slot,
				   write_nr, elected_nr, unmount_barrier,
				   vote_slot, flags);

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		scoutfs_inc_counter(sb, quorum_waited);
	}

out:
	kfree(super);
	kfree(hist);

	if (ret) {
		memset(qei, 0, sizeof(*qei));
		scoutfs_inc_counter(sb, quorum_election_error);
	}

	return ret;
}

/*
 * The calling server is shutting down and has finished modifying
 * persistent state.  We clear the elected flag from our quorum block so
 * that mounts won't try to connect and so that the next next leader
 * won't try to fence.
 *
 * By definition nothing has written to the slot since we wrote our
 * elected quorum block and the slot could not have been reclaimed.  To
 * reclaim the slot would have required proving that we were gone or
 * fencing us.
 *
 * If this fails then the mount is in trouble because it'll probably be
 * fenced by the next elected leader.
 *
 * XXX I think there's an interesting race here.  If the server is
 * running in an old config then the server's slot can be reclaimed if
 * the server sees a connection from the current gen.   If the server is
 * taking a client connection as an indication that the slot won't be
 * written then the client needs to shut down the server before trying
 * to connect with a new gen.
 */
int scoutfs_quorum_clear_elected(struct super_block *sb,
				 struct scoutfs_quorum_elected_info *qei)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	qei->flags &= ~SCOUTFS_QUORUM_BLOCK_FLAG_ELECTED;

	return write_quorum_block(sb, super->hdr.fsid, qei->config_gen,
				  qei->config_slot, qei->write_nr,
				  qei->elected_nr, qei->unmount_barrier,
				  qei->config_slot, qei->flags);
}

int scoutfs_quorum_update_barrier(struct super_block *sb,
				  struct scoutfs_quorum_elected_info *qei,
				  u64 unmount_barrier)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;

	qei->unmount_barrier = unmount_barrier;

	return write_quorum_block(sb, super->hdr.fsid, qei->config_gen,
				  qei->config_slot, qei->write_nr,
				  qei->elected_nr, qei->unmount_barrier,
				  qei->config_slot, qei->flags);
}

/*
 * If there's only one or two active slots then a single vote is sufficient
 * for a majority.
 */
int scoutfs_quorum_majority(struct super_block *sb,
			    struct scoutfs_quorum_config *conf)
{
	struct scoutfs_quorum_slot *slot;
	int nr_active = 0;
	int majority;
	int i;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &conf->slots[i];

		if (slot->flags & SCOUTFS_QUORUM_SLOT_ACTIVE)
			nr_active++;
	}

	if (nr_active <= 2)
		majority = 1;
	else if (nr_active & 1)
		majority = (nr_active + 1) / 2;
	else
		majority = (nr_active / 2) + 1;

	return majority;
}

bool scoutfs_quorum_voting_member(struct super_block *sb,
				  struct scoutfs_quorum_config *conf,
				  char *name)
{
	struct scoutfs_quorum_slot *slot;
	int i;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &conf->slots[i];

		if (strcmp(slot->name, name) == 0)
			return true;
	}

	return false;
}
