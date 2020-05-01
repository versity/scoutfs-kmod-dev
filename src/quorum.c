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
#include "sysfs.h"
#include "scoutfs_trace.h"

/*
 * scoutfs mounts communicate through a region of preallocated blocks to
 * elect a leader who starts the server.  Mounts which have been
 * configured with a server address and which can't connect to a server
 * attempt to form a quorum to elect a new leader who starts a new
 * server.
 *
 * The mounts participating in the election use a variant of the raft
 * election protocol to establish quorum and elect a leader.  We use
 * block reads and writes instead of network messages.  Mounts read all
 * the blocks looking for messages to receive.  Mounts write their vote
 * to a random block in the region to send a message to all other
 * mounts.  Unlikely collisions are analogous to lossy networks losing
 * messages and are handled by the protocol.
 *
 * We allow a "majority" of 1 voter when there are less than three
 * possible voters.  This lets a simple network establish quorum.  If
 * the raft quorum timeouts align to leaders could both elect themselves
 * and race to fence each other.  In the worst case they could continue
 * to do this indefinitely but it's unlikely as it would require a
 * sequence of identical random raft timeouts.
 *
 * One of the reasons we use block reads and writes as the quorum
 * communication medium is that it lets us leave behind a shared
 * persistent log of previous election results.  This then lets a newly
 * elected leader fence all previously elected leaders that haven't
 * shutdown so that they can safely assume exclusive access to the
 * shared device.  Every written block includes a log of election
 * results.  Every voter merges the log from every block it reads the
 * block it writes.  A leader doesn't attempt to fence until it's spent
 * a few cycles writing blocks with itself as the log entry.  This gives
 * other voters time to migrate the log entry through the blocks.
 *
 * Once a leader is elected it fences any previously elected leaders
 * still present in the log it merged while reading all the voting
 * blocks.  Once they've fenced they update the super block record of
 * the latest term that has been fenced.  This trims the log over time
 * and keeps from attempting to fence the same mounts multiple times.
 * As the server later shuts down it writes its term into the super to
 * stop it from being fenced.
 *
 * The final complication comes during unmount.  Clients exit after the
 * server responds to their farewell request.  But a majority of clients
 * need to be present to elect a server to process farewell requests.
 * The server knows which clients will attempt to vote for quorum and
 * only responds to their farewell requests once they're no longer
 * needed to elect a server -- either there's still quorum remaining of
 * other mounts or the only mounts remaining are all quorum voters that
 * have sent farewell requests.  Before sending these final responses
 * the server updates an unmount_barrier field in the super.  If clients
 * that are waiting for a farewell response see the unmount barrier
 * increment they know that their farewell has been processed and they
 * can assume a successful farewell response and exit cleanly.
 *
 * XXX: - actually fence
 */

struct quorum_info {
	struct scoutfs_sysfs_attrs ssa;

	bool is_leader;
};

#define DECLARE_QUORUM_INFO(sb, name) \
	struct quorum_info *name = SCOUTFS_SB(sb)->quorum_info
#define DECLARE_QUORUM_INFO_KOBJ(kobj, name) \
	DECLARE_QUORUM_INFO(SCOUTFS_SYSFS_ATTRS_SB(kobj), name)

/*
 * Return an absolute ktime timeout expires value in the future after a
 * random duration between hi and lo where both limits are possible.
 */
static ktime_t random_to(u32 lo, u32 hi)
{
	return ktime_add_ms(ktime_get(), lo + prandom_u32_max((hi + 1) - lo));
}

/*
 * The caller is about to read all the quorum blocks.  We invalidate any
 * cached blocks and issue one large contiguous read to repopulate the
 * cache.  The caller then uses normal sb_bread to read each block.  I'm
 * not a huge fan of the plug but I couldn't get the individual
 * readahead requests merged without it.
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

struct quorum_block_head {
	struct list_head head;
	union {
		struct scoutfs_quorum_block blk;
		u8 bytes[SCOUTFS_BLOCK_SM_SIZE];
	};
};

static void free_quorum_blocks(struct list_head *blocks)
{
	struct quorum_block_head *qbh;
	struct quorum_block_head *tmp;

	list_for_each_entry_safe(qbh, tmp, blocks, head) {
		list_del_init(&qbh->head);
		kfree(qbh);
	}
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

static size_t quorum_block_bytes(struct scoutfs_quorum_block *blk)
{
	return offsetof(struct scoutfs_quorum_block,
			log[blk->log_nr]);
}

static bool invalid_quorum_block(struct buffer_head *bh,
				 struct scoutfs_quorum_block *blk)
{
	return bh->b_size != SCOUTFS_BLOCK_SM_SIZE ||
	       sizeof(struct scoutfs_quorum_block) > SCOUTFS_BLOCK_SM_SIZE ||
	       quorum_block_crc(blk) != blk->crc ||
	       le64_to_cpu(blk->blkno) != bh->b_blocknr ||
	       blk->term == 0 ||
	       blk->log_nr > SCOUTFS_QUORUM_LOG_MAX ||
	       quorum_block_bytes(blk) > SCOUTFS_BLOCK_SM_SIZE;
}

/* true if a is stale and should be ignored */
static bool stale_quorum_block(struct scoutfs_quorum_block *a,
			       struct scoutfs_quorum_block *b)
{
	if (le64_to_cpu(a->term) < le64_to_cpu(b->term))
		return true;

	if (le64_to_cpu(a->voter_rid) == le64_to_cpu(b->voter_rid) &&
	    le64_to_cpu(a->write_nr) <= le64_to_cpu(b->write_nr))
		return true;

	return false;
}

/*
 * Get the most recent blocks from all the voters for the most recent term.
 * We ignore any corrupt blocks, blocks not for our fsid, previous terms,
 * and previous writes from a rid in the current term.
 */
static int read_quorum_blocks(struct super_block *sb, struct list_head *blocks)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_quorum_block *blk;
	struct quorum_block_head *qbh;
	struct quorum_block_head *tmp;
	struct buffer_head *bh = NULL;
	LIST_HEAD(stale);
	int ret;
	int i;

	readahead_quorum_blocks(sb);

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		brelse(bh);
		bh = sb_bread(sb, SCOUTFS_QUORUM_BLKNO + i);
		if (!bh) {
			scoutfs_inc_counter(sb, quorum_read_block_error);
			ret = -EIO;
			goto out;
		}
		blk = (void *)(bh->b_data);

		/* ignore unwritten blocks or blocks for other filesystems */
		if (blk->voter_rid == 0 || blk->fsid != super->hdr.fsid)
			continue;

		if (invalid_quorum_block(bh, blk)) {
			scoutfs_inc_counter(sb, quorum_read_invalid_block);
			continue;
		}

		list_for_each_entry_safe(qbh, tmp, blocks, head) {
			if (stale_quorum_block(blk, &qbh->blk)) {
				blk = NULL;
				break;
			}

			if (stale_quorum_block(&qbh->blk, blk))
				list_move(&qbh->head, &stale);
		}
		free_quorum_blocks(&stale);

		if (!blk)
			continue;

		qbh = kmalloc(sizeof(struct quorum_block_head),
				     GFP_NOFS);
		if (!qbh) {
			ret = -ENOMEM;
			goto out;
		}

		memcpy(&qbh->blk, blk, quorum_block_bytes(blk));
		list_add_tail(&qbh->head, blocks);
	}

	list_for_each_entry(qbh, blocks, head) {
		trace_scoutfs_quorum_read_block(sb, &qbh->blk);
		scoutfs_inc_counter(sb, quorum_read_block);
	}

	ret = 0;
out:
	brelse(bh);
	if (ret < 0)
		free_quorum_blocks(blocks);
	return ret;
}

/*
 * Synchronously write a single quorum block.  The caller has provided
 * the meaningful fields for the write.  We fill in the fsid, blkno, and
 * crc for every write and zero the rest of the block.
 */
static int write_quorum_block(struct super_block *sb,
			      struct scoutfs_quorum_block *our_blk)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_quorum_block *blk;
	struct buffer_head *bh = NULL;
	size_t size;
	int ret;

	BUILD_BUG_ON(sizeof(struct scoutfs_quorum_block) >
		     SCOUTFS_BLOCK_SM_SIZE);

	bh = sb_getblk(sb, SCOUTFS_QUORUM_BLKNO +
			   prandom_u32_max(SCOUTFS_QUORUM_BLOCKS));
	if (bh == NULL) {
		ret = -EIO;
		goto out;
	}

	size = quorum_block_bytes(our_blk);
	if (WARN_ON_ONCE(size > SCOUTFS_BLOCK_SM_SIZE || size > bh->b_size)) {
		ret = -EIO;
		goto out;
	}

	blk = (void *)bh->b_data;
	memset(blk, 0, bh->b_size);
	memcpy(blk, our_blk, size);

	blk->fsid = super->hdr.fsid;
	blk->blkno = cpu_to_le64(bh->b_blocknr);
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
		trace_scoutfs_quorum_write_block(sb, blk);
		scoutfs_inc_counter(sb, quorum_write_block);
	}
out:
	if (ret)
		scoutfs_inc_counter(sb, quorum_write_block_error);
	brelse(bh);
	return ret;
}

/*
 * Returns true if there's an entry for the given election.
 */
static bool log_contains(struct scoutfs_quorum_block *blk, u64 term, u64 rid)
{
	int i;

	for (i = 0; i < blk->log_nr; i++) {
		if (le64_to_cpu(blk->log[i].term) == term &&
		    le64_to_cpu(blk->log[i].rid) == rid)
			return true;
	}

	return false;
}

/* add an entry to the log, returning error if it's full */
static int log_add(struct scoutfs_quorum_block *blk, u64 term, u64 rid,
		   struct scoutfs_inet_addr *addr)
{
	int i;

	if (log_contains(blk, term, rid))
		return 0;

	if (blk->log_nr == SCOUTFS_QUORUM_LOG_MAX)
		return -ENOSPC;

	i = blk->log_nr++;
	blk->log[i].term = cpu_to_le64(term);
	blk->log[i].rid = cpu_to_le64(rid);
	blk->log[i].addr = *addr;

	return 0;
}

/* migrate live log entries between blocks, returning err if full */
static int log_merge(struct scoutfs_quorum_block *our_blk,
		     struct scoutfs_quorum_block *blk,
		     u64 fenced_term)
{
	int ret;
	int i;

	for (i = 0; i < blk->log_nr; i++) {
		if (le64_to_cpu(blk->log[i].term) > fenced_term) {
			ret = log_add(our_blk, le64_to_cpu(blk->log[i].term),
				      le64_to_cpu(blk->log[i].rid),
				      &blk->log[i].addr);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

/* Remove old log entries for a voter before a given term. */
static void log_purge(struct scoutfs_quorum_block *blk, u64 term, u64 rid)
{
	int i;

	for (i = 0; i < blk->log_nr; i++) {
		if (le64_to_cpu(blk->log[i].term) < term &&
		    le64_to_cpu(blk->log[i].rid) == rid) {
			if (i != blk->log_nr - 1)
				swap(blk->log[i], blk->log[blk->log_nr - 1]);
			blk->log_nr--;
			i--; /* continue from swapped in entry */
		}
	}
}


/*
 * The caller received a majority of votes and has been elected.  Before
 * assuming exclusive write access to the device we fence the winners of
 * any previous elections still present in the log.  Once they're fenced
 * we re-read the super and update the fenced_term to indicate that
 * those previous elections can be ignored and purged from the log.
 *
 * We can be attempting this concurrently with both previous and future
 * elected leaders.  The leader with the greatest elected term will win
 * and fence all previous elected leaders.
 *
 * We clobber the caller's block as we go to not fence rids multiple times.
 */
static int fence_previous(struct super_block *sb,
			  struct scoutfs_quorum_block *blk,
			  u64 our_rid, u64 fenced_term, u64 term)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct sockaddr_in their_sin;
	int ret;
	int i;

	for (i = 0; i < blk->log_nr; i++) {
		if (le64_to_cpu(blk->log[i].rid) != our_rid &&
		    le64_to_cpu(blk->log[i].term) > fenced_term &&
		    le64_to_cpu(blk->log[i].term) < term) {

			scoutfs_inc_counter(sb, quorum_fenced);
			scoutfs_addr_to_sin(&their_sin, &blk->log[i].addr);
			scoutfs_err(sb, "fencing "SCSBF" at "SIN_FMT,
					SCSB_LEFR_ARGS(super->hdr.fsid,
						       blk->log[i].rid),
					SIN_ARG(&their_sin));

			log_purge(blk, term, le64_to_cpu(blk->log[i].rid));
			i = -1; /* start over */
		}
	}

	/* update fenced term now that we have exclusive access */
	ret = 0;
	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (super) {
		ret = scoutfs_read_super(sb, super);
		if (ret == 0) {
			super->quorum_fenced_term = cpu_to_le64(term - 1);
			ret = scoutfs_write_super(sb, super);

		}
		kfree(super);
	} else {
		ret = -ENOMEM;
	}

	if (ret != 0) {
		scoutfs_err(sb, "failed to update fenced_term in super, this mount will probably be fenced");
	}

	return ret;
}



/*
 * The calling voting mount couldn't connect to a server.  Participate
 * in a raft election to chose a mount to start a new server.  If a
 * majority of other mounts join us then one of us will be elected and
 * our caller will start the server.
 *
 * Voting members read the blocks at regular intervals.  If they see a
 * new election they vote for that candidate for the remainder of the
 * election.  If the election timeout expires they will start a new
 * election and vote for themselves.  Eventually a sufficient majority
 * sees a new election and all vote in the majority for that candidate.
 *
 * The calling client may have just failed to connect to an elected
 * address in the super block.  We assume that server is dead and ignore
 * it when trying to elect a new leader.  But we eventually return with
 * a timeout because the server could actually be fine and the client
 * could have had communication to the server restored.
 *
 * We return success if we see a new server elected.  If we are elected
 * we set the caller's elected_term so they know to start the server.
 */
int scoutfs_quorum_election(struct super_block *sb, ktime_t timeout_abs,
			    u64 prev_term, u64 *elected_term)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct mount_options *opts = &SCOUTFS_SB(sb)->opts;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_quorum_block *our_blk = NULL;
	struct scoutfs_quorum_block *blk;
	struct quorum_block_head *qbh;
	struct scoutfs_inet_addr addr;
	enum { VOTER, CANDIDATE };
	ktime_t cycle_to;
	ktime_t term_to;
	LIST_HEAD(blocks);
	u64 vote_for_write_nr;
	u64 vote_for_rid;
	u64 write_nr;
	u64 term;
	int log_cycles = 0;
	int votes;
	int role;
	int ret;

	*elected_term = 0;

	trace_scoutfs_quorum_election(sb, prev_term);

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	our_blk = kmalloc(SCOUTFS_BLOCK_SM_SIZE, GFP_NOFS);
	if (!super || !our_blk) {
		ret = -ENOMEM;
		goto out;
	}

	/* start out as a passive voter */
	role = VOTER;
	term = 0;
	write_nr = 0;
	vote_for_rid = 0;
	vote_for_write_nr = 0;

	/* we'll become a candidate if we don't see another candidate */
	term_to = random_to(SCOUTFS_QUORUM_TERM_LO_MS,
			    SCOUTFS_QUORUM_TERM_HI_MS);

	for (;;) {
		memset(our_blk, 0, SCOUTFS_BLOCK_SM_SIZE);

		scoutfs_inc_counter(sb, quorum_cycle);

		ret = scoutfs_read_super(sb, super);
		if (ret)
			goto out;

		/* done if we see evidence of a new server */
		if (le64_to_cpu(super->quorum_server_term) > prev_term) {
			scoutfs_inc_counter(sb, quorum_saw_super_leader);
			ret = 0;
			goto out;
		}

		/* done if we couldn't elect anyone */
		if (ktime_after(ktime_get(), timeout_abs)) {
			scoutfs_inc_counter(sb, quorum_timedout);
			ret = -ETIMEDOUT;
			goto out;
		}

		/* become a candidate if the election times out */
		if (ktime_after(ktime_get(), term_to)) {
			scoutfs_inc_counter(sb, quorum_election_timeout);
			term_to = random_to(SCOUTFS_QUORUM_TERM_LO_MS,
					    SCOUTFS_QUORUM_TERM_HI_MS);
			role = CANDIDATE;
			term++;
			vote_for_rid = sbi->rid;
			log_cycles = 0;
		}

		free_quorum_blocks(&blocks);
		ret = read_quorum_blocks(sb, &blocks);
		if (ret < 0)
			goto out;

		votes = 0;

		list_for_each_entry(qbh, &blocks, head) {
			blk = &qbh->blk;

			/*
			 * Become a voter for a candidate the first time
			 * we see a new term.
			 *
			 * And also if we're a candidate and see a
			 * higher rid candidate in our term.  This
			 * minimizes instability when two quorums are
			 * possible and race to elect two leaders.  This
			 * is only barely reasonable when accepting the
			 * risk of instability in two mount
			 * configurations.
			 */
			if ((le64_to_cpu(blk->term) > term) ||
			    (role == CANDIDATE &&
			     le64_to_cpu(blk->term) == term &&
			     blk->voter_rid == blk->vote_for_rid &&
			     le64_to_cpu(blk->voter_rid) > sbi->rid)) {
				role = VOTER;
				term = le64_to_cpu(blk->term);
				vote_for_rid = le64_to_cpu(blk->vote_for_rid);
				vote_for_write_nr = 0;
				votes = 0;
				log_cycles = 0;
			}

			/* candidate writes suppress voter election timers */
			if (role == VOTER &&
			    blk->voter_rid == blk->vote_for_rid &&
			    le64_to_cpu(blk->write_nr) > vote_for_write_nr) {
				term_to = random_to(SCOUTFS_QUORUM_TERM_LO_MS,
						    SCOUTFS_QUORUM_TERM_HI_MS);
				vote_for_write_nr = le64_to_cpu(blk->write_nr);
			}

			/* count our votes */
			if (role == CANDIDATE &&
			    le64_to_cpu(blk->vote_for_rid) == sbi->rid) {
				votes++;
			}

			/* try to write greater write_nr */
			write_nr = max(write_nr, le64_to_cpu(blk->write_nr));
		}

		trace_scoutfs_quorum_election_vote(sb, role, term,
						   vote_for_rid, votes,
						   log_cycles,
						   super->quorum_count);

		/* first merge logs from all votes this term */
		list_for_each_entry(qbh, &blocks, head) {
			blk = &qbh->blk;

			ret = log_merge(our_blk, blk,
					le64_to_cpu(super->quorum_fenced_term));
			if (ret < 0)
				goto out;
		}

		/* remove logs for voters that can't be servers */
		list_for_each_entry(qbh, &blocks, head) {
			blk = &qbh->blk;

			if (blk->voter_rid != blk->vote_for_rid)
				log_purge(our_blk, le64_to_cpu(blk->term),
					  le64_to_cpu(blk->voter_rid));
		}

		/* add ourselves to the log when we see vote quorum */
		if (role == CANDIDATE && votes >= super->quorum_count) {
			scoutfs_addr_from_sin(&addr, &opts->server_addr);
			ret = log_add(our_blk, term, vote_for_rid, &addr);
			if (ret < 0)
				goto out;
			log_cycles++; /* will be written *this* cycle */
		}

		/* elected candidates can proceed after their log cycles */
		if (role == CANDIDATE &&
		    log_cycles > SCOUTFS_QUORUM_ELECTED_LOG_CYCLES) {
			/* our_blk is clobbered */
			ret = fence_previous(sb, our_blk, sbi->rid,
					le64_to_cpu(super->quorum_fenced_term),
					term);
			if (ret < 0)
				goto out;
			scoutfs_inc_counter(sb, quorum_elected_leader);
			qinf->is_leader = true;
			*elected_term = term;
			goto out;
		}

		/* write our block every cycle */
		if (term > 0) {
			our_blk->term = cpu_to_le64(term);
			write_nr++;
			our_blk->write_nr = cpu_to_le64(write_nr);
			our_blk->voter_rid = cpu_to_le64(sbi->rid);
			our_blk->vote_for_rid = cpu_to_le64(vote_for_rid);

			ret = write_quorum_block(sb, our_blk);
			if (ret < 0)
				goto out;
		}

		/* add a small random delay to each cycle */
		cycle_to = random_to(SCOUTFS_QUORUM_CYCLE_LO_MS,
				     SCOUTFS_QUORUM_CYCLE_HI_MS);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_hrtimeout(&cycle_to, HRTIMER_MODE_ABS);
	}

out:
	free_quorum_blocks(&blocks);
	kfree(super);
	kfree(our_blk);

	trace_scoutfs_quorum_election_ret(sb, ret, *elected_term);
	if (ret)
		scoutfs_inc_counter(sb, quorum_failure);

	return ret;
}

void scoutfs_quorum_clear_leader(struct super_block *sb)
{
	DECLARE_QUORUM_INFO(sb, qinf);

	qinf->is_leader = false;
}

static ssize_t is_leader_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	DECLARE_QUORUM_INFO_KOBJ(kobj, qinf);

	return snprintf(buf, PAGE_SIZE, "%u", !!qinf->is_leader);
}
SCOUTFS_ATTR_RO(is_leader);

static struct attribute *quorum_attrs[] = {
	SCOUTFS_ATTR_PTR(is_leader),
	NULL,
};

int scoutfs_quorum_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct quorum_info *qinf;
	int ret;

	qinf = kzalloc(sizeof(struct quorum_info), GFP_KERNEL);
	if (!qinf) {
		ret = -ENOMEM;
		goto out;
	}
	scoutfs_sysfs_init_attrs(sb, &qinf->ssa);

	sbi->quorum_info = qinf;

	ret = scoutfs_sysfs_create_attrs(sb, &qinf->ssa, quorum_attrs,
					 "quorum");
out:
	if (ret)
		scoutfs_quorum_destroy(sb);

	return 0;
}

void scoutfs_quorum_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct quorum_info *qinf = SCOUTFS_SB(sb)->quorum_info;

	if (qinf) {
		scoutfs_sysfs_destroy_attrs(sb, &qinf->ssa);
		kfree(qinf);
		sbi->quorum_info = NULL;
	}
}
