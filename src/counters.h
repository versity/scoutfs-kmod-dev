#ifndef _SCOUTFS_COUNTERS_H_
#define _SCOUTFS_COUNTERS_H_

#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/percpu_counter.h>

#include "super.h"

/*
 * We only have to define each counter here and it'll be enumerated in
 * other places by this macro.  Don't forget to update LAST_COUNTER.
 */
#define EXPAND_EACH_COUNTER					\
	EXPAND_COUNTER(block_cache_access)			\
	EXPAND_COUNTER(block_cache_alloc_failure)		\
	EXPAND_COUNTER(block_cache_alloc_page_order)		\
	EXPAND_COUNTER(block_cache_alloc_virt)			\
	EXPAND_COUNTER(block_cache_end_io_error)		\
	EXPAND_COUNTER(block_cache_forget)			\
	EXPAND_COUNTER(block_cache_free)			\
	EXPAND_COUNTER(block_cache_invalidate)			\
	EXPAND_COUNTER(block_cache_lru_move)			\
	EXPAND_COUNTER(block_cache_shrink)			\
	EXPAND_COUNTER(btree_read_error)			\
	EXPAND_COUNTER(btree_stale_read)			\
	EXPAND_COUNTER(client_farewell_error)			\
	EXPAND_COUNTER(corrupt_btree_block_level)		\
	EXPAND_COUNTER(corrupt_btree_no_child_ref)		\
	EXPAND_COUNTER(corrupt_dirent_backref_name_len)		\
	EXPAND_COUNTER(corrupt_dirent_name_len)			\
	EXPAND_COUNTER(corrupt_dirent_readdir_name_len)		\
	EXPAND_COUNTER(corrupt_inode_block_counts)		\
	EXPAND_COUNTER(corrupt_symlink_inode_size)		\
	EXPAND_COUNTER(corrupt_symlink_missing_item)		\
	EXPAND_COUNTER(corrupt_symlink_not_null_term)		\
	EXPAND_COUNTER(dentry_revalidate_error)			\
	EXPAND_COUNTER(dentry_revalidate_invalid)		\
	EXPAND_COUNTER(dentry_revalidate_locked)		\
	EXPAND_COUNTER(dentry_revalidate_orphan)		\
	EXPAND_COUNTER(dentry_revalidate_rcu)			\
	EXPAND_COUNTER(dentry_revalidate_root)			\
	EXPAND_COUNTER(dentry_revalidate_valid)			\
	EXPAND_COUNTER(dir_backref_excessive_retries)		\
	EXPAND_COUNTER(forest_roots_next_hint)			\
	EXPAND_COUNTER(forest_roots_lock)			\
	EXPAND_COUNTER(forest_roots_server)			\
	EXPAND_COUNTER(lock_alloc)				\
	EXPAND_COUNTER(lock_free)				\
	EXPAND_COUNTER(lock_grace_elapsed)			\
	EXPAND_COUNTER(lock_grace_extended)			\
	EXPAND_COUNTER(lock_grace_set)				\
	EXPAND_COUNTER(lock_grace_wait)				\
	EXPAND_COUNTER(lock_grant_request)			\
	EXPAND_COUNTER(lock_grant_response)			\
	EXPAND_COUNTER(lock_invalidate_commit)			\
	EXPAND_COUNTER(lock_invalidate_coverage)		\
	EXPAND_COUNTER(lock_invalidate_inode)			\
	EXPAND_COUNTER(lock_invalidate_request)			\
	EXPAND_COUNTER(lock_invalidate_response)		\
	EXPAND_COUNTER(lock_lock)				\
	EXPAND_COUNTER(lock_lock_error)				\
	EXPAND_COUNTER(lock_nonblock_eagain)			\
	EXPAND_COUNTER(lock_recover_request)			\
	EXPAND_COUNTER(lock_shrink_queued)			\
	EXPAND_COUNTER(lock_shrink_request_aborted)		\
	EXPAND_COUNTER(lock_unlock)				\
	EXPAND_COUNTER(lock_wait)				\
	EXPAND_COUNTER(net_dropped_response)			\
	EXPAND_COUNTER(net_send_bytes)				\
	EXPAND_COUNTER(net_send_error)				\
	EXPAND_COUNTER(net_send_messages)			\
	EXPAND_COUNTER(net_recv_bytes)				\
	EXPAND_COUNTER(net_recv_dropped_duplicate)		\
	EXPAND_COUNTER(net_recv_error)				\
	EXPAND_COUNTER(net_recv_invalid_message)		\
	EXPAND_COUNTER(net_recv_messages)			\
	EXPAND_COUNTER(net_unknown_request)			\
	EXPAND_COUNTER(quorum_cycle)				\
	EXPAND_COUNTER(quorum_elected_leader)			\
	EXPAND_COUNTER(quorum_election_timeout)			\
	EXPAND_COUNTER(quorum_failure)				\
	EXPAND_COUNTER(quorum_read_block)			\
	EXPAND_COUNTER(quorum_read_block_error)			\
	EXPAND_COUNTER(quorum_read_invalid_block)		\
	EXPAND_COUNTER(quorum_saw_super_leader)			\
	EXPAND_COUNTER(quorum_timedout)				\
	EXPAND_COUNTER(quorum_write_block)			\
	EXPAND_COUNTER(quorum_write_block_error)		\
	EXPAND_COUNTER(quorum_fenced)				\
	EXPAND_COUNTER(radix_alloc)				\
	EXPAND_COUNTER(radix_alloc_data)			\
	EXPAND_COUNTER(radix_block_cow)				\
	EXPAND_COUNTER(radix_block_read)			\
	EXPAND_COUNTER(radix_complete_dirty_block)		\
	EXPAND_COUNTER(radix_create_synth)			\
	EXPAND_COUNTER(radix_free)				\
	EXPAND_COUNTER(radix_free_data)				\
	EXPAND_COUNTER(radix_enospc_data)			\
	EXPAND_COUNTER(radix_enospc_meta)			\
	EXPAND_COUNTER(radix_enospc_synth)			\
	EXPAND_COUNTER(radix_inconsistent_eio)			\
	EXPAND_COUNTER(radix_inconsistent_ref)			\
	EXPAND_COUNTER(radix_merge)				\
	EXPAND_COUNTER(radix_merge_empty)			\
	EXPAND_COUNTER(radix_undo_ref)				\
	EXPAND_COUNTER(radix_walk)				\
	EXPAND_COUNTER(server_commit_hold)			\
	EXPAND_COUNTER(server_commit_prepare)			\
	EXPAND_COUNTER(server_commit_queue)			\
	EXPAND_COUNTER(server_commit_worker)			\
	EXPAND_COUNTER(trans_commit_data_alloc_low)		\
	EXPAND_COUNTER(trans_commit_fsync)			\
	EXPAND_COUNTER(trans_commit_full)			\
	EXPAND_COUNTER(trans_commit_sync_fs)			\
	EXPAND_COUNTER(trans_commit_timer)			\
	EXPAND_COUNTER(trans_commit_written)

#define FIRST_COUNTER	block_cache_access
#define LAST_COUNTER	trans_commit_written

#undef EXPAND_COUNTER
#define EXPAND_COUNTER(which) struct percpu_counter which;

struct scoutfs_counters {
	/* $sysfs/fs/scoutfs/$id/counters/ */
	struct kobject kobj;
	struct completion comp;

	EXPAND_EACH_COUNTER
};

#define scoutfs_foreach_counter(sb, pcpu) 			\
	for (pcpu = &SCOUTFS_SB(sb)->counters->FIRST_COUNTER;	\
	     pcpu <= &SCOUTFS_SB(sb)->counters->LAST_COUNTER;	\
	     pcpu++)

#define scoutfs_inc_counter(sb, which) \
	percpu_counter_inc(&SCOUTFS_SB(sb)->counters->which)

#define scoutfs_add_counter(sb, which, cnt) \
	percpu_counter_add(&SCOUTFS_SB(sb)->counters->which, cnt)

void __init scoutfs_init_counters(void);
int scoutfs_setup_counters(struct super_block *sb);
void scoutfs_destroy_counters(struct super_block *sb);

#endif
