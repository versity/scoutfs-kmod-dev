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
	EXPAND_COUNTER(btree_read_error)			\
	EXPAND_COUNTER(btree_stale_read)			\
	EXPAND_COUNTER(btree_write_error)			\
	EXPAND_COUNTER(compact_operations)			\
	EXPAND_COUNTER(compact_segment_moved)			\
	EXPAND_COUNTER(compact_segment_read)			\
	EXPAND_COUNTER(compact_segment_write_bytes)		\
	EXPAND_COUNTER(compact_segment_writes)			\
	EXPAND_COUNTER(compact_stale_error)			\
	EXPAND_COUNTER(compact_sticky_upper)			\
	EXPAND_COUNTER(compact_sticky_written)			\
	EXPAND_COUNTER(corrupt_btree_block_level)		\
	EXPAND_COUNTER(corrupt_btree_no_child_ref)		\
	EXPAND_COUNTER(corrupt_data_extent_trunc_cleanup)	\
	EXPAND_COUNTER(corrupt_data_extent_alloc_cleanup)	\
	EXPAND_COUNTER(corrupt_data_extent_fallocate_cleanup)	\
	EXPAND_COUNTER(corrupt_dirent_backref_name_len)		\
	EXPAND_COUNTER(corrupt_dirent_name_len)			\
	EXPAND_COUNTER(corrupt_dirent_readdir_name_len)		\
	EXPAND_COUNTER(corrupt_inode_block_counts)		\
	EXPAND_COUNTER(corrupt_extent_add_cleanup)		\
	EXPAND_COUNTER(corrupt_extent_rem_cleanup)		\
	EXPAND_COUNTER(corrupt_server_extent_cleanup)		\
	EXPAND_COUNTER(corrupt_symlink_inode_size)		\
	EXPAND_COUNTER(corrupt_symlink_missing_item)		\
	EXPAND_COUNTER(corrupt_symlink_not_null_term)		\
	EXPAND_COUNTER(data_end_writeback_page)			\
	EXPAND_COUNTER(data_invalidatepage)			\
	EXPAND_COUNTER(data_readpage)				\
	EXPAND_COUNTER(data_write_begin)			\
	EXPAND_COUNTER(data_write_end)				\
	EXPAND_COUNTER(data_writepage)				\
	EXPAND_COUNTER(dentry_revalidate_error)			\
	EXPAND_COUNTER(dentry_revalidate_invalid)		\
	EXPAND_COUNTER(dentry_revalidate_locked)		\
	EXPAND_COUNTER(dentry_revalidate_orphan)		\
	EXPAND_COUNTER(dentry_revalidate_rcu)			\
	EXPAND_COUNTER(dentry_revalidate_root)			\
	EXPAND_COUNTER(dentry_revalidate_valid)			\
	EXPAND_COUNTER(dir_backref_excessive_retries)		\
	EXPAND_COUNTER(extent_add)				\
	EXPAND_COUNTER(extent_delete)				\
	EXPAND_COUNTER(extent_insert)				\
	EXPAND_COUNTER(extent_next)				\
	EXPAND_COUNTER(extent_remove)				\
	EXPAND_COUNTER(item_alloc)				\
	EXPAND_COUNTER(item_batch_duplicate)			\
	EXPAND_COUNTER(item_batch_inserted)			\
	EXPAND_COUNTER(item_create)				\
	EXPAND_COUNTER(item_delete)				\
	EXPAND_COUNTER(item_free)				\
	EXPAND_COUNTER(item_lookup_hit)				\
	EXPAND_COUNTER(item_lookup_miss)			\
	EXPAND_COUNTER(item_range_alloc)			\
	EXPAND_COUNTER(item_range_free)				\
	EXPAND_COUNTER(item_range_hit)				\
	EXPAND_COUNTER(item_range_insert)			\
	EXPAND_COUNTER(item_range_miss)				\
	EXPAND_COUNTER(item_shrink)				\
	EXPAND_COUNTER(item_shrink_alone)			\
	EXPAND_COUNTER(item_shrink_empty_range)			\
	EXPAND_COUNTER(item_shrink_next_dirty)			\
	EXPAND_COUNTER(item_shrink_outside)			\
	EXPAND_COUNTER(item_shrink_range_end)			\
	EXPAND_COUNTER(item_shrink_small_split)			\
	EXPAND_COUNTER(item_shrink_split_range)			\
	EXPAND_COUNTER(lock_alloc)				\
	EXPAND_COUNTER(lock_ast)				\
	EXPAND_COUNTER(lock_ast_edeadlk)			\
	EXPAND_COUNTER(lock_ast_error)				\
	EXPAND_COUNTER(lock_bast)				\
	EXPAND_COUNTER(lock_dlm_call)				\
	EXPAND_COUNTER(lock_dlm_call_error)			\
	EXPAND_COUNTER(lock_free)				\
	EXPAND_COUNTER(lock_grace_enforced)			\
	EXPAND_COUNTER(lock_grace_expired)			\
	EXPAND_COUNTER(lock_grace_extended)			\
	EXPAND_COUNTER(lock_invalidate_clean_item)		\
	EXPAND_COUNTER(lock_lock)				\
	EXPAND_COUNTER(lock_lock_error)				\
	EXPAND_COUNTER(lock_nonblock_eagain)			\
	EXPAND_COUNTER(lock_shrink)				\
	EXPAND_COUNTER(lock_write_dirty_item)			\
	EXPAND_COUNTER(lock_unlock)				\
	EXPAND_COUNTER(manifest_compact_migrate)		\
	EXPAND_COUNTER(manifest_hard_stale_error)		\
	EXPAND_COUNTER(manifest_read_excluded_key)		\
	EXPAND_COUNTER(seg_alloc)				\
	EXPAND_COUNTER(seg_free)				\
	EXPAND_COUNTER(seg_shrink)				\
	EXPAND_COUNTER(seg_stale_read)				\
	EXPAND_COUNTER(server_alloc_segno)			\
	EXPAND_COUNTER(server_extent_alloc)			\
	EXPAND_COUNTER(server_extent_alloc_error)		\
	EXPAND_COUNTER(server_free_extent)			\
	EXPAND_COUNTER(server_free_pending_extent)		\
	EXPAND_COUNTER(server_free_pending_error)		\
	EXPAND_COUNTER(server_free_segno)			\
	EXPAND_COUNTER(trans_commit_fsync)			\
	EXPAND_COUNTER(trans_commit_full)			\
	EXPAND_COUNTER(trans_commit_item_flush)			\
	EXPAND_COUNTER(trans_commit_sync_fs)			\
	EXPAND_COUNTER(trans_commit_timer)			\
	EXPAND_COUNTER(trans_level0_seg_write_bytes)		\
	EXPAND_COUNTER(trans_level0_seg_writes)			\
	EXPAND_COUNTER(trans_write_item)			\
	EXPAND_COUNTER(trans_write_deletion_item)

#define FIRST_COUNTER	btree_read_error
#define LAST_COUNTER	trans_write_deletion_item

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
