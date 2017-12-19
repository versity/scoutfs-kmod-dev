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
	EXPAND_COUNTER(alloc_alloc)				\
	EXPAND_COUNTER(alloc_free)				\
	EXPAND_COUNTER(btree_stale_read)			\
	EXPAND_COUNTER(compact_operations)			\
	EXPAND_COUNTER(compact_segment_moved)			\
	EXPAND_COUNTER(compact_segment_read)			\
	EXPAND_COUNTER(compact_segment_write_bytes)		\
	EXPAND_COUNTER(compact_segment_writes)			\
	EXPAND_COUNTER(compact_stale_error)			\
	EXPAND_COUNTER(compact_sticky_upper)			\
	EXPAND_COUNTER(compact_sticky_written)			\
	EXPAND_COUNTER(data_end_writeback_page)			\
	EXPAND_COUNTER(data_invalidatepage)			\
	EXPAND_COUNTER(data_readpage)				\
	EXPAND_COUNTER(data_write_begin)			\
	EXPAND_COUNTER(data_write_end)				\
	EXPAND_COUNTER(data_writepage)				\
	EXPAND_COUNTER(dlm_cancel_convert)			\
	EXPAND_COUNTER(dlm_convert_request)			\
	EXPAND_COUNTER(dlm_cw_downconvert)			\
	EXPAND_COUNTER(dlm_ex_downconvert)			\
	EXPAND_COUNTER(dlm_lock_request)			\
	EXPAND_COUNTER(dlm_pr_downconvert)			\
	EXPAND_COUNTER(dlm_unlock_request)			\
	EXPAND_COUNTER(item_alloc)				\
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
	EXPAND_COUNTER(lock_blocked_wait)			\
	EXPAND_COUNTER(lock_busy_wait)				\
	EXPAND_COUNTER(lock_free)				\
	EXPAND_COUNTER(lock_incompat_wait)			\
	EXPAND_COUNTER(lock_type_ino_downconvert)		\
	EXPAND_COUNTER(lock_type_idx_downconvert)		\
	EXPAND_COUNTER(manifest_compact_migrate)		\
	EXPAND_COUNTER(manifest_hard_stale_error)		\
	EXPAND_COUNTER(seg_alloc)				\
	EXPAND_COUNTER(seg_free)				\
	EXPAND_COUNTER(seg_shrink)				\
	EXPAND_COUNTER(seg_stale_read)				\
	EXPAND_COUNTER(trans_commit_fsync)			\
	EXPAND_COUNTER(trans_commit_full)			\
	EXPAND_COUNTER(trans_commit_item_flush)			\
	EXPAND_COUNTER(trans_commit_sync_fs)			\
	EXPAND_COUNTER(trans_commit_timer)			\
	EXPAND_COUNTER(trans_level0_seg_write_bytes)		\
	EXPAND_COUNTER(trans_level0_seg_writes)


#define FIRST_COUNTER	alloc_alloc
#define LAST_COUNTER	trans_level0_seg_writes

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
