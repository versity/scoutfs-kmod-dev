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
#define EXPAND_EACH_COUNTER 		\
	EXPAND_COUNTER(alloc_alloc)	\
	EXPAND_COUNTER(alloc_free)	\
	EXPAND_COUNTER(block_mem_alloc)	\
	EXPAND_COUNTER(block_mem_free) \
	EXPAND_COUNTER(seg_lru_shrink) \
	EXPAND_COUNTER(trans_level0_seg_write) \
	EXPAND_COUNTER(manifest_compact_migrate) \
	EXPAND_COUNTER(compact_operations) \
	EXPAND_COUNTER(compact_segment_moved) \
	EXPAND_COUNTER(compact_segment_skipped) \
	EXPAND_COUNTER(compact_segment_read)	\
	EXPAND_COUNTER(compact_segment_written)	\
	EXPAND_COUNTER(data_readpage)		\
	EXPAND_COUNTER(data_write_begin)	\
	EXPAND_COUNTER(data_write_end)		\
	EXPAND_COUNTER(data_invalidatepage)	\
	EXPAND_COUNTER(data_writepage)		\
	EXPAND_COUNTER(data_end_writeback_page)	\
	EXPAND_COUNTER(item_create)		\
	EXPAND_COUNTER(item_create_ephemeral)	\
	EXPAND_COUNTER(item_update_ephemeral)	\
	EXPAND_COUNTER(item_lookup_hit)		\
	EXPAND_COUNTER(item_lookup_miss)	\
	EXPAND_COUNTER(item_delete)		\
	EXPAND_COUNTER(item_forget)		\
	EXPAND_COUNTER(item_range_hit)		\
	EXPAND_COUNTER(item_range_miss)		\
	EXPAND_COUNTER(item_range_insert)

#define FIRST_COUNTER alloc_alloc
#define LAST_COUNTER item_range_insert

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

void __init scoutfs_init_counters(void);
int scoutfs_setup_counters(struct super_block *sb);
void scoutfs_destroy_counters(struct super_block *sb);

#endif
