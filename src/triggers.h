#ifndef _SCOUTFS_TRIGGERS_H_
#define _SCOUTFS_TRIGGERS_H_

enum {
	SCOUTFS_TRIGGER_BTREE_STALE_READ,
	SCOUTFS_TRIGGER_BTREE_ADVANCE_RING_HALF,
	SCOUTFS_TRIGGER_HARD_STALE_ERROR,
	SCOUTFS_TRIGGER_SEG_STALE_READ,
	SCOUTFS_TRIGGER_STATFS_LOCK_PURGE,
	SCOUTFS_TRIGGER_NR,
};

bool scoutfs_trigger_test_and_clear(struct super_block *sb, unsigned int t);

#define scoutfs_trigger(sb, which)	\
	scoutfs_trigger_test_and_clear(sb, SCOUTFS_TRIGGER_##which)

int scoutfs_setup_triggers(struct super_block *sb);
void scoutfs_destroy_triggers(struct super_block *sb);

#endif
