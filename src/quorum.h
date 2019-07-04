#ifndef _SCOUTFS_QUORUM_H_
#define _SCOUTFS_QUORUM_H_

int scoutfs_quorum_election(struct super_block *sb, ktime_t timeout_abs,
			    u64 prev_term, u64 *elected_term);
void scoutfs_quorum_clear_leader(struct super_block *sb);

int scoutfs_quorum_setup(struct super_block *sb);
void scoutfs_quorum_destroy(struct super_block *sb);
#endif
