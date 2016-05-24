#ifndef _SCOUTFS_WRLOCK_H_
#define _SCOUTFS_WRLOCK_H_

#include "wire.h"

struct scoutfs_wrlock_held {
	bool held_trans;
	u8 nr_shards;
	u32 shards[SCOUTFS_WRLOCK_MAX_SHARDS];
};

#define DECLARE_SCOUTFS_WRLOCK_HELD(held) \
	struct scoutfs_wrlock_held held = {0, }

int scoutfs_wrlock_lock(struct super_block *sb,
			struct scoutfs_wrlock_held *held, int nr_inos, ...);
void scoutfs_wrlock_unlock(struct super_block *sb,
			   struct scoutfs_wrlock_held *held);

void scoutfs_wrlock_roster_update(struct super_block *sb, u64 peer_id,
				  bool join);
int scoutfs_wrlock_process_request(struct super_block *sb, u64 peer_id,
				   struct scoutfs_wrlock_request *req);
void scoutfs_wrlock_process_grant(struct super_block *sb,
				  struct scoutfs_wrlock_grant *grant);

int scoutfs_wrlock_setup(struct super_block *sb);
void scoutfs_wrlock_teardown(struct super_block *sb);

#endif
