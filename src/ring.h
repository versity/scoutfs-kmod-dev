#ifndef _SCOUTFS_RING_H_
#define _SCOUTFS_RING_H_

int scoutfs_replay_ring(struct super_block *sb);
int scoutfs_dirty_ring_entry(struct super_block *sb, u8 type, void *data,
			     u16 len);
int scoutfs_finish_dirty_ring(struct super_block *sb);

#endif
