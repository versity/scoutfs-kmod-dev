#ifndef _SCOUTFS_ROSTER_H_
#define _SCOUTFS_ROSTER_H_

struct scoutfs_message;

int scoutfs_roster_add(struct super_block *sb);
void scoutfs_roster_remove(struct super_block *sb);

void scoutfs_roster_send(struct super_block *sb, u64 peer_id,
			 struct scoutfs_message *msg);
void scoutfs_roster_broadcast(struct super_block *sb, u64 since_id,
			      struct scoutfs_message *msg);

#endif
