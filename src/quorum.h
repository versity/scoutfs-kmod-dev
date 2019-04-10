#ifndef _SCOUTFS_QUORUM_H_
#define _SCOUTFS_QUORUM_H_

struct scoutfs_quorum_elected_info {
	struct sockaddr_in sin;
	__le64 config_gen;
	__le64 write_nr;
	u64 elected_nr;
	u64 unmount_barrier;
	unsigned int config_slot;
	bool run_server;
	u8 flags;
};

int scoutfs_quorum_election(struct super_block *sb, char *our_name,
			    u64 old_elected_nr, ktime_t timeout_abs,
			    bool unmounting, u64 our_umb,
			    struct scoutfs_quorum_elected_info *qei);
int scoutfs_quorum_clear_elected(struct super_block *sb,
				 struct scoutfs_quorum_elected_info *qei);
int scoutfs_quorum_update_barrier(struct super_block *sb,
				  struct scoutfs_quorum_elected_info *qei,
				  u64 unmount_barrier);
int scoutfs_quorum_majority(struct super_block *sb,
			    struct scoutfs_quorum_config *conf);
bool scoutfs_quorum_voting_member(struct super_block *sb,
				  struct scoutfs_quorum_config *conf,
				  char *name);

#endif
