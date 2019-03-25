#ifndef _SCOUTFS_QUORUM_H_
#define _SCOUTFS_QUORUM_H_

struct scoutfs_quorum_elected_info {
	struct sockaddr_in sin;
	__le64 config_gen;
	__le64 write_nr;
	u64 elected_nr;
	unsigned int config_slot;
	bool run_server;
};

int scoutfs_quorum_election(struct super_block *sb, char *our_name,
			    u64 old_elected_nr, ktime_t timeout_abs,
			    struct scoutfs_quorum_elected_info *qei);
int scoutfs_quorum_clear_elected(struct super_block *sb,
				 struct scoutfs_quorum_elected_info *qei);

#endif
