#ifndef _SCOUTFS_WIRE_H_
#define _SCOUTFS_WIRE_H_

/* an arbitrarily small number to keep things reasonable */
#define SCOUTFS_WRLOCK_MAX_SHARDS 5

enum {
	SCOUTFS_MSG_WRLOCK_REQUEST = 1,
	SCOUTFS_MSG_WRLOCK_GRANT = 2,
};

struct scoutfs_wrlock_id {
	__le64 counter;
	__le32 jitter;
} __packed;

struct scoutfs_wrlock_request {
	struct scoutfs_wrlock_id wid;
	u8 nr_shards;
	__le32 shards[SCOUTFS_WRLOCK_MAX_SHARDS];
} __packed;

struct scoutfs_wrlock_grant {
	struct scoutfs_wrlock_id wid;
} __packed;

struct scoutfs_message {
	u8 cmd;
	u8 len;
	union {
		struct scoutfs_wrlock_grant grant;
		struct scoutfs_wrlock_request request;
	} __packed;
} __packed;

#endif
