#ifndef _SCOUTFS_NET_H_
#define _SCOUTFS_NET_H_

#include <linux/in.h>
#include "endian_swap.h"
#include "tseq.h"

struct scoutfs_net_connection;

/* These are called in their own blocking context */
typedef int (*scoutfs_net_request_t)(struct super_block *sb,
				     struct scoutfs_net_connection *conn,
				     u8 cmd, u64 id, void *arg, u16 arg_len);

/* These are called in their own blocking context */
typedef int (*scoutfs_net_response_t)(struct super_block *sb,
				      struct scoutfs_net_connection *conn,
				      void *resp, unsigned int resp_len,
				      int error, void *data);

typedef void (*scoutfs_net_notify_t)(struct super_block *sb,
				     struct scoutfs_net_connection *conn,
				     void *info, u64 rid);

/*
 * The conn is only here so that tracing can get at its fields without
 * having trace functions with a trillion arguments.  Tracing requires
 * duplicating the arguments for every event, no thanks.
 */

struct scoutfs_net_connection {
	struct super_block *sb;
	scoutfs_net_notify_t notify_up;
	scoutfs_net_notify_t notify_down;
	size_t info_size;
	scoutfs_net_request_t *req_funcs;

	spinlock_t lock;
	wait_queue_head_t waitq;

	unsigned long flags; /* CONN_FL_* bitmask */
	unsigned long reconn_deadline;

	struct sockaddr_in connect_sin;
	unsigned long connect_timeout_ms;

	struct socket *sock;
	u64 rid;
	u64 greeting_id;
	struct sockaddr_in sockname;
	struct sockaddr_in peername;

	struct list_head accepted_head;
	struct scoutfs_net_connection *listening_conn;
	struct list_head accepted_list;

	u64 next_send_seq;
	u64 next_send_id;
	struct list_head send_queue;
	struct list_head resend_queue;

	atomic64_t recv_seq;

	struct workqueue_struct *workq;
	struct work_struct listen_work;
	struct work_struct connect_work;
	struct work_struct send_work;
	struct work_struct recv_work;
	struct work_struct shutdown_work;
	struct work_struct destroy_work;
	struct delayed_work reconn_free_dwork;
	/* message_recv proc_work also executes in the conn workq */

	struct scoutfs_tseq_entry tseq_entry;

	void *info;
};

enum conn_flags {
	CONN_FL_valid_greeting = (1UL << 0), /* other commands can proceed */
	CONN_FL_established =	 (1UL << 1), /* added sends queue send work */
	CONN_FL_shutting_down =	 (1UL << 2), /* shutdown work was queued */
	CONN_FL_saw_greeting =	 (1UL << 3), /* saw greeting on this sock */
	CONN_FL_saw_farewell =	 (1UL << 4), /* saw farewell response */
	CONN_FL_reconn_wait =	 (1UL << 5), /* shutdown, waiting for reconn */
	CONN_FL_reconn_freeing = (1UL << 6), /* waiting done, setter frees */
};

#define SIN_FMT		"%pIS:%u"
#define SIN_ARG(sin)	sin, be16_to_cpu((sin)->sin_port)

static inline void scoutfs_addr_to_sin(struct sockaddr_in *sin,
				       struct scoutfs_inet_addr *addr)
{
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = cpu_to_be32(le32_to_cpu(addr->addr));
	sin->sin_port = cpu_to_be16(le16_to_cpu(addr->port));
}

static inline void scoutfs_addr_from_sin(struct scoutfs_inet_addr *addr,
					 struct sockaddr_in *sin)
{
	addr->addr = be32_to_le32(sin->sin_addr.s_addr);
	addr->port = be16_to_le16(sin->sin_port);
	memset(addr->__pad, 0, sizeof(addr->__pad));
}

struct scoutfs_net_connection *
scoutfs_net_alloc_conn(struct super_block *sb,
		       scoutfs_net_notify_t notify_up,
		       scoutfs_net_notify_t notify_down, size_t info_size,
		       scoutfs_net_request_t *req_funcs, char *name_suffix);
u64 scoutfs_net_client_rid(struct scoutfs_net_connection *conn);
int scoutfs_net_connect(struct super_block *sb,
			struct scoutfs_net_connection *conn,
			struct sockaddr_in *sin, unsigned long timeout_ms);
int scoutfs_net_bind(struct super_block *sb,
		     struct scoutfs_net_connection *conn,
		     struct sockaddr_in *sin);
void scoutfs_net_listen(struct super_block *sb,
			struct scoutfs_net_connection *conn);
int scoutfs_net_submit_request(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, void *arg, u16 arg_len,
			       scoutfs_net_response_t resp_func,
			       void *resp_data, u64 *id_ret);
int scoutfs_net_submit_request_node(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    u64 rid, u8 cmd, void *arg, u16 arg_len,
				    scoutfs_net_response_t resp_func,
				    void *resp_data, u64 *id_ret);
void scoutfs_net_cancel_request(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id);
int scoutfs_net_sync_request(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     u8 cmd, void *arg, unsigned arg_len,
			     void *resp, size_t resp_len);
int scoutfs_net_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 u8 cmd, u64 id, int error, void *resp, u16 resp_len);
int scoutfs_net_response_node(struct super_block *sb,
			      struct scoutfs_net_connection *conn,
			      u64 rid, u8 cmd, u64 id, int error,
			      void *resp, u16 resp_len);
void scoutfs_net_shutdown(struct super_block *sb,
			  struct scoutfs_net_connection *conn);
void scoutfs_net_free_conn(struct super_block *sb,
			   struct scoutfs_net_connection *conn);

void scoutfs_net_client_greeting(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 bool new_server);
void scoutfs_net_server_greeting(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 u64 rid, u64 greeting_id,
				 bool reconnecting, bool first_contact,
				 bool farewell);
void scoutfs_net_farewell(struct super_block *sb,
			  struct scoutfs_net_connection *conn);

int scoutfs_net_setup(struct super_block *sb);
void scoutfs_net_destroy(struct super_block *sb);

#endif
