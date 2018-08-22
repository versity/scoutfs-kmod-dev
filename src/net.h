#ifndef _SCOUTFS_NET_H_
#define _SCOUTFS_NET_H_

#include <linux/in.h>

#define SIN_FMT		"%pIS:%u"
#define SIN_ARG(sin)	sin, be16_to_cpu((sin)->sin_port)

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
				     void *info, u64 node_id);

struct scoutfs_net_connection *
scoutfs_net_alloc_conn(struct super_block *sb,
		       scoutfs_net_notify_t notify_up,
		       scoutfs_net_notify_t notify_down, size_t info_size,
		       scoutfs_net_request_t *req_funcs, char *name_suffix);
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
				    u64 node_id, u8 cmd,
				    void *arg, u16 arg_len,
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
void scoutfs_net_shutdown(struct super_block *sb,
			  struct scoutfs_net_connection *conn);
void scoutfs_net_free_conn(struct super_block *sb,
			   struct scoutfs_net_connection *conn);

int scoutfs_net_setup(struct super_block *sb);
void scoutfs_net_destroy(struct super_block *sb);

#endif
