#ifndef _SCOUTFS_SOCK_H_
#define _SCOUTFS_SOCK_H_

int scoutfs_sock_recvmsg(struct socket *sock, void *buf, unsigned len);
int scoutfs_sock_sendmsg(struct socket *sock, struct kvec *kv, unsigned kv_len);

#endif
