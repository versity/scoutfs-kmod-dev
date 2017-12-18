#ifndef _SCOUTFS_KVEC_H_
#define _SCOUTFS_KVEC_H_

#include <linux/uio.h>

static inline void kvec_init(struct kvec *kv, void *base, size_t len)
{
	kv->iov_base = base;
	kv->iov_len = len;
}

#endif
