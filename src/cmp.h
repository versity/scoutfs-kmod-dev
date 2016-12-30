#ifndef _SCOUTFS_CMP_H_
#define _SCOUTFS_CMP_H_

#include <linux/kernel.h>

static inline int scoutfs_cmp_u64s(u64 a, u64 b)
{
	return a < b ? -1 : a > b ? 1 : 0;
}

#endif
