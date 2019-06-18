#ifndef _SCOUTFS_HASH_H_
#define _SCOUTFS_HASH_H_

#include <linux/crc32c.h>

/* XXX replace with xxhash */
static inline u64 scoutfs_hash64(const void *data, unsigned int len)
{
       unsigned int half = (len + 1) / 2;

       return crc32c(~0, data, half) |
              ((u64)crc32c(~0, data + len - half, half) << 32);
}

#endif
