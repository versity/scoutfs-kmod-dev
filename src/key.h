#ifndef _SCOUTFS_KEY_H_
#define _SCOUTFS_KEY_H_

#include <linux/types.h>
#include "format.h"

#define CKF "%llu.%u.%llu"
#define CKA(key) \
	le64_to_cpu((key)->inode), (key)->type, le64_to_cpu((key)->offset)

static inline u64 scoutfs_key_inode(struct scoutfs_key *key)
{
	return le64_to_cpu(key->inode);
}

static inline u64 scoutfs_key_offset(struct scoutfs_key *key)
{
	return le64_to_cpu(key->offset);
}

static inline int le64_cmp(__le64 a, __le64 b)
{
	return le64_to_cpu(a) < le64_to_cpu(b) ? -1 : 
	       le64_to_cpu(a) > le64_to_cpu(b) ? 1 : 0;
}

static inline int scoutfs_key_cmp(struct scoutfs_key *a, struct scoutfs_key *b)
{
	return le64_cmp(a->inode, b->inode) ?:
	       ((short)a->type - (short)b->type) ?: 
	       le64_cmp(a->offset, b->offset);
}

/*
 * return -ve, 0, +ve if the key is less than, contained within, or greater
 * than the given range of keys.
 */
static inline int scoutfs_key_cmp_range(struct scoutfs_key *key,
					struct scoutfs_key *first,
					struct scoutfs_key *last)
{
	int cmp;

	WARN_ON_ONCE(scoutfs_key_cmp(first, last) > 0);

	cmp = scoutfs_key_cmp(key, first);
	if (cmp > 0) {
		cmp = scoutfs_key_cmp(key, last);
		if (cmp < 0)
			cmp = 0;
	}
	return cmp;
}

	
static inline void scoutfs_set_key(struct scoutfs_key *key, u64 inode, u8 type,
				   u64 offset)
{
	key->inode = cpu_to_le64(inode);
	key->type = type;
	key->offset = cpu_to_le64(offset);
}

#endif
