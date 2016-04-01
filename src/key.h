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
 * return -ve if the first range is completely before the second, +ve for
 * completely after, and 0 if they intersect.
 */
static inline int scoutfs_cmp_key_ranges(struct scoutfs_key *a_first,
					 struct scoutfs_key *a_last,
					 struct scoutfs_key *b_first,
					 struct scoutfs_key *b_last)
{
	if (scoutfs_key_cmp(a_last, b_first) < 0)
		return -1;
	if (scoutfs_key_cmp(a_first, b_last) > 0)
		return 1;
	return 0;
}

static inline int scoutfs_cmp_key_range(struct scoutfs_key *key,
					struct scoutfs_key *first,
					struct scoutfs_key *last)
{
	return scoutfs_cmp_key_ranges(key, key, first, last);
}

static inline void scoutfs_set_key(struct scoutfs_key *key, u64 inode, u8 type,
				   u64 offset)
{
	key->inode = cpu_to_le64(inode);
	key->type = type;
	key->offset = cpu_to_le64(offset);
}

static inline void scoutfs_inc_key(struct scoutfs_key *key)
{
	le64_add_cpu(&key->offset, 1);
	if (!key->offset) {
		if (++key->type == 0)
			le64_add_cpu(&key->inode, 1);
	}
}

static inline struct scoutfs_key *scoutfs_max_key(struct scoutfs_key *a,
						  struct scoutfs_key *b)
{
	return scoutfs_key_cmp(a, b) > 0 ? a : b;
}

#endif
