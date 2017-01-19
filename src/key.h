#ifndef _SCOUTFS_KEY_H_
#define _SCOUTFS_KEY_H_

#include <linux/types.h>
#include "format.h"

struct scoutfs_key_buf {
	void *data;
	u16 key_len;
	u16 buf_len;
};

struct scoutfs_key_buf *scoutfs_key_alloc(struct super_block *sb, u16 len);
struct scoutfs_key_buf *scoutfs_key_dup(struct super_block *sb,
					struct scoutfs_key_buf *key);
void scoutfs_key_free(struct super_block *sb, struct scoutfs_key_buf *key);
void scoutfs_key_inc(struct scoutfs_key_buf *key);
void scoutfs_key_dec(struct scoutfs_key_buf *key);


/*
 * Point the key buf, usually statically allocated, at an existing
 * contiguous key stored elsewhere.
 */
static inline void scoutfs_key_init(struct scoutfs_key_buf *key,
				    void *data, u16 len)
{
	WARN_ON_ONCE(len > SCOUTFS_MAX_KEY_SIZE);

	key->data = data;
	key->key_len = len;
	key->buf_len = len;
}

/*
 * Compare the fs keys in segment sort order.
 */
static inline int scoutfs_key_compare(struct scoutfs_key_buf *a,
				      struct scoutfs_key_buf *b)
{
	return memcmp(a->data, b->data, min(a->key_len, b->key_len)) ?:
	       a->key_len < b->key_len ? -1 : a->key_len > b->key_len ? 1 : 0;
}

/*
 * Compare ranges of keys where overlapping is equality.  Returns:
 *      -1: a_end < b_start
 *       1: a_start > b_end
 *  else 0: ranges overlap
 */
static inline int scoutfs_key_compare_ranges(struct scoutfs_key_buf *a_start,
				             struct scoutfs_key_buf *a_end,
				             struct scoutfs_key_buf *b_start,
				             struct scoutfs_key_buf *b_end)
{
	return scoutfs_key_compare(a_end, b_start) < 0 ? -1 :
	       scoutfs_key_compare(a_start, b_end) > 0 ? 1 :
	       0;
}

/*
 * Copy as much of the contents of the source buffer that fits into the
 * dest buffer.
 */
static inline void scoutfs_key_copy(struct scoutfs_key_buf *dst,
				    struct scoutfs_key_buf *src)
{
	dst->key_len = min(dst->buf_len, src->key_len);
	memcpy(dst->data, src->data, dst->key_len);
}

/*
 * Initialize the dst buffer to point to the source buffer in all ways,
 * including the buf len.  The contents of the buffer are shared by the
 * fields describing the buffers are not.
 */
static inline void scoutfs_key_clone(struct scoutfs_key_buf *dst,
				     struct scoutfs_key_buf *src)
{
	*dst = *src;
}

/*
 * Memset as much of the length as fits in the buffer and set that to
 * the new key length.
 */
static inline void scoutfs_key_memset(struct scoutfs_key_buf *key, int c,
				      u16 len)
{
	if (WARN_ON_ONCE(len > SCOUTFS_MAX_KEY_SIZE))
		return;

	key->key_len = min(key->buf_len, len);
	memset(key->data, c, key->key_len);
}

/*
 * Set the contents of the buffer to the smallest possible key by sort
 * order.  It might be truncated if the buffer isn't large enough.
 */
static inline void scoutfs_key_set_min(struct scoutfs_key_buf *key)
{
	scoutfs_key_memset(key, 0, sizeof(struct scoutfs_inode_key));
}

/*
 * Set the contents of the buffer to the largest possible key by sort
 * order.  It might be truncated if the buffer isn't large enough.
 */
static inline void scoutfs_key_set_max(struct scoutfs_key_buf *key)
{
	scoutfs_key_memset(key, 0xff, sizeof(struct scoutfs_inode_key));
}

/*
 * What follows are the key functions for the small fixed size btree
 * keys.  It will all be removed once the callers are converted from
 * the btree to the item cache.
 */

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

/*
 * Items are sorted by type and then by inode to reflect the relative
 * frequency of use.  Inodes and xattrs are hot, then dirents, then file
 * data extents.  We want each use class to be hot and dense, we don't
 * want a scan of the inodes to have to skip over each inode's extent
 * items.
 */
static inline int scoutfs_key_cmp(struct scoutfs_key *a, struct scoutfs_key *b)
{
	return ((short)a->type - (short)b->type) ?:
	       le64_cmp(a->inode, b->inode) ?:
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

static inline void scoutfs_set_max_key(struct scoutfs_key *key)
{
	scoutfs_set_key(key, ~0ULL, ~0, ~0ULL);
}

/*
 * This saturates at (~0,~0,~0) instead of wrapping.  This will never be
 * an issue for real item keys but parent item keys along the right
 * spine of the tree have maximal key values that could wrap if
 * incremented.
 */
static inline void scoutfs_inc_key(struct scoutfs_key *key)
{
	if (key->inode == cpu_to_le64(~0ULL) &&
	    key->type == (u8)~0 &&
	    key->offset == cpu_to_le64(~0ULL))
		return;

	le64_add_cpu(&key->offset, 1);
	if (!key->offset) {
		if (++key->type == 0)
			le64_add_cpu(&key->inode, 1);
	}
}

static inline void scoutfs_dec_key(struct scoutfs_key *key)
{
	le64_add_cpu(&key->offset, -1ULL);
	if (key->offset == cpu_to_le64(~0ULL)) {
		if (key->type-- == 0)
			le64_add_cpu(&key->inode, -1ULL);
	}
}

static inline struct scoutfs_key *scoutfs_max_key(struct scoutfs_key *a,
						  struct scoutfs_key *b)
{
	return scoutfs_key_cmp(a, b) > 0 ? a : b;
}

static inline bool scoutfs_key_is_zero(struct scoutfs_key *key)
{
	return key->inode == 0 && key->type == 0 && key->offset == 0;
}

static inline void scoutfs_key_set_zero(struct scoutfs_key *key)
{
	key->inode = 0;
	key->type = 0;
	key->offset = 0;
}

#endif
