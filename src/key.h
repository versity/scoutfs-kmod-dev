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
void scoutfs_key_inc_cur_len(struct scoutfs_key_buf *key);
void scoutfs_key_dec(struct scoutfs_key_buf *key);
void scoutfs_key_dec_cur_len(struct scoutfs_key_buf *key);

int scoutfs_key_str(char *buf, struct scoutfs_key_buf *key);

/*
 * Initialize a small key in a larger allocated buffer.  This lets
 * callers, for example, search for a small key and get a larger key
 * copied in.
 */
static inline void scoutfs_key_init_buf_len(struct scoutfs_key_buf *key,
				            void *data, u16 key_len,
					    u16 buf_len)
{
	WARN_ON_ONCE(buf_len > SCOUTFS_MAX_KEY_SIZE);
	WARN_ON_ONCE(key_len > buf_len);

	key->data = data;
	key->key_len = key_len;
	key->buf_len = buf_len;
}

/*
 * Point the key buf, usually statically allocated, at an existing
 * contiguous key stored elsewhere.
 */
static inline void scoutfs_key_init(struct scoutfs_key_buf *key,
				    void *data, u16 len)
{
	scoutfs_key_init_buf_len(key, data, len, len);
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

#endif
