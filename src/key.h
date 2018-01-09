#ifndef _SCOUTFS_KEY_H_
#define _SCOUTFS_KEY_H_

#include <linux/types.h>
#include "format.h"
#include "cmp.h"
#include "endian_swap.h"

extern char *scoutfs_zone_strings[SCOUTFS_MAX_ZONE];
extern char *scoutfs_type_strings[SCOUTFS_MAX_ZONE][SCOUTFS_MAX_TYPE];
#define U8_STR_MAX 5 /* u%3u'\0' */
extern char scoutfs_unknown_u8_strings[U8_MAX][U8_STR_MAX];

int __init scoutfs_key_init(void);

static inline char *sk_zone_str(u8 zone)
{
	if (zone >= SCOUTFS_MAX_ZONE || scoutfs_zone_strings[zone] == NULL)
		return scoutfs_unknown_u8_strings[zone];

	return scoutfs_zone_strings[zone];
}

static inline char *sk_type_str(u8 zone, u8 type)
{
	if (zone >= SCOUTFS_MAX_ZONE || type >= SCOUTFS_MAX_TYPE ||
	    scoutfs_type_strings[zone][type] == NULL)
		return scoutfs_unknown_u8_strings[type];

	return scoutfs_type_strings[zone][type];
}

#define SK_FMT		"%s.%llu.%s.%llu.%llu.%u"
/* This does not support null keys */
#define SK_ARG(key)	sk_zone_str((key)->sk_zone),			\
			le64_to_cpu((key)->_sk_first),			\
			sk_type_str((key)->sk_zone, (key)->sk_type),	\
			le64_to_cpu((key)->_sk_second),			\
			le64_to_cpu((key)->_sk_third),			\
			(key)->_sk_fourth

static inline void scoutfs_key_set_zeros(struct scoutfs_key *key)
{
	key->sk_zone = 0;
	key->_sk_first = 0;
	key->sk_type = 0;
	key->_sk_second = 0;
	key->_sk_third = 0;
	key->_sk_fourth = 0;
}

static inline void scoutfs_key_copy_or_zeros(struct scoutfs_key *dst,
					     struct scoutfs_key *src)
{
	if (src)
		*dst = *src;
	else
		scoutfs_key_set_zeros(dst);
}

static inline void scoutfs_key_set_ones(struct scoutfs_key *key)
{
	key->sk_zone = U8_MAX;
	key->_sk_first = cpu_to_le64(U64_MAX);
	key->sk_type = U8_MAX;
	key->_sk_second = cpu_to_le64(U64_MAX);
	key->_sk_third = cpu_to_le64(U64_MAX);
	key->_sk_fourth = U8_MAX;
}

/*
 * Return a -1/0/1 comparison of keys.
 *
 * It turns out that these ternary chains are consistently cheaper than
 * other alternatives across keys that first differ in any of the
 * values.  Say maybe 20% faster than memcmp.
 */
static inline int scoutfs_key_compare(struct scoutfs_key *a,
				      struct scoutfs_key *b)
{
	return scoutfs_cmp(a->sk_zone, b->sk_zone) ?:
	  scoutfs_cmp(le64_to_cpu(a->_sk_first), le64_to_cpu(b->_sk_first)) ?:
	  scoutfs_cmp(a->sk_type, b->sk_type) ?:
	  scoutfs_cmp(le64_to_cpu(a->_sk_second), le64_to_cpu(b->_sk_second)) ?:
	  scoutfs_cmp(le64_to_cpu(a->_sk_third), le64_to_cpu(b->_sk_third)) ?:
	  scoutfs_cmp(a->_sk_fourth, b->_sk_fourth);
}

/*
 * Compare ranges of keys where overlapping is equality.  Returns:
 *      -1: a_end < b_start
 *       1: a_start > b_end
 *  else 0: ranges overlap
 */
static inline int scoutfs_key_compare_ranges(struct scoutfs_key *a_start,
				             struct scoutfs_key *a_end,
				             struct scoutfs_key *b_start,
				             struct scoutfs_key *b_end)
{
	return scoutfs_key_compare(a_end, b_start) < 0 ? -1 :
	       scoutfs_key_compare(a_start, b_end) > 0 ? 1 :
	       0;
}

static inline void scoutfs_key_inc(struct scoutfs_key *key)
{
	if (++key->_sk_fourth != 0)
		return;

	le64_add_cpu(&key->_sk_third, 1);
	if (key->_sk_third != 0)
		return;

	le64_add_cpu(&key->_sk_second, 1);
	if (key->_sk_second != 0)
		return;

	if (++key->sk_type != 0)
		return;

	le64_add_cpu(&key->_sk_first, 1);
	if (key->_sk_first != 0)
		return;

	key->sk_zone++;
}

static inline void scoutfs_key_dec(struct scoutfs_key *key)
{
	if (--key->_sk_fourth != U8_MAX)
		return;

	le64_add_cpu(&key->_sk_third, -1);
	if (key->_sk_third != cpu_to_le64(U64_MAX))
		return;

	le64_add_cpu(&key->_sk_second, -1);
	if (key->_sk_second != cpu_to_le64(U64_MAX))
		return;

	if (--key->sk_type != U8_MAX)
		return;

	le64_add_cpu(&key->_sk_first, -1);
	if (key->_sk_first != cpu_to_le64(U64_MAX))
		return;

	key->sk_zone--;
}

static inline void scoutfs_key_to_be(struct scoutfs_key_be *be,
				     struct scoutfs_key *key)
{
	BUILD_BUG_ON(sizeof(struct scoutfs_key_be) !=
		     sizeof(struct scoutfs_key));

	be->sk_zone = key->sk_zone;
	be->_sk_first = le64_to_be64(key->_sk_first);
	be->sk_type = key->sk_type;
	be->_sk_second = le64_to_be64(key->_sk_second);
	be->_sk_third = le64_to_be64(key->_sk_third);
	be->_sk_fourth = key->_sk_fourth;
}

static inline void scoutfs_key_from_be(struct scoutfs_key *key,
				       struct scoutfs_key_be *be)
{
	key->sk_zone = be->sk_zone;
	key->_sk_first = be64_to_le64(be->_sk_first);
	key->sk_type = be->sk_type;
	key->_sk_second = be64_to_le64(be->_sk_second);
	key->_sk_third = be64_to_le64(be->_sk_third);
	key->_sk_fourth = be->_sk_fourth;
}

#endif
