#ifndef _SCOUTFS_KEY_H_
#define _SCOUTFS_KEY_H_

#include <linux/types.h>
#include "format.h"
#include "cmp.h"
#include "endian_swap.h"

#define SK_FMT		"%u.%llu.%u.%llu.%llu.%u"

/* This does not support null keys */
#define SK_ARG(key)	(key)->sk_zone,			\
			le64_to_cpu((key)->_sk_first),	\
			(key)->sk_type,			\
			le64_to_cpu((key)->_sk_second),	\
			le64_to_cpu((key)->_sk_third),	\
			(key)->_sk_fourth

/* userspace trace event printing doesn't like arguments with structure
 * field references.  So we explode structures into their fields instead
 * of
 */
#define sk_trace_define(name)			\
	__field(__u8, name##_zone)		\
	__field(__u64, name##_first)		\
	__field(__u8, name##_type)		\
	__field(__u64, name##_second)		\
	__field(__u64, name##_third)		\
	__field(__u8, name##_fourth)

#define sk_trace_assign(name, key)					\
do {									\
	__typeof__(key) _key = (key);					\
	if (_key) {							\
		__entry->name##_zone = _key->sk_zone;			\
		__entry->name##_first = le64_to_cpu(_key->_sk_first);	\
		__entry->name##_type = _key->sk_type;			\
		__entry->name##_second = le64_to_cpu(_key->_sk_second);\
		__entry->name##_third = le64_to_cpu(_key->_sk_third);	\
		__entry->name##_fourth = _key->_sk_fourth;		\
	} else {							\
		__entry->name##_zone = 0;				\
		__entry->name##_first = 0;				\
		__entry->name##_type = 0;				\
		__entry->name##_second = 0;				\
		__entry->name##_third = 0;				\
		__entry->name##_fourth = 0;				\
	}								\
} while (0)

#define sk_trace_args(name) \
	__entry->name##_zone, __entry->name##_first, __entry->name##_type, \
	__entry->name##_second, __entry->name##_third, __entry->name##_fourth

/*
 * copy fields between keys with the same fields but different types.
 * The destination type might have internal padding so we zero it.
 */
#define scoutfs_key_copy_types(a, b)		\
do {						\
	__typeof__(a) _to = (a);		\
	__typeof__(b) _from = (b);		\
						\
	memset(_to, 0, sizeof(*_to));		\
	_to->sk_zone = _from->sk_zone;		\
	_to->_sk_first = _from->_sk_first;	\
	_to->sk_type = _from->sk_type;		\
	_to->_sk_second = _from->_sk_second;	\
	_to->_sk_third = _from->_sk_third;	\
	_to->_sk_fourth = _from->_sk_fourth;	\
} while (0)

static inline void scoutfs_key_set_zeros(struct scoutfs_key *key)
{
	key->sk_zone = 0;
	key->_sk_first = 0;
	key->sk_type = 0;
	key->_sk_second = 0;
	key->_sk_third = 0;
	key->_sk_fourth = 0;
}

static inline bool scoutfs_key_is_zeros(struct scoutfs_key *key)
{
	return key->sk_zone == 0 && key->_sk_first == 0 && key->sk_type == 0 &&
	       key->_sk_second == 0 && key->_sk_third == 0 &&
	       key->_sk_fourth == 0;
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

/*
 * Some key types are used by multiple subsystems and shouldn't have
 * duplicate private key init functions.
 */

static inline void scoutfs_key_init_log_trees(struct scoutfs_key *key,
					      u64 rid, u64 nr)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_LOG_TREES_ZONE,
		.sklt_rid = cpu_to_le64(rid),
		.sklt_nr = cpu_to_le64(nr),
	};
}

#endif
