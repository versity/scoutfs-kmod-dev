#ifndef _SCOUTFS_CMP_H_
#define _SCOUTFS_CMP_H_

/*
 * A generic ternary comparison macro with strict type checking.
 */
#define scoutfs_cmp(a, b)				\
({							\
	__typeof__(a) _a = (a);				\
	__typeof__(b) _b = (b);				\
	int _ret;					\
							\
	(void) (&_a == &_b);				\
	_ret = _a < _b ? -1 : _a > _b ? 1 : 0;		\
	_ret;						\
})

static inline int scoutfs_cmp_u64s(u64 a, u64 b)
{
	return a < b ? -1 : a > b ? 1 : 0;
}

#endif
