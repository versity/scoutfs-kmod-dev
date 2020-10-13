#ifndef _SCOUTFS_SORT_PRIV_H_
#define _SCOUTFS_SORT_PRIV_H_

void sort_priv(void *priv, void *base, size_t num, size_t size,
	       int (*cmp_func)(void *priv, const void *, const void *),
	       void (*swap_func)(void *priv, void *, void *, int size));

#endif
