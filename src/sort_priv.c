/*
 * A copy of sort() from upstream with a priv argument that's passed
 * to comparison, like list_sort().
 */

/* ------------------------ */

/*
 * A fast, small, non-recursive O(nlog n) sort for the Linux kernel
 *
 * Jan 23 2005  Matt Mackall <mpm@selenic.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include "sort_priv.h"

/**
 * sort - sort an array of elements
 * @priv: caller's pointer to pass to comparison and swap functions
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap_func function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

void sort_priv(void *priv, void *base, size_t num, size_t size,
	       int (*cmp_func)(void *priv, const void *, const void *),
	       void (*swap_func)(void *priv, void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num/2 - 1) * size, n = num * size, c, r;

	/* heapify */
	for ( ; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r  = c) {
			c = r * 2 + size;
			if (c < n - size &&
			    cmp_func(priv, base + c, base + c + size) < 0)
				c += size;
			if (cmp_func(priv, base + r, base + c) >= 0)
				break;
			swap_func(priv, base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size) {
		swap_func(priv, base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size &&
			    cmp_func(priv, base + c, base + c + size) < 0)
				c += size;
			if (cmp_func(priv, base + r, base + c) >= 0)
				break;
			swap_func(priv, base + r, base + c, size);
		}
	}
}
