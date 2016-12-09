#ifndef _SCOUTFS_KVEC_H_
#define _SCOUTFS_KVEC_H_

#include <linux/uio.h>

/*
 * The item APIs use kvecs to represent variable size item keys and
 * values.
 */

/*
 * This ends up defining the max item size as nr - 1 * page _size.
 */
#define SCOUTFS_KVEC_NR 2
#define SCOUTFS_KVEC_BYTES (SCOUTFS_KVEC_NR * sizeof(struct kvec))

#define SCOUTFS_DECLARE_KVEC(name) \
	struct kvec name[SCOUTFS_KVEC_NR]

static inline void scoutfs_kvec_init_all(struct kvec *kvec,
					 void *ptr0, size_t len0,
					 void *ptr1, size_t len1,
					 void *ptr2, ...)
{
	BUG_ON(ptr2 != NULL);

	kvec[0].iov_base = ptr0;
	kvec[0].iov_len = len0;
	kvec[1].iov_base = ptr1;
	kvec[1].iov_len = len1;
}

/*
 * Provide a nice variadic initialization function without having to
 * iterate over the callers arg types.  We play some macro games to pad
 * out the callers ptr/len pairs to the full possible number.  This will
 * produce confusing errors if an odd number of arguments is given and
 * the padded ptr/length types aren't compatible with the fixed
 * arguments in the static inline.
 */
#define scoutfs_kvec_init(val, ...) \
	scoutfs_kvec_init_all(val, __VA_ARGS__, NULL, 0, NULL, 0)

static inline int scoutfs_kvec_length(struct kvec *kvec)
{
	BUILD_BUG_ON(sizeof(struct kvec) != sizeof(struct iovec));
	BUILD_BUG_ON(offsetof(struct kvec, iov_len) !=
		     offsetof(struct iovec, iov_len));
	BUILD_BUG_ON(member_sizeof(struct kvec, iov_len) !=
		     member_sizeof(struct iovec, iov_len));

	return iov_length((struct iovec *)kvec, SCOUTFS_KVEC_NR);
}

void scoutfs_kvec_clone(struct kvec *dst, struct kvec *src);
int scoutfs_kvec_memcmp(struct kvec *a, struct kvec *b);
int scoutfs_kvec_cmp_overlap(struct kvec *a, struct kvec *b,
			     struct kvec *c, struct kvec *d);
int scoutfs_kvec_memcpy(struct kvec *dst, struct kvec *src);
int scoutfs_kvec_memcpy_truncate(struct kvec *dst, struct kvec *src);
int scoutfs_kvec_dup_flatten(struct kvec *dst, struct kvec *src);
void scoutfs_kvec_kfree(struct kvec *kvec);
void scoutfs_kvec_init_null(struct kvec *kvec);
void scoutfs_kvec_swap(struct kvec *a, struct kvec *b);

#endif
