#ifndef _SCOUTFS_BTREE_H_
#define _SCOUTFS_BTREE_H_

#include <linux/uio.h>

struct scoutfs_btree_val {
	struct kvec vec[3];
};

static inline void __scoutfs_btree_init_val(struct scoutfs_btree_val *val,
					    void *ptr0, unsigned int len0,
					    void *ptr1, unsigned int len1,
					    void *ptr2, unsigned int len2)
{
	*val = (struct scoutfs_btree_val) {
		{ { ptr0, len0 }, { ptr1, len1 }, { ptr2, len2 } }
	};
}

#define _scoutfs_btree_init_val(v, p0, l0, p1, l1, p2, l2, ...) \
	__scoutfs_btree_init_val(v, p0, l0, p1, l1, p2, l2)

/*
 * Provide a nice variadic initialization function without having to
 * iterate over the callers arg types.  We play some macro games to pad
 * out the callers ptr/len pairs to the full possible number.  This will
 * produce confusing errors if an odd number of arguments is given and
 * the padded ptr/length types aren't compatible with the fixed
 * arguments in the static inline.
 */
#define scoutfs_btree_init_val(val, ...) \
	_scoutfs_btree_init_val(val, __VA_ARGS__, NULL, 0, NULL, 0, NULL, 0)

static inline int scoutfs_btree_val_length(struct scoutfs_btree_val *val)
{

	return iov_length((struct iovec *)val->vec, ARRAY_SIZE(val->vec));
}

int scoutfs_btree_lookup(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 struct scoutfs_btree_val *val);
int scoutfs_btree_insert(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 struct scoutfs_btree_val *val);
int scoutfs_btree_delete(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key);
int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *first, struct scoutfs_key *last,
		       struct scoutfs_key *found,
		       struct scoutfs_btree_val *val);
int scoutfs_btree_dirty(struct super_block *sb,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key);
int scoutfs_btree_update(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
		         struct scoutfs_btree_val *val);
int scoutfs_btree_hole(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *first,
		       struct scoutfs_key *last, struct scoutfs_key *hole);
int scoutfs_btree_since(struct super_block *sb,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *first, struct scoutfs_key *last,
			u64 seq, struct scoutfs_key *found, u64 *found_seq,
		        struct scoutfs_btree_val *val);

#endif
