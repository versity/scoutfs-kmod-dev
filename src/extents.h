#ifndef _SCOUTFS_EXTENTS_H_
#define _SCOUTFS_EXTENTS_H_

/*
 * Native storage for an extent.  Read and write translates between
 * these and persistent storage.
 */
struct scoutfs_extent {
	u64 owner;
	u64 start;
	u64 len;
	u64 map;
	u8 type;
	u8 flags;
};

#define SE_FMT		"%llu.%llu.%llu.%llu.%u.%x"
#define SE_ARG(ext)	(ext)->owner, (ext)->start, (ext)->len, (ext)->map, \
			(ext)->type, (ext)->flags

enum {
	SEI_NEXT,
	SEI_PREV,
	SEI_INSERT,
	SEI_DELETE,
};
typedef int (*scoutfs_extent_io_t)(struct super_block *sb, int op,
				   struct scoutfs_extent *ext, void *data);

int scoutfs_extent_init(struct scoutfs_extent *ext, u8 type, u64 owner,
			u64 start, u64 len, u64 map, u8 flags);
bool scoutfs_extent_intersection(struct scoutfs_extent *a,
				 struct scoutfs_extent *b);

int scoutfs_extent_next(struct super_block *sb, scoutfs_extent_io_t iof,
			struct scoutfs_extent *ext, void *data);
int scoutfs_extent_prev(struct super_block *sb, scoutfs_extent_io_t iof,
			struct scoutfs_extent *ext, void *data);
int scoutfs_extent_add(struct super_block *sb, scoutfs_extent_io_t iof,
		       struct scoutfs_extent *add, void *data);
int scoutfs_extent_remove(struct super_block *sb, scoutfs_extent_io_t iof,
			  struct scoutfs_extent *rem, void *data);

/*
 * The process of modifying an extent creates and deletes many
 * intermediate extents.  If we hit an error we need to undo the
 * process.  If we then hit an error we can be left with inconsistent
 * extent items.
 *
 * We could fix this for extents that are stored in the item cache
 * because it has tools for ensuring that operations can't fail.
 * Extents that are stored in the btree currently can't avoid errors.
 * We'd have to predirty blocks, allow deletion to fall below thresholds
 * if merging saw an error, and preallocate blocks to be used for
 * splitting/growth.  It'd probably be worth it.
 */
#define scoutfs_extent_cleanup(cond, ext_func, sb, iof, clean, data,	      \
			       which, ctr, ext)				      \
do {									      \
	__typeof__(sb) _sb = (sb);					      \
	int _ret;							      \
									      \
	if ((cond) && (_ret = ext_func(_sb, iof, clean, data)) < 0)	      \
		scoutfs_corruption(_sb, which, ctr,			      \
				   "ext "SE_FMT" clean "SE_FMT" ret %d",      \
				   SE_ARG(ext), SE_ARG(clean), _ret);	      \
} while (0)

#endif
