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
int scoutfs_extent_add(struct super_block *sb, scoutfs_extent_io_t iof,
		       struct scoutfs_extent *add, void *data);
int scoutfs_extent_remove(struct super_block *sb, scoutfs_extent_io_t iof,
			  struct scoutfs_extent *rem, void *data);

#endif
