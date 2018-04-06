#ifndef _SCOUTFS_COUNT_H_
#define _SCOUTFS_COUNT_H_

/*
 * Our estimate of the space consumed while dirtying items is based on
 * the number of items and the size of their values.
 *
 * The estimate is still a read-only input to entering the transaction.
 * We'd like to use it as a clean rhs arg to hold_trans.  We define SIC_
 * functions which return the count struct.  This lets us have a single
 * arg and avoid bugs in initializing and passing in struct pointers
 * from callers.  The internal __count functions are used compose an
 * estimate out of the sets of items it manipulates.  We program in much
 * clearer C instead of in the preprocessor.
 *
 * Compilers are able to collapse the inlines into constants for the
 * constant estimates.
 */

struct scoutfs_item_count {
	signed items;
	signed vals;
};

/*
 * Allocating an inode creates a new set of indexed items.
 */
static inline void __count_alloc_inode(struct scoutfs_item_count *cnt)
{
	const int nr_indices = SCOUTFS_INODE_INDEX_NR;

	cnt->items += 1 + nr_indices;
	cnt->vals += sizeof(struct scoutfs_inode);
}

/*
 * Dirtying an inode dirties the inode item and can delete and create
 * the full set of indexed items.
 */
static inline void __count_dirty_inode(struct scoutfs_item_count *cnt)
{
	const int nr_indices = 2 * SCOUTFS_INODE_INDEX_NR;

	cnt->items += 1 + nr_indices;
	cnt->vals += sizeof(struct scoutfs_inode);
}

static inline const struct scoutfs_item_count SIC_ALLOC_INODE(void)
{
	struct scoutfs_item_count cnt = {0,};

	__count_alloc_inode(&cnt);

	return cnt;
}

static inline const struct scoutfs_item_count SIC_DIRTY_INODE(void)
{
	struct scoutfs_item_count cnt = {0,};

	__count_dirty_inode(&cnt);

	return cnt;
}

/*
 * Directory entries are stored in three items.
 */
static inline void __count_dirents(struct scoutfs_item_count *cnt,
				   unsigned name_len)
{
	cnt->items += 3;
	cnt->vals += 3 * offsetof(struct scoutfs_dirent, name[name_len]);
}

static inline void __count_sym_target(struct scoutfs_item_count *cnt,
				      unsigned size)
{
	unsigned nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);

	cnt->items += nr;
	cnt->vals += size;
}

static inline void __count_orphan(struct scoutfs_item_count *cnt)
{

	cnt->items += 1;
}

static inline void __count_mknod(struct scoutfs_item_count *cnt,
				 unsigned name_len)
{
	__count_alloc_inode(cnt);
	__count_dirents(cnt, name_len);
	__count_dirty_inode(cnt);
}

static inline const struct scoutfs_item_count SIC_MKNOD(unsigned name_len)
{
	struct scoutfs_item_count cnt = {0,};

	__count_mknod(&cnt, name_len);

	return cnt;
}

static inline const struct scoutfs_item_count SIC_LINK(unsigned name_len)
{
	struct scoutfs_item_count cnt = {0,};

	__count_dirents(&cnt, name_len);
	__count_dirty_inode(&cnt);
	__count_dirty_inode(&cnt);

	return cnt;
}

/*
 * Unlink can add orphan items.
 */
static inline const struct scoutfs_item_count SIC_UNLINK(unsigned name_len)
{
	struct scoutfs_item_count cnt = {0,};

	__count_dirents(&cnt, name_len);
	__count_dirty_inode(&cnt);
	__count_dirty_inode(&cnt);
	__count_orphan(&cnt);

	return cnt;
}

static inline const struct scoutfs_item_count SIC_SYMLINK(unsigned name_len,
							  unsigned size)
{
	struct scoutfs_item_count cnt = {0,};

	__count_mknod(&cnt, name_len);
	__count_sym_target(&cnt, size);

	return cnt;
}

/*
 * This assumes the worst case of a rename between directories that
 * unlinks an existing target.  That'll be worse than the common case
 * by a few hundred bytes.
 */
static inline const struct scoutfs_item_count SIC_RENAME(unsigned old_len,
							 unsigned new_len)
{
	struct scoutfs_item_count cnt = {0,};

	/* dirty dirs and inodes */
	__count_dirty_inode(&cnt);
	__count_dirty_inode(&cnt);
	__count_dirty_inode(&cnt);
	__count_dirty_inode(&cnt);

	/* unlink old and new, link new */
	__count_dirents(&cnt, old_len);
	__count_dirents(&cnt, new_len);
	__count_dirents(&cnt, new_len);

	/* orphan the existing target */
	__count_orphan(&cnt);

	return cnt;
}

/*
 * Creating an xattr results in a dirty set of items with values that
 * store the xattr header, name, and value.  There's always at least one
 * item with the header and name.  Any previously existing items are
 * deleted which dirties their key but removes their value.  The two
 * sets of items are indexed by different ids so their items don't
 * overlap.
 */
static inline const struct scoutfs_item_count SIC_XATTR_SET(unsigned old_parts,
							    bool creating,
							    unsigned name_len,
							    unsigned size)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned int new_parts;

	__count_dirty_inode(&cnt);

	if (old_parts)
		cnt.items += old_parts;

	if (creating) {
		new_parts = SCOUTFS_XATTR_NR_PARTS(name_len, size)

		cnt.items += new_parts;
		cnt.vals += sizeof(struct scoutfs_xattr) + name_len + size;
	}

	return cnt;
}

/*
 * write_begin can have to allocate all the blocks in the page and can
 * have to add a big allocation from the server to do so:
 *  - merge added free extents from the server
 *  - remove a free extent per block
 *  - remove an offline extent for every other block
 *  - add a file extent per block
 */
static inline const struct scoutfs_item_count SIC_WRITE_BEGIN(void)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned nr_free = (SCOUTFS_BULK_ALLOC_COUNT +
			    SCOUTFS_BLOCKS_PER_PAGE) * 3;
	unsigned nr_file = (DIV_ROUND_UP(SCOUTFS_BLOCKS_PER_PAGE, 2) +
			    SCOUTFS_BLOCKS_PER_PAGE) * 3;

	__count_dirty_inode(&cnt);

	cnt.items += nr_free + nr_file;
	cnt.vals += nr_file * sizeof(struct scoutfs_file_extent);

	return cnt;
}

/*
 * Truncating a block mapping item's worth of blocks can modify both
 * free blkno and free segno items per block.  Then the largest possible
 * mapping item.
 */
static inline const struct scoutfs_item_count SIC_TRUNC_BLOCK(void)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned nr_free = (2 * SCOUTFS_BLOCK_MAPPING_BLOCKS);

	cnt.items += 1 + nr_free;
	cnt.vals += SCOUTFS_BLOCK_MAPPING_MAX_BYTES +
		    (nr_free * sizeof(struct scoutfs_free_bits));

	return cnt;
}

/*
 * Truncating an extent can:
 *  - delete existing file extent,
 *  - create two surrounding file extents,
 *  - add an offline file extent,
 *  - delete two existing free extents
 *  - create a merged free extent
 */
static inline const struct scoutfs_item_count SIC_TRUNC_EXTENT(void)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned int nr_file = 1 + 2 + 1;
	unsigned int nr_free = (2 + 1) * 2;

	cnt.items += nr_file + nr_free;
	cnt.vals += nr_file * sizeof(struct scoutfs_file_extent);

	return cnt;
}

#endif
