#ifndef _SCOUTFS_COUNT_H_
#define _SCOUTFS_COUNT_H_

/*
 * Our estimate of the space consumed while dirtying items isn't a
 * single value.  We're packing items into segments which have different
 * overheads for items (header overhead), keys (block aligned), and
 * values (can span blocks, not aligned).
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
	signed keys;
	signed vals;
};

/*
 * Allocating an inode creates a new set of indexed items.
 */
static inline void __count_alloc_inode(struct scoutfs_item_count *cnt)
{
	const int nr_indices = SCOUTFS_INODE_INDEX_NR;

	cnt->items += 1 + nr_indices;
	cnt->keys += sizeof(struct scoutfs_inode_key) +
		     (nr_indices * sizeof(struct scoutfs_inode_index_key));
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
	cnt->keys += sizeof(struct scoutfs_inode_key) +
		     (nr_indices * sizeof(struct scoutfs_inode_index_key));
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
 * Adding a dirent adds the entry key, readdir key, and backref.
 */
static inline void __count_dirents(struct scoutfs_item_count *cnt,
				   unsigned name_len)
{

	cnt->items += 3;
	cnt->keys += offsetof(struct scoutfs_dirent_key, name[name_len]) +
		      sizeof(struct scoutfs_readdir_key) +
		      offsetof(struct scoutfs_link_backref_key, name[name_len]);
	cnt->vals += 2 * offsetof(struct scoutfs_dirent, name[name_len]);
}

static inline void __count_sym_target(struct scoutfs_item_count *cnt,
				      unsigned size)
{
	unsigned nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);

	cnt->items += nr;
	cnt->keys += nr * sizeof(struct scoutfs_symlink_key);
	cnt->vals += size;
}

static inline void __count_orphan(struct scoutfs_item_count *cnt)
{

	cnt->items += 1;
	cnt->keys += sizeof(struct scoutfs_orphan_key);
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
 * Setting an xattr can create a full set of items for an xattr with a
 * max name and length.  Any existing items will be dirtied rather than
 * deleted so we won't have more items than a max xattr's worth.
 */
static inline const struct scoutfs_item_count SIC_XATTR_SET(unsigned name_len,
							    unsigned size)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned parts = DIV_ROUND_UP(size, SCOUTFS_XATTR_PART_SIZE);

	__count_dirty_inode(&cnt);

	cnt.items += parts;
	cnt.keys += parts * (offsetof(struct scoutfs_xattr_key,
					name[name_len]) +
			       sizeof(struct scoutfs_xattr_key_footer));
	cnt.vals += parts * (sizeof(struct scoutfs_xattr_val_header) +
			       SCOUTFS_XATTR_PART_SIZE);

	return cnt;
}

/*
 * write_begin can add local free segment items, modify another to
 * alloc, add a free blkno item, and modify dirty the mapping.
 */
static inline const struct scoutfs_item_count SIC_WRITE_BEGIN(void)
{
	struct scoutfs_item_count cnt = {0,};
	unsigned nr_free = SCOUTFS_BULK_ALLOC_COUNT + 1 + 1;

	__count_dirty_inode(&cnt);

	cnt.items += 1 + nr_free;
	cnt.keys += sizeof(struct scoutfs_block_mapping_key) +
		    (nr_free * sizeof(struct scoutfs_free_bits_key));
	cnt.vals += SCOUTFS_BLOCK_MAPPING_MAX_BYTES +
		    (nr_free * sizeof(struct scoutfs_free_bits));

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
	cnt.keys += sizeof(struct scoutfs_block_mapping_key) +
		    (nr_free * sizeof(struct scoutfs_free_bits_key));
	cnt.vals += SCOUTFS_BLOCK_MAPPING_MAX_BYTES +
		    (nr_free * sizeof(struct scoutfs_free_bits));

	return cnt;
}

#endif
