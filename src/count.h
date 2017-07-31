#ifndef _SCOUTFS_COUNT_H_
#define _SCOUTFS_COUNT_H_

struct scoutfs_item_count {
	signed items;
	signed keys;
	signed vals;
};

#define DECLARE_ITEM_COUNT(name) \
	struct scoutfs_item_count name = { 0, }

/*
 * Allocating an inode creates a new set of indexed items.
 */
static inline void scoutfs_count_alloc_inode(struct scoutfs_item_count *cnt)
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
static inline void scoutfs_count_dirty_inode(struct scoutfs_item_count *cnt)
{
	const int nr_indices = 2 * SCOUTFS_INODE_INDEX_NR;

	cnt->items += 1 + nr_indices;
	cnt->keys += sizeof(struct scoutfs_inode_key) +
		     (nr_indices * sizeof(struct scoutfs_inode_index_key));
	cnt->vals += sizeof(struct scoutfs_inode);
}

/*
 * Adding a dirent adds the entry key, readdir key, and backref.
 */
static inline void scoutfs_count_dirents(struct scoutfs_item_count *cnt,
					   unsigned name_len)
{

	cnt->items += 3;
	cnt->keys += offsetof(struct scoutfs_dirent_key, name[name_len]) +
		      sizeof(struct scoutfs_readdir_key) +
		      offsetof(struct scoutfs_link_backref_key, name[name_len]);
	cnt->vals += 2 * offsetof(struct scoutfs_dirent, name[name_len]);
}

static inline void scoutfs_count_sym_target(struct scoutfs_item_count *cnt,
					      unsigned size)
{
	unsigned nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);

	cnt->items += nr;
	cnt->keys += nr * sizeof(struct scoutfs_symlink_key);
	cnt->vals += size;
}

static inline void scoutfs_count_orphan(struct scoutfs_item_count *cnt)
{

	cnt->items += 1;
	cnt->keys += sizeof(struct scoutfs_orphan_key);
}

static inline void scoutfs_count_mknod(struct scoutfs_item_count *cnt,
					 unsigned name_len)
{
	scoutfs_count_alloc_inode(cnt);
	scoutfs_count_dirents(cnt, name_len);
	scoutfs_count_dirty_inode(cnt);
}

static inline void scoutfs_count_link(struct scoutfs_item_count *cnt,
					unsigned name_len)
{
	scoutfs_count_dirents(cnt, name_len);
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_dirty_inode(cnt);
}

/*
 * Unlink can add orphan items.
 */
static inline void scoutfs_count_unlink(struct scoutfs_item_count *cnt,
					  unsigned name_len)
{
	scoutfs_count_dirents(cnt, name_len);
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_orphan(cnt);
}

static inline void scoutfs_count_symlink(struct scoutfs_item_count *cnt,
					   unsigned name_len, unsigned size)
{
	scoutfs_count_mknod(cnt, name_len);
	scoutfs_count_sym_target(cnt, size);
}

/*
 * This assumes the worst case of a rename between directories that
 * unlinks an existing target.  That'll be worse than the common case
 * by a few hundred bytes.
 */
static inline void scoutfs_count_rename(struct scoutfs_item_count *cnt,
					unsigned old_len, unsigned new_len)
{
	/* dirty dirs and inodes */
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_dirty_inode(cnt);
	scoutfs_count_dirty_inode(cnt);

	/* unlink old and new, link new */
	scoutfs_count_dirents(cnt, old_len);
	scoutfs_count_dirents(cnt, new_len);
	scoutfs_count_dirents(cnt, new_len);

	/* orphan the existing target */
	scoutfs_count_orphan(cnt);
}

/*
 * Setting an xattr can create a full set of items for an xattr with a
 * max name and length.  Any existing items will be dirtied rather than
 * deleted so we won't have more items than a max xattr's worth.
 */
static inline void scoutfs_count_xattr_set(struct scoutfs_item_count *cnt,
					     unsigned name_len, unsigned size)
{
	unsigned parts = DIV_ROUND_UP(size, SCOUTFS_XATTR_PART_SIZE);

	scoutfs_count_dirty_inode(cnt);

	cnt->items += parts;
	cnt->keys += parts * (offsetof(struct scoutfs_xattr_key,
					name[name_len]) +
			       sizeof(struct scoutfs_xattr_key_footer));
	cnt->vals += parts * (sizeof(struct scoutfs_xattr_val_header) +
			       SCOUTFS_XATTR_PART_SIZE);
}

/*
 * Both insertion and removal modifications can dirty three extents
 * at most: insertion can delete two existing neighbours and create a
 * third new extent and removal can delete an existing extent and create
 * two new remaining extents.
 */
static inline void scoutfs_count_extents(struct scoutfs_item_count *cnt,
					   unsigned nr_mod, unsigned sz)
{

	cnt->items += nr_mod * 3;
	cnt->keys += (nr_mod * 3) * sz;
}

/*
 * write_begin can refill local free extents after a bulk alloc rpc,
 * alloc an block, delete an offline mapping, and insert the new allocated
 * mapping.
 */
static inline void scoutfs_count_write_begin(struct scoutfs_item_count *cnt)
{
	BUILD_BUG_ON(sizeof(struct scoutfs_free_extent_blkno_key) !=
		     sizeof(struct scoutfs_free_extent_blocks_key));

	scoutfs_count_dirty_inode(cnt);

	scoutfs_count_extents(cnt, 2 * (SCOUTFS_BULK_ALLOC_COUNT + 1),
			        sizeof(struct scoutfs_free_extent_blkno_key));
	scoutfs_count_extents(cnt, 2,
			        sizeof(struct scoutfs_file_extent_key));
}

/*
 * Truncating a block can free an allocated block, delete an online
 * mapping, and create an offline mapping.
 */
static inline void scoutfs_count_trunc_block(struct scoutfs_item_count *cnt)
{
	scoutfs_count_extents(cnt, 2 * 1,
			        sizeof(struct scoutfs_free_extent_blkno_key));
	scoutfs_count_extents(cnt, 2,
			        sizeof(struct scoutfs_file_extent_key));
}

#endif
