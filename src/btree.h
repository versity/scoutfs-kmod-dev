#ifndef _SCOUTFS_BTREE_H_
#define _SCOUTFS_BTREE_H_

struct scoutfs_btree_cursor {
	/* for btree.c */
	struct scoutfs_block *bl;
	struct scoutfs_btree_item *item;

	/* for callers */
	struct scoutfs_key *key;
	unsigned val_len;
	void *val;
};

static inline int scoutfs_btree_lookup(struct super_block *sb,
				       struct scoutfs_key *key,
				       struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}

static inline int scoutfs_btree_insert(struct super_block *sb,
				       struct scoutfs_key *key,
				       unsigned short val_len,
				       struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}

static inline int scoutfs_btree_dirty(struct super_block *sb,
				      struct scoutfs_key *key,
				      unsigned short val_len,
				      struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}


static inline int scoutfs_btree_delete(struct super_block *sb,
				       struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}

static inline int scoutfs_btree_next(struct super_block *sb,
				     struct scoutfs_key *first,
				     struct scoutfs_key *last,
				     struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}

static inline int scoutfs_btree_release(struct scoutfs_btree_cursor *curs)
{
	return -ENOSYS;
}

#endif
