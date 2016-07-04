#ifndef _SCOUTFS_BTREE_H_
#define _SCOUTFS_BTREE_H_

struct scoutfs_btree_cursor {
	/* for btree.c */
	struct scoutfs_block *bl;
	struct scoutfs_btree_item *item;

	/* for callers */
	struct scoutfs_key *key;
	void *val;
	u16 val_len;
	u16 write:1;
};

#define DECLARE_SCOUTFS_BTREE_CURSOR(name) \
        struct scoutfs_btree_cursor name = {NULL,}

int scoutfs_btree_lookup(struct super_block *sb, struct scoutfs_key *key,
			 struct scoutfs_btree_cursor *curs);
int scoutfs_btree_insert(struct super_block *sb, struct scoutfs_key *key,
			 unsigned int val_len,
			 struct scoutfs_btree_cursor *curs);
int scoutfs_btree_delete(struct super_block *sb, struct scoutfs_key *key);
int scoutfs_btree_next(struct super_block *sb, struct scoutfs_key *first,
		       struct scoutfs_key *last,
		       struct scoutfs_btree_cursor *curs);
int scoutfs_btree_dirty(struct super_block *sb, struct scoutfs_key *key);
void scoutfs_btree_update(struct super_block *sb, struct scoutfs_key *key,
                          struct scoutfs_btree_cursor *curs);
int scoutfs_btree_hole(struct super_block *sb, struct scoutfs_key *first,
		       struct scoutfs_key *last, struct scoutfs_key *hole);

void scoutfs_btree_release(struct scoutfs_btree_cursor *curs);

#endif
