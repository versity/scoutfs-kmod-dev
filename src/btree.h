#ifndef _SCOUTFS_BTREE_H_
#define _SCOUTFS_BTREE_H_

#include <linux/uio.h>

struct scoutfs_radix_allocator;
struct scoutfs_block_writer;
struct scoutfs_block;

struct scoutfs_btree_item_ref {
	struct super_block *sb;
	struct scoutfs_block *bl;
	struct scoutfs_key *key;
	void *val;
	unsigned val_len;
};

#define SCOUTFS_BTREE_ITEM_REF(name) \
	struct scoutfs_btree_item_ref name = {NULL,}


int scoutfs_btree_lookup(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_insert(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len);
int scoutfs_btree_update(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len);
int scoutfs_btree_force(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key,
			void *val, unsigned val_len);
int scoutfs_btree_delete(struct super_block *sb,
			 struct scoutfs_radix_allocator *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key);
int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_dirty(struct super_block *sb,
			struct scoutfs_radix_allocator *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key);

void scoutfs_btree_put_iref(struct scoutfs_btree_item_ref *iref);

#endif
