#ifndef _SCOUTFS_BTREE_H_
#define _SCOUTFS_BTREE_H_

#include <linux/uio.h>

struct scoutfs_btree_item_ref {
	void *key;
	unsigned key_len;
	void *val;
	unsigned val_len;
};

#define SCOUTFS_BTREE_ITEM_REF(name) \
	struct scoutfs_btree_item_ref name = {NULL,}

int scoutfs_btree_lookup(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_insert(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 void *val, unsigned val_len);
int scoutfs_btree_update(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len,
			 void *val, unsigned val_len);
int scoutfs_btree_delete(struct super_block *sb, struct scoutfs_btree_root *root,
			 void *key, unsigned key_len);
int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       void *key, unsigned key_len,
		       struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_after(struct super_block *sb, struct scoutfs_btree_root *root,
		        void *key, unsigned key_len,
		        struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       void *key, unsigned key_len,
		       struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_before(struct super_block *sb, struct scoutfs_btree_root *root,
		         void *key, unsigned key_len,
		         struct scoutfs_btree_item_ref *iref);
int scoutfs_btree_dirty(struct super_block *sb, struct scoutfs_btree_root *root,
			void *key, unsigned key_len);

void scoutfs_btree_put_iref(struct scoutfs_btree_item_ref *iref);

bool scoutfs_btree_has_dirty(struct super_block *sb);
int scoutfs_btree_write_dirty(struct super_block *sb);
void scoutfs_btree_write_complete(struct super_block *sb);

int scoutfs_btree_setup(struct super_block *sb);
void scoutfs_btree_destroy(struct super_block *sb);

#endif
