#ifndef _SCOUTFS_ITEM_H_
#define _SCOUTFS_ITEM_H_

#include <linux/uio.h>

int scoutfs_item_lookup(struct super_block *sb, struct kvec *key,
			struct kvec *val);
int scoutfs_item_lookup_exact(struct super_block *sb, struct kvec *key,
			      struct kvec *val, int size);
int scoutfs_item_insert(struct super_block *sb, struct kvec *key,
		        struct kvec *val);

int scoutfs_item_setup(struct super_block *sb);
void scoutfs_item_destroy(struct super_block *sb);

#endif
