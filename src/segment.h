#ifndef _SCOUTFS_SEGMENT_H_
#define _SCOUTFS_SEGMENT_H_

struct scoutfs_item_ref {
	/* usable by callers */
	struct scoutfs_key *key;
	unsigned int val_len;
	void *val;

	/* private buffer head refs */
	struct buffer_head *item_bh;
	struct buffer_head *val_bh;
};

#define DECLARE_SCOUTFS_ITEM_REF(name) \
	struct scoutfs_item_ref name = {NULL ,}

void scoutfs_put_ref(struct scoutfs_item_ref *ref);
void scoutfs_put_iter_list(struct list_head *list);

int scoutfs_read_item(struct super_block *sb, struct scoutfs_key *key,
		      struct scoutfs_item_ref *ref);
int scoutfs_create_item(struct super_block *sb, struct scoutfs_key *key,
		        unsigned bytes, struct scoutfs_item_ref *ref);
int scoutfs_dirty_item(struct super_block *sb, struct scoutfs_key *key,
		       unsigned bytes, struct scoutfs_item_ref *ref);
int scoutfs_delete_item(struct super_block *sb, struct scoutfs_item_ref *ref);
int scoutfs_next_item(struct super_block *sb, struct scoutfs_key *first,
		      struct scoutfs_key *last, struct list_head *iter_list,
		      struct scoutfs_item_ref *ref);

int scoutfs_sync_fs(struct super_block *sb, int wait);


#endif
