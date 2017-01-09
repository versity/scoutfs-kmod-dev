#ifndef _SCOUTFS_TREAP_H_
#define _SCOUTFS_TREAP_H_

struct scoutfs_bio_completion;

/*
 * The runtime root that's used by operations.  It's loaded and stored
 * from the persistent root in the super block as transactions are written.
 */
struct scoutfs_treap;

struct scoutfs_treap_ops {
	int (*compare)(void *key, void *data);
	void (*fill)(void *data, void *fill_arg);
	bool (*update_aug)(void *parent_data, bool left, void *node_data);
};

struct scoutfs_treap *scoutfs_treap_alloc(struct super_block *sb,
					  struct scoutfs_treap_ops *ops,
					  struct scoutfs_treap_root *root);
void scoutfs_treap_update_root(struct scoutfs_treap_root *root,
			       struct scoutfs_treap *treap);
void scoutfs_treap_free(struct scoutfs_treap *treap);

void *scoutfs_treap_insert(struct scoutfs_treap *treap, void *key, u16 bytes,
			   void *fill_arg);
int scoutfs_treap_delete(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup_dirty(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup_next(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup_next_dirty(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup_prev(struct scoutfs_treap *treap, void *key);
void *scoutfs_treap_lookup_prev_dirty(struct scoutfs_treap *treap, void *key);

void *scoutfs_treap_first(struct scoutfs_treap *treap);
void *scoutfs_treap_last(struct scoutfs_treap *treap);
void *scoutfs_treap_next(struct scoutfs_treap *treap, void *data);
void *scoutfs_treap_prev(struct scoutfs_treap *treap, void *data);

int scoutfs_treap_has_dirty(struct scoutfs_treap *treap);
int scoutfs_treap_dirty_ring(struct scoutfs_treap *treap);
int scoutfs_treap_submit_write(struct super_block *sb,
			       struct scoutfs_bio_completion *comp);

int scoutfs_treap_setup(struct super_block *sb);
void scoutfs_treap_destroy(struct super_block *sb);

#endif
