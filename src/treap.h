#ifndef _SCOUTFS_TREAP_H_
#define _SCOUTFS_TREAP_H_

#include "format.h"

typedef int (*scoutfs_treap_cmp_t)(struct scoutfs_treap_node *a,
				   struct scoutfs_treap_node *b);

static inline void scoutfs_treap_init(struct scoutfs_treap_root *root)
{
	root->off = 0;
}

int scoutfs_treap_insert(struct scoutfs_treap_root *root,
		         scoutfs_treap_cmp_t cmp_func,
			 struct scoutfs_treap_node *ins);
void scoutfs_treap_delete(struct scoutfs_treap_root *root,
			  struct scoutfs_treap_node *node);
struct scoutfs_treap_node *scoutfs_treap_lookup(struct scoutfs_treap_root *root,
						scoutfs_treap_cmp_t cmp_func,
						struct scoutfs_treap_node *key);
struct scoutfs_treap_node *scoutfs_treap_first(struct scoutfs_treap_root *root);
struct scoutfs_treap_node *scoutfs_treap_last(struct scoutfs_treap_root *root);
struct scoutfs_treap_node *scoutfs_treap_before(struct scoutfs_treap_root *root,
						scoutfs_treap_cmp_t cmp_func,
						struct scoutfs_treap_node *key);
struct scoutfs_treap_node *scoutfs_treap_after(struct scoutfs_treap_root *root,
					       scoutfs_treap_cmp_t cmp_func,
					       struct scoutfs_treap_node *key);
struct scoutfs_treap_node *scoutfs_treap_next(struct scoutfs_treap_root *root,
					      struct scoutfs_treap_node *node);
struct scoutfs_treap_node *scoutfs_treap_prev(struct scoutfs_treap_root *root,
					      struct scoutfs_treap_node *node);
void scoutfs_treap_move(struct scoutfs_treap_root *root,
		        struct scoutfs_treap_node *from,
		        struct scoutfs_treap_node *to);

#endif
