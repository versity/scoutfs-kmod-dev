#ifndef _SCOUTFS_AVL_H_
#define _SCOUTFS_AVL_H_

#include "format.h"

typedef int (*scoutfs_avl_compare_t)(void *arg,
				       struct scoutfs_avl_node *node);

struct scoutfs_avl_node *
scoutfs_avl_search(struct scoutfs_avl_root *root,
		   scoutfs_avl_compare_t compare, void *arg, int *cmp_ret,
		   struct scoutfs_avl_node **par,
		   struct scoutfs_avl_node **next,
		   struct scoutfs_avl_node **prev);
struct scoutfs_avl_node *scoutfs_avl_first(struct scoutfs_avl_root *root);
struct scoutfs_avl_node *scoutfs_avl_last(struct scoutfs_avl_root *root);
struct scoutfs_avl_node *scoutfs_avl_next(struct scoutfs_avl_root *root,
					  struct scoutfs_avl_node *node);
struct scoutfs_avl_node *scoutfs_avl_prev(struct scoutfs_avl_root *root,
					  struct scoutfs_avl_node *node);
void scoutfs_avl_insert(struct scoutfs_avl_root *root,
			  struct scoutfs_avl_node *parent,
			  struct scoutfs_avl_node *node, int cmp);
void scoutfs_avl_delete(struct scoutfs_avl_root *root,
			  struct scoutfs_avl_node *node);
void scoutfs_avl_relocate(struct scoutfs_avl_root *root,
			    struct scoutfs_avl_node *to,
			    struct scoutfs_avl_node *from);

#endif
