#ifndef _SCOUTFS_IVAL_H_
#define _SCOUTFS_IVAL_H_

struct scoutfs_ival_tree {
	struct rb_root root;
};

struct scoutfs_ival {
	struct rb_node node;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct scoutfs_key subtree_end;
};

void scoutfs_insert_ival(struct scoutfs_ival_tree *tree,
			 struct scoutfs_ival *ins);
void scoutfs_remove_ival(struct scoutfs_ival_tree *tree,
			 struct scoutfs_ival *ival);
struct scoutfs_ival *scoutfs_next_ival(struct scoutfs_ival_tree *tree,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end,
				       struct scoutfs_ival *ival);

// struct rb_node {
//         long unsigned int          __rb_parent_color;    /*     0     8 */
//         struct rb_node *           rb_right;             /*     8     8 */
//         struct rb_node *           rb_left;              /*    16     8 */
//
//         /* size: 24, cachelines: 1, members: 3 */
//         /* last cacheline: 24 bytes */
// };
// struct rb_root {
//         struct rb_node *           rb_node;              /*     0     8 */
//
//         /* size: 8, cachelines: 1, members: 1 */
//         /* last cacheline: 8 bytes */
// };

/*
 * Try to find out if the imported hacked rbtree in ival.c goes out of
 * sync with the rbtree in the distro kernel.
 */
static inline void giant_rbtree_hack_build_bugs(void)
{
	size_t sz = sizeof(long);

	BUILD_BUG_ON(offsetof(struct rb_node, __rb_parent_color) != 0);
	BUILD_BUG_ON(offsetof(struct rb_node, rb_right) != sz);
	BUILD_BUG_ON(offsetof(struct rb_node, rb_left) != (sz * 2));
	BUILD_BUG_ON(sizeof(struct rb_node) != (sz * 3));

	BUILD_BUG_ON(offsetof(struct rb_root, rb_node) != 0);
	BUILD_BUG_ON(sizeof(struct rb_root) != sz);
}

#endif
