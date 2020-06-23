#ifndef _SCOUTFS_SRCH_H_
#define _SCOUTFS_SRCH_H_

struct scoutfs_block;

struct scoutfs_srch_rb_root {
	struct rb_root root;
	struct rb_node *last;
	unsigned long nr;
};

struct scoutfs_srch_rb_node {
	struct rb_node node;
	u64 ino;
	u64 id;
};

#define scoutfs_srch_foreach_rb_node(snode, node, sroot)		\
	for (node = rb_first(&(sroot)->root);				\
	     node && (snode = container_of(node, struct scoutfs_srch_rb_node, \
					   node), 1);			\
	     node = rb_next(node))

int scoutfs_srch_add(struct super_block *sb,
		     struct scoutfs_radix_allocator *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_srch_file *sfl,
		     struct scoutfs_block **bl_ret,
		     u64 hash, u64 ino, u64 id);

void scoutfs_srch_destroy_rb_root(struct scoutfs_srch_rb_root *sroot);
int scoutfs_srch_search_xattrs(struct super_block *sb,
			       struct scoutfs_srch_rb_root *sroot,
			       u64 hash, u64 ino, u64 last_ino, bool *done);

int scoutfs_srch_rotate_log(struct super_block *sb,
			    struct scoutfs_radix_allocator *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_btree_root *root,
			    struct scoutfs_srch_file *sfl);
int scoutfs_srch_get_compact(struct super_block *sb,
			     struct scoutfs_radix_allocator *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_btree_root *root,
			     u64 rid,
			     struct scoutfs_srch_compact_input *scin_ret);
int scoutfs_srch_update_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact_input *scin);
int scoutfs_srch_commit_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_srch_compact_result *scres,
				struct scoutfs_radix_root *av,
				struct scoutfs_radix_root *fr);
int scoutfs_srch_cancel_compact(struct super_block *sb,
				struct scoutfs_radix_allocator *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_btree_root *root, u64 rid,
				struct scoutfs_radix_root *av,
				struct scoutfs_radix_root *fr);

void scoutfs_srch_destroy(struct super_block *sb);
int scoutfs_srch_setup(struct super_block *sb);

#endif
