#ifndef _SCOUTFS_TSEQ_H_
#define _SCOUTFS_TSEQ_H_

#include <linux/debugfs.h>

struct scoutfs_tseq_entry;
typedef void (*scoutfs_tseq_show_t)(struct seq_file *m,
				    struct scoutfs_tseq_entry *ent);

struct scoutfs_tseq_tree {
	spinlock_t lock;
	struct rb_root root;
	scoutfs_tseq_show_t show;
};

struct scoutfs_tseq_entry {
	struct rb_node node;
	loff_t pos;
	loff_t total;
};

void scoutfs_tseq_tree_init(struct scoutfs_tseq_tree *tree,
			    scoutfs_tseq_show_t show);
void scoutfs_tseq_add(struct scoutfs_tseq_tree *tree,
		      struct scoutfs_tseq_entry *ent);
void scoutfs_tseq_del(struct scoutfs_tseq_tree *tree,
		      struct scoutfs_tseq_entry *ent);

struct dentry *scoutfs_tseq_create(const char *name, struct dentry *parent,
				   struct scoutfs_tseq_tree *tree);

#endif
