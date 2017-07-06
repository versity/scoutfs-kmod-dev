#ifndef _SCOUTFS_NET_H_
#define _SCOUTFS_NET_H_

struct scoutfs_key_buf;
struct scoutfs_segment;

int scoutfs_net_alloc_inodes(struct super_block *sb);
int scoutfs_net_alloc_segno(struct super_block *sb, u64 *segno);
int scoutfs_net_record_segment(struct super_block *sb,
			       struct scoutfs_segment *seg, u8 level);
u64 *scoutfs_net_bulk_alloc(struct super_block *sb);

int scoutfs_net_get_compaction(struct super_block *sb, void *curs);
int scoutfs_net_finish_compaction(struct super_block *sb, void *curs,
				  void *list);
int scoutfs_net_get_last_seq(struct super_block *sb, u64 *seq);
int scoutfs_net_advance_seq(struct super_block *sb, u64 *seq);

int scoutfs_net_get_manifest_root(struct super_block *sb,
				  struct scoutfs_btree_root *root);

int scoutfs_net_setup(struct super_block *sb);
void scoutfs_net_destroy(struct super_block *sb);

#endif
