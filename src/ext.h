#ifndef _SCOUTFS_EXT_H_
#define _SCOUTFS_EXT_H_

struct scoutfs_extent {
	u64 start;
	u64 len;
	u64 map;
	u8 flags;
};

struct scoutfs_ext_ops {
	int (*next)(struct super_block *sb, void *arg,
		    u64 start, u64 len, struct scoutfs_extent *ext);
	int (*insert)(struct super_block *sb, void *arg,
		      u64 start, u64 len, u64 map, u8 flags);
	int (*remove)(struct super_block *sb, void *arg, u64 start, u64 len,
		      u64 map, u8 flags);
};

bool scoutfs_ext_can_merge(struct scoutfs_extent *left,
			   struct scoutfs_extent *right);

int scoutfs_ext_next(struct super_block *sb, struct scoutfs_ext_ops *ops,
		     void *arg, u64 start, u64 len, struct scoutfs_extent *ext);
int scoutfs_ext_insert(struct super_block *sb, struct scoutfs_ext_ops *ops,
		       void *arg, u64 start, u64 len, u64 map, u8 flags);
int scoutfs_ext_remove(struct super_block *sb, struct scoutfs_ext_ops *ops,
		       void *arg, u64 start, u64 len);
int scoutfs_ext_alloc(struct super_block *sb, struct scoutfs_ext_ops *ops,
		      void *arg, u64 start, u64 len, u64 limit,
		      struct scoutfs_extent *ext);
int scoutfs_ext_set(struct super_block *sb, struct scoutfs_ext_ops *ops,
		    void *arg, u64 start, u64 len, u64 map, u8 flags);

#endif
