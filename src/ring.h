#ifndef _SCOUTFS_RING_H_
#define _SCOUTFS_RING_H_

#include <linux/uio.h>

struct scoutfs_bio_completion;

int scoutfs_ring_read(struct super_block *sb);
void scoutfs_ring_append(struct super_block *sb,
			 struct scoutfs_ring_entry_header *eh);

int scoutfs_ring_submit_write(struct super_block *sb,
			      struct scoutfs_bio_completion *comp);

int scoutfs_ring_setup(struct super_block *sb);
void scoutfs_ring_destroy(struct super_block *sb);

#endif
