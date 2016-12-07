#ifndef _SCOUTFS_BIO_H_
#define _SCOUTFS_BIO_H_

/*
 * Our little block IO wrapper is just a convenience wrapper that takes
 * our block size units and handles tracks multiple bios per larger io.
 *
 * If bios could hold an unlimited number of pages instead of
 * BIO_MAX_PAGES then this would just use a single bio directly.
 */

/*
 * Track aggregate IO completion for multiple multi-bio submissions.
 */
struct scoutfs_bio_completion {
	atomic_t pending;
	struct completion comp;
	long err;
};

typedef void (*scoutfs_bio_end_io_t)(struct super_block *sb, void *data,
				     int err);

void scoutfs_bio_submit(struct super_block *sb, int rw, struct page **pages,
		        u64 blkno, unsigned int nr_blocks,
			scoutfs_bio_end_io_t end_io, void *data);

void scoutfs_bio_init_comp(struct scoutfs_bio_completion *comp);
void scoutfs_bio_submit_comp(struct super_block *sb, int rw,
			     struct page **pages, u64 blkno,
			     unsigned int nr_blocks,
			     struct scoutfs_bio_completion *comp);
int scoutfs_bio_wait_comp(struct super_block *sb,
			  struct scoutfs_bio_completion *comp);

int scoutfs_bio_read(struct super_block *sb, struct page **pages,
		     u64 blkno, unsigned int nr_blocks);

void *scoutfs_page_block_address(struct page **pages, unsigned int blk);

#endif
