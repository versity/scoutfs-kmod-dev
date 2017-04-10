#ifndef _SCOUTFS_RING_H_
#define _SCOUTFS_RING_H_

struct scoutfs_bio_completion;

typedef int (*scoutfs_ring_cmp_t)(void *a, void *b);

struct scoutfs_ring_info {
	struct scoutfs_ring_descriptor *rdesc;

	scoutfs_ring_cmp_t compare_key;
	scoutfs_ring_cmp_t compare_data;

	struct rb_root rb_root;

	struct list_head clean_list;
	struct list_head dirty_list;

	unsigned long dirty_bytes;
	u64 first_dirty_block;
	u64 first_dirty_seq;

	struct page **pages;
	unsigned long nr_pages;
};

void scoutfs_ring_init(struct scoutfs_ring_info *ring,
		       struct scoutfs_ring_descriptor *rdesc,
		       scoutfs_ring_cmp_t compare_key,
		       scoutfs_ring_cmp_t compare_data);

int scoutfs_ring_load(struct super_block *sb, struct scoutfs_ring_info *ring);

void *scoutfs_ring_insert(struct scoutfs_ring_info *ring, void *key,
			  unsigned data_len);

void *scoutfs_ring_first(struct scoutfs_ring_info *ring);
void *scoutfs_ring_lookup(struct scoutfs_ring_info *ring, void *key);
void *scoutfs_ring_lookup_next(struct scoutfs_ring_info *ring, void *key);
void *scoutfs_ring_lookup_prev(struct scoutfs_ring_info *ring, void *key);

void *scoutfs_ring_next(struct scoutfs_ring_info *ring, void *rdata);
void *scoutfs_ring_prev(struct scoutfs_ring_info *ring, void *rdata);
void scoutfs_ring_dirty(struct scoutfs_ring_info *ring, void *rdata);
void scoutfs_ring_delete(struct scoutfs_ring_info *ring, void *rdata);

int scoutfs_ring_has_dirty(struct scoutfs_ring_info *ring);
int scoutfs_ring_submit_write(struct super_block *sb,
			      struct scoutfs_ring_info *ring,
			      struct scoutfs_bio_completion *comp);
void scoutfs_ring_write_complete(struct scoutfs_ring_info *ring);

void scoutfs_ring_destroy(struct scoutfs_ring_info *ring);

#endif
