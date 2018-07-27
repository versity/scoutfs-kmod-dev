#ifndef _SCOUTFS_MANIFEST_H_
#define _SCOUTFS_MANIFEST_H_

#include "key.h"

struct scoutfs_bio_completion;

/*
 * This native manifest entry references the physical storage of a
 * manifest entry which can exist in a segment header and its edge keys,
 * a network transmission of a packed entry and its keys, or in btree
 * blocks spread between an item key and value.
 */
struct scoutfs_manifest_entry {
	u8 level;
	u64 segno;
	u64 seq;
	struct scoutfs_key first;
	struct scoutfs_key last;
};

void scoutfs_manifest_init_entry(struct scoutfs_manifest_entry *ment,
				 u64 level, u64 segno, u64 seq,
				 struct scoutfs_key *first,
				 struct scoutfs_key *last);
int scoutfs_manifest_add(struct super_block *sb,
			 struct scoutfs_manifest_entry *ment);
int scoutfs_manifest_del(struct super_block *sb,
			 struct scoutfs_manifest_entry *ment);

int scoutfs_manifest_lock(struct super_block *sb);
int scoutfs_manifest_unlock(struct super_block *sb);

int scoutfs_manifest_read_items(struct super_block *sb,
				struct scoutfs_key *key,
				struct scoutfs_key *start,
				struct scoutfs_key *end);
int scoutfs_manifest_next_key(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_key *next_key);

int scoutfs_manifest_should_compact(struct super_block *sb);
int scoutfs_manifest_next_compact(struct super_block *sb,
				  struct scoutfs_net_compact_request *req);
void scoutfs_manifest_compact_done(struct super_block *sb,
				   struct scoutfs_net_compact_request *req);

bool scoutfs_manifest_level0_full(struct super_block *sb);

int scoutfs_manifest_setup(struct super_block *sb);
void scoutfs_manifest_destroy(struct super_block *sb);

#endif
