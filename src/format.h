#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */

/* block header magic values, chosen at random */
#define SCOUTFS_BLOCK_MAGIC_SUPER	0x103c428b
#define SCOUTFS_BLOCK_MAGIC_BTREE	0xe597f96d
#define SCOUTFS_BLOCK_MAGIC_BLOOM	0x31995604
#define SCOUTFS_BLOCK_MAGIC_SRCH_BLOCK	0x897e4a7d
#define SCOUTFS_BLOCK_MAGIC_SRCH_PARENT	0xb23a2a05
#define SCOUTFS_BLOCK_MAGIC_ALLOC_LIST	0x8a93ac83

/*
 * The super block, quorum block, and file data allocation granularity
 * use the smaller 4KB block.
 */
#define SCOUTFS_BLOCK_SM_SHIFT		12
#define SCOUTFS_BLOCK_SM_SIZE		(1 << SCOUTFS_BLOCK_SM_SHIFT)
#define SCOUTFS_BLOCK_SM_MASK		(SCOUTFS_BLOCK_SM_SIZE - 1)
#define SCOUTFS_BLOCK_SM_PER_PAGE	(PAGE_SIZE / SCOUTFS_BLOCK_SM_SIZE)
#define SCOUTFS_BLOCK_SM_SECTOR_SHIFT	(SCOUTFS_BLOCK_SM_SHIFT - 9)
#define SCOUTFS_BLOCK_SM_SECTORS	(1 << SCOUTFS_BLOCK_SM_SECTOR_SHIFT)
#define SCOUTFS_BLOCK_SM_MAX		(U64_MAX >> SCOUTFS_BLOCK_SM_SHIFT)
#define SCOUTFS_BLOCK_SM_PAGES_PER	(SCOUTFS_BLOCK_SM_SIZE / PAGE_SIZE)
#define SCOUTFS_BLOCK_SM_PAGE_ORDER	(SCOUTFS_BLOCK_SM_SHIFT - PAGE_SHIFT)

/*
 * The radix and btree structures, and the forest bloom block, use the
 * larger 64KB metadata block size.
 */
#define SCOUTFS_BLOCK_LG_SHIFT		16
#define SCOUTFS_BLOCK_LG_SIZE		(1 << SCOUTFS_BLOCK_LG_SHIFT)
#define SCOUTFS_BLOCK_LG_MASK		(SCOUTFS_BLOCK_LG_SIZE - 1)
#define SCOUTFS_BLOCK_LG_PER_PAGE	(PAGE_SIZE / SCOUTFS_BLOCK_LG_SIZE)
#define SCOUTFS_BLOCK_LG_SECTOR_SHIFT	(SCOUTFS_BLOCK_LG_SHIFT - 9)
#define SCOUTFS_BLOCK_LG_SECTORS	(1 << SCOUTFS_BLOCK_LG_SECTOR_SHIFT)
#define SCOUTFS_BLOCK_LG_MAX		(U64_MAX >> SCOUTFS_BLOCK_LG_SHIFT)
#define SCOUTFS_BLOCK_LG_PAGES_PER	(SCOUTFS_BLOCK_LG_SIZE / PAGE_SIZE)
#define SCOUTFS_BLOCK_LG_PAGE_ORDER	(SCOUTFS_BLOCK_LG_SHIFT - PAGE_SHIFT)

#define SCOUTFS_BLOCK_SM_LG_SHIFT	(SCOUTFS_BLOCK_LG_SHIFT - \
					 SCOUTFS_BLOCK_SM_SHIFT)


/*
 * The super block leaves some room before the first block for platform
 * structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64ULL * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * A reasonably large region of aligned quorum blocks follow the super
 * block.  Each voting cycle reads the entire region so we don't want it
 * to be too enormous.  256K seems like a reasonably chunky single IO.
 * The number of blocks in the region also determines the number of
 * mounts that have a reasonable probability of not overwriting each
 * other's random block locations.
 */
#define SCOUTFS_QUORUM_BLKNO	((256ULL * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)
#define SCOUTFS_QUORUM_BLOCKS	((256ULL * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Start data on the data device aligned as well.
 */
#define SCOUTFS_DATA_DEV_START_BLKNO ((256ULL * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)


#define SCOUTFS_UNIQUE_NAME_MAX_BYTES	64 /* includes null */

/*
 * Base types used by other structures.
 */
struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
	__u8 __pad[4];
};

/* XXX ipv6 */
struct scoutfs_inet_addr {
	__le32 addr;
	__le16 port;
	__u8 __pad[2];
};

/*
 * This header is stored at the start of btree blocks and the super
 * block for verification.  The crc field is not included in the
 * calculation of the crc.
 */
struct scoutfs_block_header {
	__le32 crc;
	__le32 magic;
	__le64 fsid;
	__le64 seq;
	__le64 blkno;
};

/*
 * scoutfs identifies all file system metadata items by a small key
 * struct.
 *
 * Each item type maps their logical structures to the fixed fields in
 * sort order.  This lets us print keys without needing per-type
 * formats.
 *
 * The keys are compared by considering the fields in struct order from
 * most to least significant.  They are considered a multi precision
 * value when navigating the keys in ordered key space.  We can
 * increment them, subtract them from each other, etc.
 */
struct scoutfs_key {
	__le64	_sk_first;
	__le64	_sk_second;
	__le64	_sk_third;
	__u8	_sk_fourth;
	__u8	sk_zone;
	__u8	sk_type;
	__u8	__pad[5];
};

/* inode index */
#define skii_major	_sk_second
#define skii_ino	_sk_third

/* node orphan inode */
#define sko_rid		_sk_first
#define sko_ino		_sk_second

/* inode */
#define ski_ino		_sk_first

/* xattr parts */
#define skx_ino		_sk_first
#define skx_name_hash	_sk_second
#define skx_id		_sk_third
#define skx_part	_sk_fourth

/* directory entries */
#define skd_ino		_sk_first
#define skd_major	_sk_second
#define skd_minor	_sk_third

/* symlink target */
#define sks_ino		_sk_first
#define sks_nr		_sk_second

/* data extents */
#define skdx_ino	_sk_first
#define skdx_end	_sk_second
#define skdx_len	_sk_third

/* log trees */
#define sklt_rid	_sk_first
#define sklt_nr		_sk_second

/* lock clients */
#define sklc_rid	_sk_first

/* seqs */
#define skts_trans_seq	_sk_first
#define skts_rid	_sk_second

/* mounted clients */
#define skmc_rid	_sk_first

/* free extents by blkno */
#define skfb_end	_sk_second
#define skfb_len	_sk_third
/* free extents by len */
#define skfl_neglen	_sk_second
#define skfl_blkno	_sk_third

struct scoutfs_radix_block {
	struct scoutfs_block_header hdr;
	union {
		struct scoutfs_radix_ref {
			__le64 blkno;
			__le64 seq;
			__le64 sm_total;
			__le64 lg_total;
		} refs[0];
		__le64 bits[0];
	};
};

struct scoutfs_avl_root {
	__le16 node;
};

struct scoutfs_avl_node {
	__le16 parent;
	__le16 left;
	__le16 right;
	__u8 height;
	__u8 __pad[1];
};

/* when we split we want to have multiple items on each side */
#define SCOUTFS_BTREE_MAX_VAL_LEN 896

/*
 * A 4EB test image measured a worst case height of 17.  This is plenty
 * generous.
 */
#define SCOUTFS_BTREE_MAX_HEIGHT 20

struct scoutfs_btree_ref {
	__le64 blkno;
	__le64 seq;
};

/*
 * A height of X means that the first block read will have level X-1 and
 * the leaves will have level 0.
 */
struct scoutfs_btree_root {
	struct scoutfs_btree_ref ref;
	__u8 height;
	__u8 __pad[7];
};

struct scoutfs_btree_item {
	struct scoutfs_avl_node node;
	struct scoutfs_key key;
	__le16 val_off;
	__le16 val_len;
	__u8 __pad[4];
};

struct scoutfs_btree_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_avl_root item_root;
	__le16 nr_items;
	__le16 total_item_bytes;
	__le16 mid_free_len;
	__u8 level;
	__u8 __pad[7];
	struct scoutfs_btree_item items[0];
	/* leaf blocks have a fixed size item offset hash table at the end */
};

#define SCOUTFS_BTREE_VALUE_ALIGN 8

/*
 * Try to aim for a 75% load in a leaf full of items with no value.
 * We'll almost never see this because most items have values and most
 * blocks aren't full.
 */
#define SCOUTFS_BTREE_LEAF_ITEM_HASH_NR_UNALIGNED			  \
	((SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block)) /	  \
	 (sizeof(struct scoutfs_btree_item) + (sizeof(__le16))) * 100 / 75)
#define SCOUTFS_BTREE_LEAF_ITEM_HASH_NR					  \
	(round_up(SCOUTFS_BTREE_LEAF_ITEM_HASH_NR_UNALIGNED,		  \
		  SCOUTFS_BTREE_VALUE_ALIGN))
#define SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES \
	(SCOUTFS_BTREE_LEAF_ITEM_HASH_NR * sizeof(__le16))

struct scoutfs_alloc_list_ref {
	__le64 blkno;
	__le64 seq;
};

/*
 * first_nr tracks the nr of the first block in the list and is used for
 * allocation sizing. total_nr is the sum of the nr of all the blocks in
 * the list and is used for calculating total free block counts.
 */
struct scoutfs_alloc_list_head {
	struct scoutfs_alloc_list_ref ref;
	__le64 total_nr;
	__le32 first_nr;
	__u8 __pad[4];
};

/*
 * While the main allocator uses extent items in btree blocks, metadata
 * allocations for a single transaction are recorded in arrays in
 * blocks.  This limits the number of allocations and frees needed to
 * cow and modify the structure.  The blocks can be stored in a list
 * which lets us create a persistent log of pending frees that are
 * generated as we cow btree blocks to insert freed extents.
 *
 * The array floats in the block so that both adding and removing blknos
 * only modifies an index.
 */
struct scoutfs_alloc_list_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_alloc_list_ref next;
	__le32 start;
	__le32 nr;
	__le64 blknos[0]; /* naturally aligned for sorting */
};

#define SCOUTFS_ALLOC_LIST_MAX_BLOCKS					      \
	((SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_alloc_list_block)) /  \
	 (member_sizeof(struct scoutfs_alloc_list_block, blknos[0])))

/*
 * These can safely be initialized to all-zeros.
 */
struct scoutfs_alloc_root {
	__le64 total_len;
	struct scoutfs_btree_root root;
};

/* types of allocators, exposed to alloc_detail ioctl */
#define SCOUTFS_ALLOC_OWNER_NONE	0
#define SCOUTFS_ALLOC_OWNER_SERVER	1
#define SCOUTFS_ALLOC_OWNER_MOUNT	2
#define SCOUTFS_ALLOC_OWNER_SRCH	3

struct scoutfs_mounted_client_btree_val {
	__u8 flags;
};

#define SCOUTFS_MOUNTED_CLIENT_VOTER	(1 << 0)

/*
 * srch files are a contiguous run of blocks with compressed entries
 * described by a dense parent radix.  The files can be stored in
 * log_tree items when the files contain unsorted entries written by
 * mounts during their transactions.  Sorted files of increasing size
 * are kept in a btree off the super for searching and further
 * compacting.
 */
struct scoutfs_srch_entry {
	__le64 hash;
	__le64 ino;
	__le64 id;
};

#define SCOUTFS_SRCH_ENTRY_MAX_BYTES	(2 + (sizeof(__u64) * 3))

struct scoutfs_srch_ref {
	__le64 blkno;
	__le64 seq;
};

struct scoutfs_srch_file {
	struct scoutfs_srch_entry first;
	struct scoutfs_srch_entry last;
	struct scoutfs_srch_ref ref;
	__le64 blocks;
	__le64 entries;
	__u8 height;
	__u8 __pad[7];
};

struct scoutfs_srch_parent {
	struct scoutfs_block_header hdr;
	struct scoutfs_srch_ref refs[0];
};

#define SCOUTFS_SRCH_PARENT_REFS				\
	((SCOUTFS_BLOCK_LG_SIZE -				\
	  offsetof(struct scoutfs_srch_parent, refs)) /		\
	 sizeof(struct scoutfs_srch_ref))

struct scoutfs_srch_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_srch_entry first;
	struct scoutfs_srch_entry last;
	struct scoutfs_srch_entry tail;
	__le32 entry_nr;
	__le32 entry_bytes;
	__u8 entries[0];
};

/*
 * Decoding loads final small deltas with full __u64 loads.  Rather than
 * check the size before each load we stop coding entries past the point
 * where a full size entry could overflow the block.  A final entry can
 * start at this byte count and consume the rest of the block, though
 * its unlikely.
 */
#define SCOUTFS_SRCH_BLOCK_SAFE_BYTES					\
	(SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_srch_block) -	\
	 SCOUTFS_SRCH_ENTRY_MAX_BYTES)

#define SCOUTFS_SRCH_LOG_BLOCK_LIMIT	(1024 * 1024 / SCOUTFS_BLOCK_LG_SIZE)
#define SCOUTFS_SRCH_COMPACT_ORDER	2
#define SCOUTFS_SRCH_COMPACT_NR		(1 << SCOUTFS_SRCH_COMPACT_ORDER)

/*
 * A persistent record of a srch file compaction operation in progress.
 *
 * When compacting log files blk and pos aren't used.  When compacting
 * sorted files blk is the logical block number and pos is the byte
 * offset of the next entry.  When deleting files pos is the height of
 * the level that we're deleting, and blk is the logical block offset of
 * the next parent ref array index to descend through.
 */
struct scoutfs_srch_compact {
	struct scoutfs_alloc_list_head meta_avail;
	struct scoutfs_alloc_list_head meta_freed;
	__le64 id;
	__u8 nr;
	__u8 flags;
	__u8 __pad[6];
	struct scoutfs_srch_file out;
	struct scoutfs_srch_compact_input {
		struct scoutfs_srch_file sfl;
		__le64 blk;
		__le64 pos;
	} in[SCOUTFS_SRCH_COMPACT_NR];
};

/* server -> client: combine input log file entries into output file */
#define SCOUTFS_SRCH_COMPACT_FLAG_LOG		(1 << 0)
/* server -> client: combine input sorted file entries into output file */
#define SCOUTFS_SRCH_COMPACT_FLAG_SORTED	(1 << 1)
/* server -> client: delete input files */
#define SCOUTFS_SRCH_COMPACT_FLAG_DELETE	(1 << 2)
/* client -> server: compaction phase (LOG,SORTED,DELETE) done */
#define SCOUTFS_SRCH_COMPACT_FLAG_DONE		(1 << 4)
/* client -> server: compaction failed */
#define SCOUTFS_SRCH_COMPACT_FLAG_ERROR		(1 << 5)

/*
 * XXX I imagine we should rename these now that they've evolved to track
 * all the btrees that clients use during a transaction.  It's not just
 * about item logs, it's about clients making changes to trees.
 */
struct scoutfs_log_trees {
	struct scoutfs_alloc_list_head meta_avail;
	struct scoutfs_alloc_list_head meta_freed;
	struct scoutfs_btree_root item_root;
	struct scoutfs_btree_ref bloom_ref;
	struct scoutfs_alloc_root data_avail;
	struct scoutfs_alloc_root data_freed;
	struct scoutfs_srch_file srch_file;
	__le64 max_item_vers;
	__le64 rid;
	__le64 nr;
};

struct scoutfs_log_item_value {
	__le64 vers;
	__u8 flags;
	__u8 __pad[7];
	__u8 data[0];
};

/*
 * FS items are limited by the max btree value length with the log item
 * value header.
 */
#define SCOUTFS_MAX_VAL_SIZE \
	(SCOUTFS_BTREE_MAX_VAL_LEN - sizeof(struct scoutfs_log_item_value))

#define SCOUTFS_LOG_ITEM_FLAG_DELETION		(1 << 0)

struct scoutfs_bloom_block {
	struct scoutfs_block_header hdr;
	__le64 total_set;
	__le64 bits[0];
};

/*
 * Item log trees are accompanied by a block of bits that make up a
 * bloom filter which indicate if the item log trees may contain items
 * covered by a lock.  The log trees should be finalized and merged long
 * before the bloom filters fill up and start returning excessive false
 * positives.
 */
#define SCOUTFS_FOREST_BLOOM_NRS		3
#define SCOUTFS_FOREST_BLOOM_BITS \
	(((SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_bloom_block)) /  \
	 member_sizeof(struct scoutfs_bloom_block, bits[0])) *		  \
	 member_sizeof(struct scoutfs_bloom_block, bits[0]) * 8)
#define SCOUTFS_FOREST_BLOOM_FUNC_BITS		(SCOUTFS_BLOCK_LG_SHIFT + 3)

/*
 * Keys are first sorted by major key zones.
 */
#define SCOUTFS_INODE_INDEX_ZONE		1
#define SCOUTFS_RID_ZONE			2
#define SCOUTFS_FS_ZONE				3
#define SCOUTFS_LOCK_ZONE			4
/* Items only stored in server btrees */
#define SCOUTFS_LOG_TREES_ZONE			6
#define SCOUTFS_LOCK_CLIENTS_ZONE		7
#define SCOUTFS_TRANS_SEQ_ZONE			8
#define SCOUTFS_MOUNTED_CLIENT_ZONE		9
#define SCOUTFS_SRCH_ZONE			10
#define SCOUTFS_FREE_EXTENT_ZONE		11

/* inode index zone */
#define SCOUTFS_INODE_INDEX_META_SEQ_TYPE	1
#define SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE	2
#define SCOUTFS_INODE_INDEX_NR			3 /* don't forget to update */

/* rid zone (also used in server alloc btree) */
#define SCOUTFS_ORPHAN_TYPE			1

/* fs zone */
#define SCOUTFS_INODE_TYPE			1
#define SCOUTFS_XATTR_TYPE			2
#define SCOUTFS_DIRENT_TYPE			3
#define SCOUTFS_READDIR_TYPE			4
#define SCOUTFS_LINK_BACKREF_TYPE		5
#define SCOUTFS_SYMLINK_TYPE			6
#define SCOUTFS_DATA_EXTENT_TYPE		7

/* lock zone, only ever found in lock ranges, never in persistent items */
#define SCOUTFS_RENAME_TYPE			1

/* srch zone, only in server btrees */
#define SCOUTFS_SRCH_LOG_TYPE		1
#define SCOUTFS_SRCH_BLOCKS_TYPE	2
#define SCOUTFS_SRCH_PENDING_TYPE	3
#define SCOUTFS_SRCH_BUSY_TYPE		4

/* free extents in allocator btrees in client and server, by blkno or len */
#define SCOUTFS_FREE_EXTENT_BLKNO_TYPE	1
#define SCOUTFS_FREE_EXTENT_LEN_TYPE	2

/* file data extents have start and len in key */
struct scoutfs_data_extent_val {
	__le64 blkno;
	__u8 flags;
	__u8 __pad[7];
};

#define SEF_OFFLINE	(1 << 0)
#define SEF_UNWRITTEN	(1 << 1)
#define SEF_UNKNOWN	(U8_MAX << 2)

/*
 * The first xattr part item has a header that describes the xattr.  The
 * name and value are then packed into the following bytes in the first
 * part item and overflow into the values of the rest of the part items.
 */
struct scoutfs_xattr {
	__le16 val_len;
	__u8 name_len;
	__u8 __pad[5];
	__u8 name[0];
};


/* XXX does this exist upstream somewhere? */
#define member_sizeof(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))

#define SCOUTFS_UUID_BYTES 16

/*
 * Mounts read all the quorum blocks and write to one random quorum
 * block during a cycle.  The min cycle time limits the per-mount iop
 * load during elections.  The random cycle delay makes it less likely
 * that mounts will read and write at the same time and miss each
 * other's writes.  An election only completes if a quorum of mounts
 * vote for a leader before any of their elections timeout.  This is
 * made less likely by the probability that mounts will overwrite each
 * others random block locations.  The max quorum count limits that
 * probability.  9 mounts only have a 55% chance of writing to unique 4k
 * blocks in a 256k region.  The election timeout is set to include
 * enough cycles to usually complete the election.  Once a leader is
 * elected it spends a number of cycles writing out blocks with itself
 * logged as a leader.  This reduces the possibility that servers
 * will have their log entries overwritten and not be fenced.
 */
#define SCOUTFS_QUORUM_MAX_COUNT		9
#define SCOUTFS_QUORUM_CYCLE_LO_MS		10
#define SCOUTFS_QUORUM_CYCLE_HI_MS		20
#define SCOUTFS_QUORUM_TERM_LO_MS		250
#define SCOUTFS_QUORUM_TERM_HI_MS		500
#define SCOUTFS_QUORUM_ELECTED_LOG_CYCLES	10

struct scoutfs_quorum_block {
	__le64 fsid;
	__le64 blkno;
	__le64 term;
	__le64 write_nr;
	__le64 voter_rid;
	__le64 vote_for_rid;
	__le32 crc;
	__u8 log_nr;
	__u8 __pad[3];
	struct scoutfs_quorum_log {
		__le64 term;
		__le64 rid;
		struct scoutfs_inet_addr addr;
	} log[0];
};

#define SCOUTFS_QUORUM_LOG_MAX						  \
	((SCOUTFS_BLOCK_SM_SIZE - sizeof(struct scoutfs_quorum_block)) /  \
		sizeof(struct scoutfs_quorum_log))

#define SCOUTFS_FLAG_IS_META_BDEV 0x01

struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__le64 format_hash;
	__le64 flags;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 next_ino;
	__le64 next_trans_seq;
	__le64 total_meta_blocks;	/* both static and dynamic */
	__le64 first_meta_blkno;	/* first dynamically allocated */
	__le64 last_meta_blkno;
	__le64 total_data_blocks;
	__le64 first_data_blkno;
	__le64 last_data_blkno;
	__le64 quorum_fenced_term;
	__le64 quorum_server_term;
	__le64 unmount_barrier;
	__u8 quorum_count;
	__u8 __pad[7];
	struct scoutfs_inet_addr server_addr;
	struct scoutfs_alloc_root meta_alloc[2];
	struct scoutfs_alloc_root data_alloc;
	struct scoutfs_alloc_list_head server_meta_avail[2];
	struct scoutfs_alloc_list_head server_meta_freed[2];
	struct scoutfs_btree_root fs_root;
	struct scoutfs_btree_root logs_root;
	struct scoutfs_btree_root lock_clients;
	struct scoutfs_btree_root trans_seqs;
	struct scoutfs_btree_root mounted_clients;
	struct scoutfs_btree_root srch_root;
};

#define SCOUTFS_ROOT_INO 1


/*
 * @meta_seq: advanced the first time an inode is updated in a given
 * transaction.  It can only advance again after the inode is written
 * and a new transaction opens.
 *
 * @data_seq: advanced the first time a file's data (or size) is
 * modified in a given transaction.  It can only advance again after the
 * file is written and a new transaction opens.
 *
 * @data_version: incremented every time the contents of a file could
 * have changed.  It is exposed via an ioctl and is then provided as an
 * argument to data functions to protect racing modification.
 *
 * @online_blocks: The number of fixed 4k blocks currently allocated and
 * storing data in the volume.
 *
 * @offline_blocks: The number of fixed 4k blocks that could be made
 * online by staging.
 *
 * XXX
 *	- otime?
 *	- compat flags?
 *	- version?
 *	- generation?
 *	- be more careful with rdev?
 */
struct scoutfs_inode {
	__le64 size;
	__le64 meta_seq;
	__le64 data_seq;
	__le64 data_version;
	__le64 online_blocks;
	__le64 offline_blocks;
	__le64 next_readdir_pos;
	__le64 next_xattr_id;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le32 rdev;
	__le32 flags;
	struct scoutfs_timespec atime;
	struct scoutfs_timespec ctime;
	struct scoutfs_timespec mtime;
};

#define SCOUTFS_INO_FLAG_TRUNCATE 0x1

#define SCOUTFS_ROOT_INO 1

/* like the block size, a reasonable min PATH_MAX across platforms */
#define SCOUTFS_SYMLINK_MAX_SIZE 4096

/*
 * Dirents are stored in multiple places to isolate contention when
 * performing different operations: hashed by name for creation and
 * lookup, at incrementing positions for readdir and resolving inodes to
 * paths.  Each entry has all the metadata needed to reference all the
 * items (so an entry cached by lookup can be used to unlink all the
 * items).
 */
struct scoutfs_dirent {
	__le64 ino;
	__le64 hash;
	__le64 pos;
	__u8 type;
	__u8 __pad[7];
	__u8 name[0];
};

#define SCOUTFS_NAME_LEN 255

/* S32_MAX avoids the (int) sign bit and might avoid sloppy bugs */
#define SCOUTFS_LINK_MAX S32_MAX

/* entries begin after . and .. */
#define SCOUTFS_DIRENT_FIRST_POS 2
/* getdents returns next pos with an entry, no entry at (f_pos)~0 */
#define SCOUTFS_DIRENT_LAST_POS (U64_MAX - 1)

enum scoutfs_dentry_type {
	SCOUTFS_DT_FIFO = 0,
	SCOUTFS_DT_CHR,
	SCOUTFS_DT_DIR,
	SCOUTFS_DT_BLK,
	SCOUTFS_DT_REG,
	SCOUTFS_DT_LNK,
	SCOUTFS_DT_SOCK,
	SCOUTFS_DT_WHT,
};


#define SCOUTFS_XATTR_MAX_NAME_LEN	255
#define SCOUTFS_XATTR_MAX_VAL_LEN	65535
#define SCOUTFS_XATTR_MAX_PART_SIZE	SCOUTFS_MAX_VAL_SIZE

#define SCOUTFS_XATTR_NR_PARTS(name_len, val_len)			\
	DIV_ROUND_UP(sizeof(struct scoutfs_xattr) + name_len + val_len, \
		     (unsigned int)SCOUTFS_XATTR_MAX_PART_SIZE)

#define SCOUTFS_LOCK_INODE_GROUP_NR	1024
#define SCOUTFS_LOCK_INODE_GROUP_MASK	(SCOUTFS_LOCK_INODE_GROUP_NR - 1)
#define SCOUTFS_LOCK_SEQ_GROUP_MASK	((1ULL << 10) - 1)

/*
 * messages over the wire.
 */

/*
 * Greetings verify identity of communicating nodes.  The sender sends
 * their credentials and the receiver verifies them.
 *
 * @server_term: The raft term that elected the server.  Initially 0
 * from the client, sent by the server, then sent by the client as it
 * tries to reconnect.  Used to identify a client reconnecting to both
 * the same serer after receiving a greeting response and to a new
 * server after failover.
 *
 * @unmount_barrier: Incremented every time the remaining majority of
 * quorum members all agree to leave.  The server tells a quorum member
 * the value that it's connecting under so that if the client sees the
 * value increase in the super block then it knows that the server has
 * processed its farewell and can safely unmount.
 *
 * @rid: The client's random id that was generated once as the mount
 * started up.  This identifies a specific remote mount across
 * connections and servers.  It's set to the client's rid in both the
 * request and response for consistency.
 */
struct scoutfs_net_greeting {
	__le64 fsid;
	__le64 format_hash;
	__le64 server_term;
	__le64 unmount_barrier;
	__le64 rid;
	__le64 flags;
};

#define SCOUTFS_NET_GREETING_FLAG_FAREWELL	(1 << 0)
#define SCOUTFS_NET_GREETING_FLAG_VOTER		(1 << 1)
#define SCOUTFS_NET_GREETING_FLAG_INVALID	(~(__u64)0 << 2)

/*
 * This header precedes and describes all network messages sent over
 * sockets.
 *
 * @seq: A sequence number that is increased for each message queued for
 * send on the sender.  The sender will never reorder messages in the
 * send queue so this will always increase in recv on the receiver.  The
 * receiver can use this to drop messages that arrived twice after being
 * resent across a newly connected socket for a given connection.
 *
 * @recv_seq: The sequence number of the last received message.  The
 * receiver is sending this to the sender in every message.  The sender
 * uses them to drop responses which have been delivered.
 *
 * @id: An increasing identifier that is set in each request.  Responses
 * specify the request that they're responding to.
 *
 * Error is only set to a translated errno and will only be found in
 * response messages.
 */
struct scoutfs_net_header {
	__le64 clock_sync_id;
	__le64 seq;
	__le64 recv_seq;
	__le64 id;
	__le16 data_len;
	__u8 cmd;
	__u8 flags;
	__u8 error;
	__u8 __pad[3];
	__u8 data[0];
};

#define SCOUTFS_NET_FLAG_RESPONSE	(1 << 0)
#define SCOUTFS_NET_FLAGS_UNKNOWN	(U8_MAX << 1)

enum scoutfs_net_cmd {
	SCOUTFS_NET_CMD_GREETING = 0,
	SCOUTFS_NET_CMD_ALLOC_INODES,
	SCOUTFS_NET_CMD_GET_LOG_TREES,
	SCOUTFS_NET_CMD_COMMIT_LOG_TREES,
	SCOUTFS_NET_CMD_GET_ROOTS,
	SCOUTFS_NET_CMD_ADVANCE_SEQ,
	SCOUTFS_NET_CMD_GET_LAST_SEQ,
	SCOUTFS_NET_CMD_LOCK,
	SCOUTFS_NET_CMD_LOCK_RECOVER,
	SCOUTFS_NET_CMD_SRCH_GET_COMPACT,
	SCOUTFS_NET_CMD_SRCH_COMMIT_COMPACT,
	SCOUTFS_NET_CMD_FAREWELL,
	SCOUTFS_NET_CMD_UNKNOWN,
};

/*
 * Define a macro to evaluate another macro for each of the errnos we
 * translate over the wire.  This lets us keep our enum in sync with the
 * mapping arrays to and from host errnos.
 */
#define EXPAND_EACH_NET_ERRNO		\
	EXPAND_NET_ERRNO(ENOENT)	\
	EXPAND_NET_ERRNO(ENOMEM)	\
	EXPAND_NET_ERRNO(EIO)		\
	EXPAND_NET_ERRNO(ENOSPC)	\
	EXPAND_NET_ERRNO(EINVAL)

#undef EXPAND_NET_ERRNO
#define EXPAND_NET_ERRNO(which) SCOUTFS_NET_ERR_##which,
enum scoutfs_net_errors {
	SCOUTFS_NET_ERR_NONE = 0,
	EXPAND_EACH_NET_ERRNO
	SCOUTFS_NET_ERR_UNKNOWN,
};

/* arbitrarily chosen to be safely less than mss and allow 1k with header */
#define SCOUTFS_NET_MAX_DATA_LEN 1100

/*
 * When there's no more free inodes this will be sent with ino = ~0 and
 * nr = 0.
 */
struct scoutfs_net_inode_alloc {
	__le64 ino;
	__le64 nr;
};

struct scoutfs_net_roots {
	struct scoutfs_btree_root fs_root;
	struct scoutfs_btree_root logs_root;
	struct scoutfs_btree_root srch_root;
};

struct scoutfs_net_lock {
	struct scoutfs_key key;
	__le64 write_version;
	__u8 old_mode;
	__u8 new_mode;
	__u8 __pad[6];
};

struct scoutfs_net_lock_grant_response {
	struct scoutfs_net_lock nl;
	struct scoutfs_net_roots roots;
};

struct scoutfs_net_lock_recover {
	__le16 nr;
	__u8 __pad[6];
	struct scoutfs_net_lock locks[0];
};

#define SCOUTFS_NET_LOCK_MAX_RECOVER_NR					       \
	((SCOUTFS_NET_MAX_DATA_LEN - sizeof(struct scoutfs_net_lock_recover)) /\
	 sizeof(struct scoutfs_net_lock))

/* some enums for tracing */
enum scoutfs_lock_trace {
	SLT_CLIENT,
	SLT_SERVER,
	SLT_GRANT,
	SLT_INVALIDATE,
	SLT_REQUEST,
	SLT_RESPONSE,
};

/*
 * Read and write locks operate as you'd expect.  Multiple readers can
 * hold read locks while writers are excluded.  A single writer can hold
 * a write lock which excludes other readers and writers.  Writers can
 * read while holding a write lock.
 *
 * Multiple writers can hold write only locks but they can not read,
 * they can only generate dirty items.  It's used when the system has
 * other means of knowing that it's safe to overwrite items.
 *
 * The null mode provides no access and is used to destroy locks.
 */
enum scoutfs_lock_mode {
	SCOUTFS_LOCK_NULL = 0,
	SCOUTFS_LOCK_READ,
	SCOUTFS_LOCK_WRITE,
	SCOUTFS_LOCK_WRITE_ONLY,
	SCOUTFS_LOCK_INVALID,
};

/*
 * Scoutfs file handle structure - this can be copied out to userspace
 * via open by handle or put on the wire from NFS.
 */
struct scoutfs_fid {
	__le64 ino;
	__le64 parent_ino;
};

#define FILEID_SCOUTFS			0x81
#define FILEID_SCOUTFS_WITH_PARENT	0x82

/*
 * Identifiers for sources of corruption that can generate messages.
 */
enum scoutfs_corruption_sources {
	SC_DIRENT_NAME_LEN = 0,
	SC_DIRENT_BACKREF_NAME_LEN,
	SC_DIRENT_READDIR_NAME_LEN,
	SC_SYMLINK_INODE_SIZE,
	SC_SYMLINK_MISSING_ITEM,
	SC_SYMLINK_NOT_NULL_TERM,
	SC_BTREE_BLOCK_LEVEL,
	SC_BTREE_NO_CHILD_REF,
	SC_INODE_BLOCK_COUNTS,
	SC_NR_SOURCES,
};

#define SC_NR_LONGS DIV_ROUND_UP(SC_NR_SOURCES, BITS_PER_LONG)

#endif
