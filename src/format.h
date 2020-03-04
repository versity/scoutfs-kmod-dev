#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */

/* block header magic values, chosen at random */
#define SCOUTFS_BLOCK_MAGIC_SUPER	0x103c428b
#define SCOUTFS_BLOCK_MAGIC_BTREE	0xe597f96d
#define SCOUTFS_BLOCK_MAGIC_BLOOM	0x31995604
#define SCOUTFS_BLOCK_MAGIC_RADIX	0xebeb5e65

/*
 * The super block and btree blocks are fixed 4k.
 */
#define SCOUTFS_BLOCK_SHIFT 12
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_BLOCK_MASK (SCOUTFS_BLOCK_SIZE - 1)
#define SCOUTFS_BLOCKS_PER_PAGE (PAGE_SIZE / SCOUTFS_BLOCK_SIZE)
#define SCOUTFS_BLOCK_SECTOR_SHIFT (SCOUTFS_BLOCK_SHIFT - 9)
#define SCOUTFS_BLOCK_SECTORS (1 << SCOUTFS_BLOCK_SECTOR_SHIFT)
#define SCOUTFS_BLOCK_MAX (U64_MAX >> SCOUTFS_BLOCK_SHIFT)

#define SCOUTFS_PAGES_PER_BLOCK (SCOUTFS_BLOCK_SIZE / PAGE_SIZE)
#define SCOUTFS_BLOCK_PAGE_ORDER (SCOUTFS_BLOCK_SHIFT - PAGE_SHIFT)

/*
 * The super block leaves some room before the first block for platform
 * structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)

/*
 * A reasonably large region of aligned quorum blocks follow the super
 * block.  Each voting cycle reads the entire region so we don't want it
 * to be too enormous.  256K seems like a reasonably chunky single IO.
 * The number of blocks in the region also determines the number of
 * mounts that have a reasonable probability of not overwriting each
 * other's random block locations.
 */
#define SCOUTFS_QUORUM_BLKNO		((256ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_QUORUM_BLOCKS		((256ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)

#define SCOUTFS_UNIQUE_NAME_MAX_BYTES	64 /* includes null */

/*
 * Base types used by other structures.
 */
struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
} __packed;

struct scoutfs_betimespec {
	__be64 sec;
	__be32 nsec;
} __packed;

/* XXX ipv6 */
struct scoutfs_inet_addr {
	__le32 addr;
	__le16 port;
} __packed;

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
} __packed;

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
	__u8	sk_zone;
	__le64	_sk_first;
	__u8	sk_type;
	__le64	_sk_second;
	__le64	_sk_third;
	__u8	_sk_fourth;
}__packed;

/* inode index */
#define skii_major	_sk_second
#define skii_ino	_sk_third

/* xattr index */
#define skxi_hash	_sk_first
#define skxi_ino	_sk_second
#define skxi_id		_sk_third

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

/* packed extents */
#define skpe_ino	_sk_first
#define skpe_base	_sk_second
#define skpe_part	_sk_fourth

struct scoutfs_radix_block {
	struct scoutfs_block_header hdr;
	__le32 sm_first;
	__le32 lg_first;
	union {
		struct scoutfs_radix_ref {
			__le64 blkno;
			__le64 seq;
			__le64 sm_total;
			__le64 lg_total;
		} __packed refs[0];
		__le64 bits[0];
	} __packed;
} __packed;

struct scoutfs_radix_root {
	__u8 height;
	__le64 next_find_bit;
	struct scoutfs_radix_ref ref;
} __packed;

#define SCOUTFS_RADIX_REFS \
	((SCOUTFS_BLOCK_SIZE - offsetof(struct scoutfs_radix_block, refs[0])) /\
		sizeof(struct scoutfs_radix_ref))

/* 8 meg regions with 4k data blocks */
#define SCOUTFS_RADIX_LG_SHIFT	11
#define SCOUTFS_RADIX_LG_BITS	(1 << SCOUTFS_RADIX_LG_SHIFT)
#define SCOUTFS_RADIX_LG_MASK	(SCOUTFS_RADIX_LG_BITS - 1)

/* round block bits down to a multiple of large ranges */
#define SCOUTFS_RADIX_BITS					\
	(((SCOUTFS_BLOCK_SIZE -					\
	   offsetof(struct scoutfs_radix_block, bits[0])) * 8) &	\
	 ~(__u64)SCOUTFS_RADIX_LG_MASK)
#define SCOUTFS_RADIX_BITS_BYTES (SCOUTFS_RADIX_BITS / 8)

/*
 * The btree still uses memcmp() to compare keys.  We should fix that
 * before too long.
 */
struct scoutfs_key_be {
	__u8	sk_zone;
	__be64	_sk_first;
	__u8	sk_type;
	__be64	_sk_second;
	__be64	_sk_third;
	__u8	_sk_fourth;
}__packed;

/* chose reasonable max key lens that have room for some u64s */
#define SCOUTFS_BTREE_MAX_KEY_LEN 40
/* when we split we want to have multiple items on each side */
#define SCOUTFS_BTREE_MAX_VAL_LEN (SCOUTFS_BLOCK_SIZE / 8)

/*
 * The min number of free bytes we must leave in a parent as we descend
 * to modify.  This leaves enough free bytes to insert a possibly maximal
 * sized key as a seperator for a child block.  Fewer bytes then this
 * and split/merge might try to insert a max child item in the parent
 * that wouldn't fit.
 */
#define SCOUTFS_BTREE_PARENT_MIN_FREE_BYTES				\
	(sizeof(struct scoutfs_btree_item_header) +			\
	 sizeof(struct scoutfs_btree_item) + SCOUTFS_BTREE_MAX_KEY_LEN +\
	 sizeof(struct scoutfs_btree_ref))

/*
 * When debugging we can tune the splitting and merging thresholds to
 * create much larger trees by having blocks with many fewer items.  We
 * implement this by pretending the blocks are tiny.  They're still
 * large enough for a handful of items.
 */
#define SCOUTFS_BTREE_TINY_BLOCK_SIZE	512

/*
 * A 4EB test image measured a worst case height of 17.  This is plenty
 * generous.
 */
#define SCOUTFS_BTREE_MAX_HEIGHT 20

struct scoutfs_btree_ref {
	__le64 blkno;
	__le64 seq;
} __packed;

/*
 * A height of X means that the first block read will have level X-1 and
 * the leaves will have level 0.
 */
struct scoutfs_btree_root {
	struct scoutfs_btree_ref ref;
	__u8 height;
} __packed;

struct scoutfs_btree_item_header {
	__le32 off;
} __packed;

struct scoutfs_btree_item {
	__le16 key_len;
	__le16 val_len;
	__u8 data[0];
} __packed;

struct scoutfs_btree_block {
	struct scoutfs_block_header hdr;
	__le32 free_end;
	__le32 nr_items;
	__u8 level;
	struct scoutfs_btree_item_header item_hdrs[0];
} __packed;

/*
 * The lock server keeps a persistent record of connected clients so that
 * server failover knows who to wait for before resuming operations.
 */
struct scoutfs_lock_client_btree_key {
	__be64 rid;
} __packed;

/*
 * The server tracks transaction sequence numbers that clients have
 * open.  This limits results that can be returned from the seq indices.
 */
struct scoutfs_trans_seq_btree_key {
	__be64 trans_seq;
	__be64 rid;
} __packed;

/*
 * The server keeps a persistent record of mounted clients.
 */
struct scoutfs_mounted_client_btree_key {
	__be64 rid;
} __packed;

struct scoutfs_mounted_client_btree_val {
	__u8 flags;
} __packed;

#define SCOUTFS_MOUNTED_CLIENT_VOTER	(1 << 0)

/*
 * XXX I imagine we should rename these now that they've evolved to track
 * all the btrees that clients use during a transaction.  It's not just
 * about item logs, it's about clients making changes to trees.
 */
struct scoutfs_log_trees {
	struct scoutfs_radix_root meta_avail;
	struct scoutfs_radix_root meta_freed;
	struct scoutfs_btree_root item_root;
	struct scoutfs_btree_ref bloom_ref;
	struct scoutfs_radix_root data_avail;
	struct scoutfs_radix_root data_freed;
	__le64 rid;
	__le64 nr;
} __packed;

struct scoutfs_log_trees_key {
	__be64 rid;
	__be64 nr;
} __packed;

struct scoutfs_log_trees_val {
	struct scoutfs_radix_root meta_avail;
	struct scoutfs_radix_root meta_freed;
	struct scoutfs_btree_root item_root;
	struct scoutfs_btree_ref bloom_ref;
	struct scoutfs_radix_root data_avail;
	struct scoutfs_radix_root data_freed;
} __packed;

struct scoutfs_log_item_value {
	__le64 vers;
	__u8 flags;
	__u8 data[0];
} __packed;

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
} __packed;

/*
 * Item log trees are accompanied by a block of bits that make up a
 * bloom filter which indicate if the item log trees may contain items
 * covered by a lock.  The log trees should be finalized and merged long
 * before the bloom filters fill up and start returning excessive false
 * positives.
 */
#define SCOUTFS_FOREST_BLOOM_NRS		7
#define SCOUTFS_FOREST_BLOOM_BITS \
	(((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_bloom_block)) /	\
	 member_sizeof(struct scoutfs_bloom_block, bits[0])) *		\
	 member_sizeof(struct scoutfs_bloom_block, bits[0]) * 8)	\

/*
 * Keys are first sorted by major key zones.
 */
#define SCOUTFS_INODE_INDEX_ZONE		1
#define SCOUTFS_XATTR_INDEX_ZONE		2
#define SCOUTFS_RID_ZONE			3
#define SCOUTFS_FS_ZONE				4
#define SCOUTFS_LOCK_ZONE			5
#define SCOUTFS_MAX_ZONE			8 /* power of 2 is efficient */

/* inode index zone */
#define SCOUTFS_INODE_INDEX_META_SEQ_TYPE	1
#define SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE	2
#define SCOUTFS_INODE_INDEX_NR			3 /* don't forget to update */

/* xattr index zone */
#define SCOUTFS_XATTR_INDEX_NAME_TYPE		1

/* rid zone (also used in server alloc btree) */
#define SCOUTFS_ORPHAN_TYPE			1

/* fs zone */
#define SCOUTFS_INODE_TYPE			1
#define SCOUTFS_XATTR_TYPE			2
#define SCOUTFS_DIRENT_TYPE			3
#define SCOUTFS_READDIR_TYPE			4
#define SCOUTFS_LINK_BACKREF_TYPE		5
#define SCOUTFS_SYMLINK_TYPE			6
#define SCOUTFS_PACKED_EXTENT_TYPE		7

/* lock zone, only ever found in lock ranges, never in persistent items */
#define SCOUTFS_RENAME_TYPE			1

#define SCOUTFS_MAX_TYPE			8 /* power of 2 is efficient */


/*
 * The extents that map blocks in a fixed-size logical region of a file
 * are packed and stored in item values.  The packed extents are
 * contiguous so the starting logical block is implicit from the length
 * of previous extents.  Sparse regions are represented by 0 flags and
 * blkno.  The blkno of a packed extent is encoded as the zigzag (lsb is
 * sign bit) difference from the last blkno of the previous extent.
 * This guarantees that non-sparse extents must have a blkno delta of at
 * least -1/1.  High zero byte aren't stored.
 */
struct scoutfs_packed_extent {
	__le16 count;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 diff_bytes:4,
	     flags:3,
	     final:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 final:1,
	     flags:3,
	     diff_bytes:4;
#else
#error "no {BIG,LITTLE}_ENDIAN_BITFIELD defined?"
#endif
	__u8 le_blkno_diff[0];
} __packed;

#define SCOUTFS_PACKEXT_BLOCKS		(8 * 1024 * 1024 / SCOUTFS_BLOCK_SIZE)
#define SCOUTFS_PACKEXT_BASE_SHIFT	(ilog2(SCOUTFS_PACKEXT_BLOCKS))
#define SCOUTFS_PACKEXT_BASE_MASK	(~((__u64)SCOUTFS_PACKEXT_BLOCKS - 1))
#define SCOUTFS_PACKEXT_MAX_BYTES	SCOUTFS_MAX_VAL_SIZE

#define SEF_OFFLINE	(1 << 0)
#define SEF_UNWRITTEN	(1 << 1)
#define SEF_UNKNOWN	(U8_MAX << 2)

/*
 * The first xattr part item has a header that describes the xattr.  The
 * name and value are then packed into the following bytes in the first
 * part item and overflow into the values of the rest of the part items.
 */
struct scoutfs_xattr {
	__u8 name_len;
	__le16 val_len;
	__u8 name[0];
} __packed;


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
	struct scoutfs_quorum_log {
		__le64 term;
		__le64 rid;
		struct scoutfs_inet_addr addr;
	} __packed log[0];
} __packed;

#define SCOUTFS_QUORUM_LOG_MAX						\
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_quorum_block)) /	\
		sizeof(struct scoutfs_quorum_log))

struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__le64 format_hash;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 next_ino;
	__le64 next_trans_seq;
	__le64 total_meta_blocks;	/* both static and dynamic */
	__le64 first_meta_blkno;	/* first dynamically allocated */
	__le64 last_meta_blkno;
	__le64 free_meta_blocks;
	__le64 total_data_blocks;
	__le64 first_data_blkno;
	__le64 last_data_blkno;
	__le64 free_data_blocks;
	__le64 quorum_fenced_term;
	__le64 quorum_server_term;
	__le64 unmount_barrier;
	__u8 quorum_count;
	struct scoutfs_inet_addr server_addr;
	struct scoutfs_radix_root core_meta_avail;
	struct scoutfs_radix_root core_meta_freed;
	struct scoutfs_radix_root core_data_avail;
	struct scoutfs_radix_root core_data_freed;
	struct scoutfs_btree_root fs_root;
	struct scoutfs_btree_root logs_root;
	struct scoutfs_btree_root lock_clients;
	struct scoutfs_btree_root trans_seqs;
	struct scoutfs_btree_root mounted_clients;
} __packed;

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
} __packed;

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
	__u8 name[0];
} __packed;

#define SCOUTFS_NAME_LEN 255

/* S32_MAX avoids the (int) sign bit and might avoid sloppy bugs */
#define SCOUTFS_LINK_MAX S32_MAX

/* entries begin after . and .. */
#define SCOUTFS_DIRENT_FIRST_POS 2
/* getdents returns next pos with an entry, no entry at (f_pos)~0 */
#define SCOUTFS_DIRENT_LAST_POS (U64_MAX - 1)

enum {
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
} __packed;

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
	__u8 data[0];
} __packed;

#define SCOUTFS_NET_FLAG_RESPONSE	(1 << 0)
#define SCOUTFS_NET_FLAGS_UNKNOWN	(U8_MAX << 1)

enum {
	SCOUTFS_NET_CMD_GREETING = 0,
	SCOUTFS_NET_CMD_ALLOC_INODES,
	SCOUTFS_NET_CMD_GET_LOG_TREES,
	SCOUTFS_NET_CMD_COMMIT_LOG_TREES,
	SCOUTFS_NET_CMD_ADVANCE_SEQ,
	SCOUTFS_NET_CMD_GET_LAST_SEQ,
	SCOUTFS_NET_CMD_STATFS,
	SCOUTFS_NET_CMD_LOCK,
	SCOUTFS_NET_CMD_LOCK_RECOVER,
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
enum {
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
} __packed;

struct scoutfs_net_statfs {
	__le64 total_blocks;		/* total blocks in device */
	__le64 next_ino;		/* next unused inode number */
	__le64 bfree;			/* free blocks */
	__u8 uuid[SCOUTFS_UUID_BYTES];	/* logical volume uuid */
} __packed;

struct scoutfs_net_lock {
	struct scoutfs_key key;
	__le64 write_version;
	__u8 old_mode;
	__u8 new_mode;
} __packed;

struct scoutfs_net_lock_recover {
	__le16 nr;
	struct scoutfs_net_lock locks[0];
} __packed;

#define SCOUTFS_NET_LOCK_MAX_RECOVER_NR					       \
	((SCOUTFS_NET_MAX_DATA_LEN - sizeof(struct scoutfs_net_lock_recover)) /\
	 sizeof(struct scoutfs_net_lock))

/* some enums for tracing */
enum {
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
enum {
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
} __packed;

#define FILEID_SCOUTFS			0x81
#define FILEID_SCOUTFS_WITH_PARENT	0x82

/*
 * Identifiers for sources of corruption that can generate messages.
 */
enum {
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
