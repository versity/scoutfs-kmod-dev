#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */

/* block header magic values, chosen at random */
#define SCOUTFS_BLOCK_MAGIC_SUPER	0x103c428b
#define SCOUTFS_BLOCK_MAGIC_BTREE	0xe597f96d

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

/*
 * FS data is stored in segments, for now they're fixed size. They'll
 * be dynamic.
 */
#define SCOUTFS_SEGMENT_SHIFT 20
#define SCOUTFS_SEGMENT_SIZE (1 << SCOUTFS_SEGMENT_SHIFT)
#define SCOUTFS_SEGMENT_MASK (SCOUTFS_SEGMENT_SIZE - 1)
#define SCOUTFS_SEGMENT_PAGES (SCOUTFS_SEGMENT_SIZE / PAGE_SIZE)
#define SCOUTFS_SEGMENT_BLOCKS (SCOUTFS_SEGMENT_SIZE / SCOUTFS_BLOCK_SIZE)
#define SCOUTFS_SEGMENT_BLOCK_SHIFT \
		(SCOUTFS_SEGMENT_SHIFT - SCOUTFS_BLOCK_SHIFT)

#define SCOUTFS_PAGES_PER_BLOCK (SCOUTFS_BLOCK_SIZE / PAGE_SIZE)
#define SCOUTFS_BLOCK_PAGE_ORDER (SCOUTFS_BLOCK_SHIFT - PAGE_SHIFT)

/*
 * The super block leaves some room before the first block for platform
 * structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)

/*
 * A reasonably large region of aligned quorum blocks follow the super
 * block.
 */
#define SCOUTFS_QUORUM_BLKNO		((128ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_QUORUM_BLOCKS		((128ULL * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_QUORUM_MAX_SLOTS	SCOUTFS_QUORUM_BLOCKS

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

/* node free extent */
#define sknf_node_id	_sk_first
#define sknf_major	_sk_second
#define sknf_minor	_sk_third

/* node orphan inode */
#define sko_node_id	_sk_first
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

/* file extent */
#define skfe_ino	_sk_first
#define skfe_last	_sk_second

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

/* chose reasonable max key and value lens that have room for some u64s */
#define SCOUTFS_BTREE_MAX_KEY_LEN 40
#define SCOUTFS_BTREE_MAX_VAL_LEN 64

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
 *
 * The migration key is used to walk the tree finding old blocks to migrate
 * into the current half of the ring.
 */
struct scoutfs_btree_root {
	struct scoutfs_btree_ref ref;
	__u8 height;
	__le16 migration_key_len;
	__u8 migration_key[SCOUTFS_BTREE_MAX_KEY_LEN];
} __packed;

struct scoutfs_btree_item_header {
	__le16 off;
} __packed;

struct scoutfs_btree_item {
	__le16 key_len;
	__le16 val_len;
	__u8 data[0];
} __packed;

struct scoutfs_btree_block {
	struct scoutfs_block_header hdr;
	__le16 free_end;
	__le16 free_reclaim;
	__le16 nr_items;
	__u8 level;
	struct scoutfs_btree_item_header item_hdrs[0];
} __packed;

struct scoutfs_btree_ring {
	__le64 first_blkno;
	__le64 nr_blocks;
	__le64 next_block;
	__le64 next_seq;
} __packed;

/*
 * This is absurdly huge.  If there was only ever 1 item per segment and
 * 2^64 items the tree could get this deep.
 */
#define SCOUTFS_MANIFEST_MAX_LEVEL 20

#define SCOUTFS_MANIFEST_FANOUT 10

struct scoutfs_manifest {
	struct scoutfs_btree_root root;
	__le64 level_counts[SCOUTFS_MANIFEST_MAX_LEVEL];
} __packed;

/*
 * Manifest entries are split across btree keys and values.  Putting
 * some entry fields in the value keeps the key smaller and increases
 * the fanout of the btree which keeps the tree smaller and reduces
 * block IO.
 *
 * The key is made up of the level, first key, and seq.  At level 0
 * segments can completely overlap and have identical key ranges but we
 * avoid duplicate btree keys by including the unique seq.
 */
struct scoutfs_manifest_btree_key {
	__u8 level;
	struct scoutfs_key_be first_key;
	__be64 seq;
} __packed;

struct scoutfs_manifest_btree_val {
	__le64 segno;
	struct scoutfs_key last_key;
} __packed;

/*
 * Free extents are stored in the server in an allocation btree.  The
 * type differentiates whether start or length is in stored in the major
 * value and is the primary sort key.  'start' is set to the final block
 * in the extent so that overlaping queries can be done with next
 * instead prev.
 */
struct scoutfs_extent_btree_key {
	__u8 type;
	__be64 major;
	__be64 minor;
} __packed;

/*
 * The lock server keeps a persistent record of connected clients so that
 * server failover knows who to wait for before resuming operations.
 */
struct scoutfs_lock_client_btree_key {
	__be64 node_id;
} __packed;

/*
 * The max number of links defines the max number of entries that we can
 * index in o(log n) and the static list head storage size in the
 * segment block.  We always pay the static storage cost, which is tiny,
 * and we can look at the number of items to know the greatest number of
 * links and skip most of the initial 0 links.
 */
#define SCOUTFS_MAX_SKIP_LINKS 32

/*
 * Items are packed into segments and linked together in a skip list.
 * Each item's header, links, key, and value are stored contiguously.
 * They're not allowed to cross a block boundary.
 */
struct scoutfs_segment_item {
	struct scoutfs_key key;
	__le16 val_len;
	__u8 flags;
	__u8 nr_links;
	__le32 skip_links[0];
	/* __u8 val_bytes[val_len] */
} __packed;

#define SCOUTFS_ITEM_FLAG_DELETION (1 << 0)

/*
 * Each large segment starts with a segment block that describes the
 * rest of the blocks that make up the segment.
 *
 * The crc covers the initial total_bytes of the segment but starts
 * after the padding.
 */
struct scoutfs_segment_block {
	__le32 crc;
	__le32 _padding;
	__le64 segno;
	__le64 seq;
	__le32 last_item_off;
	__le32 total_bytes;
	__le32 nr_items;
	__le32 skip_links[SCOUTFS_MAX_SKIP_LINKS];
	/* packed items */
} __packed;

/*
 * Keys are first sorted by major key zones.
 */
#define SCOUTFS_INODE_INDEX_ZONE		1
#define SCOUTFS_NODE_ZONE			2
#define SCOUTFS_FS_ZONE				3
#define SCOUTFS_LOCK_ZONE			4
#define SCOUTFS_MAX_ZONE			8 /* power of 2 is efficient */

/* inode index zone */
#define SCOUTFS_INODE_INDEX_META_SEQ_TYPE	1
#define SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE	2
#define SCOUTFS_INODE_INDEX_NR			3 /* don't forget to update */

/* node zone (also used in server alloc btree) */
#define SCOUTFS_FREE_EXTENT_BLKNO_TYPE		1
#define SCOUTFS_FREE_EXTENT_BLOCKS_TYPE		2

/* fs zone */
#define SCOUTFS_INODE_TYPE			1
#define SCOUTFS_XATTR_TYPE			2
#define SCOUTFS_DIRENT_TYPE			3
#define SCOUTFS_READDIR_TYPE			4
#define SCOUTFS_LINK_BACKREF_TYPE		5
#define SCOUTFS_SYMLINK_TYPE			6
#define SCOUTFS_FILE_EXTENT_TYPE		7
#define SCOUTFS_ORPHAN_TYPE			8

/* lock zone, only ever found in lock ranges, never in persistent items */
#define SCOUTFS_RENAME_TYPE			1

#define SCOUTFS_MAX_TYPE			16 /* power of 2 is efficient */

/*
 * File extents have more data than easily fits in the key so we move
 * the non-indexed fields into the value.
 */
struct scoutfs_file_extent {
	__le64 blkno;
	__le64 len;
	__u8 flags;
} __packed;

#define SEF_OFFLINE	0x1
#define SEF_UNWRITTEN	0x2

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
#define SCOUTFS_UNIQUE_NAME_MAX_BYTES	64 /* includes null */

/*
 * During each quorum voting interval the fabric has to process 2 reads
 * and a write for each voting mount.  The only reason we limit the
 * number of active quorum mounts is to limit the number of IOs per
 * interval.  We use a pretty conservative interval given that IOs will
 * generally be faster than our constant and we'll have fewer active
 * than the max.
 */
#define SCOUTFS_QUORUM_MAX_ACTIVE	7
#define SCOUTFS_QUORUM_IO_LATENCY_MS	10
#define SCOUTFS_QUORUM_INTERVAL_MS \
	(SCOUTFS_QUORUM_MAX_ACTIVE * 3 * SCOUTFS_QUORUM_IO_LATENCY_MS)

/*
 * Each mount that is found in the quorum config in the super block can
 * write to quorum blocks indicating which mount they vote for as
 * the leader.
 *
 * @config_gen: references the config gen in the super block
 * @write_nr: incremented for every write, only 0 when never written
 * @elected_nr: incremented when elected, 0 otherwise
 * @vote_slot: the active config slot that the writer is voting for
 */
struct scoutfs_quorum_block {
	__le64 fsid;
	__le64 blkno;
	__le64 config_gen;
	__le64 write_nr;
	__le64 elected_nr;
	__le32 crc;
	__u8 vote_slot;
} __packed;

#define SCOUTFS_QUORUM_MAX_SLOTS	SCOUTFS_QUORUM_BLOCKS

/*
 * Each quorum voter is described by a slot which corresponds to the
 * block that the voter will write to.
 *
 * The stale flag is used to support config migration.  A new
 * configuration is written in free slots and the old configuration is
 * marked stale.  Stale slots can only be reclaimed once we have
 * evidence that the named mount won't try and write to it by seeing it
 * write to other slots or connect with the new gen.
 */
struct scoutfs_quorum_config {
	__le64 gen;
	struct scoutfs_quorum_slot {
		__u8 name[SCOUTFS_UNIQUE_NAME_MAX_BYTES];
		struct scoutfs_inet_addr addr;
		__u8 vote_priority;
		__u8 flags;
	} __packed slots[SCOUTFS_QUORUM_MAX_SLOTS];
} __packed;

#define SCOUTFS_QUORUM_SLOT_ACTIVE		(1 << 0)
#define SCOUTFS_QUORUM_SLOT_STALE		(1 << 1)
#define SCOUTFS_QUORUM_SLOT_FLAGS_UNKNOWN	(U8_MAX << 2)

struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__le64 format_hash;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 next_ino;
	__le64 next_seq;
	__le64 total_blocks;
	__le64 free_blocks;
	__le64 alloc_cursor;
	struct scoutfs_btree_ring bring;
	__le64 next_seg_seq;
	__le64 next_node_id;
	__le64 next_compact_id;
	struct scoutfs_btree_root alloc_root;
	struct scoutfs_manifest manifest;
	struct scoutfs_quorum_config quorum_config;
	struct scoutfs_btree_root lock_clients;
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
#define SCOUTFS_XATTR_MAX_PART_SIZE	512U

#define SCOUTFS_XATTR_NR_PARTS(name_len, val_len)			\
	DIV_ROUND_UP(sizeof(struct scoutfs_xattr) + name_len + val_len, \
		     SCOUTFS_XATTR_MAX_PART_SIZE);

#define SCOUTFS_MAX_VAL_SIZE	SCOUTFS_XATTR_MAX_PART_SIZE

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
 * tries to reconnect.  Used to identify a client reconnecting to a
 * server that has timed out its connection.
 *
 * @node_id: The id of the client.  Initially 0 from the client,
 * assigned by the server, and sent by the client as it reconnects.
 * Used by the server to identify reconnecting clients whose existing
 * state must be dealt with.
 */
struct scoutfs_net_greeting {
	__le64 fsid;
	__le64 format_hash;
	__le64 server_term;
	__le64 node_id;
	__le64 flags;
} __packed;

#define SCOUTFS_NET_GREETING_FLAG_FAREWELL	(1 << 0)
#define SCOUTFS_NET_GREETING_FLAG_INVALID	(~(__u64)0 << 1)

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
	SCOUTFS_NET_CMD_ALLOC_EXTENT,
	SCOUTFS_NET_CMD_FREE_EXTENTS,
	SCOUTFS_NET_CMD_ALLOC_SEGNO,
	SCOUTFS_NET_CMD_RECORD_SEGMENT,
	SCOUTFS_NET_CMD_ADVANCE_SEQ,
	SCOUTFS_NET_CMD_GET_LAST_SEQ,
	SCOUTFS_NET_CMD_GET_MANIFEST_ROOT,
	SCOUTFS_NET_CMD_STATFS,
	SCOUTFS_NET_CMD_COMPACT,
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

struct scoutfs_net_key_range {
	__le16 start_len;
	__le16 end_len;
	__u8 key_bytes[0];
} __packed;

struct scoutfs_net_manifest_entry {
	__le64 segno;
	__le64 seq;
	struct scoutfs_key first;
	struct scoutfs_key last;
	__u8 level;
} __packed;

struct scoutfs_net_statfs {
	__le64 total_blocks;		/* total blocks in device */
	__le64 next_ino;		/* next unused inode number */
	__le64 bfree;			/* free blocks */
	__u8 uuid[SCOUTFS_UUID_BYTES];	/* logical volume uuid */
} __packed;

struct scoutfs_net_extent {
	__le64 start;
	__le64 len;
} __packed;

struct scoutfs_net_extent_list {
	__le64 nr;
	struct {
		__le64 start;
		__le64 len;
	} __packed extents[0];
} __packed;

#define SCOUTFS_NET_EXTENT_LIST_BYTES(nr) \
	offsetof(struct scoutfs_net_extent_list, extents[nr])

/* arbitrarily makes a nice ~1k extent list payload */
#define SCOUTFS_NET_EXTENT_LIST_MAX_NR	64

/* one upper segment and fanout lower segments */
#define SCOUTFS_COMPACTION_MAX_INPUT        (1 + SCOUTFS_MANIFEST_FANOUT)
/* sticky can split the input and item alignment padding can add a lower */
#define SCOUTFS_COMPACTION_SEGNO_OVERHEAD   2
#define SCOUTFS_COMPACTION_MAX_OUTPUT       \
	(SCOUTFS_COMPACTION_MAX_INPUT + SCOUTFS_COMPACTION_SEGNO_OVERHEAD)

/*
 * A compact request is sent by the server to the client.  It provides
 * the input segments and enough allocated segnos to write the results.
 * The id uniquely identifies this compaction request and is included in
 * the response to clean up its allocated resources.
 */
struct scoutfs_net_compact_request {
	__le64 id;
	__u8 last_level;
	__u8 flags;
	__le64 segnos[SCOUTFS_COMPACTION_MAX_OUTPUT];
	struct scoutfs_net_manifest_entry ents[SCOUTFS_COMPACTION_MAX_INPUT];
} __packed;

/*
 * A sticky compaction has more lower level segments that overlap with
 * the end of the upper after the last lower level segment included in
 * the compaction.  Items left in the upper segment after the last lower
 * need to be written to the upper level instead of the lower.  The
 * upper segment "sticks" in place instead of moving down to the lower
 * level.
 */
#define SCOUTFS_NET_COMPACT_FLAG_STICKY (1 << 0)

/*
 * A compact response is sent by the client to the server.  It describes
 * the written output segments that need to be added to the manifest.
 * The server compares the response to the request to free unused
 * allocated segnos and input manifest entries.  An empty response is
 * valid and can happen if, say, the upper input segment completely
 * deleted all the items in a single overlapping lower segment.
 */
struct scoutfs_net_compact_response {
	__le64 id;
	struct scoutfs_net_manifest_entry ents[SCOUTFS_COMPACTION_MAX_OUTPUT];
} __packed;

struct scoutfs_net_lock {
	struct scoutfs_key key;
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
	SC_EXTENT_ADD_CLEANUP,
	SC_EXTENT_REM_CLEANUP,
	SC_DATA_EXTENT_TRUNC_CLEANUP,
	SC_DATA_EXTENT_ALLOC_CLEANUP,
	SC_SERVER_EXTENT_CLEANUP,
	SC_DATA_EXTENT_FALLOCATE_CLEANUP,
	SC_NR_SOURCES,
};

#define SC_NR_LONGS DIV_ROUND_UP(SC_NR_SOURCES, BITS_PER_LONG)

#endif
