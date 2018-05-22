#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

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
 * The super blocks leave some room at the start of the first block for
 * platform structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64 * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_SUPER_NR 2

/*
 * This header is found at the start of every block so that we can
 * verify that it's what we were looking for.  The crc and padding
 * starts the block so that its calculation operations on a nice 64bit
 * aligned region.
 */
struct scoutfs_block_header {
	__le32 crc;
	__le32 _pad;
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
	__le64 fsid;
	__le64 blkno;
	__le64 seq;
	__le32 crc;
	__le32 _pad;
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
#define SCOUTFS_MAX_ZONE			4 /* power of 2 is efficient */

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

struct scoutfs_betimespec {
	__be64 sec;
	__be32 nsec;
} __packed;

/* XXX does this exist upstream somewhere? */
#define member_sizeof(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))

#define SCOUTFS_UUID_BYTES 16

/* XXX ipv6 */
struct scoutfs_inet_addr {
	__le32 addr;
	__le16 port;
} __packed;

#define SCOUTFS_DEFAULT_PORT 12345

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
	struct scoutfs_btree_root alloc_root;
	struct scoutfs_manifest manifest;
	struct scoutfs_inet_addr server_addr;
} __packed;

#define SCOUTFS_ROOT_INO 1

struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
} __packed;

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

/*
 * structures used by dlm
 */
#define SCOUTFS_LOCK_SCOPE_GLOBAL 1
#define SCOUTFS_LOCK_SCOPE_FS_ITEMS 2

#define SCOUTFS_LOCK_TYPE_GLOBAL_RENAME 1
#define SCOUTFS_LOCK_TYPE_GLOBAL_SERVER 2

struct scoutfs_lock_name {
	__u8 scope;
	__u8 zone;
	__u8 type;
	__le64 first;
	__le64 second;
} __packed;

#define SCOUTFS_LOCK_INODE_GROUP_NR	1024
#define SCOUTFS_LOCK_INODE_GROUP_MASK	(SCOUTFS_LOCK_INODE_GROUP_NR - 1)

#define SCOUTFS_LOCK_SEQ_GROUP_MASK	((1ULL << 10) - 1)

/*
 * messages over the wire.
 */

struct scoutfs_net_greeting {
	__le64 fsid;
	__le64 format_hash;
} __packed;

/*
 * This header precedes and describes all network messages sent over
 * sockets.  The id is set by the request and sent in the reply.  The
 * type is strictly redundant in the reply because the id will find the
 * send but we include it in both packets to make it easier to observe
 * replies without having the id from their previous request.
 */
struct scoutfs_net_header {
	__le64 id;
	__le16 data_len;
	__u8 type;
	__u8 status;
	__u8 data[0];
} __packed;

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
	__u8 keys[0];
} __packed;

struct scoutfs_net_statfs {
	__le64 total_blocks;		/* total blocks in device */
	__le64 next_ino;		/* next unused inode number */
	__le64 bfree;			/* free blocks */
	__u8 uuid[SCOUTFS_UUID_BYTES];	/* logical volume uuid */
} __packed;

/* XXX eventually we'll have net compaction and will need agents to agree */

/* one upper segment and fanout lower segments */
#define SCOUTFS_COMPACTION_MAX_INPUT	(1 + SCOUTFS_MANIFEST_FANOUT)
/* sticky can add one, and so can item page alignment */
#define SCOUTFS_COMPACTION_SLOP		2
/* delete all inputs and insert all outputs (same goes for alloc|free segnos) */
#define SCOUTFS_COMPACTION_MAX_UPDATE \
	(2 * (SCOUTFS_COMPACTION_MAX_INPUT + SCOUTFS_COMPACTION_SLOP))

enum {
	SCOUTFS_NET_ALLOC_INODES = 0,
	SCOUTFS_NET_ALLOC_EXTENT,
	SCOUTFS_NET_ALLOC_SEGNO,
	SCOUTFS_NET_RECORD_SEGMENT,
	SCOUTFS_NET_ADVANCE_SEQ,
	SCOUTFS_NET_GET_LAST_SEQ,
	SCOUTFS_NET_GET_MANIFEST_ROOT,
	SCOUTFS_NET_STATFS,
	SCOUTFS_NET_UNKNOWN,
};

enum {
	SCOUTFS_NET_STATUS_REQUEST = 0,
	SCOUTFS_NET_STATUS_SUCCESS,
	SCOUTFS_NET_STATUS_ERROR,
	SCOUTFS_NET_STATUS_UNKNOWN,
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
	SC_NR_SOURCES,
};

#define SC_NR_LONGS DIV_ROUND_UP(SC_NR_SOURCES, BITS_PER_LONG)

#endif
