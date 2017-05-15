#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

/*
 * The super block and ring blocks are fixed 4k.
 */
#define SCOUTFS_BLOCK_SHIFT 12
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_BLOCK_MASK (SCOUTFS_BLOCK_SIZE - 1)
#define SCOUTFS_BLOCKS_PER_PAGE (PAGE_SIZE / SCOUTFS_BLOCK_SIZE)

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

struct scoutfs_ring_entry {
	__le16 data_len;
	__u8 flags;
	__u8 data[0];
} __packed;

#define SCOUTFS_RING_ENTRY_FLAG_DELETION (1 << 0)

struct scoutfs_ring_block {
	__le32 crc;
	__le32 pad;
	__le64 fsid;
	__le64 seq;
	__le64 block;
	__le32 nr_entries;
	struct scoutfs_ring_entry entries[0];
} __packed;

struct scoutfs_ring_descriptor {
	__le64 blkno;
	__le64 total_blocks;
	__le64 first_block;
	__le64 first_seq;
	__le64 nr_blocks;
} __packed;

/*
 * This is absurdly huge.  If there was only ever 1 item per segment and
 * 2^64 items the tree could get this deep.
 */
#define SCOUTFS_MANIFEST_MAX_LEVEL 20

#define SCOUTFS_MANIFEST_FANOUT 10

struct scoutfs_manifest {
	struct scoutfs_ring_descriptor ring;
	__le64 level_counts[SCOUTFS_MANIFEST_MAX_LEVEL];
} __packed;

struct scoutfs_manifest_entry {
	__le64 segno;
	__le64 seq;
	__le16 first_key_len;
	__le16 last_key_len;
	__u8 level;
	__u8 keys[0];
} __packed;

#define SCOUTFS_ALLOC_REGION_SHIFT 8
#define SCOUTFS_ALLOC_REGION_BITS (1 << SCOUTFS_ALLOC_REGION_SHIFT)
#define SCOUTFS_ALLOC_REGION_MASK (SCOUTFS_ALLOC_REGION_BITS - 1)

/*
 * The bits need to be aligned so that the host can use native long
 * bitops on the bits in memory.
 */
struct scoutfs_alloc_region {
	__le64 index;
	__le64 bits[SCOUTFS_ALLOC_REGION_BITS / 64];
} __packed;

/*
 * We really want these to be a power of two size so that they're naturally
 * aligned.  This ensures that they won't cross page boundaries and we
 * can use pointers to them in the page vecs that make up segments without
 * funny business.
 */
struct scoutfs_segment_item {
	__le64 seq;
	__le32 key_off;
	__le32 val_off;
	__le16 key_len;
	__le16 val_len;
	__u8 padding[11];
	__u8 flags;
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
	__le32 nr_items;
	__le32 _moar_pads;
	struct scoutfs_segment_item items[0];
	/* packed keys */
	/* packed vals */
} __packed;

/*
 * Currently we sort keys by the numeric value of the types, but that
 * isn't necessary.  We could have an arbitrary sort order.  So we don't
 * have to stress about cleverly allocating the types.
 */
#define SCOUTFS_INODE_KEY		1
#define SCOUTFS_XATTR_KEY		3
#define SCOUTFS_DIRENT_KEY		5
#define SCOUTFS_READDIR_KEY		6
#define SCOUTFS_LINK_BACKREF_KEY	7
#define SCOUTFS_SYMLINK_KEY		8
#define SCOUTFS_FILE_EXTENT_KEY		9
#define SCOUTFS_ORPHAN_KEY		10
#define SCOUTFS_FREE_EXTENT_BLKNO_KEY	11
#define SCOUTFS_FREE_EXTENT_BLOCKS_KEY	12
#define SCOUTFS_INODE_INDEX_CTIME_KEY	13
#define SCOUTFS_INODE_INDEX_MTIME_KEY	14
#define SCOUTFS_INODE_INDEX_SIZE_KEY	15
/* not found in the fs */
#define SCOUTFS_MAX_UNUSED_KEY		253
#define SCOUTFS_NET_ADDR_KEY		254
#define SCOUTFS_NET_LISTEN_KEY		255

/* value is struct scoutfs_inode */
struct scoutfs_inode_key {
	__u8 type;
	__be64 ino;
} __packed;

/* value is struct scoutfs_dirent without the name */
struct scoutfs_dirent_key {
	__u8 type;
	__be64 ino;
	__u8 name[0];
} __packed;

/* value is struct scoutfs_dirent with the name */
struct scoutfs_readdir_key {
	__u8 type;
	__be64 ino;
	__be64 pos;
} __packed;

/* value is empty */
struct scoutfs_link_backref_key {
	__u8 type;
	__be64 ino;
	__be64 dir_ino;
	__u8 name[0];
} __packed;

/* no value */
struct scoutfs_orphan_key {
	__u8 type;
	__be64 ino;
} __packed;

/* no value */
struct scoutfs_file_extent_key {
	__u8 type;
	__be64 ino;
	__be64 last_blk_off;
	__be64 last_blkno;
	__be64 blocks;
	__u8 flags;
} __packed;

#define SCOUTFS_FILE_EXTENT_OFFLINE (1 << 0)

/* no value */
struct scoutfs_free_extent_blkno_key {
	__u8 type;
	__be64 node_id;
	__be64 last_blkno;
	__be64 blocks;
} __packed;

struct scoutfs_free_extent_blocks_key {
	__u8 type;
	__be64 node_id;
	__be64 blocks;
	__be64 last_blkno;
} __packed;

/* value is each item's part of the full xattr value for the off/len */
struct scoutfs_xattr_key {
	__u8 type;
	__be64 ino;
	__u8 name[0];
} __packed;

struct scoutfs_xattr_key_footer {
	__u8 null;
	__u8 part;
} __packed;

struct scoutfs_xattr_val_header {
	__le16 part_len;
	__u8 last_part;
} __packed;

/* value is the null terminated target path */
struct scoutfs_symlink_key {
	__u8 type;
	__be64 ino;
} __packed;

struct scoutfs_betimespec {
	__be64 sec;
	__be32 nsec;
} __packed;

struct scoutfs_inode_index_key {
	__u8 type;
	__be64 major;
	__be32 minor;
	__be64 ino;
} __packed;

/* XXX does this exist upstream somewhere? */
#define member_sizeof(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))

#define SCOUTFS_UUID_BYTES 16


/*
 * The ring fields describe the statically allocated ring log.  The
 * head and tail indexes are logical 4k blocks offsets inside the ring.
 * The head block should contain the seq.
 */
struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 next_ino;
	__le64 alloc_uninit;
	__le64 total_segs;
	__le64 free_segs;
	__le64 ring_blkno;
	__le64 ring_blocks;
	__le64 ring_tail_block;
	__le64 ring_gen;
	__le64 next_seg_seq;
	struct scoutfs_ring_descriptor alloc_ring;
	struct scoutfs_manifest manifest;
} __packed;

#define SCOUTFS_ROOT_INO 1

struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
} __packed;

/*
 * @data_version: incremented every time the contents of a file could
 * have changed.  It is exposed via an ioctl and is then provided as an
 * argument to data functions to protect racing modification.
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
	__le64 blocks;
	__le64 data_version;
	__le64 next_readdir_pos;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le32 rdev;
	struct scoutfs_timespec atime;
	struct scoutfs_timespec ctime;
	struct scoutfs_timespec mtime;
} __packed;

#define SCOUTFS_ROOT_INO 1

/* like the block size, a reasonable min PATH_MAX across platforms */
#define SCOUTFS_SYMLINK_MAX_SIZE 4096

/*
 * Dirents are stored in items with an offset of the hash of their name.
 * Colliding names are packed into the value.
 */
struct scoutfs_dirent {
	__le64 ino;
	__le64 counter;
	__le64 readdir_pos;
	__u8 type;
	__u8 name[0];
} __packed;

#define SCOUTFS_NAME_LEN 255

/* S32_MAX avoids the (int) sign bit and might avoid sloppy bugs */
#define SCOUTFS_LINK_MAX S32_MAX

#define SCOUTFS_XATTR_MAX_NAME_LEN 255
#define SCOUTFS_XATTR_MAX_SIZE 65536
#define SCOUTFS_XATTR_PART_SIZE \
	(SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_xattr_val_header))
#define SCOUTFS_XATTR_MAX_PARTS \
	DIV_ROUND_UP(SCOUTFS_XATTR_MAX_SIZE, SCOUTFS_XATTR_PART_SIZE)

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

/* ino_path can search for backref items with a null term */
#define SCOUTFS_MAX_KEY_SIZE \
	offsetof(struct scoutfs_link_backref_key, name[SCOUTFS_NAME_LEN + 1])

/*
 * messages over the wire.
 */

/* XXX ipv6 */
struct scoutfs_inet_addr {
	__le32 addr;
	__le16 port;
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

struct scoutfs_net_manifest_entries {
	__le16 nr;
	struct scoutfs_manifest_entry ments[0];
} __packed;

struct scoutfs_net_segnos {
	__le16 nr;
	__le64 segnos[0];
} __packed;

enum {
	/* sends and receives a struct scoutfs_timeval */
	SCOUTFS_NET_TRADE_TIME = 0,
	SCOUTFS_NET_ALLOC_INODES,
	SCOUTFS_NET_MANIFEST_RANGE_ENTRIES,
	SCOUTFS_NET_ALLOC_SEGNO,
	SCOUTFS_NET_RECORD_SEGMENT,
	SCOUTFS_NET_BULK_ALLOC,
	SCOUTFS_NET_UNKNOWN,
};

enum {
	SCOUTFS_NET_STATUS_REQUEST = 0,
	SCOUTFS_NET_STATUS_SUCCESS,
	SCOUTFS_NET_STATUS_ERROR,
	SCOUTFS_NET_STATUS_UNKNOWN,
};

#endif
