#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

/*
 * Some fs structures are stored in smaller fixed size 4k bricks.
 */
#define SCOUTFS_BRICK_SHIFT 12
#define SCOUTFS_BRICK_SIZE (1 << SCOUTFS_BRICK_SHIFT)

/*
 * A large block size reduces the amount of per-block overhead throughout
 * the system: block IO, manifest communications and storage, etc. 
 */
#define SCOUTFS_BLOCK_SHIFT 22
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)

/* for shifting between brick and block numbers */
#define SCOUTFS_BLOCK_BRICK (SCOUTFS_BLOCK_SHIFT - SCOUTFS_BRICK_SHIFT)

/*
 * The super bricks leave a bunch of room at the start of the first
 * block for platform structures like boot loaders.
 */
#define SCOUTFS_SUPER_BRICK 16

/*
 * This header is found at the start of every brick and block
 * so that we can verify that it's what we were looking for.
 */
struct scoutfs_header {
	__le32 crc;
	__le64 fsid;
	__le64 seq;
	__le64 nr;
} __packed;

#define SCOUTFS_UUID_BYTES 16

/*
 * The super is stored in a pair of bricks in the first block.
 */
struct scoutfs_super {
	struct scoutfs_header hdr;
	__le64 id;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 total_blocks;
	__le64 ring_layout_block;
	__le64 ring_layout_seq;
	__le64 last_ring_brick;
	__le64 last_ring_seq;
	__le64 last_block_seq;
} __packed;

/*
 * We should be able to make the offset smaller if neither dirents nor
 * data items use the full 64 bits.
 */
struct scoutfs_key {
	__le64 inode;
	u8 type;
	__le64 offset;
} __packed;

#define SCOUTFS_ROOT_INO 1

#define SCOUTFS_INODE_KEY 128
#define SCOUTFS_DIRENT_KEY 192

struct scoutfs_ring_layout {
	struct scoutfs_header hdr;
	__le32 nr_blocks;
	__le64 blocks[0];
} __packed;

struct scoutfs_ring_entry {
	u8 type;
	__le16 len;
} __packed;

/*
 * Ring blocks are 4k blocks stored inside the large ring blocks
 * referenced by the ring descriptor block.
 *
 * The manifest entries describe the position of a given block in the
 * manifest.  They're keyed by the block number so that we can log
 * movement of a block in the manifest with one log entry and we can log
 * deletion with just the block number.
 */ 
struct scoutfs_ring_brick {
	struct scoutfs_header hdr;
	__le16 nr_entries;
} __packed;

enum {
	SCOUTFS_RING_REMOVE_MANIFEST = 0,
	SCOUTFS_RING_ADD_MANIFEST,
	SCOUTFS_RING_BITMAP,
};

/*
 * Manifest entries are logged by their block number.  This lets us log
 * a change with one entry and a removal with a tiny block number
 * without the key.
 */
struct scoutfs_ring_remove_manifest {
	__le64 block;
} __packed;

/*
 * Including both keys might make the manifest too large.  It might be
 * better to only include one key and infer a block's range from the
 * neighbour's key.  The downside of that is that we assume that there
 * isn't unused key space between blocks in a level.  We might search
 * blocks when we didn't need to.
 */
struct scoutfs_ring_add_manifest {
	__le64 block;
	__le64 seq;
	__u8 level;
	struct scoutfs_key first;
	struct scoutfs_key last;
} __packed;

struct scoutfs_ring_bitmap {
	__le32 offset;
	__le64 bits[2];
} __packed;

/*
 * This bloom size is chosen to have a roughly 1% false positive rate
 * for ~90k items which is roughly the worst case for a block full of
 * dirents with reasonably small names.  Pathologically smaller items
 * could be even more dense.
 */
#define SCOUTFS_BLOOM_FILTER_BYTES (128 * 1024)
#define SCOUTFS_BLOOM_FILTER_BITS (SCOUTFS_BLOOM_FILTER_BYTES * 8)
#define SCOUTFS_BLOOM_INDEX_BITS (ilog2(SCOUTFS_BLOOM_FILTER_BITS))
#define SCOUTFS_BLOOM_INDEX_MASK ((1 << SCOUTFS_BLOOM_INDEX_BITS) - 1)
#define SCOUTFS_BLOOM_INDEX_NR 7

struct scoutfs_lsm_block {
	struct scoutfs_header hdr;
	struct scoutfs_key first;
	struct scoutfs_key last;
	__le32 nr_items;
	/* u8 bloom[SCOUTFS_BLOOM_BYTES]; */
	/* struct scoutfs_item_header items[0] .. */
} __packed;

struct scoutfs_item_header {
	struct scoutfs_key key;
	__le16 len;
} __packed;

struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
} __packed;

/*
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
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le32 rdev;
	__le32 salt;
	struct scoutfs_timespec atime;
	struct scoutfs_timespec ctime;
	struct scoutfs_timespec mtime;
} __packed;

#define SCOUTFS_ROOT_INO 1

/*
 * Dirents are stored in items with an offset of the hash of their name.
 * Colliding names are packed into the value.
 */
struct scoutfs_dirent {
	__le64 ino;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 type:4,
	     coll_nr:4;
#else
	__u8 coll_nr:4,
	     type:4;
#endif
	__u8 name_len;
	__u8 name[0];
} __packed;

#define SCOUTFS_NAME_LEN 255

/*
 * We only use 31 bits for readdir positions so that we don't confuse
 * old signed 32bit f_pos applications or those on the other side of
 * network protocols that have limited readir positions.
 */

#define SCOUTFS_DIRENT_OFF_BITS 27
#define SCOUTFS_DIRENT_OFF_MASK ((1 << SCOUTFS_DIRENT_OFF_BITS) - 1)
#define SCOUTFS_DIRENT_COLL_BITS 4
#define SCOUTFS_DIRENT_COLL_MASK ((1 << SCOUTFS_DIRENT_COLL_BITS) - 1)

/* getdents returns the *next* pos with each entry. so we can't return ~0 */
#define SCOUTFS_DIRENT_MAX_POS \
	(((1 << (SCOUTFS_DIRENT_OFF_BITS + SCOUTFS_DIRENT_COLL_BITS)) - 1) - 1)

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

#endif
