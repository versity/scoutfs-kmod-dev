#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

/*
 * Everything is stored in and addressed as 4k fixed size blocks.  This
 * avoids having to manage contiguous cpu mappings of larger blocks.
 * Larger structures are read and written as multiple blocks.
 */
#define SCOUTFS_BLOCK_SHIFT 12
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_BLOCK_MASK (SCOUTFS_BLOCK_SIZE - 1)

/*
 * The allocator works on larger chunks.  Smaller metadata structures
 * like the super blocks and the ring are stored in chunks.
 *
 * A log segment is a collection of smaller blocks (bloom filter, item blocks)
 * stored in a chunk.
 */
#define SCOUTFS_CHUNK_SHIFT 22
#define SCOUTFS_CHUNK_SIZE (1 << SCOUTFS_CHUNK_SHIFT)
#define SCOUTFS_CHUNK_BLOCK_SHIFT (SCOUTFS_CHUNK_SHIFT - SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_CHUNK_BLOCK_MASK ((1 << SCOUTFS_CHUNK_BLOCK_SHIFT) - 1)
#define SCOUTFS_BLOCKS_PER_CHUNK (1 << SCOUTFS_CHUNK_BLOCK_SHIFT)

/*
 * The super blocks leave some room at the start of the first block for
 * platform structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64 * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_SUPER_NR 2

/*
 * The bloom filters are statically sized.  It's a tradeoff between
 * storage overhead and false positive rate.  At the moment we have
 * as few as 1000 and as many as 18000 items in a segment.  We can
 * get a ~1% false positive rate (triggering header search) rate at
 * the high end with a ~20k bloom filter.
 *
 *  n = 18,000, p = 0.01 (1 in 100) → m = 172,532 (21.06KB), k = 7
 */
#define SCOUTFS_BLOOM_BITS 7
#define SCOUTFS_BLOOM_BIT_WIDTH 18 /* 2^18 > m */
#define SCOUTFS_BLOOM_BIT_MASK ((1 << SCOUTFS_BLOOM_BIT_WIDTH) - 1)
#define SCOUTFS_BLOOM_BLOCKS ((20 * 1024) / SCOUTFS_BLOCK_SIZE)
#define SCOUTFS_BLOOM_SALTS \
	DIV_ROUND_UP(SCOUTFS_BLOOM_BITS * SCOUTFS_BLOOM_BIT_WIDTH, 32)

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

#define SCOUTFS_UUID_BYTES 16

/*
 * The super is stored in a pair of blocks in the first chunk on the
 * device.
 *
 * The ring map blocks describe the chunks that make up the ring.
 *
 * The rest of the ring fields describe the state of the ring blocks
 * that are stored in their chunks.  The active portion of the ring
 * describes the current state of the system and is replayed on mount.
 */
struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le32 bloom_salts[SCOUTFS_BLOOM_SALTS];
	__le64 total_chunks;
	__le64 ring_map_blkno;
	__le64 ring_map_seq;
	__le64 ring_first_block;
	__le64 ring_active_blocks;
	__le64 ring_total_blocks;
	__le64 ring_seq;
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

/*
 * Currently we sort keys by the numeric value of the types, but that
 * isn't necessary.  We could have an arbitrary sort order.  So we don't
 * have to stress about cleverly allocating the types.
 */
#define SCOUTFS_INODE_KEY	1
#define SCOUTFS_DIRENT_KEY	2
#define SCOUTFS_DATA_KEY	3

struct scoutfs_ring_map_block {
	struct scoutfs_block_header hdr;
	__le32 nr_chunks;
	__le64 blknos[0];
} __packed;

#define SCOUTFS_RING_MAP_BLOCKS \
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_ring_map_block)) / \
		sizeof(__le64))

struct scoutfs_ring_entry {
	u8 type;
	__le16 len;
} __packed;

/*
 * Ring blocks are stored in chunks described by the ring map blocks.
 *
 * The manifest entries describe the position of a given log segment in
 * the manifest.  They're keyed by the block number so that we can
 * record movement of a log segment in the manifest with one ring entry
 * and we can record deletion with just the block number.
 */ 
struct scoutfs_ring_block {
	struct scoutfs_block_header hdr;
	__le16 nr_entries;
} __packed;

enum {
	SCOUTFS_RING_ADD_MANIFEST = 0,
	SCOUTFS_RING_DEL_MANIFEST,
	SCOUTFS_RING_BITMAP,
};

/*
 * Including both keys might make the manifest too large.  It might be
 * better to only include one key and infer a block's range from the
 * neighbour's key.  The downside of that is that we assume that there
 * isn't unused key space between blocks in a level.  We might search
 * blocks when we didn't need to.
 */
struct scoutfs_ring_manifest_entry {
	__le64 blkno;
	__le64 seq;
	__u8 level;
	struct scoutfs_key first;
	struct scoutfs_key last;
} __packed;

struct scoutfs_ring_del_manifest {
	__le64 blkno;
} __packed;

/* 2^22 * 10^13 > 2^64 */
#define SCOUTFS_MAX_LEVEL 13

struct scoutfs_ring_bitmap {
	__le32 offset;
	__le64 bits[2];
} __packed;


struct scoutfs_bloom_block {
	struct scoutfs_block_header hdr;
	__le64 bits[0];
} __packed;

#define SCOUTFS_BLOOM_BITS_PER_BLOCK \
	(((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_block_header)) / 8) * 64)

/*
 * Items in log segments are sorted in a skip list by their key.  We
 * have a rough limit of 64k items.
 */
#define SCOUTFS_SKIP_HEIGHT 16
struct scoutfs_skip_root {
	__le32 next[SCOUTFS_SKIP_HEIGHT];
} __packed;

/*
 * An item block follows the bloom filter blocks at the start of a log
 * segment.  Its skip root references the item structs which then
 * reference the item values in the rest of the block.  The references
 * are byte offsets from the start of the chunk.
 */
struct scoutfs_item_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_skip_root skip_root;
} __packed;

struct scoutfs_item {
	struct scoutfs_key key;
	__le32 offset;
	__le16 len;
	u8 skip_height;
	__le32 skip_next[0];
} __packed;

/*
 * Item size caps item file data item length so that they fit in checksummed
 * 4k blocks with a bit of expansion room.
 */
#define SCOUTFS_MAX_ITEM_LEN \
	(SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_block_header) - 32)

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
	__u8   max_dirent_hash_nr;
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
	__u8 type;
	__u8 name[0];
} __packed;

/*
 * The max number of dirent hash values determines the overhead of
 * lookups in very large directories.  With 31bit offsets the number
 * of entries stored before enospc tends to plateau around 200 million
 * entries around 8 functions.  That seems OK for now.
 */
#define SCOUTFS_MAX_DENT_HASH_NR 8
#define SCOUTFS_NAME_LEN 255

/*
 * We only use 31 bits for readdir positions so that we don't confuse
 * old signed 32bit f_pos applications or those on the other side of
 * network protocols that have limited readir positions.
 */

#define SCOUTFS_DIRENT_OFF_BITS 31
#define SCOUTFS_DIRENT_OFF_MASK ((1U << SCOUTFS_DIRENT_OFF_BITS) - 1)
/* getdents returns next pos with an entry, no entry at (f_pos)~0 */
#define SCOUTFS_DIRENT_LAST_POS (INT_MAX - 1)

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
