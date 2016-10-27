#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

#define SCOUTFS_BLOCK_SHIFT 12
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_BLOCK_MASK (SCOUTFS_BLOCK_SIZE - 1)

#define SCOUTFS_PAGES_PER_BLOCK (SCOUTFS_BLOCK_SIZE / PAGE_SIZE)
#define SCOUTFS_BLOCK_PAGE_ORDER (SCOUTFS_BLOCK_SHIFT - PAGE_SHIFT)

/*
 * The super blocks leave some room at the start of the first block for
 * platform structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64 * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_SUPER_NR 2
#define SCOUTFS_BUDDY_BLKNO (SCOUTFS_SUPER_BLKNO + SCOUTFS_SUPER_NR)

#define SCOUTFS_MAX_TRANS_BLOCKS  (128 * 1024 * 1024 / SCOUTFS_BLOCK_SIZE)

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
 * Block references include the sequence number so that we can detect
 * readers racing with writers and so that we can tell that we don't
 * need to follow a reference when traversing based on seqs.
 */
struct scoutfs_block_ref {
	__le64 blkno;
	__le64 seq;
} __packed;

/*
 * If the block was full of bits the largest possible order would be
 * the block size shift + 3 (BITS_PER_BYTE).  But the header uses
 * up some space and then the buddy bits mean two bits per block.
 * Then +1 for this being the number, not the greatest order.
 */
#define SCOUTFS_BUDDY_ORDERS (SCOUTFS_BLOCK_SHIFT + 3 - 2 + 1)

struct scoutfs_buddy_block {
	struct scoutfs_block_header hdr;
	__le16 first_set[SCOUTFS_BUDDY_ORDERS];
	__u8 level;
	__u8 __pad[3]; /* naturally align bits */
	union {
		struct scoutfs_buddy_slot {
			__le64 seq;
			__le16 free_orders;
			/* XXX seems like we could hide a bit somewhere */
			__u8 blkno_off;
		} __packed slots[0];
		__le64 bits[0];
	} __packed;
} __packed;

/*
 * Each buddy leaf block references order 0 blocks with half of its
 * bitmap.  The other half of the bits are used for the higher order
 * bits.
 */
#define SCOUTFS_BUDDY_ORDER0_BITS \
	(((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_buddy_block)) * 8) / 2)

#define SCOUTFS_BUDDY_SLOTS						\
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_buddy_block)) /	\
		sizeof(struct scoutfs_buddy_slot))

struct scoutfs_buddy_root {
	struct scoutfs_buddy_slot slot;
	__u8 height;
} __packed;

/* ((SCOUTFS_BUDDY_SLOTS^5) * SCOUTFS_BUDDY_ORDER0_BITS) > 2^52 */
#define SCOUTFS_BUDDY_MAX_HEIGHT 6

/*
 * We should be able to make the offset smaller if neither dirents nor
 * data items use the full 64 bits.
 */
struct scoutfs_key {
	__le64 inode;
	u8 type;
	__le64 offset;
} __packed;

/*
 * Currently we sort keys by the numeric value of the types, but that
 * isn't necessary.  We could have an arbitrary sort order.  So we don't
 * have to stress about cleverly allocating the types.
 */
#define SCOUTFS_INODE_KEY		1
#define SCOUTFS_XATTR_KEY		2
#define SCOUTFS_XATTR_NAME_HASH_KEY	3
#define SCOUTFS_XATTR_VAL_HASH_KEY	4
#define SCOUTFS_DIRENT_KEY		5
#define SCOUTFS_LINK_BACKREF_KEY	6
#define SCOUTFS_SYMLINK_KEY		7
#define SCOUTFS_BMAP_KEY		8
#define SCOUTFS_ORPHAN_KEY		9

#define SCOUTFS_MAX_ITEM_LEN 512

struct scoutfs_btree_root {
	u8 height;
	struct scoutfs_block_ref ref;
} __packed;

/*
 * @free_end: records the byte offset of the first byte after the free
 * space in the block between the header and the first item.  New items
 * are allocated by subtracting the space they need.
 *
 * @free_reclaim: records the number of bytes of free space amongst the
 * items after free_end.  If a block is compacted then this much new
 * free space would be reclaimed.
 */
struct scoutfs_btree_block {
	struct scoutfs_block_header hdr;
	__le16 free_end;
	__le16 free_reclaim;
	__u8 nr_items;
	__le16 item_offs[0];
} __packed;

/*
 * The item sequence number is set to the dirty block's sequence number
 * when the item is modified.  It is not changed by splits or merges.
 */
struct scoutfs_btree_item {
	struct scoutfs_key key;
	__le64 seq;
	__le16 val_len;
	char val[0];
} __packed;

/* Blocks are no more than half free. */
#define SCOUTFS_BTREE_FREE_LIMIT \
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block)) / 2)

/* XXX does this exist upstream somewhere? */
#define member_sizeof(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))

#define SCOUTFS_BTREE_MAX_ITEMS \
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block)) /	\
	 (member_sizeof(struct scoutfs_btree_block, item_offs[0]) +	\
          sizeof(struct scoutfs_btree_item)))

/*
 * We can calculate the max tree depth by calculating how many leaf
 * blocks the tree could reference.  The block device can only reference
 * 2^64 bytes.  The tallest parent tree has half full parent blocks.
 *
 * So we have the relation:
 *
 * ceil(max_items / 2) ^ (max_depth - 1) >= 2^64 / block_size
 *
 * and solve for depth:
 *
 * max_depth = log(ceil(max_items / 2), 2^64 / block_size) + 1
 */
#define SCOUTFS_BTREE_MAX_DEPTH 10

#define SCOUTFS_UUID_BYTES 16

struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 next_ino;
	__le64 total_blocks;
	__le64 free_blocks;
	__le64 buddy_blocks;
        struct scoutfs_buddy_root buddy_root;
        struct scoutfs_btree_root btree_root;
} __packed;

#define SCOUTFS_ROOT_INO 1

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
	__le64 link_counter;
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

/* like the block size, a reasonable min PATH_MAX across platforms */
#define SCOUTFS_SYMLINK_MAX_SIZE 4096

/*
 * Dirents are stored in items with an offset of the hash of their name.
 * Colliding names are packed into the value.
 */
struct scoutfs_dirent {
	__le64 ino;
	__le64 counter;
	__u8 type;
	__u8 name[0];
} __packed;

/*
 * Dirent items are stored at keys with the offset set to the hash of
 * the name.  Creation can find that hash values collide and will
 * attempt to linearly probe this many following hash values looking for
 * an unused value.
 *
 * In small directories this doesn't really matter because hash values
 * will so very rarely collide.  At around 50k items we start to see our
 * first collisions.  16 slots is still pretty quick to scan in the
 * btree and it gets us up into the hundreds of millions of entries
 * before enospc is returned as we run out of hash values.
 */
#define SCOUTFS_DIRENT_COLL_NR 16

#define SCOUTFS_NAME_LEN 255

/*
 * This is arbitrarily limiting the max size of the single buffer
 * that's needed in the inode_paths ioctl to return all the paths
 * that link to an inode.  The structures could easily support much
 * more than this but then we'd need to grow a more thorough interface
 * for iterating over referring paths.  That sounds horrible.
 */
#define SCOUTFS_LINK_MAX 255

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

#define SCOUTFS_MAX_XATTR_LEN 255
#define SCOUTFS_XATTR_NAME_HASH_MASK 7ULL

struct scoutfs_xattr {
	__u8 name_len;
	__u8 value_len;
	__u8 name[0];
} __packed;

/*
 * We use simple block map items to map a aligned fixed group of logical
 * block offsets to physical blocks.  We make them a decent size to
 * reduce the item storage overhead per block referenced, but we don't
 * want them so large that they start to take up an extraordinary amount
 * of space for small files.  8 block items ranges from around 3% to .3%
 * overhead for files that use only one or all of the blocks in the
 * mapping item.
 */
#define SCOUTFS_BLOCK_MAP_SHIFT 3
#define SCOUTFS_BLOCK_MAP_COUNT (1 << SCOUTFS_BLOCK_MAP_SHIFT)
#define SCOUTFS_BLOCK_MAP_MASK (SCOUTFS_BLOCK_MAP_COUNT - 1)

struct scoutfs_block_map {
	__le64 blkno[SCOUTFS_BLOCK_MAP_COUNT];
	__le64 seq[SCOUTFS_BLOCK_MAP_COUNT];
};

/*
 * link backrefs give us a way to find all the hard links that refer
 * to a target inode.  They're stored at an offset determined by an
 * advancing counter in their inode.
 */
struct scoutfs_link_backref {
	__le64 ino;
	__le64 offset;
} __packed;

#endif
