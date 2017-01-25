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

struct scoutfs_treap_ref {
	__le64 off;
	__le64 gen;
	__u8 aug_bits;
} __packed;

/*
 * The lesser and greater bits are persistent on disk so that we can migrate
 * nodes from the older half of the ring.
 *
 * The dirty bit is only used for in-memory nodes.
 */
#define SCOUTFS_TREAP_AUG_LESSER	(1 << 0)
#define SCOUTFS_TREAP_AUG_GREATER	(1 << 1)
#define SCOUTFS_TREAP_AUG_HALVES	(SCOUTFS_TREAP_AUG_LESSER | \
					 SCOUTFS_TREAP_AUG_GREATER)
#define SCOUTFS_TREAP_AUG_DIRTY		(1 << 2)

/*
 * Treap nodes are stored at byte offset in the ring of blocks described
 * by the super block.  Each reference contains the off and gen that it
 * will find in the node for verification.  Each node has the header
 * and data payload covered by a crc.
 */
struct scoutfs_treap_node {
	__le32 crc;
	__le64 off;
	__le64 gen;
	__le64 prio;
	struct scoutfs_treap_ref left;
	struct scoutfs_treap_ref right;
	__le16 bytes;
	u8 data[0];
} __packed;

struct scoutfs_treap_root {
	struct scoutfs_treap_ref ref;
} __packed;

/*
 * This is absurdly huge.  If there was only ever 1 item per segment and
 * 2^64 items the tree could get this deep.
 */
#define SCOUTFS_MANIFEST_MAX_LEVEL 20

#define SCOUTFS_MANIFEST_FANOUT 10

struct scoutfs_manifest {
	struct scoutfs_treap_root root;
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
#define SCOUTFS_READDIR_KEY		6
#define SCOUTFS_LINK_BACKREF_KEY	7
#define SCOUTFS_SYMLINK_KEY		8
#define SCOUTFS_EXTENT_KEY		9
#define SCOUTFS_ORPHAN_KEY		10
#define SCOUTFS_MAX_UNUSED_KEY		255

#define SCOUTFS_MAX_ITEM_LEN 512

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

/* no value */
struct scoutfs_orphan_key {
	__u8 type;
	__be64 ino;
} __packed;

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
	__le16 nr_items;
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
	__le64 total_blocks;
	__le64 free_blocks;
	__le64 ring_blkno;
	__le64 ring_blocks;
	__le64 ring_tail_block;
	__le64 ring_gen;
	__le64 next_seg_seq;
	__le64 buddy_blocks;
        struct scoutfs_buddy_root buddy_root;
        struct scoutfs_btree_root btree_root;
	struct scoutfs_treap_root alloc_treap_root;
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
	__le64 link_counter;
	__le64 data_version;
	__le64 next_readdir_pos;
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
	__le64 readdir_pos;
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

/* S32_MAX avoids the (int) sign bit and might avoid sloppy bugs */
#define SCOUTFS_LINK_MAX S32_MAX

/*
 * We only use 31 bits for readdir positions so that we don't confuse
 * old signed 32bit f_pos applications or those on the other side of
 * network protocols that have limited readir positions.
 */

#define SCOUTFS_DIRENT_OFF_BITS 31
#define SCOUTFS_DIRENT_OFF_MASK ((1U << SCOUTFS_DIRENT_OFF_BITS) - 1)
/* getdents returns next pos with an entry, no entry at (f_pos)~0 */
#define SCOUTFS_DIRENT_FIRST_POS 2
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

struct scoutfs_extent {
	__le64	blkno;
	__le64	len;
	__u8	flags;
} __packed;

#define SCOUTFS_EXTENT_FLAG_OFFLINE (1 << 0)

/*
 * link backrefs give us a way to find all the hard links that refer
 * to a target inode.  They're stored at an offset determined by an
 * advancing counter in their inode.
 */
struct scoutfs_link_backref {
	__le64 ino;
	__le64 offset;
} __packed;

#define SCOUTFS_MAX_KEY_SIZE \
	offsetof(struct scoutfs_dirent_key, name[SCOUTFS_NAME_LEN])

#endif
