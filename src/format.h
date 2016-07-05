#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

#define SCOUTFS_BLOCK_SHIFT 14
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
#define SCOUTFS_INODE_KEY	1
#define SCOUTFS_XATTR_KEY	2
#define SCOUTFS_DIRENT_KEY	3
#define SCOUTFS_DATA_KEY	4

#define SCOUTFS_MAX_ITEM_LEN 2048

/*
 * Block references include the sequence number so that we can detect
 * readers racing with writers and so that we can tell that we don't
 * need to follow a reference when traversing based on seqs.
 */
struct scoutfs_block_ref {
	__le64 blkno;
	__le64 seq;
} __packed;

struct scoutfs_treap_root {
	__le16 off;
} __packed;

struct scoutfs_treap_node {
	__le16 parent;
	__le16 left;
	__le16 right;
	__le32 prio;
} __packed;

struct scoutfs_btree_root {
	u8 height;
	struct scoutfs_block_ref ref;
} __packed;

struct scoutfs_btree_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_treap_root treap;
	__le16 total_free;
	__le16 tail_free;
	__le16 nr_items;
} __packed;

/*
 * The item sequence number is set to the dirty block's sequence number
 * when the item is modified.  It is not changed by splits or merges.
 */
struct scoutfs_btree_item {
	struct scoutfs_key key;
	struct scoutfs_treap_node tnode;
	__le64 seq;
	__le16 val_len;
	char val[0];
} __packed;

/* Blocks are no more than half free. */
#define SCOUTFS_BTREE_FREE_LIMIT \
	((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block)) / 2)

#define SCOUTFS_UUID_BYTES 16

/*
 * Arbitrarily choose a reasonably fine grained 64byte chunk.  This is a
 * balance between write amplification of writing chunks with a single
 * modified bit, storage overhead of partial blocks losing a chunk to
 * make room for the block header and having a pos field per chunk, and
 * runtime memory overhead of a bit per chunk.
 */
#define SCOUTFS_BUDDY_CHUNK_LE64S 8
#define SCOUTFS_BUDDY_CHUNK_BYTES (SCOUTFS_BUDDY_CHUNK_LE64S * 8)
#define SCOUTFS_BUDDY_CHUNK_BITS (SCOUTFS_BUDDY_CHUNK_BYTES * 8)

/*
 * After the pair of super blocks are a preallocated ring of blocks
 * which record modified regions of the buddy bitmap allocator.
 *
 * The seq's header needs to match the unwrapped ring index of the
 * block.
 */
struct scoutfs_buddy_block {
	struct scoutfs_block_header hdr;
	u8 nr_chunks;
	struct scoutfs_buddy_chunk {
		__le32 pos;
		__le64 bits[SCOUTFS_BUDDY_CHUNK_LE64S];
	} __packed chunks[0];
} __packed;

#define SCOUTFS_BUDDY_CHUNKS_PER_BLOCK \
	((SCOUTFS_BLOCK_SIZE - offsetof(struct scoutfs_buddy_block, chunks)) /\
	 SCOUTFS_BUDDY_CHUNK_BYTES)


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
	__le64 next_ino;
	__le64 total_blocks;
	__le32 buddy_blocks;
	__le32 buddy_sweep_bit;
	__le64 buddy_head;
	__le64 buddy_tail;
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

#define SCOUTFS_MAX_XATTR_NAME_LEN 255
#define SCOUTFS_MAX_XATTR_VALUE_LEN 255
#define SCOUTFS_XATTR_HASH_MASK 7ULL

struct scoutfs_xattr {
	__u8 name_len;
	__u8 value_len;
	__u8 name[0];
} __packed;

#endif
