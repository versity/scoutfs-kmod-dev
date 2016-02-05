#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

#define SCOUTFS_SUPER_MAGIC       0x554f4353      /* "SCOU" */

#define SCOUTFS_BLOCK_SHIFT 22
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)

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

/*
 * We should be able to make the offset smaller if neither dirents nor
 * data items use the full 64 bits.
 */
struct scoutfs_key {
	__le64 inode;
	u8 type;
	__le64 offset;
} __packed;

#define SCOUTFS_INODE_KEY 128
#define SCOUTFS_DIRENT_KEY 192

struct scoutfs_lsm_block {
	struct scoutfs_key first;
	struct scoutfs_key last;
	__le32 nr_items;
	/* u8 bloom[SCOUTFS_BLOOM_BYTES]; */
	/* struct scoutfs_item_header items[0] .. */
} __packed;

struct scoutfs_item_header {
	struct scoutfs_key key;
	__le16 val_len;
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
