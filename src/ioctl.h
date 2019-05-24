#ifndef _SCOUTFS_IOCTL_H_
#define _SCOUTFS_IOCTL_H_

/* XXX I have no idea how these are chosen. */
#define SCOUTFS_IOCTL_MAGIC 's'

struct scoutfs_ioctl_walk_inodes_entry {
	__u64 major;
	__u32 minor;
	__u64 ino;
} __packed;

/*
 * Walk inodes in an index that is sorted by one of their fields.
 *
 * Each index is built from generic index items that have major and
 * minor values that are set to the field being indexed.  In time
 * indices, for example, major is seconds and minor is nanoseconds.
 *
 * @first       The first index entry that can be returned.
 * @last        The last index entry that can be returned.
 * @entries_ptr Pointer to emory containing buffer for entry results.
 * @nr_entries  The number of entries that can fit in the buffer.
 * @index       Which index to walk, enumerated in _WALK_INODES_ constants.
 *
 * To start iterating first can be memset to 0 and last to 0xff.  Then
 * after each set of results first can be set to the last entry returned
 * and then the fields can be incremented in reverse sort order (ino <
 * minor < major) as each increasingly significant value wraps around to
 * 0.
 *
 * These indexes are not strictly consistent.  The items that back these
 * index entries aren't updated with cluster locks so they're not
 * guaranteed to be visible the moment you read after writing.  They're
 * only visible when the transaction that updated them is synced.
 *
 * In addition, the seq indexes will only allow walking through sequence
 * space that has been consistent.  This prevents old dirty entries from
 * becoming visible after newer stable entries are displayed.
 *
 * If first is greater than last then the walk will return 0 entries.
 *
 * XXX invalidate before reading.
 */
struct scoutfs_ioctl_walk_inodes {
	struct scoutfs_ioctl_walk_inodes_entry first;
	struct scoutfs_ioctl_walk_inodes_entry last;
	__u64 entries_ptr;
	__u32 nr_entries;
	__u8 index;
} __packed;

enum {
	SCOUTFS_IOC_WALK_INODES_META_SEQ = 0,
	SCOUTFS_IOC_WALK_INODES_DATA_SEQ,
	SCOUTFS_IOC_WALK_INODES_UNKNOWN,
};

/*
 * Adds entries to the user's buffer for each inode that is found in the
 * given index between the first and last positions.
 */
#define SCOUTFS_IOC_WALK_INODES _IOW(SCOUTFS_IOCTL_MAGIC, 1, \
				     struct scoutfs_ioctl_walk_inodes)

/*
 * Fill the result buffer with the next absolute path to the target
 * inode searching from a given position in a parent directory.
 *
 * @ino: The target ino that we're finding paths to.  Constant across
 * all the calls that make up an iteration over all the inode's paths.
 *
 * @dir_ino: The inode number of the directory containing the entry to
 * our inode to search from.  If this parent directory contains no more
 * entries to our inode then we'll search through other parent directory
 * inodes in inode order.
 *
 * @dir_pos: The position in the dir_ino parent directory of the entry
 * to our inode to search from.  If there is no entry at this position
 * then we'll search through other entry positions in increasing order.
 * If we exhaust the parent directory then we'll search through
 * additional parent directories in inode order.
 *
 * @result_ptr: A pointer to the buffer where the result struct and
 * absolute path will be stored.
 *
 * @result_bytes: The size of the buffer that will contain the result
 * struct and the null terminated absolute path name.
 *
 * To start iterating set the desired target inode, dir_ino to 0,
 * dir_pos to 0, and set result_ptr and _bytes to a sufficiently large
 * buffeer (sizeof(result) + PATH_MAX is a solid choice).
 *
 * After each returned result set the next search dir_ino and dir_pos to
 * the returned dir_ino and dir_pos.  Then increment the search dir_pos,
 * and if it wrapped to 0, increment dir_ino.
 *
 * This only walks back through full hard links.  None of the returned
 * paths will reflect symlinks to components in the path.
 *
 * This doesn't ensure that the caller has permissions to traverse the
 * returned paths to the inode.  It requires CAP_DAC_READ_SEARCH which
 * bypasses permissions checking.
 *
 * This call is not serialized with any modification (create, rename,
 * unlink) of the path components.  It will return all the paths that
 * were stable both before and after the call.  It may or may not return
 * paths which are created or unlinked during the call.
 *
 * On success 0 is returned and result struct is filled with the next
 * absolute path.  The path_bytes length of the path includes a null
 * terminating byte.  dir_ino and dir_pos refer to the position of the
 * final component in its parent directory and can be advanced to search
 * for the next terminal entry whose path is then built by walking up
 * parent directories.
 *
 * ENOENT is returned when no paths are found.
 *
 * ENAMETOOLONG is returned when the result struct and path found
 * doesn't fit in the result buffer.
 *
 * Many other errnos indicate hard failure to find the next path.
 */
struct scoutfs_ioctl_ino_path {
	__u64 ino;
	__u64 dir_ino;
	__u64 dir_pos;
	__u64 result_ptr;
	__u16 result_bytes;
} __packed;

struct scoutfs_ioctl_ino_path_result {
	__u64 dir_ino;
	__u64 dir_pos;
	__u16 path_bytes;
	__u8  path[0];
} __packed;

/* Get a single path from the root to the given inode number */
#define SCOUTFS_IOC_INO_PATH _IOW(SCOUTFS_IOCTL_MAGIC, 2, \
				      struct scoutfs_ioctl_ino_path)

#define SCOUTFS_IOC_DATA_VERSION _IOW(SCOUTFS_IOCTL_MAGIC, 4, __u64)

/*
 * "Release" a contiguous range of logical blocks of file data.
 * Released blocks are removed from the file system like truncation, but
 * an offline record is left behind to trigger demand staging if the
 * file is read.
 *
 * The starting block offset and number of blocks to release are in
 * units 4KB blocks.
 *
 * The specified range can extend past i_size and can straddle sparse
 * regions or blocks that are already offline.  The only change it makes
 * is to free and mark offline any existing blocks that intersect with
 * the region.
 *
 * Returns 0 if the operation succeeds.  If an error is returned then
 * some partial region of the blocks in the region may have been marked
 * offline.
 *
 * If the operation succeeds then inode metadata that reflects file data
 * contents are not updated.  This is intended to be transparent to the
 * presentation of the data in the file.
 */
struct scoutfs_ioctl_release {
	__u64 block;
	__u64 count;
	__u64 data_version;
} __packed;

#define SCOUTFS_IOC_RELEASE _IOW(SCOUTFS_IOCTL_MAGIC, 5, \
				  struct scoutfs_ioctl_release)

struct scoutfs_ioctl_stage {
	__u64 data_version;
	__u64 buf_ptr;
	__u64 offset;
	__s32 count;
} __packed;

#define SCOUTFS_IOC_STAGE _IOW(SCOUTFS_IOCTL_MAGIC, 6, \
			       struct scoutfs_ioctl_stage)

/*
 * Give the user inode fields that are not otherwise visible.  statx()
 * isn't always available and xattrs are relatively expensive.
 *
 * @valid_bytes stores the number of bytes that are valid in the
 * structure.  The caller sets this to the size of the struct that they
 * understand.  The kernel then fills and copies back the min of the
 * size they and the user caller understand.  The user can tell if a
 * field is set if all of its bytes are within the valid_bytes that the
 * kernel set on return.
 *
 * New fields are only added to the end of the struct.
 */
struct scoutfs_ioctl_stat_more {
	__u64 valid_bytes;
	__u64 meta_seq;
	__u64 data_seq;
	__u64 data_version;
	__u64 online_blocks;
	__u64 offline_blocks;
} __packed;

#define SCOUTFS_IOC_STAT_MORE _IOW(SCOUTFS_IOCTL_MAGIC, 7, \
				   struct scoutfs_ioctl_stat_more)

/*
 * Fills the buffer with either the keys for the cached items or the
 * keys for the cached ranges found starting with the given key.  The
 * number of keys filled in the buffer is returned.  When filling range
 * keys the returned number will always be a multiple of two.
 */
struct scoutfs_ioctl_item_cache_keys {
	struct scoutfs_key key;
	__u64 buf_ptr;
	__u16 buf_nr;
	__u8 which;
} __packed;

enum {
	SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS = 0,
	SCOUTFS_IOC_ITEM_CACHE_KEYS_RANGES,
};

#define SCOUTFS_IOC_ITEM_CACHE_KEYS _IOW(SCOUTFS_IOCTL_MAGIC, 8, \
					 struct scoutfs_ioctl_item_cache_keys)

struct scoutfs_ioctl_data_waiting_entry {
	__u64 ino;
	__u64 iblock;
	__u8 op;
} __packed;

#define SCOUTFS_IOC_DWO_READ		(1 << 0)
#define SCOUTFS_IOC_DWO_WRITE		(1 << 1)
#define SCOUTFS_IOC_DWO_CHANGE_SIZE	(1 << 2)
#define SCOUTFS_IOC_DWO_UNKNOWN		(U8_MAX << 3)

struct scoutfs_ioctl_data_waiting {
	__u64 flags;
	__u64 after_ino;
	__u64 after_iblock;
	__u64 ents_ptr;
	__u16 ents_nr;
} __packed;

#define SCOUTFS_IOC_DATA_WAITING_FLAGS_UNKNOWN		(U8_MAX << 0)

#define SCOUTFS_IOC_DATA_WAITING _IOW(SCOUTFS_IOCTL_MAGIC, 9, \
				      struct scoutfs_ioctl_data_waiting)

/*
 * If i_size is set then data_version must be non-zero.  If the offline
 * flag is set then i_size must be set and a offline extent will be
 * created from offset 0 to i_size.
 */
struct scoutfs_ioctl_setattr_more {
	__u64 data_version;
	__u64 i_size;
	__u64 flags;
	struct scoutfs_timespec ctime;
} __packed;

#define SCOUTFS_IOC_SETATTR_MORE_OFFLINE		(1 << 0)
#define SCOUTFS_IOC_SETATTR_MORE_UNKNOWN		(U8_MAX << 1)

#define SCOUTFS_IOC_SETATTR_MORE _IOW(SCOUTFS_IOCTL_MAGIC, 10, \
				      struct scoutfs_ioctl_setattr_more)

#endif
