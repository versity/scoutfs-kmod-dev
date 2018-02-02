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
 * Fill the path buffer with the next path to the target inode.  An
 * iteration cursor is stored in the cursor buffer which advances
 * through the paths to the inode at each call.
 *
 * @ino: The target ino that we're finding paths to.  Constant across
 * all the calls that make up an iteration over all the inode's paths.
 *
 * @cursor_ptr: A pointer to the buffer that will hold the iteration
 * cursor.  It must be initialized to 0 before iterating.  Each call
 * modifies it to skip past the result of that call.
 *
 * @cusur_bytes: The length of the cursor buffer.  Must be
 * SCOUTFS_IOC_INO_PATH_CURSOR_BYTES.
 *
 * @path_ptr: The buffer to store each found path.
 *
 * @path_bytes: The size of the buffer that will the found path
 * including null termination.  (PATH_MAX is a solid choice.)
 *
 * This only walks back through full hard links.  None of the returned
 * paths will reflect symlinks to components in the path.
 *
 * This doesn't ensure that the caller has permissions to traverse the
 * returned paths to the inode.  It requires CAP_DAC_READ_SEARCH which
 * bypasses permissions checking.
 *
 * ENAMETOOLONG is returned when the next path found from the cursor
 * doesn't fit in the path buffer.
 *
 * This call is not serialized with any modification (create, rename,
 * unlink) of the path components.  It will return all the paths that
 * were stable both before and after the call.  It may or may not return
 * paths which are created or unlinked during the call.
 *
 * The number of bytes in the path, including the null terminator, are
 * returned when a path is found.  0 is returned when there are no more
 * paths to the link to the inode from the cursor.
 */
struct scoutfs_ioctl_ino_path {
	__u64 ino;
	__u64 cursor_ptr;
	__u64 path_ptr;
	__u16 cursor_bytes;
	__u16 path_bytes;
} __packed;

#define SCOUTFS_IOC_INO_PATH_CURSOR_BYTES \
	(sizeof(__u64) + SCOUTFS_NAME_LEN + 1)

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

struct scoutfs_ioctl_item_cache_keys {
	__u64 key_ptr;
	__u64 key_len;
	__u64 buf_ptr;
	__u64 buf_len;
	__u8 which;
} __packed;

enum {
	SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS = 0,
	SCOUTFS_IOC_ITEM_CACHE_KEYS_RANGES,
};

#define SCOUTFS_IOC_ITEM_CACHE_KEYS _IOW(SCOUTFS_IOCTL_MAGIC, 8, \
					 struct scoutfs_ioctl_item_cache_keys)

#endif
