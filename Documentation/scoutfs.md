
# scoutfs Engineering Compendium

-----

## Document Overview

This document is intended to be a relatively unstructured but thorough
coverage of the design, implementation, and deployment of scoutfs.

*Not Yet Discussed: repair, dump/restore, remote namespace
synchronization, compression, encryption, trim, dedup, hole punching,
SMR, iops v. bw, range locking, sorting keys by type/inode, enospc,
compaction priority, manifest server, manifest network protocol, inode
allocation, clustered open-unlink, seq queries, offline data, LSM,
forward/back compat.*

## Raison D'être

scoutfs is an archival posix file system.  It's built to provide a posix
interface to petabytes of data in trillions of files through thousands
of nodes.

scoutfs uses log-structured merge trees to achieve high operation
throughput with low device command rates.  It uses ranged locking to
maintain consistent POSIX semantics amongst clustered nodes with minimum
synchronization overhead.  It offers additional metadata indexing and
data residency interfaces for efficiently executing archival policies.
It is deployed on a shared block fabric for high bandwidth and low
latency.

## Super Block

The super block is the anchor of all the persistent storage in the block
device.  It contains volume-wide configuration information and
references to the current stable versions of persistent data structures
in the rest of the block device.  The super block is stored in two 4KB
blocks at a known location at the start of the device.

To read the current super block both block locations are read.  The
valid super block with the most recent sequence number is used.  Either
of the super blocks can be corrupt because they're overwritten in place
and a crash during a write could scramble the block.

Each new version of the super block is written to the block that doesn't
contain the current super block.  If this new super block write fails
then the old super block can still be used and no data is lost.

The super block, and indeed all file system data, doesn't touch a few
blocks at the start of the device to avoid corrupting blocks that are
used by host platforms that store data inside devices to manage them.

## Inodes

Inodes are stored in items identified by the inode number.

	key = struct scoutfs_inode_key {
		.type = SCOUTFS_INODE_KEY,
		.ino,
	}
	
	val = struct scoutfs_inode {
		size, nlink, uid, gid, atime, mtime, ...,
	}

The variable length value that stores the item struct gives us dense
inode packing without having to predefine an inode storage size when the
file system is created and gives us a future expansion mechanism that
uses the item length to determine the version of the inode struct that
is written.

Inode numbers are 64bit and are never re-used.  By never re-using inode
numbers we don't need to manage an inode number allocator that would
need to be consistent across nodes.  We can grant large ranges of
numbers to mount clients for allocation.  Each inode number uniquely
identify the lifetime of a file and avoids having to store a seperate
generation number for each inode number.

## Extended Attributes

Extended attributes are stored in items on the inode at the full name of
the attribute.  The attribute name is limited to 255 bytes and the
attribute values is limited to 64KB.  The max xattr value size is larger
than our max item size so we can store an xattr in multiple items, but
in the common case a single xattr is efficiently stored in a single
item.

	key = struct scoutfs_xattr_key {
		.type = SCOUTFS_XATTR_KEY,
		.ino,
		.name,
		struct scoutfs_xattr_key_footer {
			.null = '\0',
			.part,
		}
	}

Storing the null after the attribute name, which can't be found in any
name, lets us accurately locate a given name in the presence of other
names that share partial prefixes.  The part identifies each key's
position in the set of keys that make up the large value.  Storing the
full name in each key ensures that all the keys that make up an
attribute are stored adjacent to each other.

Each item's value starts with a header which describes portion of the
attribute value stored in the item.

	val = struct scoutfs_xattr_val_header {
		.part_len,
		.last_part,
		.data,
	}

The result of all this is that operations on xattrs iterate over keys
starting with the name and part 0 and stop when they hit the final part
(or error on corruption if the parts aren't consistent.)

## Directory Entries

Directory entry items store the target inode number referred to by a
given entry name in a parent directory.  The name is limited to 255
non-null bytes.  The large keys supported by our items let us store
directory entries in items indexed by the full entry name itself.

	key = struct scoutfs_dirent_key {
		.type = SCOUTFS_DIRENT_KEY,
		.ino,
		.name,
	}
	
	val = struct scoutfs_dirent {
		.ino,
		.readdir_pos,
		.type,
	}

These full precision items let us work on each item for a given name
directly rather than scrambling their sorting by storing them at a hash
value of their name.  Storing at a hash value not only adds the
complexity of collisions, it critically causes entry lock attempts in a
directory between mounts to be perfectly randomly distributed and
constantly conflicting with each other.  Storing and range locking the
directory entries at their full name preserves non-overlapping patterns
between mounts and gives them a chance to efficiently operate on
disjoint sets of names.

We index the directory entry items by the full name of the entry so
there is no limit imposed on the number of entries in a directory.  The
system will run out of blocks to store entries long before the index is
incapable of storing them.

While we can satisfy lookups with a full precision index, readdir
doesn't use a full precision iterator.  It forces us to describe each
entry with a small scalar directory position.  We use a separate item
that's indexed by this readdir position instead of the file name.

	key = struct scoutfs_readdir_key {
		.type = SCOUTFS_DIRENT_KEY,
		.ino,
		.readdir_pos,
	}
	
	val = struct scoutfs_dirent {
		.ino,
		.readdir_pos,
		.type,
		.name,
	}

The key's position is allocated as each entry is created.  This results
in readdir returning entries ordered by creation time.  Like inode
numbers, readdir positions are never re-used so that we don't have to
risk contention by maintaining a consistent free position index across
nodes.

## Directory Entry Link Backrefs

The third and final item used by each directory entry is an item that is
stored at the target inode instead of in the parent directory.  These
backref items can be traversed to find the full paths from the root
inode to all the entries that link to the target inode.

	key = struct scoutfs_link_backref_key {
		.type = SCOUTFS_LINK_BACKREF_KEY,
		.ino,
		.dir_ino,
		.name,
	}
	
	/* no value */

Iterating over these items for a given target ino yields the parent
dir_ino and full file name of every entry that references the target
inode.  The entry items in the parent dir are stored at the full file
name so the only way for us to reference them is with another copy of
the file name, brining the total to three full copies of the name stored
for every directory entry.

Because we store the full name for these backref items they do not
impose a limit on the number of hard links to an inode.

## Regular File Data Extents

scoutfs stores file data in block extents at 4KB granularity.  Items
describe the extents of 4KB blocks that map logical file offsets to
physical block extents in the device:

	key = struct scoutfs_extent_key {
		.type = SCOUTFS_EXTENT_KEY,
		.ino,
		.iblock,
		.blkno,
		.count,
		.flags,
	}

	/* no value */

The flags field indicates the state of the extent, for example it can be
preallocated but unwritten or offline.  If the extent is offline then
the blkno is unused and should be zero.

Checksums of file data are contained in items at the physical block
offset of the checksumed blocks.  Each item contains a fixed number of
checksums for a given group of blocks.

	key = struct scoutfs_checksum_key {
		.type = SCOUTFS_CHECKSUM_KEY,
		.blkno,
	}
	
	val = {
		.crcs[8],
	}

The checksum items are keyed by the physical block number instead of the
logical file position so that the checksum items are only written as new
data is written.  The checksum items are left alone as the file data
references change: truncate, unlink, hole punching, and cloning don't
have to modify checksum items.

With these structures in place the file read and write paths in scoutfs
look very much like most other block file systems in Linux.  The generic
buffer_head support code is used and our get_blocks callback reads and
writes the extent items that reference block extents.  Write and sync
patterns, with the help of delalloc, preallocation, and fallocate,
determine the physical contiguity of extent allocations.  Buffered
read-ahead and O_DIRECT reads walk the extent items and build large
efficient bios if the extents are physically contiguous.

## Allocating Regular File Data Extents

The primary persistent allocator for blocks on the device uses an
efficient bitmap with a bit for each 1MB segment.  File data allocation
wants to track extents at 4KB granularity and also index them by the
size of the free extent, neither of which the segment bitmap allocator
supports.

We have free extent items that track free block extents in the device at
the finer 4K granularity.  There are two keys for each free extent: one
indexed by the block location and one by the size of the free extent.
Modifying a free extent can thus modify three different positions in the
key namespace: the block location, the old size location, and the new
size location.  LSM lets us generate and merge these disjoint items
across different mounts efficiently.

To avoid the prohibitively expensive lock contention of modifying these
items from multiple mounts, we first create groups of free extents and
assign a given mount to a group for the lifetime of its mount.

	key = struct scoutfs_free_extent_loc_key
		.type = SCOUTFS_FREE_EXTENT_LOC_KEY,
		.group,
		.blkno,
		.count,
	}

	key = struct scoutfs_free_extent_len_key
		.type = SCOUTFS_FREE_EXTENT_LEN_KEY,
		.group,
		.count,
		.blkno,
	}

Mounts are responsible for mangement of the free extent items.  They're
populated with the result from requests from the manifest server for
free segment blocks.  They're consumed as file data is written and
logical extents are allocated.  They're repopulated as file data is
truncated and its extents are freed.  They're returned to the segment
allocator when they contain aligned 1MB free extents.

Like all persistent filesystem items, the free extent items are
protected by range locks.  In the common case a single mount will be
operating on its group and having all the lock operations satisfied by
range matches.  Any mount can modify any group's extents by acquiring
the right locks, but this should be limited to rare attempts to
defragment or migrate free extents between groups.

The manifest server is responsible for tracking the assigment of mounts
to groups as mounts come and go through clean mounts and unclean crashes
and recovery.  Free extents can get stranded in groups that don't have
an assigned mount.  A mount scrambling to find free space in other
groups would need a mechanism to discover other groups, perhaps with a
set of keys that record the presence of extents in each group.

## Indexing Inodes by Modification Time

As files are modified archival agents need to find these modified files
so that the archive can be updated.  As inode counts explode it becomes
infeasible to scan the entire inode population and meet archival
deadlines.

scoutfs maintains an index of inodes by modification time.  An ioctl is
offered which iterates over the inodes in the order that they were
modified.  The ioctl takes a timespec cursor from which to walk.  It
fills a buffer with inodes and the time they were modified, sorted by
time.

The ioctl results are inherently racey.  There's nothing to stop an
inode from being modified and moved in the index between when the call
returns and the caller operates on the inode.

This index is maintained by having time fields in the inode and
modification time items at those time values.  The item key sorts the
items by time for the ioctl to iterate over.  The items have no value.

	.type = SCOUTFS_MODTIME_KEY,
	.ino = inode,
	.ts.tv_sec = seconds,
	.ts.tv_nsec = nanoseconds,

As inodes are modified deletion items are created for the old time and
new items are inserted.  LSM's ability to let us create items without
strictly locking their key value keeps these items from creating
unacceptable lock contention.  If the modifying task has sufficient
locking on the inode it can modify these items and LSM will eventually
merge them into place.

The index is keyed on real world time so that we don't have to create
our own consistent advancing clock.  The clock only needs to be as
accurate as the users of the index require (this often doesn't add
unreasonable requirements, it's often already the case that arhicval
policies involve time and motivate a reasonably synchronized clock
across the cluster.)

As inodes are deleted their modification items are deleted.

> *XXX Need to figure out how to resolve multiple items created by
> concurrent writers.  We want concurrent parallel writers, say, and
> they'll all way to create their own items at their write times.  We'd
> need to be able to find those to delete them during future
> modification or deletion.  Sort of sounds like we want
> per-node-identity backrefs for each to maintain and to purge as nodes
> leave the cluster.
