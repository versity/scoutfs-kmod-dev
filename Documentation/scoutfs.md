
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
