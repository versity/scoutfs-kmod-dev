# Introduction

scoutfs is a clustered in-kernel Linux filesystem designed and built
from the ground up to support large archival systems.

Its key differentiating features are:

 - Integrated consistent indexing to accelerate archival maintenance operations
 - Shared LSM index structure to scale metadata rates with storage bandwidth
 - Decoupled logical locking from serialized device writes to reduce contention

It meets best of breed expectations:

 * Fully consistent POSIX semantics between nodes
 * Rich metadata to ensure the integrity of metadata references
 * Atomic transactions to maintain consistent persistent structures
 * First class kernel implementation for high performance and low latency
 * Open GPLv2 implementation
 
Learn more in the [white paper](https://docs.wixstatic.com/ugd/aaa89b_88a5cc84be0b4d1a90f60d8900834d28.pdf).

# Current Status

**Alpha Open Source Development**

scoutfs is under heavy active development.  We're developing it in the
open to give the community an opportunity to affect the design and
implementation.

The core architectural design elements are in place.  Much surrounding
functionality hasn't been implemented.  It's appropriate for early
adopters and interested developers, not for production use.

In that vein, expect significant incompatible changes to both the format
of network messages and persistent structures.  To avoid mistakes the
implementation currently calculates a hash of the format and ioctl
header files in the source tree.  The kernel module will refuse to mount
a volume created by userspace utilities with a mismatched hash, and it
will refuse to connect to a remote node with a mismatched hash.  This
means having to unmount, mkfs, and remount everything across many
functional changes.  Once the format is nailed down we'll wire up
forward and back compat machinery and remove this temporary safety
measure. 

The current kernel module is developed against the RHEL/CentOS 7.x
kernel to minimize the friction of developing and testing with partners'
existing infrastructure.  Once we're happy with the design we'll shift
development to the upstream kernel while maintaining distro
compatibility branches.

# Community Mailing List

Please join us on the open scoutfs-devel@scoutfs.org [mailing list
hosted on Google Groups](https://groups.google.com/a/scoutfs.org/forum/#!forum/scoutfs-devel)
for all discussion of scoutfs.

# Quick Start

**This following a very rough example of the procedure to get up and
running, experience will be needed to fill in the gaps.  We're happy to
help on the mailing list.**

The requirements for running scoutfs on a small cluster are:

 1. One or more nodes running x86-64 CentOS/RHEL 7.4 (or 7.3)
 2. Access to a single shared block device
 3. IPv4 connectivity between the nodes

The steps for getting scoutfs mounted and operational are:

 1. Get the kernel module running on the nodes
 2. Make a new filesystem on the device with the userspace utilities
 3. Mount the device on all the nodes

In this example we run all of these commands on three nodes.  The block
device name is the same on all the nodes.

1. Get the Kernel Module and Userspace Binaries

   * Either use snapshot RPMs built from git by Versity:

   ```shell
   rpm -i https://scoutfs.s3-us-west-2.amazonaws.com/scoutfs-repo-0.0.1-1.el7_4.noarch.rpm
   yum install scoutfs-utils kmod-scoutfs
   ```

   * Or use the binaries built from checked out git repositories:

   ```shell
   yum install kernel-devel
   git clone git@github.com:versity/scoutfs-kmod-dev.git
   make -C scoutfs-kmod-dev module 
   modprobe libcrc32c
   insmod scoutfs-kmod-dev/src/scoutfs.ko

   git clone git@github.com:versity/scoutfs-utils-dev.git
   make -C scoutfs-utils-dev
   alias scoutfs=$PWD/scoutfs-utils-dev/src/scoutfs
   ```

2. Make a New Filesystem (**destroys contents, no questions asked**)

   We specify that two of our three nodes must be present to form a
   quorum for the system to function.

   ```shell
   scoutfs mkfs -Q 2 /dev/shared_block_device
   ```

3. Mount the Filesystem

   Each mounting node provides its local IP address on which it will run
   an internal server for the other mounts if it is elected the leader by
   the quorum.

   ```shell
   mkdir /mnt/scoutfs
   mount -t scoutfs -o server_address=$NODE_ADDR /dev/shared_block_device /mnt/scoutfs
   ```

4. For Kicks, Observe the Metadata Change Index

   The `meta_seq` index tracks the inodes that are changed in each
   transaction.

   ```shell
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/one; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/two; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/one; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   ```
