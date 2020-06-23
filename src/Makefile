obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_super.o = -DSCOUTFS_GIT_DESCRIBE=\"$(SCOUTFS_GIT_DESCRIBE)\" \
		 -DSCOUTFS_FORMAT_HASH=0x$(SCOUTFS_FORMAT_HASH)LLU

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include

# add EXTRA_CFLAGS defines for kernel compat
-include $(src)/Makefile.kernelcompat
 
scoutfs-y +=			\
	avl.o			\
	block.o			\
	btree.o			\
	client.o		\
	counters.o		\
	data.o			\
	dir.o			\
	export.o		\
	file.o			\
	forest.o		\
	inode.o			\
	ioctl.o			\
	lock.o			\
	lock_server.o		\
	msg.o			\
	net.o			\
	options.o		\
	per_task.o		\
	quorum.o		\
	radix.o			\
	scoutfs_trace.o		\
	server.o		\
	spbm.o			\
	srch.o			\
	super.o			\
	sysfs.o			\
	trans.o			\
	triggers.o		\
	tseq.o			\
	xattr.o

#
# The raw types aren't available in userspace headers.  Make sure all
# the types we use in the headers are the exported __ versions.
#
# XXX dunno how we're really supposed to do this in kbuild
#
.PHONY: $(src)/check_exported_types
$(src)/check_exported_types:
	@if egrep '\<[us](8|16|32|64\>)' $(src)/format.h $(src)/ioctl.h; then \
		echo "no raw types in exported headers, preface with __";     \
		exit 1;							      \
	fi

extra-y += check_exported_types
