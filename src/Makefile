obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_super.o = -DSCOUTFS_GIT_DESCRIBE=\"$(SCOUTFS_GIT_DESCRIBE)\" \
		 -DSCOUTFS_FORMAT_HASH=0x$(SCOUTFS_FORMAT_HASH)LLU

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += bio.o btree.o client.o compact.o counters.o data.o dir.o \
	     export.o extents.o file.o inode.o ioctl.o item.o lock.o \
	     manifest.o msg.o options.o per_task.o seg.o server.o \
	     scoutfs_trace.o sock.o sort_priv.o super.o sysfs.o trans.o \
	     triggers.o xattr.o

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
