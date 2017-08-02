obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_super.o = -DSCOUTFS_GIT_DESCRIBE=\"$(SCOUTFS_GIT_DESCRIBE)\"

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += alloc.o bio.o btree.o compact.o counters.o data.o dir.o kvec.o \
	     inode.o ioctl.o item.o key.o lock.o manifest.o msg.o net.o \
	     options.o seg.o scoutfs_trace.o sort_priv.o super.o trans.o xattr.o
