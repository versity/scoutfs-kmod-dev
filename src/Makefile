obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += alloc.o bio.o compact.o counters.o data.o dir.o kvec.o inode.o \
	     ioctl.o item.o key.o lock.o manifest.o msg.o net.o  options.o \
	     ring.o seg.o scoutfs_trace.o super.o trans.o xattr.o
