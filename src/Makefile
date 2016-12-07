obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += alloc.o bio.o block.o btree.o buddy.o counters.o crc.o dir.o \
	     filerw.o kvec.o inode.o ioctl.o item.o manifest.o msg.o name.o \
	     ring.o seg.o scoutfs_trace.o super.o trans.o xattr.o
