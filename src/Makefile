obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += block.o bloom.o chunk.o crc.o dir.o filerw.o inode.o manifest.o \
	     msg.o ring.o scoutfs_trace.o segment.o skip.o super.o
