obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
scoutfs-y += block.o btree.o counters.o crc.o dir.o filerw.o inode.o msg.o \
	     scoutfs_trace.o super.o treap.o
