obj-$(CONFIG_SCOUTFS_FS) := scoutfs.o

CFLAGS_scoutfs_trace.o = -I$(src) # define_trace.h double include
 
#
# these first and last objects are a super lame hack to put boundary
# symbols around trace printf formats that are put in an elf section.
# That should be done in a linker script, of course, but I'll be honest:
# I didn't go digging to see if modules can have linker scripts today.
#
scoutfs-y += first.o

scoutfs-y += block.o btree.o buddy.o counters.o crc.o dir.o filerw.o \
	     inode.o ioctl.o msg.o name.o scoutfs_trace.o super.o trace.o \
	     trans.o treap.o xattr.o

scoutfs-y += last.o
