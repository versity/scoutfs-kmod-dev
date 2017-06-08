ALL: module

# default to building against the installed source for the running kernel
ifeq ($(SK_KSRC),)
SK_KSRC := $(shell echo /lib/modules/`uname -r`/build)
endif

# fail if sparse fails if we find it
ifeq ($(shell sparse && echo found),found)
SP =
else
SP = @:
endif

SCOUTFS_ARGS := CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) -I $(CURDIR)/dlm/include M=$(CURDIR)/src
DLM_ARGS := CONFIG_DLM=m CONFIG_DLM_DEBUG=y -C $(SK_KSRC) M=$(CURDIR)/dlm

all: module

module:
	make $(DLM_ARGS)
	cp $(CURDIR)/dlm/Module.symvers $(CURDIR)/src/
	make $(SCOUTFS_ARGS)
	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(SCOUTFS_ARGS)
# Do not enable until we can clean up some warnings
#	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(DLM_ARGS)

clean:
	make $(SCOUTFS_ARGS) clean
	make $(DLM_ARGS) clean
