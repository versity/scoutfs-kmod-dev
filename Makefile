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

ARGS := CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(CURDIR)/src

all: module

module:
	make $(ARGS)
	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(ARGS)

clean:
	make $(ARGS) clean
