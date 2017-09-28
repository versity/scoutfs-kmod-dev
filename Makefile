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

SCOUTFS_GIT_DESCRIBE := \
	$(shell git describe --all --abbrev=6 --long 2>/dev/null || \
		echo not-in-a-git-repository)

SCOUTFS_ARGS := SCOUTFS_GIT_DESCRIBE=$(SCOUTFS_GIT_DESCRIBE) \
		CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(CURDIR)/src \
		EXTRA_CFLAGS=-Werror

all: module

module:
	make $(SCOUTFS_ARGS)
	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(SCOUTFS_ARGS)

clean:
	make $(SCOUTFS_ARGS) clean
