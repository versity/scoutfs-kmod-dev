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
		echo no-git)

SCOUTFS_FORMAT_HASH := \
	$(shell cat src/format.h src/ioctl.h | md5sum | cut -b1-16)

SCOUTFS_ARGS := SCOUTFS_GIT_DESCRIBE=$(SCOUTFS_GIT_DESCRIBE) \
		SCOUTFS_FORMAT_HASH=$(SCOUTFS_FORMAT_HASH) \
		CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(CURDIR)/src \
		EXTRA_CFLAGS="-Werror"

# - We use the git describe from tags to set up the RPM versioning
RPM_VERSION := $(shell git describe --long --tags | awk -F '-' '{gsub(/^v/,""); print $$1}')
RPM_GITHASH := $(shell git rev-parse --short HEAD)
TARFILE = scoutfs-kmod-$(RPM_VERSION).tar


.PHONY: .FORCE

all: module

module:
	make $(SCOUTFS_ARGS)
	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(SCOUTFS_ARGS)


modules_install:
	make $(SCOUTFS_ARGS) modules_install


%.spec: %.spec.in .FORCE
	sed -e 's/@@VERSION@@/$(RPM_VERSION)/g' \
	    -e 's/@@GITHASH@@/$(RPM_GITHASH)/g' < $< > $@+
	mv $@+ $@


dist: scoutfs-kmod.spec
	git archive --format=tar --prefix scoutfs-kmod-$(RPM_VERSION)/ HEAD^{tree} > $(TARFILE)
	@ tar rf $(TARFILE) --transform="s@\(.*\)@scoutfs-$(RPM_VERSION)/\1@" scoutfs-kmod.spec

clean:
	make $(SCOUTFS_ARGS) clean
