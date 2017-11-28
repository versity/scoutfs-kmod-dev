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

SCOUTFS_FORMAT_HASH := \
	$(shell cat src/format.h src/ioctl.h | md5sum | cut -b1-16)

SCOUTFS_ARGS := SCOUTFS_GIT_DESCRIBE=$(SCOUTFS_GIT_DESCRIBE) \
		SCOUTFS_FORMAT_HASH=$(SCOUTFS_FORMAT_HASH) \
		CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(CURDIR)/src \
		EXTRA_CFLAGS="-Werror"

# move damage locally, this will also help make it easier to cleanup after the build
RPM_DIR = $(shell pwd)/rpmbuild

# - We use the git describe from tags to set up the RPM versioning
RPM_VERSION := $(shell git describe --long --tags | awk -F '-' '{gsub(/^v/,""); print $$1}')
RPM_RELEASE := $(shell git describe --long --tags | awk -F '-' '{print $$2"."$$3}')
FULL_VERSION := $(RPM_VERSION).$(RPM_RELEASE)
TARFILE = $(RPM_DIR)/SOURCES/scoutfs-kmod-$(FULL_VERSION).tar

.PHONY: .FORCE

all: module

module:
	make $(SCOUTFS_ARGS)
	$(SP) make C=2 CF="-D__CHECK_ENDIAN__" $(SCOUTFS_ARGS)


modules_install:
	make $(SCOUTFS_ARGS) modules_install


# remake this each time..
$(RPM_DIR): .FORCE
	@echo "## Clean up on isle $(RPM_DIR)..."
	rm -frv $(RPM_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	mkdir -p $(RPM_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}


%.spec: %.spec.in .FORCE
	sed -e 's/@@VERSION@@/$(RPM_VERSION)/g' \
		-e s'/@@TAR_VERSION@@/$(FULL_VERSION)/g' \
		-e s'/@@RELEASE@@/$(RPM_RELEASE)/g' < $< > $@+
	mv $@+ $@


# NOTE: Both tar & rpm are capable of being built natively on Linux, provided
# you have a local install of rpmbuild.sh for the rpm target.
# Normal exection is to use docker, as that pulls our canned image and tooling for the user.
# ./indocker.sh make tar
# ./indocker.sh make rpm
#
tar: $(RPM_DIR) scoutfs-kmod.spec
	git archive --format=tar --prefix scoutfs-$(FULL_VERSION)/ HEAD^{tree} > $(TARFILE)
	@ tar rf $(TARFILE) --transform="s@\(.*\)@scoutfs-$(FULL_VERSION)/\1@" scoutfs-kmod.spec
	gzip -f -9 $(TARFILE)


$(TARFILE).gz: tar

rpm: $(TARFILE).gz scoutfs-kmod.spec
	rpmbuild.sh $(TARFILE).gz


clean:
	make $(SCOUTFS_ARGS) clean
