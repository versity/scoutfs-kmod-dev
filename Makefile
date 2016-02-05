ALL: module

module:
	make CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(PWD)/src
