ALL: module

#
# SK_KSRC points to the kernel header build dir to build against.
# On a running machine this could be /lib/modules/$(uname -r)/build with
# the right kernel-headers package installed.  I tend to build on other
# hosts so I extract the kernel-headers package for the target machine's
# kernel in a dir somehere.
#
# sparse is critical for avoiding endian mistakes.  It should just work
# if the sparse package is installed.
#
# but sometimes kernel-headers are broken.    For example, the
# rhel 3.10.0-327.el7.x86_64 kernel needs the following patch.
# We'll try to have a git tree with fixed headers.
#
#
# diff --git a/include/linux/rh_kabi.h b/include/linux/rh_kabi.h
# index 1767770..0a8e5f3 100644
# --- a/include/linux/rh_kabi.h
# +++ b/include/linux/rh_kabi.h
# @@ -73,7 +73,6 @@
#                 struct {                                \
#                         _orig;                          \
#                 } __UNIQUE_ID(rh_kabi_hide);            \
# -               __RH_KABI_CHECK_SIZE_ALIGN(_orig, _new);        \
#         }
#
#  #define _RH_KABI_REPLACE_UNSAFE(_orig, _new)   _new

module:
	make CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(PWD)/src
	make C=2 CF="-D__CHECK_ENDIAN__" CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(PWD)/src
