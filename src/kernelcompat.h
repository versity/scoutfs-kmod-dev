#ifndef _SCOUTFS_KERNELCOMPAT_H_
#define _SCOUTFS_KERNELCOMPAT_H_

#ifndef KC_ITERATE_DIR_CONTEXT
#include <linux/fs.h>
typedef filldir_t kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, dirent, ctx)
#define KC_FOP_READDIR readdir
#define kc_readdir_pos(filp, ctx) (filp)->f_pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, dirent, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	(ctx(dirent, name, name_len, pos, ino, dt) == 0)
#else
typedef struct dir_context * kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, ctx)
#define KC_FOP_READDIR iterate
#define kc_readdir_pos(filp, ctx) (ctx)->pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	dir_emit(ctx, name, name_len, ino, dt)
#endif

#ifndef KC_DIR_EMIT_DOTS
/*
 * Kernels before ->iterate and don't have dir_emit_dots so we give them
 * one that works with the ->readdir() filldir() method.
 */
static inline int dir_emit_dots(struct file *file, void *dirent,
				filldir_t filldir)
{
	if (file->f_pos == 0) {
		if (filldir(dirent, ".", 1, 1,
			    file->f_path.dentry->d_inode->i_ino, DT_DIR))
			return 0;
		file->f_pos = 1;
	}

	if (file->f_pos == 1) {
		if (filldir(dirent, "..", 2, 1,
			    parent_ino(file->f_path.dentry), DT_DIR))
			return 0;
		file->f_pos = 2;
	}

	return 1;
}
#endif

#endif
