/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/exportfs.h>

#include "export.h"
#include "inode.h"
#include "dir.h"
#include "format.h"
#include "scoutfs_trace.h"

/* describe the length of the fileid type in terms of number of u32's used. */
static int scoutfs_fileid_len(int fh_type)
{
	switch (fh_type) {
	case FILEID_SCOUTFS:
		return 2;
	case FILEID_SCOUTFS_WITH_PARENT:
		return 4;
	}
	return FILEID_INVALID;
}

static bool scoutfs_valid_fileid(int fh_type)
{
	return scoutfs_fileid_len(fh_type) != FILEID_INVALID;
}

static int scoutfs_encode_fh(struct inode *inode, __u32 *fh, int *max_len,
			     struct inode *parent)
{
	struct scoutfs_fid *fid = (struct scoutfs_fid *)fh;
	int fh_type = FILEID_SCOUTFS;
	int len;

	if (parent)
		fh_type = FILEID_SCOUTFS_WITH_PARENT;

	len = scoutfs_fileid_len(fh_type);

	if (*max_len < len) {
		*max_len = len;
		return FILEID_INVALID;
	}
	*max_len = len;

	fid->ino = cpu_to_le64(scoutfs_ino(inode));
	if (parent)
		fid->parent_ino = cpu_to_le64(scoutfs_ino(parent));

	trace_scoutfs_encode_fh(inode->i_sb, fh_type, fid);

	return fh_type;
}

static struct dentry *scoutfs_fh_to_dentry(struct super_block *sb,
					   struct fid *fid, int fh_len,
					   int fh_type)
{
	struct scoutfs_fid *sfid = (struct scoutfs_fid *)fid;
	struct inode *inode = NULL;

	if (fh_len < scoutfs_fileid_len(fh_type))
		return NULL;

	trace_scoutfs_fh_to_dentry(sb, fh_type, sfid);

	if (scoutfs_valid_fileid(fh_type))
		inode = scoutfs_iget(sb, le64_to_cpu(sfid->ino));

	return d_obtain_alias(inode);
}

static struct dentry *scoutfs_fh_to_parent(struct super_block *sb,
					   struct fid *fid, int fh_len,
					   int fh_type)
{
	struct scoutfs_fid *sfid = (struct scoutfs_fid *)fid;
	struct inode *inode = NULL;

	if (fh_len < scoutfs_fileid_len(fh_type))
		return NULL;

	trace_scoutfs_fh_to_parent(sb, fh_type, sfid);

	if (scoutfs_valid_fileid(fh_type) &&
	    fh_type == FILEID_SCOUTFS_WITH_PARENT)
		inode = scoutfs_iget(sb, le64_to_cpu(sfid->parent_ino));

	return d_obtain_alias(inode);
}

static struct dentry *scoutfs_get_parent(struct dentry *child)
{
	struct inode *inode = child->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_link_backref_entry *ent;
	LIST_HEAD(list);
	int ret;
	u64 ino;

	ret = scoutfs_dir_add_next_linkref(sb, scoutfs_ino(inode), 0, NULL, 0,
					   &list);
	if (ret)
		return ERR_PTR(ret);

	ent = list_first_entry(&list, struct scoutfs_link_backref_entry, head);
	ino = be64_to_cpu(ent->lbkey.dir_ino);
	scoutfs_dir_free_backref_path(sb, &list);
	trace_scoutfs_get_parent(sb, inode, ino);

	inode = scoutfs_iget(sb, ino);

	return d_obtain_alias(inode);
}

static int scoutfs_get_name(struct dentry *parent, char *name,
			    struct dentry *child)
{
	u64 dir_ino = scoutfs_ino(parent->d_inode);
	struct scoutfs_link_backref_entry *ent;
	struct inode *inode = child->d_inode;
	struct super_block *sb = inode->i_sb;
	LIST_HEAD(list);
	int ret;

	ret = scoutfs_dir_add_next_linkref(sb, scoutfs_ino(inode), dir_ino,
					   NULL, 0, &list);
	if (ret)
		return ret;

	ret = -ENOENT;
	ent = list_first_entry(&list, struct scoutfs_link_backref_entry, head);
	if (be64_to_cpu(ent->lbkey.ino) == scoutfs_ino(inode) &&
	    be64_to_cpu(ent->lbkey.dir_ino) == dir_ino &&
	    ent->name_len <= NAME_MAX) {
		memcpy(name, ent->lbkey.name, ent->name_len);
		name[ent->name_len] = '\0';
		ret = 0;
		trace_scoutfs_get_name(sb, parent->d_inode, inode, name);
	}
	scoutfs_dir_free_backref_path(sb, &list);

	return ret;
}

const struct export_operations scoutfs_export_ops = {
	.encode_fh = scoutfs_encode_fh,
	.fh_to_dentry = scoutfs_fh_to_dentry,
	.fh_to_parent = scoutfs_fh_to_parent,
	.get_parent = scoutfs_get_parent,
	.get_name = scoutfs_get_name,
};
