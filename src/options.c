/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/debugfs.h>

#include <linux/parser.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/in.h>

#include "msg.h"
#include "options.h"
#include "super.h"

static const match_table_t tokens = {
	{Opt_uniq_name, "uniq_name=%s"},
	{Opt_err, NULL}
};

struct options_sb_info {
	struct dentry *debugfs_dir;
	u32 btree_force_tiny_blocks;
};

u32 scoutfs_option_u32(struct super_block *sb, int token)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct options_sb_info *osi = sbi->options;

	switch(token) {
		case Opt_btree_force_tiny_blocks:
			return osi->btree_force_tiny_blocks;
	}

	WARN_ON_ONCE(1);
	return 0;
}

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed)
{
	substring_t args[MAX_OPT_ARGS];
	int token, len;
	char *p;

	/* Set defaults */
	memset(parsed, 0, sizeof(*parsed));

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uniq_name:
			len = match_strlcpy(parsed->uniq_name, args,
					    SCOUTFS_UNIQUE_NAME_MAX_BYTES);
			if (len == 0 || len > SCOUTFS_UNIQUE_NAME_MAX_BYTES)
				return -EINVAL;
			break;
		default:
			scoutfs_err(sb, "Unknown or malformed option, \"%s\"",
				    p);
			break;
		}
	}

	if (parsed->uniq_name[0] == '\0') {
		scoutfs_err(sb, "must provide a uniq_name option");
		return -EINVAL;
	}

	return 0;
}

int scoutfs_options_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct options_sb_info *osi;
	int ret;

	osi = kzalloc(sizeof(struct options_sb_info), GFP_KERNEL);
	if (!osi)
		return -ENOMEM;

	sbi->options = osi;

	osi->debugfs_dir = debugfs_create_dir("options", sbi->debug_root);
	if (!osi->debugfs_dir) {
		ret = -ENOMEM;
		goto out;
	}

	if (!debugfs_create_bool("btree_force_tiny_blocks", 0644,
				 osi->debugfs_dir,
				 &osi->btree_force_tiny_blocks)) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_options_destroy(sb);
	return ret;
}

void scoutfs_options_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct options_sb_info *osi = sbi->options;

	if (osi) {
		if (osi->debugfs_dir)
			debugfs_remove_recursive(osi->debugfs_dir);
		kfree(osi);
		sbi->options = NULL;
	}
}
