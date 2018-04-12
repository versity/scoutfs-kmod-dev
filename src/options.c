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
	{Opt_listen, "listen=%s"},
	{Opt_cluster, "cluster=%s"},
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
	char ipstr[INET_ADDRSTRLEN + 1];
	substring_t args[MAX_OPT_ARGS];
	int token, len;
	__be32 addr;
	char *p;

	/* Set defaults */
	memset(parsed, 0, sizeof(*parsed));
	strcpy(parsed->cluster_name, "scoutfs");

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_listen:
			match_strlcpy(ipstr, args, ARRAY_SIZE(ipstr));
			addr = in_aton(ipstr);
			if (ipv4_is_multicast(addr) || ipv4_is_lbcast(addr) ||
			    ipv4_is_zeronet(addr) || ipv4_is_local_multicast(addr))
				return -EINVAL;
			parsed->listen_addr.addr =
				cpu_to_le32(be32_to_cpu(addr));
			break;
		case Opt_cluster:
			len = args[0].to - args[0].from;
			if (len == 0 || len > (MAX_CLUSTER_NAME_LEN - 1))
				return -EINVAL;
			match_strlcpy(parsed->cluster_name, args,
				      MAX_CLUSTER_NAME_LEN);
			break;
		default:
			scoutfs_err(sb, "Unknown or malformed option, \"%s\"\n",
				    p);
			break;
		}
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
