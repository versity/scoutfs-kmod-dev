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
	{Opt_server_addr, "server_addr=%s"},
	{Opt_err, NULL}
};

struct options_sb_info {
	struct dentry *debugfs_dir;
};

u32 scoutfs_option_u32(struct super_block *sb, int token)
{
	WARN_ON_ONCE(1);
	return 0;
}

/* The caller's string is null terminted and can be clobbered */
static int parse_ipv4(struct super_block *sb, char *str,
		      struct sockaddr_in *sin)
{
	unsigned long port = 0;
	__be32 addr;
	char *c;
	int ret;

	/* null term port, if specified */
	c = strchr(str, ':');
	if (c)
		*c = '\0';

	/* parse addr */
	addr = in_aton(str);
	if (ipv4_is_multicast(addr) || ipv4_is_lbcast(addr) ||
	    ipv4_is_zeronet(addr) ||
	    ipv4_is_local_multicast(addr)) {
		scoutfs_err(sb, "invalid unicast ipv4 address: %s", str);
		return -EINVAL;
	}

	/* parse port, if specified */
	if (c) {
		c++;
		ret = kstrtoul(c, 0, &port);
		if (ret != 0 || port == 0 || port >= U16_MAX) {
			scoutfs_err(sb, "invalid port in ipv4 address: %s", c);
			return -EINVAL;
		}
	}

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
	sin->sin_port = cpu_to_be16(port);

	return 0;
}

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed)
{
	char ipstr[INET_ADDRSTRLEN + 1];
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *p;
	int ret;

	/* Set defaults */
	memset(parsed, 0, sizeof(*parsed));

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_server_addr:

			match_strlcpy(ipstr, args, ARRAY_SIZE(ipstr));
			ret = parse_ipv4(sb, ipstr, &parsed->server_addr);
			if (ret < 0)
				return ret;
			break;
		default:
			scoutfs_err(sb, "Unknown or malformed option, \"%s\"",
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
