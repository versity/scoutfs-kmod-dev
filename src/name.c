/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/crc32c.h>
#include <linux/string.h>

#include "name.h"

/*
 * XXX This crc nonsense is a quick hack.  We'll want something a
 * lot stronger like siphash.
 */
u64 scoutfs_name_hash(const char *name, unsigned int len)
{
	unsigned int half = (len + 1) / 2;

	return crc32c(~0, name, half) |
	       ((u64)crc32c(~0, name + len - half, half) << 32);
}

int scoutfs_names_equal(const char *name_a, int len_a,
			       const char *name_b, int len_b)
{
	return (len_a == len_b) && !memcmp(name_a, name_b, len_a);
}
