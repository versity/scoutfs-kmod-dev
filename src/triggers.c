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
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/debugfs.h>

#include "super.h"
#include "triggers.h"

/*
 * We have debugfs files we can write to which arm triggers which
 * atomically fire once for testing or debugging.
 */

/*
 * The atomic cachelines are kept hot and shared by being read by fast
 * paths.  They're very rarely modified by debugfs writes which arm them
 * and then the next read will atomically clear and return true.
 */
struct scoutfs_triggers {
	struct dentry *dir;
	atomic_t atomics[SCOUTFS_TRIGGER_NR];
};

#define DECLARE_TRIGGERS(sb, name) \
	struct scoutfs_triggers *name = SCOUTFS_SB(sb)->triggers

static char *names[] = {
	[SCOUTFS_TRIGGER_BTREE_STALE_READ] = "btree_stale_read",
	[SCOUTFS_TRIGGER_HARD_STALE_ERROR] = "hard_stale_error",
	[SCOUTFS_TRIGGER_SEG_STALE_READ] = "seg_stale_read",
	[SCOUTFS_TRIGGER_STATFS_LOCK_PURGE] = "statfs_lock_purge",
};

bool scoutfs_trigger_test_and_clear(struct super_block *sb, unsigned int t)
{
	DECLARE_TRIGGERS(sb, triggers);
	atomic_t *atom;
	int old;
	int mem;

	BUG_ON(t >= SCOUTFS_TRIGGER_NR);
	atom = &triggers->atomics[t];

	mem = atomic_read(atom);
	if (likely(!mem))
		return 0;

	do {
		old = mem;
		mem = atomic_cmpxchg(atom, old, 0);
	} while (mem && mem != old);

	return !!mem;
}

int scoutfs_setup_triggers(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_triggers *triggers;
	int ret;
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(names) != SCOUTFS_TRIGGER_NR);

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (WARN_ON(!names[i]))
			return -EINVAL;
	}

	triggers = kzalloc(sizeof(struct scoutfs_triggers), GFP_KERNEL);
	if (!triggers)
		return -ENOMEM;

	sbi->triggers = triggers;

	triggers->dir = debugfs_create_dir("trigger", sbi->debug_root);
	if (!triggers->dir) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(triggers->atomics); i++) {
		if (!debugfs_create_atomic_t(names[i], 0644, triggers->dir,
					     &triggers->atomics[i])) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = 0;
out:
	if (ret)
		scoutfs_destroy_triggers(sb);
	return ret;
}

void scoutfs_destroy_triggers(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_triggers *triggers = sbi->triggers;

	if (triggers) {
		if (triggers->dir)
			debugfs_remove_recursive(triggers->dir);
		kfree(triggers);
		sbi->triggers = NULL;
	}
}
