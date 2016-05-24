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
#include <linux/random.h>

#include "super.h"
#include "wire.h"
#include "wrlock.h"
#include "roster.h"

/*
 * The roster tracks all the mounts on nodes that are working with a
 * scoutfs volume.
 *
 * This trivial first pass lets us test multiple mounts on the same
 * node.  It'll get a lot more involved as all the nodes manage a roster
 * in the shared device.
 */
static DEFINE_MUTEX(roster_mutex);
static u64 roster_next_id = 1;
static LIST_HEAD(roster_list);

/*
 * A new mount is adding itself to the roster.  It gets a new increasing
 * id assigned and all the other mounts are told that it's now a member.
 */
int scoutfs_roster_add(struct super_block *sb)
{
	struct scoutfs_sb_info *us = SCOUTFS_SB(sb);
	struct scoutfs_sb_info *them;

	mutex_lock(&roster_mutex);
	list_add_tail(&us->roster_head, &roster_list);
	us->roster_id = roster_next_id++;

	list_for_each_entry(them, &roster_list, roster_head) {
		if (us->roster_id != them->roster_id) {
			scoutfs_wrlock_roster_update(them->sb, us->roster_id,
						     true);
		}
	}

	mutex_unlock(&roster_mutex);

	return 0;
}

/*
 * A mount is removing itself to the roster.  All the other remaining
 * mounts are told that it has gone away.
 *
 * This is safe to call without having called _add.
 */
void scoutfs_roster_remove(struct super_block *sb)
{
	struct scoutfs_sb_info *us = SCOUTFS_SB(sb);
	struct scoutfs_sb_info *them;

	mutex_lock(&roster_mutex);

	if (!list_empty(&us->roster_head)) {
		list_del_init(&us->roster_head);

		list_for_each_entry(them, &roster_list, roster_head)
			scoutfs_wrlock_roster_update(them->sb, us->roster_id,
						     false);
	}

	mutex_unlock(&roster_mutex);
}

static int process_message(struct super_block *sb, u64 peer_id,
			   struct scoutfs_message *msg)
{
	int ret = 0;

	switch (msg->cmd) {
		case SCOUTFS_MSG_WRLOCK_REQUEST:
			ret = scoutfs_wrlock_process_request(sb, peer_id,
							     &msg->request);
			break;
		case SCOUTFS_MSG_WRLOCK_GRANT:
			scoutfs_wrlock_process_grant(sb, &msg->grant);
			ret = 0;
			break;
		default:
			ret = -EINVAL;
	}

	return ret;
}

/*
 * Send a message to a specific member of the roster identified by its
 * id.
 *
 * We don't actually send anything, we call directly into the receivers
 * message processing path with the caller's message.
 */
void scoutfs_roster_send(struct super_block *sb, u64 peer_id,
			 struct scoutfs_message *msg)
{
	struct scoutfs_sb_info *us = SCOUTFS_SB(sb);
	struct scoutfs_sb_info *them;
	int ret;

	mutex_lock(&roster_mutex);

	list_for_each_entry(them, &roster_list, roster_head) {
		if (them->roster_id == peer_id) {
			ret = process_message(them->sb, us->roster_id, msg);
			break;
		}
	}

	/* XXX errors? */

	mutex_unlock(&roster_mutex);
}

/*
 * Send a message to all of the current members which have an id greater
 * than the caller's specified id.
 *
 * We don't actually send anything, we call directly into the receivers
 * message processing path with the caller's message.
 */
void scoutfs_roster_broadcast(struct super_block *sb, u64 since_id,
			      struct scoutfs_message *msg)
{
	struct scoutfs_sb_info *us = SCOUTFS_SB(sb);
	struct scoutfs_sb_info *them;
	int ret;

	mutex_lock(&roster_mutex);

	list_for_each_entry(them, &roster_list, roster_head) {
		if (us->roster_id != them->roster_id &&
		    them->roster_id > since_id) {
			ret = process_message(them->sb, us->roster_id, msg);
			if (ret)
				break;
		}
	}

	/* XXX errors? */

	mutex_unlock(&roster_mutex);
}
