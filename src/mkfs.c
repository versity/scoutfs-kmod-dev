#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/random.h>

#include "super.h"
#include "item.h"
#include "key.h"
#include "mkfs.h"

/*
 * For now a file system system only exists in the item cache for the
 * duration of the mount.  This "mkfs" hack creates a root dir inode in
 * the item cache on mount so that we can run tests in memory and not
 * worry about user space or persistent storage.
 */
int scoutfs_mkfs(struct super_block *sb)
{
	const struct timespec ts = current_kernel_time();
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_inode *cinode;
	struct scoutfs_item *item;
	struct scoutfs_key key;
	int i;

	atomic64_set(&sbi->next_ino, SCOUTFS_ROOT_INO + 1);
	atomic64_set(&sbi->next_blkno, 2);

	for (i = 0; i < ARRAY_SIZE(sbi->bloom_hash_keys); i++) {
		get_random_bytes(&sbi->bloom_hash_keys[i],
				 sizeof(sbi->bloom_hash_keys[i]));
	}

	scoutfs_set_key(&key, SCOUTFS_ROOT_INO, SCOUTFS_INODE_KEY, 0);

	item = scoutfs_item_create(sb, &key, sizeof(struct scoutfs_inode));
	if (IS_ERR(item))
		return PTR_ERR(item);

	cinode = item->val;
	memset(cinode, 0, sizeof(struct scoutfs_inode));
	cinode->nlink = cpu_to_le32(2);
	cinode->mode = cpu_to_le32(S_IFDIR | 0755);
	cinode->atime.sec = cpu_to_le64(ts.tv_sec);
	cinode->atime.nsec = cpu_to_le32(ts.tv_nsec);
	cinode->ctime = cinode->atime;
	cinode->mtime = cinode->atime;
	get_random_bytes(&cinode->salt, sizeof(cinode->salt));

	scoutfs_item_put(item);
	return 0;
}
