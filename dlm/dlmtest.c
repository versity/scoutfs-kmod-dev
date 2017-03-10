#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/atomic.h>

#include "include/linux/dlm.h"

static atomic_t granted;
static atomic_t blocking;
static int val = 1;
static dlm_lockspace_t *ls;
static char *lockres_name = "test_resource";

struct lockinfo {
	char *lockname;
	int unlocking;
	u64	start;
	u64	end;
	struct dlm_key startkey;
	struct dlm_key endkey;
	struct dlm_lksb	lksb;
};

static inline void set_lock_endpoints(struct lockinfo *lock, u64 start, u64 end)
{
	lock->start = cpu_to_be64(start);
	lock->startkey.val = &lock->start;
	lock->startkey.len = sizeof(lock->start);
	lock->end = cpu_to_be64(end);
	lock->endkey.val = &lock->end;
	lock->endkey.len = sizeof(lock->end);
}

#define	NUM_LOCKS	3
static struct lockinfo locks[NUM_LOCKS] = {
	{ "lock0", },
	{ "lock1", },
	{ "lock2", },
};

static int glbl_exmode = 0;
module_param(glbl_exmode, int, 0);
MODULE_PARM_DESC(glbl_exmode, "Take global lock exclusively.");

static void init_counters(void)
{
	atomic_set(&granted, 0);
	atomic_set(&blocking, 0);
	val = 1;
}

static void wait_for_blocking_asts(int count)
{
	printk("wait for %d blocking asts\n", count);
	while (atomic_read(&blocking) != count) {
		printk("blocking: %d\n", atomic_read(&blocking));
		msleep_interruptible(2000);
	}
}

static void wait_for_lock_grants(int count)
{
	printk("wait for %d grants\n", count);
	while (atomic_read(&granted) != count) {
		printk("granted: %d\n", atomic_read(&granted));
		msleep_interruptible(2000);
	}
}

static void grant_function(void *arg)
{
	char *name = arg;
	printk("lock %s granted\n", name);
	atomic_add(val, &granted);
}

static void blocking_function(void *arg, int mode, struct dlm_key *start,
			      struct dlm_key *end)
{
	char *name = arg;
	BUG_ON(!start);
	BUG_ON(!end);
	printk("lock %s blocking mode %d, range (%llu, %llu)\n", name, mode,
	       be64_to_cpu(*((u64 *)start->val)), be64_to_cpu(*((u64 *)end->val)));
	atomic_inc(&blocking);
}

static int _test_lock(unsigned int lockidx, unsigned int mode,
		      unsigned long long start, unsigned long long end,
		      unsigned int flags)
{
	struct lockinfo *lock = &locks[lockidx];

	BUG_ON(lockidx > NUM_LOCKS);

	set_lock_endpoints(lock, start, end);

	printk("lock %s (%u, %llu, %llu)\n", lock->lockname, mode, start, end);
	return dlm_lock_range(ls, mode, &lock->startkey, &lock->endkey,
			      &lock->lksb, flags, lockres_name,
			      strlen(lockres_name), 0, grant_function,
			      lock->lockname, blocking_function);
}

static inline int test_lock(unsigned int lockidx, unsigned int mode,
			    unsigned long long start, unsigned long long end)
{
	return _test_lock(lockidx, mode, start, end, 0);
}

static inline int test_convert(unsigned int lockidx, unsigned int mode,
			       unsigned long long start,
			       unsigned long long end)
{
	return _test_lock(lockidx, mode, start, end, DLM_LKF_CONVERT);
}

static int test_unlock(int lockidx)
{
	struct lockinfo *lock = &locks[lockidx];

	printk("unlock %s (%llu, %llu)\n", lock->lockname,
	       be64_to_cpu(lock->start), be64_to_cpu(lock->end));
	return dlm_unlock(ls, lock->lksb.sb_lkid, 0, &lock->lksb, lock->lockname);
}

static int test_locking(void)
{
	int ret;

	printk("Test basic lock/unlock.\n");

	init_counters();

	ret = test_lock(0, DLM_LOCK_EX, 0, 16384);
	if (ret)
		goto out;

	ret = test_lock(1, DLM_LOCK_EX, 16385, 32768);
	if (ret)
		goto out;

	wait_for_lock_grants(2);

	ret = test_lock(2, DLM_LOCK_EX, 0, 32768);
	if (ret)
		goto out;

	wait_for_blocking_asts(2);

	val = -1;

	ret = test_unlock(0);
	if (ret)
		goto out;
	ret = test_unlock(1);
	if (ret)
		goto out;

	wait_for_lock_grants(-1);

	ret = test_unlock(2);
	if (ret)
		goto out;

	wait_for_lock_grants(-2);

out:
	return ret;
}

static int test_lock_conversions(void)
{
	int ret;

	printk("Test lock conversions\n");

	init_counters();

	ret = test_lock(0, DLM_LOCK_PR, 0, 16384);
	if (ret)
		goto out;

	ret = test_lock(1, DLM_LOCK_PR, 16385, 32768);
	if (ret)
		goto out;

	ret = test_lock(2, DLM_LOCK_PR, 0, 32768);
	if (ret)
		goto out;

	wait_for_lock_grants(3);

	ret = test_convert(0, DLM_LOCK_EX, 0, 16384);
	if (ret)
		goto out;

	wait_for_blocking_asts(2);

	init_counters();

	ret = test_convert(1, DLM_LOCK_NL, 16385, 32768);
	if (ret)
		goto out;
	ret = test_convert(2, DLM_LOCK_NL, 0, 32768);
	if (ret)
		goto out;

	wait_for_lock_grants(3);

	init_counters();

	ret = test_unlock(1);
	if (ret)
		goto out;
	ret = test_unlock(2);
	if (ret)
		goto out;

	ret = test_unlock(0);
	if (ret)
		goto out;

	wait_for_lock_grants(3);

out:
	return ret;
}

#define	glbl_res	"global"
#define	glbl_res_len	strlen(glbl_res)
static atomic_t	glbl_grants;
static struct dlm_lksb glbl_lksb;

static void glbl_granted(void *arg)
{
	printk("Got global lock at %d mode\n", *((int *) arg));
	atomic_set(&glbl_grants, 1);
}

static void glbl_blocking(void *arg, int mode)
{
	printk("Global lock at %d mode blocking %d lock\n", *((int *)arg), mode);
}

static int test_multinode(void)
{
	int ret;
	int mode = DLM_LOCK_EX;

	printk("Test a global lock\n");

	ret = dlm_lock(ls, mode, &glbl_lksb, 0, glbl_res, glbl_res_len, 0,
		       glbl_granted, &mode, glbl_blocking);
	if (ret)
		return ret;

	while (!atomic_read(&glbl_grants))
		msleep_interruptible(5000);

	mode = 0;
	ret = dlm_unlock(ls, glbl_lksb.sb_lkid, 0, &glbl_lksb, &mode);
	return ret;
}

static int __init init_dlm_test(void)
{
	int ret;

	printk("dlmtest loaded!\n");

	ret = dlm_new_lockspace("lockspace", "scoutfs",
				DLM_LSFL_FS|DLM_LSFL_NEWEXCL, 8, NULL, NULL,
				NULL, &ls);
	if (ret) {
		printk("new_lockspace returns %d\n", ret);
		return ret;
	}

	ret = test_multinode();
	if (!ret)
		ret = test_locking();
	if (!ret)
		ret = test_lock_conversions();

	if (ret)
		printk("FAILURE: Locking test returns %d\n", ret);
	else
		printk("Locking test completed with no errors.\n");

	return 0;
}

static void __exit exit_dlm_test(void)
{
	int ret;

	ret = dlm_release_lockspace(ls, 1);
	printk("dlmtest unloaded (ret=%d)!\n", ret);
}

module_init(init_dlm_test);
module_exit(exit_dlm_test);

MODULE_DESCRIPTION("dlmtest");
MODULE_AUTHOR("Mark Fasheh");
MODULE_LICENSE("GPL");
