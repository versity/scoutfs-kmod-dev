#ifndef _SCOUTFS_PER_TASK_H_
#define _SCOUTFS_PER_TASK_H_

struct scoutfs_per_task {
	spinlock_t lock;
	struct list_head list;
};

struct scoutfs_per_task_entry {
	struct list_head head;
	struct task_struct *task;
	void *ptr;
};

#define SCOUTFS_DECLARE_PER_TASK_ENTRY(name) \
	struct scoutfs_per_task_entry name

void *scoutfs_per_task_get(struct scoutfs_per_task *pt);
void scoutfs_per_task_add(struct scoutfs_per_task *pt,
			  struct scoutfs_per_task_entry *ent, void *ptr);
void scoutfs_per_task_del(struct scoutfs_per_task *pt,
			  struct scoutfs_per_task_entry *ent);
void scoutfs_per_task_init(struct scoutfs_per_task *pt);

#endif
