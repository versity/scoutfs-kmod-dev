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
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/uio.h>
#include <linux/debugfs.h>

#include "trace.h"
#include "super.h"
#include "ioctl.h"

/*
 * This tracing gives us:
 *
 *  - Always on.  We get history leading up to an event without having
 *  had to predict the event.
 *
 *  - Cheap.  Recording the format pointer index and packed arguments is
 *  cheap enough that we don't mind always doing it at a reasonable
 *  frequency.
 *
 *  - Trivial to add.  We want to err on the side of too much logging.
 *  We don't want there to be so much garbage associated with adding a
 *  single logging message that people are discouraged from doing it.
 *
 *  - Easy to extract from crash dumps.  The more the computer can tell
 *  us about what happened when the world went sideways, the better.
 *
 *  The implementation is reasonably straight forward.
 *
 * Log statements are simple printf format strings and arguments.  The
 * first trick bit is that we only support u64 arguments.  This lets us
 * use macro hacks to walk the arguments without having to parse the
 * format string.  This actually isn't a great hardship because often
 * the things we might want to print as strings -- process names,
 * xattrs, directory entries -- could in fact be sensitive user data
 * that we don't want to see.
 *
 * Each log statement is packed into a variable byte size record.  The
 * records are packed into long  term per-page pages.  We only support
 * logging from task context so that we don't have to fool around with
 * serializing between contexts on a cpu.  Writers record the number of
 * record bytes stored in each page in page->private.
 *
 * Userspace reads the format strings and trace records from trivial
 * ioctls that copy the entire data set in one go.  This avoids all the
 * nonsense of trying to translate the changing set of records into a
 * seekable byte stream of formatted output.  Readers of each page of
 * records samples page->private to discover when they race with writers
 * and retry.
 */

/*
 * This tries to strike a balance between having enough logging on a cpu
 * and not allocating an enormous amount of memory on systems with many
 * cpus.
 */
#define TRACE_PAGES_PER_CPU DIV_ROUND_UP(256 * 1024, PAGE_SIZE)

struct trace_percpu {
	int cur_page;
	struct page *pages[TRACE_PAGES_PER_CPU];
};

static DEFINE_PER_CPU(struct trace_percpu, scoutfs_trace_percpu);

static int rec_bytes(int bytes)
{
	return offsetof(struct scoutfs_trace_record, data[bytes]);
}

/*
 * We compact the record of the trace format by referencing it with a
 * small offset into a section that contains all the format strings.
 * This shrinks the per-record format reference from an 8 byte pointer
 * to a 2 byte offset.  6 bytes is a lot when records are 15 bytes.
 */
static char *trace_format(u16 off)
{
	return &scoutfs_trace_first_format[1 + off];
}

static u16 trace_format_off(char *fmt)
{
	return fmt - scoutfs_trace_first_format - 1;
}

static int trace_format_bytes(void)
{
	return trace_format_off(scoutfs_trace_last_format);
}

static int valid_trace_format(char *fmt)
{
	return fmt > scoutfs_trace_first_format &&
	       fmt < scoutfs_trace_last_format;
}

/*
 * We only support trace messages with integer arguments.  Most of them
 * are small: counters, pids, sizes, cpus, etc.  It's worth spending a
 * few cycles to remove the leading bytes full of zeros.
 *
 * VLQ is very simple and does reasonably well.  I'd happily consider
 * alternatives with similar complexity but better space efficiency.
 *
 * This is the most boring conservative iterative implementation.  A
 * much cooler implementation would efficiently transform all the bits,
 * store the whole little endian value, and return the number of bytes
 * with bits set.
 */
static unsigned char encode_u64_bytes(u8 *data, u64 val)
{
	unsigned char bytes = 0;

	do {
		*data = val & 127;
		val >>= 7;
		*(data++) += (!!val) << 7;
		bytes++;
	} while (val);

	return bytes;
}

/*
 * Write a trace record to a percpu page.  We only write from task
 * context so one writer is racing with many readers.  Readers sample
 * the count of total written bytes in the page at page private and
 * retry the copy if the count changes.  It's a poor man's seqlock.
 *
 * The calling trace wrapper has pinned our task to the cpu.
 */
void scoutfs_trace_write(char *fmt, int nr, ...)
{
        struct trace_percpu *pcpu = this_cpu_ptr(&scoutfs_trace_percpu);
	struct scoutfs_trace_record *rec;
	struct page *page;
	unsigned long page_bytes;
	int encoded;
	va_list args;
	int i;

	if (WARN_ON_ONCE(in_interrupt() || in_softirq() || in_irq()) ||
	    WARN_ON_ONCE(!valid_trace_format(fmt)) ||
	    WARN_ON_ONCE(trace_format_bytes() > U16_MAX))
		return;

next_page:
	page = pcpu->pages[pcpu->cur_page];
	page_bytes = page->private & ~PAGE_MASK;
	rec = page_address(page) + page_bytes;

	encoded = 0;
	va_start(args, nr);
	for (i = 0; i < nr; i++) {
		if (page_bytes + rec_bytes(encoded + 9) >= PAGE_SIZE) {
			if (++pcpu->cur_page == TRACE_PAGES_PER_CPU)
				pcpu->cur_page = 0;

			page = pcpu->pages[pcpu->cur_page];
			/* XXX barriers? */
			page->private = round_up(page->private, PAGE_SIZE);
			va_end(args);
			goto next_page;
		}

		encoded += encode_u64_bytes(&rec->data[encoded],
					    va_arg(args, u64));
	}
	va_end(args);

	rec->format_off = trace_format_off(fmt);
	rec->nr = nr;
	/* XXX barriers? */
	page->private += rec_bytes(encoded);
}

/*
 * Give userspace all of the format strings.  They're packed and null
 * terminated.
 *
 * We return the number of bytes copied.  A return size smaller than the
 * buffer len indicates a partial copy and the user can retry with a
 * larger buffer.
 */
static int scoutfs_ioc_get_trace_formats(void __user *buf, int len)
{
	int bytes= trace_format_bytes();

	if (bytes <= len) {
		if (copy_to_user(buf, trace_format(0), bytes))
			return -EFAULT;
	}

	return bytes;
}

/*
 * Copy all the trace records on all the cpus' pages to the user buffer.
 * Each page's records will be copied atomically so records won't be
 * scrambled.  But writers can cycle through the pages as we copy so the
 * entire set of records returned is not an atomic snapshot of all the
 * pages.
 *
 * We return the number of bytes copied.  A return size smaller than the
 * buffer len indicates a partial copy and the user can retry with a
 * larger buffer.
 */
static int scoutfs_ioc_get_trace_records(void __user *buf, int len)
{
        struct trace_percpu *pcpu;
	unsigned long before;
	unsigned long after;
	struct page *page;
	int total = 0;
	int bytes;
	int ret;
	int cpu;
	int i;

	if (len < 0)
		return -EINVAL;

	/* quickly give the caller the largest possible buffer size */
	ret = num_online_cpus() * TRACE_PAGES_PER_CPU;
	if (ret > len)
		return ret;

	for_each_online_cpu(cpu) {
		pcpu = per_cpu_ptr(&scoutfs_trace_percpu, cpu);

		for (i = 0; i < TRACE_PAGES_PER_CPU; i++) {
			page = pcpu->pages[i];

			do {
				before = ACCESS_ONCE(page->private);
				bytes = before & ~PAGE_MASK;

				/* ret still nr * pages */
				if (total + bytes > len)
					goto out;

				if (copy_to_user(buf + total,
						 page_address(page), bytes)) {
					ret = -EFAULT;
					goto out;
				}
				after = ACCESS_ONCE(page->private);
			} while (after != before);

			total += bytes;
		}
	}

	ret = total;
out:
	return ret;
}

static long scoutfs_trace_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct iovec iov;

	switch (cmd) {
	case SCOUTFS_IOC_GET_TRACE_FORMATS:
		return scoutfs_copy_ibuf(&iov, arg) ?:
		       scoutfs_ioc_get_trace_formats(iov.iov_base, iov.iov_len);

	case SCOUTFS_IOC_GET_TRACE_RECORDS:
		return scoutfs_copy_ibuf(&iov, arg) ?:
		       scoutfs_ioc_get_trace_records(iov.iov_base, iov.iov_len);
	}

	return -ENOTTY;
}

static const struct file_operations scoutfs_trace_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= scoutfs_trace_ioctl,
};

static struct dentry *scoutfs_debugfs_dir;
static struct dentry *scoutfs_trace_dentry;

int __init scoutfs_trace_init(void)
{
        struct trace_percpu *pcpu;
	int cpu;
	int i;

	if (WARN_ON_ONCE(&scoutfs_trace_first_format >=
			 &scoutfs_trace_last_format) ||
	    WARN_ON_ONCE(trace_format_bytes() > U16_MAX))
		return -EINVAL;

	/* XXX possible instead of online?  yikes? */
	for_each_possible_cpu(cpu) {
		pcpu = per_cpu_ptr(&scoutfs_trace_percpu, cpu);
		for (i = 0; i < TRACE_PAGES_PER_CPU; i++) {
			pcpu->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!pcpu->pages[i])
				return -ENOMEM;
			pcpu->pages[i]->private = 0;
		}
	}

	scoutfs_debugfs_dir = debugfs_create_dir("scoutfs", NULL);
	if (!scoutfs_debugfs_dir)
		return -ENOMEM;

	scoutfs_trace_dentry = debugfs_create_file("trace", 0600,
						   scoutfs_debugfs_dir, NULL,
						   &scoutfs_trace_fops);
	if (!scoutfs_trace_dentry)
		return -ENOMEM;

	return 0;
}

void __exit scoutfs_trace_exit(void)
{
        struct trace_percpu *pcpu;
	int cpu;
	int i;

	if (scoutfs_trace_dentry) {
		debugfs_remove(scoutfs_trace_dentry);
		scoutfs_trace_dentry = NULL;
	}

	if (scoutfs_debugfs_dir) {
		debugfs_remove(scoutfs_debugfs_dir);
		scoutfs_debugfs_dir = NULL;
	}

	/* XXX possible instead of online?  yikes? */
	for_each_possible_cpu(cpu) {
		pcpu = per_cpu_ptr(&scoutfs_trace_percpu, cpu);
		for (i = 0; i < TRACE_PAGES_PER_CPU; i++) {
			if (pcpu->pages[i]) {
				__free_page(pcpu->pages[i]);
				pcpu->pages[i] = NULL;
			}
		}
	}
}
