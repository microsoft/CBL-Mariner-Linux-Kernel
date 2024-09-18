// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * This module implements reading diagnostics logs that contains errors,
 * warnings, etc. from the hypervisor. Due to lack of synchronization,
 * records could be lost.
 *
 * At a high level, there are N bufs of size P pages. Hypervisor starts with
 * one buf, and just rotates to next one. Each buf has a header. There is no
 * notification from the hypervisor when a buffer is updated or full.
 *
 * Authors:
 *   Praveen K Paladugu <prapal@linux.microsoft.com>
 *   Mukesh Rathor <mrathor@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/vmalloc.h>

#include <asm/mshyperv.h>
#include <hyperv/hvtrapi.h>
#include "../mshv.h"

static size_t MSHV_TICKS_PER_SEC = NSEC_PER_SEC/100; /* 1 tick is 100 ns long in mshv */

/* Context saved in FDs private_data */
struct fd_ctx {
	struct hv_eventlog_buffer_header *cur_buf;
	u64 saved_ts;	/* saved timestamp */
	uint next_offs; /* offset of next rec that *will* be sent */
	u64 mshv_ref_time0; /* mshv reference time at T0 */
	u64 ktime_real0;  /* real ktime at T0 */
};

static void *vmap_start;
struct hv_system_diag_log_buffer_config hv_logbuf_info;
static uint logbuf_sz;	/* once set, it doesn't change */

/* Return the starting address of buffer given its index */
static void *bufhdr_from_idx(int idx)
{
	return (char *)vmap_start + (logbuf_sz * idx);
}

/* find buffer with least time_stamp greater than cur_ts */
static struct hv_eventlog_buffer_header *find_next_valid_buf(u64 cur_ts)
{
	struct hv_eventlog_buffer_header *bufhdr, *retval = NULL;
	u64 i, prev = U64_MAX;

	for (i = 0; i < hv_logbuf_info.buffer_count; i++) {
		bufhdr = bufhdr_from_idx(i);
		if (bufhdr->time_stamp > cur_ts && bufhdr->time_stamp < prev) {
			prev = bufhdr->time_stamp;
			retval = bufhdr;
		}
	}
	return retval;
}

static struct hv_eventlog_entry_header *get_next_entry_ptr(
						struct fd_ctx *fd_ctx)
{
	char *retp;
	int bufhdr_sz = sizeof(struct hv_eventlog_buffer_header);

	retp = (char *)fd_ctx->cur_buf + bufhdr_sz + fd_ctx->next_offs;

	/* make sure the retp is within bounds */
	if (retp >= (char *)fd_ctx->cur_buf + logbuf_sz) {
		fd_ctx->cur_buf = NULL; /* skip this buffer, something bad */
		return NULL;
	}

	return (struct hv_eventlog_entry_header *)retp;
}

/*
 * Check and update our buffer if the hyp has rotated the current buffer.
 * Returns: true if there is data available in the current or rotated buffer
 */
static bool validate_buf_and_chk_newdata(struct fd_ctx *fd_ctx)
{
	u32 bufst;

	/*
	 * NB: there is a race when hyp marks a buffer complete and us checking
	 *     next buffer offset. Hence we must recheck post barrier()
	 */
	bufst = fd_ctx->cur_buf->buffer_state;
	if (bufst == HV_EVENT_LOG_BUFFER_STATE_COMPLETE) {
		struct hv_eventlog_buffer_header *bufhdr;

		barrier();
		if (fd_ctx->next_offs < fd_ctx->cur_buf->next_buffer_offset) {
			/* there is uncopied data in the current buffer */
			return true;
		}

		/*
		 * Hyp has moved on to a new buffer, however it is not usable
		 * until the timestamp on it is updated
		 */
		bufhdr = bufhdr_from_idx(fd_ctx->cur_buf->next_buffer_index);
		if (bufhdr->time_stamp > fd_ctx->saved_ts) {
			fd_ctx->cur_buf = bufhdr;
			fd_ctx->saved_ts = fd_ctx->cur_buf->time_stamp;
			fd_ctx->next_offs = 0;

			return !!bufhdr->next_buffer_offset;
		}
	} else
		return fd_ctx->next_offs < fd_ctx->cur_buf->next_buffer_offset;

	return false;
}

/*
 * ABI alert: hypervisor pads each event record to make sure it aligns
 *	      at the largest element in hv_eventlog_entry_header. Since
 *	      we __pack the struct, we use a hardcoded value. Hypervisor has
 *	      asserts to notify us in case it changes.
 */
#define EVENT_HDR_ALIGN 8	/* alignment of the largest field in struct */

/* Returns: number of bytes copied which could be 0, or -errno */
static int copy_next_record(struct fd_ctx *fd_ctx, char __user *ubuf,
			    int ubuf_remain)
{
	s64 offset_secs;
	struct hv_eventlog_entry_header *entry = get_next_entry_ptr(fd_ctx);
	struct hv_eventlog_entry_header tmp_header;
	size_t hv_eventlog_entry_header_sz =
					sizeof(struct hv_eventlog_entry_header);


	offset_secs = (s64)(fd_ctx->mshv_ref_time0 - entry->time_stamp)/
			   (s64)MSHV_TICKS_PER_SEC;

	memcpy(&tmp_header, entry, hv_eventlog_entry_header_sz);
	tmp_header.time_stamp = fd_ctx->ktime_real0 - offset_secs;

	if (entry == NULL || entry->type == 0)
		return 0;
	if (entry->size > ubuf_remain)
		return 0;

	/* Copy the modified header first */
	if (copy_to_user(ubuf, &tmp_header, hv_eventlog_entry_header_sz))
		return -EFAULT;

	/* Copy rest of the record */
	if (copy_to_user((char *) ubuf + hv_eventlog_entry_header_sz,
			 (char *) entry + hv_eventlog_entry_header_sz,
			 entry->size - hv_eventlog_entry_header_sz))
		return -EFAULT;

	/* next entry rec is at entry size plus any padding added by hyp */
	fd_ctx->next_offs += round_up(entry->size, EVENT_HDR_ALIGN);

	return entry->size;
}

/*
 * Note: we only return full records, partial records are not copied/returned.
 *	 Also, the reason we save timestamp is that the hyp will overwrite our
 *	 buffer if needed irrespective of whether a read has happened.
 *
 * Returns: number of bytes copied into ubuf, or -errno
 */
static ssize_t diaglog_fop_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *offset)
{
	int ret, newdata, numrd = 0;
	struct fd_ctx *fd_ctx = file->private_data;

	while (count > 0) {
		/*
		 * Check every iteration for our buffer rotating underneath,
		 * that way at most we get only one corrupted entry record
		 */

		if (fd_ctx->cur_buf == NULL ||
		    fd_ctx->saved_ts != fd_ctx->cur_buf->time_stamp) {

			fd_ctx->cur_buf = find_next_valid_buf(fd_ctx->saved_ts);
			if (fd_ctx->cur_buf == NULL)
				return 0;	/* no data, or no new data */

			fd_ctx->saved_ts = fd_ctx->cur_buf->time_stamp;
			fd_ctx->next_offs = 0;
		}

		newdata = validate_buf_and_chk_newdata(fd_ctx);
		if (!newdata)
			break;

		ret = copy_next_record(fd_ctx, ubuf, count);

		if (ret < 0)
			return ret;	/* error */
		else if (ret == 0)
			break;

		ubuf += ret;
		numrd += ret;
		count -= ret;
	}

	return numrd;
}

int diaglog_fop_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static const struct file_operations mshv_diaglog_fops = {
	.owner = THIS_MODULE,
	.read = diaglog_fop_read,
	.release = diaglog_fop_release,
};

int mshv_diaglog_get_fd(void)
{
	int fd;
	struct fd_ctx *fd_ctx;
	unsigned long flags;

	/* make sure initialization was successful */
	if (vmap_start == NULL)
		return -ENODEV;

	fd_ctx = kzalloc(sizeof(struct fd_ctx), GFP_KERNEL);
	if (!fd_ctx)
		return -ENOMEM;


	local_irq_save(flags);
	fd_ctx->mshv_ref_time0 = hv_read_reference_counter();
	fd_ctx->ktime_real0 = ktime_get_real_seconds();
	local_irq_restore(flags);

	fd = anon_inode_getfd("hv_diag_log", &mshv_diaglog_fops, fd_ctx,
			      O_RDONLY);
	if (fd < 0)
		kfree(fd_ctx);

	return fd;
}

/*
 * This gets hv to put in trace info once, like: Buildnumber, HotPatch state,
 * ApicMode, Checksum, IommuFeaturesSet, BootFlags, UpdateRevision, etc....
 * Note: this info is only put once, and appears in output only once at the top
 */
static void get_hv_header_in_diaglog(void)
{
	u64 status;

	status = hv_do_hypercall(HVCALL_LOG_HYPERVISOR_SYSTEM_CONFIG, NULL,
				 NULL);
	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
}

static int unmap_diaglog_pages(int numbufs)
{
	int i, ret = 0;
	unsigned long flags;
	u64 status;
	union hv_input_unmap_eventlog_buffer *input_page;

	for (i = 0; i < numbufs; i++) {
		local_irq_save(flags);

		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		input_page->type = HV_EVENT_LOG_TYPE_SYSTEM_DIAGNOSTICS;
		input_page->buffer_index = i;
		input_page->partition_id = HV_PARTITION_ID_SELF;
		status = hv_do_hypercall(HVCALL_UNMAP_EVENT_LOG_BUFFER,
					 input_page, NULL);
		local_irq_restore(flags);
		if (!hv_result_success(status)) {
			pr_err("%s: hypercall (unmap): status %s\n", __func__,
				hv_status_to_string(status));
			if (ret == 0)
				ret = hv_status_to_errno(status);
		}
	}

	return ret;
}

/* retrieve from hv information about the diag log buffers */
static int get_diaglog_info(void)
{
	unsigned long flags;
	u64 status;
	int ret = 0;
	struct hv_output_get_system_property *output_page = NULL;
	struct hv_input_get_system_property *input_page = NULL;
	union hv_partition_diag_log_buffer_config part_buffer_log_conf;

	local_irq_save(flags);
	if (hv_root_partition()) {
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input_page->property_id =
				      HV_SYSTEM_PROPERTY_DIAGOSTICS_LOG_BUFFERS;
		status = hv_do_hypercall(HVCALL_GET_SYSTEM_PROPERTY, input_page,
					 output_page);
		if (!hv_result_success(status)) {
			pr_err("%s: hypercall:HVCALL_GET_SYSTEM_PROPERTY, status %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			goto hvcall_fail;
		}
		hv_logbuf_info.buffer_count =
				      output_page->hv_diagbuf_info.buffer_count;
		hv_logbuf_info.buffer_size_in_pages =
			      output_page->hv_diagbuf_info.buffer_size_in_pages;
	} else {
		status = hv_call_get_partition_property(
			     hv_current_partition_id,
			     HV_PARTITION_PROPERTY_PARTITION_DIAG_BUFFER_CONFIG,
			     &part_buffer_log_conf.as_uint64);
		if (!hv_result_success(status)) {
			pr_err("%s: hypercall:HV_PARTITION_PROPERTY_PARTITION_DIAG_BUFFER_CONFIG, status %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			goto hvcall_fail;
		}
		hv_logbuf_info.buffer_count = part_buffer_log_conf.buffer_count;
		hv_logbuf_info.buffer_size_in_pages =
				      part_buffer_log_conf.buffer_size_in_pages;
	}

hvcall_fail:
	local_irq_restore(flags);
	return ret;
}

/* Returns : 0 on success. -errno on failure */
int __init mshv_diaglog_init(void)
{
	uint i, j, tot_pages, page_index = 0;
	int ret;
	unsigned long flags, pfn;
	u64 status;
	struct page **ppages;

	ret = get_diaglog_info();
	if (ret)
		return ret;

	tot_pages = hv_logbuf_info.buffer_count *
				hv_logbuf_info.buffer_size_in_pages;

	ppages = kcalloc(tot_pages, sizeof(struct page *), GFP_KERNEL);
	if (!ppages)
		return -ENOMEM;

	for (i = 0; i < hv_logbuf_info.buffer_count; i++) {
		struct hv_input_map_eventlog_buffer *input_page;
		struct hv_output_map_eventlog_buffer *output_page;
		do {
			local_irq_save(flags);

			input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
			input_page->type = HV_EVENT_LOG_TYPE_SYSTEM_DIAGNOSTICS;
			input_page->buffer_index = i;
			input_page->partition_id = HV_PARTITION_ID_SELF;
			output_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

			/* Get pfns of all pages in the buffer */
			status = hv_do_hypercall(HVCALL_MAP_EVENT_LOG_BUFFER,
						input_page, output_page);

			if (hv_result(status) == HV_STATUS_SUCCESS)
				break;

			if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
				local_irq_restore(flags);
				pr_err("%s: hypercall: status %s\n", __func__,
					hv_status_to_string(status));
				ret = hv_status_to_errno(status);
				unmap_diaglog_pages(i);
				goto out;
			}

			local_irq_restore(flags);
			ret = hv_call_deposit_pages(NUMA_NO_NODE,
						    hv_current_partition_id, 1);

		} while (!ret);

		for (j = 0; j < hv_logbuf_info.buffer_size_in_pages; j++) {
			pfn = output_page->gpa_numbers[j];
			if (!pfn_valid(pfn))
				break;

			ppages[page_index] = pfn_to_page(pfn);
			page_index++;
		}

		if (j < hv_logbuf_info.buffer_size_in_pages) {
			local_irq_restore(flags);
			pr_err("%s: bad pfn %lx i:%d j:%d\n", __func__,
			       pfn, i, j);
			unmap_diaglog_pages(i+1);
			goto out;
		}

		local_irq_restore(flags);
	}

	logbuf_sz = hv_logbuf_info.buffer_size_in_pages * PAGE_SIZE;

	vmap_start = vmap(ppages, tot_pages, VM_MAP, PAGE_KERNEL_RO);
	if (vmap_start == NULL) {
		pr_err("%s: vmap failed", __func__);
		ret = -ENOMEM;
		goto out;
	}

	pr_info("Hyper-V: Diagnostics log initialized: %d bufs, each %d pgs\n",
		hv_logbuf_info.buffer_count,
		hv_logbuf_info.buffer_size_in_pages);

	/*
	 * Initialize diagnostic logs with some hv details. Ignore failure and
	 * continue collecting logs
	 */
	get_hv_header_in_diaglog();

out:
	kfree(ppages);
	return ret;
}

int mshv_diaglog_exit(void)
{
	int ret;

	vunmap(vmap_start);	/* checks for null addr */
	ret = unmap_diaglog_pages(hv_logbuf_info.buffer_count);

	return ret;
}
