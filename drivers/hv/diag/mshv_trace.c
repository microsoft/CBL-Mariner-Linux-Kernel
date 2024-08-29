// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Functions used to read events from Microsoft Hypervisor's Local Diagnostics
 *
 * Author:
 *   Stanislav Kinsburskii <skinsburskii@linux.microsoft.com>
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <hyperv/hvhdk.h>
#include <uapi/linux/mshv.h>
#include <hyperv/hvtrapi.h>
#include <asm/mshyperv.h>

#include "mshv_diag.h"

struct mshv_trace_buffer {
	struct list_head list;
	const struct hv_eventlog_buffer_header *hdr;
};

struct mshv_trace_state {
	struct mshv_trace_config cfg;
	enum hv_eventlog_type type;
	struct mshv_trace_buffer *tbs;
	struct mshv_trace *trace;
};

struct mshv_trace {
	spinlock_t ctb_list_lock;
	struct list_head ctb_list;
	wait_queue_head_t events_queue;

	const struct task_struct *reader;
	const struct mshv_trace_buffer *ctb;

	bool enabled;
};

static DEFINE_MUTEX(mshv_trace_state_lock);
static struct mshv_trace_state *mshv_trace_state;

/*
 * The hypervisor has the ability to signal the completion of multiple event
 * buffers with a single Synthetic Interrupt (SINT) message. When this occurs,
 * the completed buffers are linked in the correct order, with the
 * 'next_buffer_index' variable in the current event buffer header pointing to
 * the subsequent buffer. If 'next_buffer_index' equals -1, it signifies that
 * this buffer is the last one completed in the chain.
 */
static struct mshv_trace_buffer *mshv_trace_next_buffer(u32 next_buffer_index)
{
	if (next_buffer_index == HV_EVENTLOG_BUFFER_INDEX_NONE)
		return NULL;
	return &mshv_trace_state->tbs[next_buffer_index];
}

void mshv_trace_buffer_complete(const struct hv_eventlog_message_payload *msg)
{
	struct mshv_trace_state *state = mshv_trace_state;
	struct mshv_trace *trace;
	struct mshv_trace_buffer *tb;

	if (!state ||
	    !state->tbs ||
	    state->cfg.max_buffers_count <= msg->buffer_index ||
	    state->type != msg->type)
		return;

	tb = &state->tbs[msg->buffer_index];

	if (!list_empty(&tb->list) ||
	    !state->trace)
		return;

	trace = state->trace;

	spin_lock(&trace->ctb_list_lock);
	while (tb) {
		list_add_tail(&tb->list, &trace->ctb_list);
		tb = mshv_trace_next_buffer(tb->hdr->next_buffer_index);
	};
	spin_unlock(&trace->ctb_list_lock);

	wake_up(&trace->events_queue);
}
EXPORT_SYMBOL_GPL(mshv_trace_buffer_complete);

static int hv_call_unmap_event_log_buffer(enum hv_eventlog_type type,
					  u32 index)
{
	union hv_input_unmap_eventlog_buffer input;
	u64 status;

	input.type = type;
	input.buffer_index = index;
	input.partition_id = HV_PARTITION_ID_SELF;

	status = hv_do_fast_hypercall16(HVCALL_UNMAP_EVENT_LOG_BUFFER,
			input.as_uint64[0], input.as_uint64[1]);

	if (!hv_result_success(status))
		pr_err("%s: hypercall: HVCALL_UNMAP_EVENT_LOG_BUFFER, status %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int hv_call_map_event_log_buffer(enum hv_eventlog_type type, u32 index,
					struct hv_output_map_eventlog_buffer *output)
{
	struct hv_input_map_eventlog_buffer *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	input->type = type;
	input->buffer_index = index;
	input->partition_id = HV_PARTITION_ID_SELF;

	status = hv_do_hypercall(HVCALL_MAP_EVENT_LOG_BUFFER, input, output);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall: HVCALL_MAP_EVENT_LOG_BUFFER, status %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int hv_call_release_event_log_buffer(enum hv_eventlog_type type,
					    u32 buffer_index)
{
	union hv_input_eventlog_release_buffer input;
	u64 status;

	input.type = type;
	input.buffer_index = buffer_index;

	status = hv_do_fast_hypercall8(HVCALL_RELEASE_EVENT_LOG_BUFFER,
				       input.as_uint64);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int mshv_trace_buffer_release(const struct mshv_trace_state *state,
				     u32 buffer_index)
{
	int err;

	err = hv_call_release_event_log_buffer(state->type, buffer_index);
	if (err)
		pr_err("%s: failed to release trace buffer %u: %d\n",
		       __func__, buffer_index, err);
	return err;
}

static const struct mshv_trace_buffer *mshv_trace_wait_for_ctb(struct mshv_trace *trace)
{
	struct mshv_trace_buffer *tb;
	unsigned long flags;

	if (wait_event_interruptible(trace->events_queue,
				     !list_empty(&trace->ctb_list) ||
				     !trace->enabled))
		return ERR_PTR(-EINTR);

	/*
	 * If the buffer list is empty, it indicates that the trace has been
	 * disabled and all flushed buffers have already been processed. In
	 * this case, we return -EINTR. This results in a return value of 0
	 * from the read function, corresponding to the disabled trace state.
	 */
	if (list_empty(&trace->ctb_list))
		return ERR_PTR(-EINTR);

	spin_lock_irqsave(&trace->ctb_list_lock, flags);
	tb = list_first_entry(&trace->ctb_list, struct mshv_trace_buffer, list);
	list_del_init(&tb->list);
	spin_unlock_irqrestore(&trace->ctb_list_lock, flags);

	return tb;
}

static ssize_t mshv_trace_read(struct file *filp, char __user *buf,
			       size_t size, loff_t *ppos)
{
	struct mshv_trace *trace = filp->private_data;
	size_t bytes_copied;
	ssize_t err;

	/*
	 * The hypervisor trace is a stream with unique metadata, managed by
	 * both the kernel and hypervisor. This driver ensures that only the
	 * task attached to the trace can read it, preventing race conditions
	 * during buffer replacement or concurrent read releases. Simply put,
	 * even if a task duplicates itself or shares its file descriptor over
	 * a Unix socket, the recipient can't read the trace.
	 */
	if (trace->reader != current)
		return -EPERM;

	bytes_copied = 0;

	while (bytes_copied < size) {
		const struct hv_eventlog_buffer_header *hdr;
		size_t ctb_size;
		size_t ctb_offset;
		size_t ctb_bytes_left;
		size_t bytes_to_copy;

		if (!trace->ctb) {
			trace->ctb = mshv_trace_wait_for_ctb(trace);
			if (IS_ERR(trace->ctb)) {
				err = PTR_ERR(trace->ctb);
				goto err;
			}
		}

		hdr = trace->ctb->hdr;
		ctb_size = sizeof(*hdr) + hdr->buffer_size;
		/*
		 * Safety check: This situation should not occur, as the buffer
		 * size is communicated to the hypervisor during trace state
		 * creation.
		 */
		if (WARN_ON_ONCE(ctb_size !=
				 mshv_trace_state->cfg.pages_per_buffer *
				 PAGE_SIZE)) {
			err = -EIO;
			goto err;
		}

		ctb_offset = *ppos % ctb_size;
		ctb_bytes_left = ctb_size - ctb_offset;
		bytes_to_copy = min(ctb_bytes_left, size - bytes_copied);

		err = -EFAULT;
		if (copy_to_user(&buf[bytes_copied],
				 (const void *)hdr + ctb_offset,
				 bytes_to_copy))
			goto err;

		ctb_bytes_left -= bytes_to_copy;
		bytes_copied += bytes_to_copy;
		*ppos += bytes_to_copy;

		if (!ctb_bytes_left) {
			(void)mshv_trace_buffer_release(mshv_trace_state,
							hdr->buffer_index);
			trace->ctb = NULL;
		}
	}

	return bytes_copied;

err:
	if (err == -EINTR) {
		if (bytes_copied)
			return bytes_copied;
		if (!trace->enabled)
			return 0;
	}
	return err;
}

static int hv_call_initialize_event_log_buffer_group(enum hv_eventlog_type type,
			     enum hv_eventlog_mode mode,
			     u32 max_buffers_count,
			     u32 pages_per_buffer,
			     u32 buffers_threshold,
			     enum hv_eventlog_entry_time_basis time_basis,
			     u64 system_time)
{
	struct hv_input_initialize_eventlog_buffer_group *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	input->init.type = type;
	input->init.mode = mode;
	input->maximum_buffer_count = max_buffers_count;
	input->buffer_size_in_bytes = pages_per_buffer * PAGE_SIZE;
	input->threshold = buffers_threshold;
	input->time_basis = time_basis;
	input->system_time = system_time;

	status = hv_do_hypercall(HVCALL_INITIALIZE_EVENT_LOG_BUFFER_GROUP,
				 input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int hv_call_finalize_event_log_buffer_group(enum hv_eventlog_type type)
{
	union hv_input_finalize_eventlog_buffer_group input;
	u64 status;

	input.type = type;

	status = hv_do_fast_hypercall8(HVCALL_FINALIZE_EVENT_LOG_BUFFER_GROUP,
				       input.as_uint64);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int mshv_trace_buffers_group_init(const struct mshv_trace_config *cfg,
					 enum hv_eventlog_type type,
					 struct mshv_trace_state **statep)
{
	struct mshv_trace_state *state;
	int err;

	state = kzalloc(sizeof(struct mshv_trace_state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	err = hv_call_initialize_event_log_buffer_group(type,
							cfg->mode,
							cfg->max_buffers_count,
							cfg->pages_per_buffer,
							cfg->buffers_threshold,
							cfg->time_basis,
							cfg->system_time);
	if (err)
		goto free_lb;

	state->type = type;
	memcpy(&state->cfg, cfg, sizeof(state->cfg));

	*statep = state;

	return 0;

free_lb:
	kfree(state);
	return err;
}

static int hv_call_delete_event_log_buffer(enum hv_eventlog_type type,
					   u32 buffer_index)
{
	union hv_input_delete_eventlog_buffer input;
	u64 status;

	input.type = type;
	input.buffer_index = buffer_index;

	status = hv_do_fast_hypercall8(HVCALL_DELETE_EVENT_LOG_BUFFER,
				       input.as_uint64);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int hv_call_create_event_log_buffer(enum hv_eventlog_type type,
					   u32 buffer_index)
{
	union hv_input_create_eventlog_buffer input;
	u64 status;

	input.type = type;
	input.buffer_index = buffer_index;
	/*
	 * There isn't logic in the hypervisor yet to prefer NUMA local buffers
	 * when allocating a free one, so probably proximity doesn't matter at
	 * the moment.
	 * Disable it for now.
	 */
	input.proximity_info = hv_numa_node_to_pxm_info(NUMA_NO_NODE);

	status = hv_do_fast_hypercall16(HVCALL_CREATE_EVENT_LOG_BUFFER,
					input.as_uint64[0], input.as_uint64[1]);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int mshv_trace_buffer_delete(const struct mshv_trace_state *state,
				    u32 buffer_index)
{
	int err;

	err = hv_call_delete_event_log_buffer(state->type, buffer_index);
	if (err)
		pr_err("%s: failed to delete trace buffer %u: %d\n",
		       __func__, buffer_index, err);
	return err;
}

static int mshv_trace_buffers_delete(struct mshv_trace_state *state)
{
	int i, err;

	for (i = 0; i < state->cfg.max_buffers_count; i++) {
		err = mshv_trace_buffer_delete(state, i);
		if (err)
			return err;
	}

	kfree(state->tbs);
	state->tbs = NULL;

	return 0;
}

static int mshv_trace_buffer_create(const struct mshv_trace_state *state,
				    u32 buffer_index)
{
	int err;

	err = hv_call_create_event_log_buffer(state->type, buffer_index);
	if (err)
		pr_err("%s: failed to create trace buffer %u: %d\n",
		       __func__, buffer_index, err);
	return err;
}

static int mshv_trace_buffers_create(struct mshv_trace_state *state)
{
	struct mshv_trace_buffer *tbs;
	int i, err;

	tbs = kcalloc(state->cfg.max_buffers_count,
		      sizeof(struct mshv_trace_buffer), GFP_KERNEL);
	if (!tbs)
		return -ENOMEM;

	for (i = 0; i < state->cfg.max_buffers_count; i++) {
		err = mshv_trace_buffer_create(state, i);
		if (err)
			goto free_buffers;
		INIT_LIST_HEAD(&tbs[i].list);
	}

	state->tbs = tbs;

	return 0;

free_buffers:
	for (i -= 1; i >= 0; i--)
		(void)mshv_trace_buffer_delete(state, i);
	kfree(tbs);
	return err;
}

static int mshv_trace_buffers_group_fini(struct mshv_trace_state *state)
{
	int err;

	err = hv_call_finalize_event_log_buffer_group(state->type);
	if (err) {
		pr_err("%s: failed to finalize trace buffer group\n",
		       __func__);
		return err;
	}

	kfree(state);

	return 0;
}

static int mshv_trace_buffer_unmap(struct mshv_trace_state *state,
				   u32 buffer_index)
{
	int err;

	err = hv_call_unmap_event_log_buffer(state->type, buffer_index);
	if (err) {
		pr_err("%s: failed to unmap trace buffer %u: %d\n",
		       __func__, buffer_index, err);
		return err;
	}

	vunmap(state->tbs[buffer_index].hdr);
	state->tbs[buffer_index].hdr = NULL;

	return 0;
}

static int mshv_trace_buffers_unmap(struct mshv_trace_state *state)
{
	int i, err;

	for (i = 0; i < state->cfg.max_buffers_count; i++) {
		err = mshv_trace_buffer_unmap(state, i);
		if (err)
			return err;
	}

	return 0;
}

static int mshv_trace_buffer_map(struct mshv_trace_state *state,
				 u32 buffer_index,
				 u64 *pfns, struct page **pages)
{
	const void *ptr;
	int i, err;

	err = hv_call_map_event_log_buffer(state->type, buffer_index,
					   (void *)pfns);
	if (err) {
		pr_err("%s: failed to map trace buffer %u: %d\n",
		       __func__, buffer_index, err);
		return err;
	}

	for (i = 0; i < state->cfg.pages_per_buffer; i++)
		pages[i] = pfn_to_page(pfns[i]);

	ptr = vmap(pages, state->cfg.pages_per_buffer, VM_MAP, PAGE_KERNEL_RO);
	if (!ptr) {
		pr_err("%s: failed to vmap pages for trace buffer %u\n",
		       __func__, buffer_index);
		goto unmap_buffer;
	}

	state->tbs[buffer_index].hdr = ptr;

	return 0;

unmap_buffer:
	hv_call_unmap_event_log_buffer(state->type, buffer_index);
	return err;
}

static int mshv_trace_buffers_map(struct mshv_trace_state *state)
{
	struct page *page, **pages;
	u64 *pfns;
	int i, err;

	page = alloc_pages(GFP_KERNEL, 1);
	if (!page)
		return -ENOMEM;

	pfns = page_address(page);
	pages = page_address(page) + PAGE_SIZE;

	for (i = 0; i < state->cfg.max_buffers_count; i++) {
		err = mshv_trace_buffer_map(state, i, pfns, pages);
		if (err)
			goto unmap_buffers;
	}

	__free_pages(page, 1);

	return 0;

unmap_buffers:
	for (i -= 1; i >= 0; i--)
		(void)mshv_trace_buffer_unmap(state, i);
	__free_pages(page, 1);
	return err;
}

static int mshv_trace_state_create(struct mshv_trace_state **statep,
				   const struct mshv_trace_config *cfg)
{
	struct mshv_trace_state *state;
	enum hv_eventlog_type type = HV_EVENT_LOG_TYPE_LOCAL_DIAGNOSTICS;
	int err;

	err = mshv_trace_buffers_group_init(cfg, type, &state);
	if (err) {
		pr_err("%s: failed to initialize trace buffer group: %d\n",
		       __func__, err);
		return err;
	}

	err = mshv_trace_buffers_create(state);
	if (err) {
		pr_err("%s: failed to create trace buffers: %d\n",
		       __func__, err);
		goto finalize_state;
	}

	err = mshv_trace_buffers_map(state);
	if (err) {
		pr_err("%s: failed to map trace buffers: %d\n",
		       __func__, err);
		goto delete_tbs;
	}

	*statep = state;

	return 0;

delete_tbs:
	(void)mshv_trace_buffers_delete(state);
finalize_state:
	(void)mshv_trace_buffers_group_fini(state);
	return err;
}

static int mshv_trace_state_destroy(struct mshv_trace_state **statep)
{
	int err;

	err = mshv_trace_buffers_unmap(*statep);
	if (!err)
		err = mshv_trace_buffers_delete(*statep);
	if (!err)
		err = mshv_trace_buffers_group_fini(*statep);
	if (err)
		return err;

	*statep = NULL;

	return 0;
}

static int mshv_trace_check_config(const struct mshv_trace_config *cfg)
{
	if (cfg->mode >= HV_EVENT_LOG_MODE_MAX) {
		pr_err("%s: unknown even log mode: %u\n", __func__, cfg->mode);
		return -EINVAL;
	}

	if (!cfg->max_buffers_count) {
		pr_err("%s: buffers count must be non-zero\n", __func__);
		return -EINVAL;
	}

	if (cfg->max_buffers_count > PAGE_SIZE / sizeof(u64)) {
		pr_err("%s: buffers count is too big: %u > %lu\n", __func__,
			cfg->max_buffers_count, PAGE_SIZE / sizeof(u64));
		return -EINVAL;
	}

	if (cfg->buffers_threshold > cfg->max_buffers_count) {
		pr_err("%s: buffers threshold is too big: %u > %u\n", __func__,
			cfg->buffers_threshold,	cfg->max_buffers_count);
		return -EINVAL;
	}

	return 0;
}

static int mshv_trace_create_state_ioctl(struct mshv_trace_state **statep,
					 const void __user *arg)
{
	struct mshv_trace_config config;

	if (*statep)
		return -EEXIST;

	if (copy_from_user(&config, arg, sizeof(config)))
		return -EFAULT;

	if (mshv_trace_check_config(&config))
		return -EINVAL;

	return mshv_trace_state_create(statep, &config);
}

static int mshv_trace_get_state_ioctl(const struct mshv_trace_state *state,
				      void __user *arg)
{
	if (!state)
		return -ENOENT;

	if (copy_to_user(arg, &state->cfg, sizeof(state->cfg)))
		return -EFAULT;

	return 0;
}

static int mshv_trace_destroy_state_ioctl(struct mshv_trace_state **statep)
{
	if (!*statep)
		return -ENOENT;

	if ((*statep)->trace)
		return -EBUSY;

	return mshv_trace_state_destroy(statep);
}

static int mshv_trace_attach_state_ioctl(struct mshv_trace *trace,
					 struct mshv_trace_state *state)
{
	if (!state)
		return -ENOENT;

	if (state->trace == trace)
		return -EALREADY;

	if (state->trace)
		return -EBUSY;

	state->trace = trace;

	trace->reader = current;

	return 0;
}

static int mshv_trace_detach_state_ioctl(const struct mshv_trace *trace,
					 struct mshv_trace_state *state)
{
	if (!state)
		return -ENOENT;

	if (state->trace != trace)
		return -EPERM;

	if (trace->enabled)
		return -EBUSY;

	state->trace = NULL;

	return 0;
}

static int hv_call_set_event_group_sources(enum hv_eventlog_type type,
		   u32 group_count,
		   u64 configuration_flags,
		   const struct hv_eventlog_eventgroup_configuration *groups)
{
	struct hv_input_eventlog_set_events *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->type = type;
	input->group_count = group_count;
	input->configuration_flags = configuration_flags;
	if (group_count)
		memcpy(input->groups, groups, sizeof(input->groups));

	status = hv_do_hypercall(HVCALL_SET_EVENT_LOG_GROUP_SOURCES,
				 input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int mshv_trace_state_set_sources(const struct mshv_trace_state *state,
					u64 flags)
{
	union hv_eventlog_extended_trace_flags extended_flags = {
		.legacy.flags = flags
	};

	/* Make sure flags are HvEventLogExtendedModeLegacy compatible */
	if (extended_flags.common.extended)
		return -EINVAL;

	return hv_call_set_event_group_sources(state->type, 0,
					       extended_flags.as_uint64, NULL);
}

static int hv_call_flush_event_log_buffer(enum hv_eventlog_type type,
					  u32 buffer_index)
{
	union hv_input_flush_eventlog_buffer input;
	u64 status;

	input.type = type;
	input.buffer_index = buffer_index;

	status = hv_do_fast_hypercall8(HVCALL_FLUSH_EVENT_LOG_BUFFER,
				       input.as_uint64);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed: %s\n",
		       __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}

static int mshv_trace_state_buffer_flush(const struct mshv_trace_state *state,
					 u32 buffer_index)
{
	int err;

	err = hv_call_flush_event_log_buffer(state->type, buffer_index);
	if (err)
		pr_err("%s: failed to flush trace buffer %u: %d\n",
		       __func__, buffer_index, err);
	return err;
}

static bool hv_eventlog_buffer_in_use(const struct hv_eventlog_buffer_header *hdr)
{
	return hdr->buffer_state == HV_EVENT_LOG_BUFFER_STATE_IN_USE;
}

static bool hv_eventlog_buffer_completed(const struct hv_eventlog_buffer_header *hdr)
{
	return hdr->buffer_state == HV_EVENT_LOG_BUFFER_STATE_COMPLETE;
}

static bool mshv_trace_buffers_in_use(const struct mshv_trace_state *state)
{
	const struct mshv_trace_buffer *tb = state->tbs;
	int i;

	for (i = 0; i < state->cfg.max_buffers_count; i++, tb++) {
		if (hv_eventlog_buffer_in_use(tb->hdr))
			return true;
	}
	return false;
}

static int mshv_trace_flush_buffers(struct mshv_trace *trace,
				    const struct mshv_trace_state *state)
{
	const struct mshv_trace_buffer *tb = state->tbs;
	int i;

	for (i = 0; i < state->cfg.max_buffers_count; i++, tb++) {
		if (hv_eventlog_buffer_in_use(tb->hdr))
			(void)mshv_trace_state_buffer_flush(state, i);
	}

	if (!wait_event_timeout(trace->events_queue,
				!mshv_trace_buffers_in_use(state), HZ)) {
		pr_err("%s: timed out to wait for buffers to get unused\n",
		       __func__);
		return -ETIME;
	}

	return 0;
}

static int mshv_trace_state_release_buffers(const struct mshv_trace_state *state)
{
	const struct mshv_trace_buffer *tb = state->tbs;
	int i;

	for (i = 0; i < state->cfg.max_buffers_count; i++, tb++) {
		if (hv_eventlog_buffer_completed(tb->hdr))
			(void)mshv_trace_buffer_release(state, i);
	}

	return 0;
}

static int mshv_trace_trace_stop(struct mshv_trace *trace,
				 const struct mshv_trace_state *state)
{
	int err;

	err = mshv_trace_state_set_sources(state, 0);
	if (!err)
		err = mshv_trace_flush_buffers(trace, state);
	if (!err)
		err = mshv_trace_state_release_buffers(state);

	return err;
}

static int mshv_trace_stop_ioctl(struct mshv_trace *trace,
				 const struct mshv_trace_state *state)
{
	int err;

	if (!state)
		return -ENOENT;

	if (state->trace != trace)
		return -EPERM;

	err = mshv_trace_trace_stop(trace, state);
	if (err)
		return err;

	trace->enabled = false;
	wmb();
	wake_up(&trace->events_queue);

	return 0;
}

static int mshv_trace_start_ioctl(struct mshv_trace *trace,
				  const struct mshv_trace_state *state,
				  u64 flags)
{
	int err;

	if (!state)
		return -ENOENT;

	if (state->trace != trace)
		return -EPERM;

	if (!(flags & HV_TR_ALL_GROUPS))
		return -EINVAL;

	err = mshv_trace_state_set_sources(state, flags);
	if (err)
		return err;

	trace->enabled = true;

	return 0;
}

static long mshv_trace_ioctl(struct file *filp, unsigned int ioctl,
			     unsigned long arg)
{
	struct mshv_trace *trace = filp->private_data;
	int ret = -ENOTTY;

	/*
	 * This lock serializes global trace state creation, mutation and
	 * destruction.
	 */
	mutex_lock(&mshv_trace_state_lock);

	switch (ioctl) {
	case MSHV_TRACE_STATE_CREATE:
		ret = mshv_trace_create_state_ioctl(&mshv_trace_state,
						    (void __user *)arg);
		break;
	case MSHV_TRACE_STATE_INFO:
		ret = mshv_trace_get_state_ioctl(mshv_trace_state,
						 (void __user *)arg);
		break;
	case MSHV_TRACE_STATE_DESTROY:
		ret = mshv_trace_destroy_state_ioctl(&mshv_trace_state);
		break;
	case MSHV_TRACE_START:
		ret = mshv_trace_start_ioctl(trace, mshv_trace_state, arg);
		break;
	case MSHV_TRACE_STOP:
		ret = mshv_trace_stop_ioctl(trace, mshv_trace_state);
		break;
	case MSHV_TRACE_STATE_ATTACH:
		ret = mshv_trace_attach_state_ioctl(trace, mshv_trace_state);
		break;
	case MSHV_TRACE_STATE_DETACH:
		ret = mshv_trace_detach_state_ioctl(trace, mshv_trace_state);
		break;
	}

	mutex_unlock(&mshv_trace_state_lock);

	return ret;
}

static int mshv_trace_release(struct inode *inode, struct file *filp)
{
	struct mshv_trace *trace = filp->private_data;

	if (mshv_trace_state && mshv_trace_state->trace == trace) {
		(void)mshv_trace_trace_stop(trace, mshv_trace_state);
		mshv_trace_state->trace = NULL;
	}

	kfree(trace);

	return 0;
}

static const struct file_operations mshv_trace_fops = {
	.owner = THIS_MODULE,
	.read = mshv_trace_read,
	.unlocked_ioctl = mshv_trace_ioctl,
	.release = mshv_trace_release,
};

static struct mshv_trace *mshv_trace_create(void)
{
	struct mshv_trace *trace;

	trace = kzalloc(sizeof(struct mshv_trace), GFP_KERNEL);
	if (!trace)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&trace->ctb_list_lock);
	INIT_LIST_HEAD(&trace->ctb_list);
	init_waitqueue_head(&trace->events_queue);

	return trace;
}

int mshv_trace_get_fd(void)
{
	struct mshv_trace *trace;
	int fd;

	trace = mshv_trace_create();
	if (IS_ERR(trace))
		return PTR_ERR(trace);

	fd = anon_inode_getfd("mshv_trace",
			      &mshv_trace_fops, trace,
			      O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		kfree(trace);

	return fd;
}

void mshv_trace_disable(void)
{
	struct mshv_trace_state *state = mshv_trace_state;

	mutex_lock(&mshv_trace_state_lock);

	if (state) {
		/*
		 * The trace needs to be disabled before kexec, otherwise the
		 * hypervisor won't allow to reinitialize it
		 */
		if (state->trace)
			mshv_trace_trace_stop(state->trace, state);
		mshv_trace_state_destroy(&state);
	}

	mutex_unlock(&mshv_trace_state_lock);
}
