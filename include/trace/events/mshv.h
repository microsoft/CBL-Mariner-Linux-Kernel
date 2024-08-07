/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Tracepoint definitions for tracepoints in mshv driver.
 *
 * Authors:
 *   Shubhangi Agrawal <t-shuagrawal@microsoft.com>
 */

#if !defined(_TRACE_MSHV_MAIN_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MSHV_MAIN_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mshv

TRACE_EVENT(mshv_create_partition,
	    TP_PROTO(long ret, u64 partition_id, int vm_fd),
	    TP_ARGS(ret, partition_id, vm_fd),

	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(int, vm_fd)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vm_fd = vm_fd;
	),

	TP_printk("ret=%ld partition_id=%llu vm_fd=%d",
		__entry->ret,
		__entry->partition_id,
		__entry->vm_fd
	)
);

TRACE_EVENT(mshv_hvcall_create_partition,
		TP_PROTO(u64 status, u64 partition_id, u64 flags),
		TP_ARGS(status, partition_id, flags),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
		__field(u64, flags)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
		__entry->flags = flags;
	),

	TP_printk("status=0x%llx partition_id=%llu flags=0x%llx",
		__entry->status,
		__entry->partition_id,
		__entry->flags
	)
);

TRACE_EVENT(mshv_hvcall_set_partition_property,
		TP_PROTO(u64 status, u64 partition_id, u64 pcode, u64 pvalue),
		TP_ARGS(status, partition_id, pcode, pvalue),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
		__field(u64, pcode)
		__field(u64, pvalue)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
		__entry->pcode = pcode;
		__entry->pvalue = pvalue;
	),

	TP_printk("status=0x%llx partition_id=%llu property_code=0x%llx property_value=0x%llx",
		__entry->status,
		__entry->partition_id,
		__entry->pcode,
		__entry->pvalue
	)
);

TRACE_EVENT(mshv_hvcall_initialize_partition,
		TP_PROTO(u64 status, u64 partition_id),
		TP_ARGS(status, partition_id),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
	),

	TP_printk("status=0x%llx partition_id=%llu",
		__entry->status,
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_partition_release,
		TP_PROTO(u64 partition_id),
		TP_ARGS(partition_id),

	TP_STRUCT__entry(
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->partition_id = partition_id;
	),

	TP_printk("partition_id=%llu",
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_destroy_partition,
		TP_PROTO(u64 partition_id),
		TP_ARGS(partition_id),

	TP_STRUCT__entry(
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->partition_id = partition_id;
	),

	TP_printk("partition_id=%llu",
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_hvcall_finalize_partition,
		TP_PROTO(u64 status, u64 partition_id),
		TP_ARGS(status, partition_id),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
	),

	TP_printk("status=0x%llx partition_id=%llu",
		__entry->status,
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_hvcall_withdraw_memory,
		TP_PROTO(u64 status, u64 partition_id),
		TP_ARGS(status, partition_id),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
	),

	TP_printk("status=0x%llx partition_id=%llu",
		__entry->status,
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_hvcall_delete_partition,
		TP_PROTO(u64 status, u64 partition_id),
		TP_ARGS(status, partition_id),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
	),

	TP_printk("status=0x%llx partition_id=%llu",
		__entry->status,
		__entry->partition_id
	)
);

TRACE_EVENT(mshv_create_vp,
		TP_PROTO(long ret, u64 partition_id, u32 vp_index, int fd),
		TP_ARGS(ret, partition_id, vp_index, fd),

	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(u32, vp_index)
		__field(int, fd)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__entry->fd = fd;
	),

	TP_printk("ret=%ld partition_id=%llu vp_index=%u vp_fd=%d",
		__entry->ret,
		__entry->partition_id,
		__entry->vp_index,
		__entry->fd
	)
);

TRACE_EVENT(mshv_hvcall_map_vp_state_page,
		TP_PROTO(u64 status, u64 partition_id, u32 vp_index, u32 page_type),
		TP_ARGS(status, partition_id, vp_index, page_type),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
		__field(u32, vp_index)
		__field(u32, page_type)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__entry->page_type = page_type;
	),

	TP_printk("status=0x%llx partition_id=%llu vp_index=%u page_type=%u",
		__entry->status,
		__entry->partition_id,
		__entry->vp_index,
		__entry->page_type
	)
);

TRACE_EVENT(mshv_drain_vp_signals,
		TP_PROTO(u64 partition_id, u32 vp_index),
		TP_ARGS(partition_id, vp_index),

	TP_STRUCT__entry(
		__field(u64, partition_id)
		__field(u32, vp_index)
	),

	TP_fast_assign(
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
	),

	TP_printk("partition_id=%llu vp_index=%u",
		__entry->partition_id,
		__entry->vp_index
	)
);

TRACE_EVENT(mshv_disable_vp_dispatch,
		TP_PROTO(long ret, u64 partition_id, u32 vp_index),
		TP_ARGS(ret, partition_id, vp_index),

	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(u32, vp_index)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
	),

	TP_printk("ret=%ld partition_id=%llu vp_index=%u",
		__entry->ret,
		__entry->partition_id,
		__entry->vp_index
	)
);

TRACE_EVENT(mshv_vp_release,
		TP_PROTO(u64 partition_id, u32 vp_index),
		TP_ARGS(partition_id, vp_index),

	TP_STRUCT__entry(
		__field(u64, partition_id)
		__field(u32, vp_index)
	),

	TP_fast_assign(
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
	),

	TP_printk("partition_id=%llu vp_index=%u",
		__entry->partition_id,
		__entry->vp_index
	)
);

TRACE_EVENT(mshv_run_vp_entry,
		TP_PROTO(u64 partition_id, u32 vp_index, char *scheduler),
		TP_ARGS(partition_id, vp_index, scheduler),
	TP_STRUCT__entry(
		__field(u64, partition_id)
		__field(u32, vp_index)
		__string(scheduler, scheduler)
	),
	TP_fast_assign(
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__assign_str(scheduler, scheduler);
	),
	TP_printk("partition_id=%llu vp_index=%u, scheduler=%s",
		__entry->partition_id,
		__entry->vp_index,
		__get_str(scheduler)
	)
);
TRACE_EVENT(mshv_run_vp_exit,
		TP_PROTO(long ret, u64 partition_id, u32 vp_index, u64 hv_message_type),
		TP_ARGS(ret, partition_id, vp_index, hv_message_type),
	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(u32, vp_index)
		__field(u64, hv_message_type)
	),
	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__entry->hv_message_type = hv_message_type;
	),
	TP_printk("ret=%ld partition_id=%llu vp_index=%u hv_msg_type=0x%llx",
		__entry->ret,
		__entry->partition_id,
		__entry->vp_index,
		__entry->hv_message_type
	)
);

TRACE_EVENT(mshv_root_sched_unsuspend_vp,
		TP_PROTO(long ret, u64 partition_id, u32 vp_index),
		TP_ARGS(ret, partition_id, vp_index),

	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(u32, vp_index)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
	),

	TP_printk("ret=%ld partition_id=%llu vp_index=%u",
		__entry->ret,
		__entry->partition_id,
		__entry->vp_index
	)
);

TRACE_EVENT(mshv_root_sched_handle_work,
		TP_PROTO(long ret, u64 partition_id, u32 vp_index, unsigned long thread_info_flag),
		TP_ARGS(ret, partition_id, vp_index, thread_info_flag),

	TP_STRUCT__entry(
		__field(long, ret)
		__field(u64, partition_id)
		__field(u32, vp_index)
		__field(unsigned long, thread_info_flag)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__entry->thread_info_flag = thread_info_flag;
	),

	TP_printk("ret=%ld partition_id=%llu vp_index=%u thread_info_flag=0x%lx",
		__entry->ret,
		__entry->partition_id,
		__entry->vp_index,
		__entry->thread_info_flag
	)
);

TRACE_EVENT(mshv_hvcall_dispatch_vp,
		TP_PROTO(u64 status, u64 partition_id, u32 vp_index, u32 flag,
				u32 dispatch_state, u32 dispatch_event),
		TP_ARGS(status, partition_id, vp_index, flag, dispatch_state, dispatch_event),

	TP_STRUCT__entry(
		__field(u64, status)
		__field(u64, partition_id)
		__field(u32, vp_index)
		__field(u32, flag)
		__field(u32, dispatch_state)
		__field(u32, dispatch_event)
	),

	TP_fast_assign(
		__entry->status = status;
		__entry->partition_id = partition_id;
		__entry->vp_index = vp_index;
		__entry->flag = flag;
		__entry->dispatch_state = dispatch_state;
		__entry->dispatch_event = dispatch_event;
	),

	TP_printk("status=0x%llx partition_id=%llu vp_index=%u flag=0x%x dispatch_state=0x%x dispatch_event=0x%x",
		__entry->status,
		__entry->partition_id,
		__entry->vp_index,
		__entry->flag,
		__entry->dispatch_state,
		__entry->dispatch_event
	)
);

#endif /* _TRACE_MSHV_MAIN_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
