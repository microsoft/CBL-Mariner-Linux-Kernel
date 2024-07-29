/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Type definitions for the hypervisor guest interface.
 */
#ifndef _UAPI_HV_HVGDK_H
#define _UAPI_HV_HVGDK_H

#include "hvgdk_mini.h"
#if defined(__KERNEL__)
#include "hvgdk_ext.h"
#endif

#define HVGDK_H_VERSION			(25125)

#if defined(__x86_64__)

enum hv_unimplemented_msr_action {
	HV_UNIMPLEMENTED_MSR_ACTION_FAULT = 0,
	HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO = 1,
	HV_UNIMPLEMENTED_MSR_ACTION_COUNT = 2,
};

#endif

/* Define connection identifier type. */
union hv_connection_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	} __packed u;
};

struct hv_input_unmap_gpa_pages {
	__u64 target_partition_id;
	__u64 target_gpa_base;
	__u32 unmap_flags;
	__u32 padding;
} __packed;

#endif /* #ifndef _UAPI_HV_HVGDK_H */
