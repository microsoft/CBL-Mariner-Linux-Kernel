/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Type definitions for the Microsoft Hypervisor.
 */
#ifndef _HV_HVGDK_H
#define _HV_HVGDK_H

#include "hvgdk_mini.h"
#include "hvgdk_ext.h"

#define HVGDK_H_VERSION			(25125)

#if IS_ENABLED(CONFIG_X86)

enum hv_unimplemented_msr_action {
	HV_UNIMPLEMENTED_MSR_ACTION_FAULT = 0,
	HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO = 1,
	HV_UNIMPLEMENTED_MSR_ACTION_COUNT = 2,
};

#endif

/* Define connection identifier type. */
union hv_connection_id {
	u32 asu32;
	struct {
		u32 id : 24;
		u32 reserved : 8;
	} __packed u;
};

struct hv_input_unmap_gpa_pages {
	u64 target_partition_id;
	u64 target_gpa_base;
	u32 unmap_flags;
	u32 padding;
} __packed;

/* NOTE: below not really in hvgdk.h */
/*
 * Hyper-V uses the software reserved 32 bytes in VMCB control area to expose
 * SVM enlightenments to guests.
 * HV_VMX_ENLIGHTENED_VMCS or SVM_NESTED_ENLIGHTENED_VMCB_FIELDS
 */
struct hv_vmcb_enlightenments {
	struct __packed hv_enlightenments_control {
		u32 nested_flush_hypercall : 1;
		u32 msr_bitmap : 1;
		u32 enlightened_npt_tlb: 1;
		u32 reserved : 29;
	} __packed hv_enlightenments_control;
	u32 hv_vp_id;
	u64 hv_vm_id;
	u64 partition_assist_page;
	u64 reserved;
} __packed;

#endif /* #ifndef _HV_HVGDK_H */
