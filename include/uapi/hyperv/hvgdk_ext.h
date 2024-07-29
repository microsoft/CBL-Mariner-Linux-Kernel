/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_HV_HVGDK_EXT_H
#define _UAPI_HV_HVGDK_EXT_H

#include "hvgdk_mini.h"

#define HVGDK_EXT_VERSION		(25294)

/* Extended hypercalls */
enum {		/* HV_EXT_CALL */
	HV_EXTCALL_QUERY_CAPABILITIES = 0x8001,
	HV_EXTCALL_MEMORY_HEAT_HINT   = 0x8003,
};

/* HV_EXT_OUTPUT_QUERY_CAPABILITIES */
#define HV_EXT_CAPABILITY_MEMORY_COLD_DISCARD_HINT BIT(8)

enum {		/* HV_EXT_MEMORY_HEAT_HINT_TYPE */
	HV_EXTMEM_HEAT_HINT_COLD = 0,
	HV_EXTMEM_HEAT_HINT_HOT = 1,
	HV_EXTMEM_HEAT_HINT_COLD_DISCARD = 2,
	HV_EXTMEM_HEAT_HINT_MAX
};

/* HvExtCallMemoryHeatHint hypercall */
struct hv_memory_hint {		/* HV_EXT_INPUT_MEMORY_HEAT_HINT */
	u64 heat_type:2;	/* HV_EXTMEM_HEAT_HINT_* */
	u64 reserved:62;
	union hv_gpa_page_range ranges[];
} __packed;

#endif /* _UAPI_HV_HVGDK_EXT_H */
