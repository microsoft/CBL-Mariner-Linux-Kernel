/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *
 */

#ifndef _HV_VSM_H
#define _HV_VSM_H

#include <linux/types.h>

#define VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL	0x1FFE0
#define VSM_VTL_CALL_FUNC_ID_BOOT_APS		0x1FFE1
#define VSM_VTL_CALL_FUNC_ID_LOCK_REGS		0x1FFE2

extern bool hv_vsm_boot_success;
extern bool hv_vsm_mbec_enabled;
extern union hv_register_vsm_code_page_offsets vsm_code_page_offsets;
extern struct resource sk_res;

struct hv_vtlcall_param {
	u64	a0;
	u64	a1;
	u64	a2;
	u64	a3;
} __packed;

union hv_register_vsm_code_page_offsets {
	u64 as_uint64;

	struct {
		u64 vtl_call_offset : 12;
		u64 vtl_return_offset : 12;
		u64 reserved_z : 40;
	};
} __packed;

int hv_vsm_boot_init(void);

int hv_vsm_get_register(u32 reg_name, u64 *result);
int hv_vsm_set_register(u32 reg_name, u64 value);
int hv_vsm_get_code_page_offsets(void);

#endif /* _HV_VSM_H */
