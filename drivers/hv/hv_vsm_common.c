// SPDX-License-Identifier: GPL-2.0
/*
 * VSM apis common to VTL0 and VTL1
 *
 * Copyright (c) 2024, Microsoft Corporation.
 *
 */

#include <asm/mshyperv.h>
#include <linux/hyperv.h>
#include "mshv.h"
#include "hv_vsm.h"

union hv_register_vsm_code_page_offsets vsm_code_page_offsets;

int __hv_vsm_get_register(u32 reg_name, u64 *result, u8 input_vtl)
{
	struct hv_register_assoc reg = {
		.name = reg_name,
	};
	union hv_input_vtl vtl = {
		.as_uint8 = input_vtl,
	};
	int ret;

	ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF,
				       HV_PARTITION_ID_SELF,
				       1, vtl, &reg);
	if (ret)
		return ret;

	*result = reg.value.reg64;

	return 0;
}

int __hv_vsm_set_register(u32 reg_name, u64 value, u8 input_vtl)
{
	struct hv_register_assoc reg = {
		.name = reg_name,
		.value.reg64 = value,
	};
	union hv_input_vtl vtl = {
		.as_uint8 = input_vtl,
	};

	return hv_call_set_vp_registers(HV_VP_INDEX_SELF,
					HV_PARTITION_ID_SELF,
					1, vtl, &reg);
}

int hv_vsm_get_register(u32 reg_name, u64 *result)
{
	return __hv_vsm_get_register(reg_name, result, 0);
}

int hv_vsm_set_register(u32 reg_name, u64 value)
{
	return __hv_vsm_set_register(reg_name, value, 0);
}

int hv_vsm_get_code_page_offsets(void)
{
	u64 result;
	int ret;

	ret = hv_vsm_get_register(HV_REGISTER_VSM_CODE_PAGE_OFFSETS, &result);
	if (!ret)
		vsm_code_page_offsets.as_uint64 = result;

	return ret;
}
