// SPDX-License-Identifier: GPL-2.0
/*
 * VSM apis common to VTL0 and VTL1
 *
 * Copyright (c) 2024, Microsoft Corporation.
 *
 */

#include <asm/mshyperv.h>
#include <linux/hyperv.h>
#include "hv_vsm.h"

union hv_register_vsm_code_page_offsets vsm_code_page_offsets;

int hv_vsm_get_register(u32 reg_name, u64 *result)
{
	u64 status;
	unsigned long flags;
	struct hv_get_vp_registers_input *hvin = NULL;
	struct hv_get_vp_registers_output *hvout = NULL;

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	hvout = *this_cpu_ptr(hyperv_pcpu_output_arg);

	hvin->header.partitionid = HV_PARTITION_ID_SELF;
	hvin->header.vpindex = HV_VP_INDEX_SELF;
	hvin->header.inputvtl = 0;
	hvin->element[0].name0 = reg_name;

	status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, 1, 0, hvin, hvout);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		return -EFAULT;

	*result = hvout->as64.low;
	return 0;
}

int hv_vsm_set_register(u32 reg_name, u64 value)
{
	u64 status;
	unsigned long flags;
	struct hv_set_vp_registers_input *hvin = NULL;

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);

	hvin->header.partitionid = HV_PARTITION_ID_SELF;
	hvin->header.vpindex = HV_VP_INDEX_SELF;
	hvin->header.inputvtl = 0;
	hvin->element[0].name = reg_name;
	hvin->element[0].valuelow = value;

	status = hv_do_rep_hypercall(HVCALL_SET_VP_REGISTERS, 1, 0, hvin, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		return -EFAULT;

	return 0;
}

int hv_vsm_get_code_page_offsets(void)
{
	u64 result;
	int ret;

	ret = hv_vsm_get_register(HV_REGISTER_VSM_CODEPAGE_OFFSETS, &result);
	if (!ret)
		vsm_code_page_offsets.as_uint64 = result;

	return ret;
}
