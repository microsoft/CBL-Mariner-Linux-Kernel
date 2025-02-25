// SPDX-License-Identifier: GPL-2.0-only
/*
 * VSM framework that enables VTL1, loads secure kernel and boots VTL1.
 *
 * Copyright © 2024 Microsoft Corporation
 */

#include <linux/module.h>

#include <hyperv/hvgdk_mini.h>
#include <hyperv/hv_vsm.h>

#include <asm/mshyperv.h>

#include "mshv.h"
#include "hv_vsm.h"

static int __init vsm_arch_has_vsm_access(void)
{
	if (!(ms_hyperv.features & HV_MSR_SYNIC_AVAILABLE))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VSM))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VP_REGS))
		return false;
	return true;
}

static int __init vsm_get_max_vtl(int *max_vtl)
{
	struct hv_register_assoc reg = {
		.name = HV_REGISTER_VSM_PARTITION_STATUS,
	};
	union hv_input_vtl input_vtl = {
		.as_uint8 = 0,
	};
	int err;

	err = hv_call_get_vp_registers(HV_VP_INDEX_SELF,
				       HV_PARTITION_ID_SELF,
				       1, input_vtl, &reg);
	if (err)
		return err;

	*max_vtl = reg.value.vsm_partition_status.max_vtl;

	return 0;
}

int __init vsm_init(void)
{
	int max_vtl;

	if (!vsm_arch_has_vsm_access())
		return 0;

	if (vsm_get_max_vtl(&max_vtl))
		return 0;

	if (max_vtl == 0)
		return 0;

	return hv_vsm_boot_init();
}
