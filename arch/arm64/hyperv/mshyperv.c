// SPDX-License-Identifier: GPL-2.0

/*
 * Core routines for interacting with Microsoft's Hyper-V hypervisor,
 * including hypervisor initialization.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#include <linux/types.h>
#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cpuhotplug.h>
#include <asm/mshyperv.h>

static bool hyperv_initialized;

#ifdef CONFIG_ACPI

static bool __init hyperv_detect_via_acpi(void)
{
	if (acpi_disabled)
		return false;
	/*
	 * Hypervisor ID is only available in ACPI v6+, and the
	 * structure layout was extended in v6 to accommodate that
	 * new field.
	 *
	 * At the very minimum, this check makes sure not to read
	 * past the FADT structure.
	 *
	 * It is also needed to catch running in some unknown
	 * non-Hyper-V environment that has ACPI 5.x or less.
	 * In such a case, it can't be Hyper-V.
	 */
	if (acpi_gbl_FADT.header.revision < 6)
		return false;
	return strncmp((char *)&acpi_gbl_FADT.hypervisor_id, "MsHyperV", 8) == 0;
}

#else

static bool __init hyperv_detect_via_acpi(void)
{
	return false;
}

#endif

static bool __init hyperv_detect_via_smccc(void)
{
	uuid_t hyperv_uuid = UUID_INIT(
		0x58ba324d, 0x6447, 0x24cd,
		0x75, 0x6c, 0xef, 0x8e,
		0x24, 0x70, 0x59, 0x16);

	return arm_smccc_hypervisor_has_uuid(&hyperv_uuid);
}

static bool __init legacy_hyperv_detect_via_smccc(void)
{
	struct arm_smccc_res res = {};

	if (arm_smccc_1_1_get_conduit() != SMCCC_CONDUIT_HVC)
		return false;

	arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return false;

	return res.a0 == 0x7948734d && res.a1 == 0x56726570 && res.a2 == 0
		&& res.a3 == 0;
}

static int __init hyperv_init(void)
{
	struct hv_get_vp_registers_output	result;
	u32	a, b, c, d;
	u64	guest_id;
	int	ret;

	/*
	 * Allow for a kernel built with CONFIG_HYPERV to be running in
	 * a non-Hyper-V environment.
	 *
	 * In such cases, do nothing and return success.
	 */
	if (!hyperv_detect_via_acpi() && !hyperv_detect_via_smccc()
		&& !legacy_hyperv_detect_via_smccc())
		return 0;

	/* Setup the guest ID */
	guest_id = hv_generate_guest_id(LINUX_VERSION_CODE);
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, guest_id);

	/* Get the features and hints from Hyper-V */
	hv_get_vpreg_128(HV_REGISTER_FEATURES, &result);
	ms_hyperv.features = result.as32.a;
	ms_hyperv.priv_high = result.as32.b;
	ms_hyperv.misc_features = result.as32.c;

	hv_get_vpreg_128(HV_REGISTER_ENLIGHTENMENTS, &result);
	ms_hyperv.hints = result.as32.a;

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high, ms_hyperv.hints,
		ms_hyperv.misc_features);

	/* Get information about the Hyper-V host version */
	hv_get_vpreg_128(HV_REGISTER_HYPERVISOR_VERSION, &result);
	a = result.as32.a;
	b = result.as32.b;
	c = result.as32.c;
	d = result.as32.d;
	pr_info("Hyper-V: Host Build %d.%d.%d.%d-%d-%d\n",
		b >> 16, b & 0xFFFF, a,	d & 0xFFFFFF, c, d >> 24);

	ret = hv_common_init();
	if (ret)
		return ret;

	ret = cpuhp_setup_state(CPUHP_AP_HYPERV_ONLINE, "arm64/hyperv_init:online",
				hv_common_cpu_init, hv_common_cpu_die);
	if (ret < 0) {
		hv_common_free();
		return ret;
	}

	hyperv_initialized = true;
	return 0;
}

early_initcall(hyperv_init);

bool hv_is_hyperv_initialized(void)
{
	return hyperv_initialized;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);
