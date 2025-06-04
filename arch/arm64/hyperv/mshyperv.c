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
bool hv_nested;

int hv_get_hypervisor_version(union hv_hypervisor_version_info *info)
{
	hv_get_vpreg_128(HV_REGISTER_HYPERVISOR_VERSION,
			 (struct hv_get_vp_registers_output *)info);

	return 0;
}
EXPORT_SYMBOL_GPL(hv_get_hypervisor_version);

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

int __init hyperv_init(void)
{
	struct hv_get_vp_registers_output	result;
	u64	guest_id;
	int	ret;

	/* Not supported on ARM64 yet */
	hv_nested = false;

	/*
	 * Allow for a kernel built with CONFIG_HYPERV to be running in
	 * a non-Hyper-V environment.
	 *
	 * In such cases, do nothing and return success.
	 */
	if (!hyperv_detect_via_acpi() && !hyperv_detect_via_smccc())
		return 0;

	/* Setup the guest ID */
	guest_id = hv_generate_guest_id(LINUX_VERSION_CODE);
	hv_set_vpreg(HV_REGISTER_GUEST_OS_ID, guest_id);

	/* Get the features and hints from Hyper-V */
	hv_get_vpreg_128(HV_REGISTER_PRIVILEGES_AND_FEATURES_INFO, &result);
	ms_hyperv.features = result.as32.a;
	ms_hyperv.priv_high = result.as32.b;
	ms_hyperv.misc_features = result.as32.c;

	hv_get_vpreg_128(HV_REGISTER_FEATURES_INFO, &result);
	ms_hyperv.hints = result.as32.a;

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high, ms_hyperv.hints,
		ms_hyperv.misc_features);

	hv_identify_partition_type();

	if (hv_root_partition()) {
		hv_dump_mshv_memory();
		hv_mark_resources();
	}

	ret = hv_common_init();
	if (ret)
		return ret;

	ret = cpuhp_setup_state(CPUHP_AP_HYPERV_ONLINE, "arm64/hyperv_init:online",
				hv_common_cpu_init, hv_common_cpu_die);
	if (ret < 0) {
		hv_common_free();
		return ret;
	}

	if (ms_hyperv.priv_high & HV_ACCESS_PARTITION_ID)
		hv_get_partition_id();

	hyperv_initialized = true;
	return 0;
}

void __init hv_smp_prepare_cpus(unsigned int max_cpus)
{
	int cpu, ccpu = smp_processor_id();
	int ret;

	if (!hv_root_partition())
		return;

	for_each_present_cpu(cpu) {
		if (cpu == ccpu)
			continue;

		hv_call_add_logical_proc(early_cpu_to_node(cpu), cpu,
				cpu_physical_id(cpu));
	}

	hv_call_notify_all_processors_started();

	for_each_present_cpu(cpu) {
		if (cpu == ccpu)
			continue;

		hv_call_create_vp(NUMA_NO_NODE, hv_current_partition_id, cpu,
				cpu);
	}
}

int hv_cpu_on(unsigned int cpu, phys_addr_t entry_point)
{
	struct hv_input_start_vp *input;
	u64 status;

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = hv_current_partition_id;
	input->vp_index = cpu;
	input->target_vtl.target_vtl = 0;
	input->vp_context.pc = entry_point;

	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);

	if (!hv_result_success(status))
		pr_err("Failed to start VP %d, status: %s\n", cpu,
		       hv_result_to_string(status));

	return hv_result_to_errno(status);
}

bool hv_is_hyperv_initialized(void)
{
	return hyperv_initialized;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);
