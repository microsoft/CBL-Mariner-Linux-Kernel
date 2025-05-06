// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clockchips.h>
#include <linux/hyperv.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>
#include <linux/minmax.h>
#include <asm/hypervisor.h>
#include <asm/mshyperv.h>
#include <asm/apic.h>
#include <asm/trace/hyperv.h>

int hv_call_add_logical_proc(int node, u32 lp_index, u32 apic_id)
{
	struct hv_input_add_logical_processor *input;
	struct hv_output_add_logical_processor *output;
	u64 status;
	unsigned long flags;
	int ret = HV_STATUS_SUCCESS;

	/*
	 * When adding a logical processor, the hypervisor may return
	 * HV_STATUS_INSUFFICIENT_MEMORY. When that happens, we deposit more
	 * pages and retry.
	 */
	do {
		local_irq_save(flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		/* We don't do anything with the output right now */
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input->lp_index = lp_index;
		input->apic_id = apic_id;
		input->proximity_domain_info = hv_numa_node_to_pxm_info(node);
		status = hv_do_hypercall(HVCALL_ADD_LOGICAL_PROCESSOR,
					 input, output);
		local_irq_restore(flags);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status)) {
				pr_err("%s: cpu %u apic ID %u, %s\n", __func__,
				       lp_index, apic_id, hv_status_to_string(status));
				ret = hv_status_to_errno(status);
			}
			break;
		}
		ret = hv_call_deposit_pages(node, hv_current_partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_notify_all_processors_started(void)
{
	struct hv_input_notify_partition_event *input;
	u64 status;
	unsigned long irq_flags;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	input->event = HV_PARTITION_ALL_LOGICAL_PROCESSORS_STARTED;

	status = hv_do_hypercall(HVCALL_NOTIFY_PARTITION_EVENT, input, NULL);

	local_irq_restore(irq_flags);

	if (!hv_result_success(status)) {
		pr_err("%s: Failed to notify all processors started, %s\n",
		       __func__, hv_status_to_string(status));
	}

	return hv_status_to_errno(status);
}

bool hv_lp_exists(u32 lp_index)
{
	struct hv_input_get_logical_processor_run_time *input;
	struct hv_output_get_logical_processor_run_time *out_page;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

	input->lp_index = lp_index;
	status = hv_do_hypercall(HVCALL_GET_LOGICAL_PROCESSOR_RUN_TIME, input,
			out_page);

	local_irq_restore(flags);

	/*
	 * This method is called early in boot before adding the LPs.
	 *
	 * HV_STATUS_SUCCESS and HV_STATUS_INVALID_LP_INDEX are the only
	 * expected return codes here. Anything else means the system is
	 * in some sort of an indeterminate state and we can't say for sure
	 * whether the LP is added or not.
	 */
	if (status != HV_STATUS_SUCCESS && status != HV_STATUS_INVALID_LP_INDEX) {
		pr_err("%s: unexpected status %llu\n", __func__, status);
		BUG();
	}

	return hv_result_success(status);
}
