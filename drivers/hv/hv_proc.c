// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clockchips.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>
#include <linux/minmax.h>
#include <linux/export.h>
#include <asm/mshyperv.h>

#define HV_DEPOSIT_MAX 512
#define HV_DEPOSIT_INP_MAX ((HV_HYP_PAGE_SIZE -  \
	offsetof(struct hv_deposit_memory, gpa_page_list)) / sizeof(u64))

/*
 * Allocate free pages for deposit to hypervisor. pfna[] must be large enough
 * to hold HV_DEPOSIT_INP_MAX (511) pages. If num_pages is 512, return last
 * pfn in lastpfn.
 *
 * Returns : -ENOMEM if zero allocated, else number of pages allocated
 */
static int hv_alloc_dep_pages(int node, u64 *pfna, u64 *lastpfnp, int num_pages,
			      bool contiguous)
{
	struct page *page;
	int num_allocd, count = 0, rc = 0;

	/* Published ABI, enforce its immutability. */
	BUILD_BUG_ON(HV_DEPOSIT_INP_MAX != 511);

	if (num_pages > HV_DEPOSIT_MAX ||
	    (num_pages == HV_DEPOSIT_MAX && lastpfnp == NULL))
		return -EINVAL;

	*lastpfnp = 0;
	while (num_pages) {
		/* Find highest order we can actually allocate */
		int order = 31 - __builtin_clz(num_pages);

		while (1) {
			page = alloc_pages_node(node, GFP_KERNEL, order);
			if (page || order == 0 || contiguous)
				break;

			order--;
		}

		if (page == NULL)
			break;

		split_page(page, order);
		num_allocd = 1 << order;
		num_pages -= num_allocd;

		while (num_allocd && count < HV_DEPOSIT_INP_MAX) {
			pfna[count++] = page_to_pfn(page++);
			num_allocd--;
		}

		if (num_allocd-- && count == HV_DEPOSIT_INP_MAX) {
			*lastpfnp = page_to_pfn(page);
			count++;
			break;
		}
	}

	if (count == 0)
		rc = -ENOMEM;
	else
		rc = count;

	return rc;
}

/*
 * Deposit memory in the hypervisor. A contiguous 2M worth of pfns is utmost
 * desired, but short of that, we deposit whatever contiguous chunks we can
 * get. If contiguous parameter is true, then the hypervisor requires deposited
 * memory to be contiguous.
 */
static int hv_call_deposit_pages(int node, u64 partition_id, bool contiguous)
{
	struct hv_deposit_memory *hc_input;
	int i, rc, num_pages;
	u64 status, *pfna, lastpfn = 0;

	BUILD_BUG_ON(HV_MAX_CONTIGUOUS_ALLOCATION_PAGES > HV_DEPOSIT_MAX);

	if (contiguous)
		num_pages = HV_MAX_CONTIGUOUS_ALLOCATION_PAGES;
	else
		num_pages = HV_DEPOSIT_MAX;

	hc_input = (struct hv_deposit_memory *)get_zeroed_page(GFP_KERNEL);
	if (hc_input == NULL)
		return -ENOMEM;

	hc_input->partition_id = partition_id;
	pfna = hc_input->gpa_page_list;

	rc = hv_alloc_dep_pages(node, pfna, &lastpfn, num_pages, contiguous);
	if (rc < 0)
		goto out_free;

	num_pages = rc;
	if (num_pages > HV_DEPOSIT_INP_MAX)
		num_pages = HV_DEPOSIT_INP_MAX;

	/* We are not using hyperv_pcpu_input_arg, so no need to disable */

	status = hv_do_rep_hypercall(HVCALL_DEPOSIT_MEMORY, num_pages,
				     0, hc_input, NULL);
	if (!hv_result_success(status)) {
		hv_status_err(status, "\n");
		rc = hv_result_to_errno(status);
		goto out_free_dep_pages;
	}

	if (lastpfn) {
		num_pages = 1;
		hc_input->gpa_page_list[0] = lastpfn;
		status = hv_do_rep_hypercall(HVCALL_DEPOSIT_MEMORY, num_pages,
					     0, hc_input, NULL);
		if (!hv_result_success(status))
			/* We deposited some earlier, so just free this */
			__free_page(pfn_to_page(lastpfn));
	}

	free_page((unsigned long)hc_input);
	return 0;

out_free_dep_pages:
	for (i = 0; i < num_pages; i++)
		__free_page(pfn_to_page(pfna[i]));
	if (lastpfn)
		__free_page(pfn_to_page(lastpfn));

out_free:
	free_page((unsigned long)hc_input);
	return rc;
}

int hv_deposit_memory_node(int node, u64 pt_id, u64 hv_status)
{
	int result = hv_result(hv_status);
	bool contiguous = false;

	if (result == HV_STATUS_INSUFFICIENT_ROOT_MEMORY ||
	    result == HV_STATUS_INSUFFICIENT_CONTIGUOUS_ROOT_MEMORY) {
		if (!hv_root_partition()) {
			hv_status_err(hv_status,
				      "Unexpected root memory deposit\n");
			return -EINVAL;
		}

		pt_id = HV_PARTITION_ID_SELF;
	}

	if (result == HV_STATUS_INSUFFICIENT_CONTIGUOUS_MEMORY ||
	    result == HV_STATUS_INSUFFICIENT_CONTIGUOUS_ROOT_MEMORY)
		contiguous = true;

	return hv_call_deposit_pages(node, pt_id, contiguous);
}
EXPORT_SYMBOL_GPL(hv_deposit_memory_node);

bool hv_result_needs_memory(u64 status)
{
	switch (hv_result(status)) {
	case HV_STATUS_INSUFFICIENT_MEMORY:
	case HV_STATUS_INSUFFICIENT_CONTIGUOUS_MEMORY:
	case HV_STATUS_INSUFFICIENT_ROOT_MEMORY:
	case HV_STATUS_INSUFFICIENT_CONTIGUOUS_ROOT_MEMORY:
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(hv_result_needs_memory);

int hv_call_add_logical_proc(int node, u32 lp_index, u32 apic_id)
{
	struct hv_input_add_logical_processor *input;
	struct hv_output_add_logical_processor *output;
	u64 status;
	unsigned long flags;
	int ret = 0;

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

		if (!hv_result_needs_memory(status)) {
			if (!hv_result_success(status)) {
				hv_status_err(status, "cpu %u apic ID: %u\n",
					      lp_index, apic_id);
				ret = hv_result_to_errno(status);
			}
			break;
		}
		ret = hv_deposit_memory_node(node, hv_current_partition_id,
					     status);
	} while (!ret);

	return ret;
}

int hv_call_create_vp(int node, u64 partition_id, u32 vp_index, u32 flags)
{
	struct hv_create_vp *input;
	u64 status;
	unsigned long irq_flags;
	int ret = 0;

	do {
		local_irq_save(irq_flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->flags = flags;
		input->subnode_type = HV_SUBNODE_ANY;
		input->proximity_domain_info = hv_numa_node_to_pxm_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_VP, input, NULL);
		local_irq_restore(irq_flags);

		if (!hv_result_needs_memory(status)) {
			if (!hv_result_success(status)) {
				hv_status_err(status, "vcpu: %u, lp: %u\n",
					      vp_index, flags);
				ret = hv_result_to_errno(status);
			}
			break;
		}
		ret = hv_deposit_memory_node(node, partition_id, status);

	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_create_vp);

int hv_call_notify_all_processors_started(void)
{
	struct hv_input_notify_partition_event *input;
	unsigned long irq_flags;
	u64 status;
	int ret = 0;

	local_irq_save(irq_flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->event = HV_PARTITION_ALL_LOGICAL_PROCESSORS_STARTED;
	status = hv_do_hypercall(HVCALL_NOTIFY_PARTITION_EVENT, input, NULL);
	local_irq_restore(irq_flags);

	if (!hv_result_success(status)) {
		hv_status_err(status, "\n");
		ret = hv_result_to_errno(status);
	}
	return ret;
}

/*
 * Probe whether logical processor @lp_index is already known to the
 * hypervisor. Used by hv_smp_prepare_cpus() to detect that we are running
 * in a kexec'd kernel and the LPs/VPs from the previous boot still exist.
 */
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
	status = hv_do_hypercall(HVCALL_GET_LOGICAL_PROCESSOR_RUN_TIME,
				 input, out_page);

	local_irq_restore(flags);

	/*
	 * Called early in boot before adding the LPs. HV_STATUS_SUCCESS and
	 * HV_STATUS_INVALID_LP_INDEX are the only expected status codes;
	 * anything else leaves the system in an indeterminate state.
	 */
	if (hv_result(status) != HV_STATUS_SUCCESS &&
	    hv_result(status) != HV_STATUS_INVALID_LP_INDEX) {
		hv_status_err(status, "lp_index %u\n", lp_index);
		BUG();
	}

	return hv_result_success(status);
}
