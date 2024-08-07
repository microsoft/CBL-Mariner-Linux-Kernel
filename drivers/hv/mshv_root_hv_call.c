// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Hypercall helper functions used by the mshv_root module.
 *
 * Authors:
 *   Nuno Das Neves <nunodasneves@linux.microsoft.com>
 *   Wei Liu <wei.liu@kernel.org>
 *   Jinank Jain <jinankjain@microsoft.com>
 *   Vineeth Remanan Pillai <viremana@linux.microsoft.com>
 *   Asher Kariv <askariv@microsoft.com>
 *   Muminul Islam <Muminul.Islam@microsoft.com>
 *   Anatol Belski <anbelski@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/mshyperv.h>

#include <trace/events/mshv.h>
#include "mshv.h"

/* Determined empirically */
#define HV_INIT_PARTITION_DEPOSIT_PAGES 208
#define HV_MAP_GPA_DEPOSIT_PAGES	256

#define HV_PAGE_COUNT_2M_ALIGNED(pg_count) (!((pg_count) & (0x200 - 1)))

#define HV_WITHDRAW_BATCH_SIZE	(HV_HYP_PAGE_SIZE / sizeof(u64))
#define HV_MAP_GPA_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_map_gpa_pages)) \
		/ sizeof(u64))
#define HV_GET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_get_vp_state)) \
		/ sizeof(u64))
#define HV_SET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_set_vp_state)) \
		/ sizeof(u64))
#define HV_GET_GPA_ACCESS_STATES_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(union hv_gpa_page_access_state)) \
		/ sizeof(union hv_gpa_page_access_state))
#define HV_MODIFY_SPARSE_SPA_PAGE_HOST_ACCESS_MAX_PAGE_COUNT                   \
	((HV_HYP_PAGE_SIZE -                                                   \
	  sizeof(struct hv_input_modify_sparse_spa_page_host_access)) /        \
	 sizeof(u64))
#define HV_ISOLATED_PAGE_BATCH_SIZE                                            \
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_import_isolated_pages)) /  \
	 sizeof(u64))

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id)
{
	struct hv_input_withdraw_memory *input_page;
	struct hv_output_withdraw_memory *output_page;
	struct page *page;
	u16 completed;
	unsigned long remaining = count;
	u64 status;
	int i;
	unsigned long flags;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	output_page = page_address(page);

	while (remaining) {
		local_irq_save(flags);

		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		memset(input_page, 0, sizeof(*input_page));
		input_page->partition_id = partition_id;
		status = hv_do_rep_hypercall(
			HVCALL_WITHDRAW_MEMORY,
			min(remaining, HV_WITHDRAW_BATCH_SIZE), 0, input_page,
			output_page);

		local_irq_restore(flags);

		completed = hv_repcomp(status);

		for (i = 0; i < completed; i++)
			__free_page(pfn_to_page(output_page->gpa_page_list[i]));

		if (!hv_result_success(status)) {
			if (hv_result(status) == HV_STATUS_NO_RESOURCES)
				status = HV_STATUS_SUCCESS;
			else
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			break;
		}

		remaining -= completed;
	}
	free_page((unsigned long)output_page);

	trace_mshv_hvcall_withdraw_memory(status, partition_id);

	return hv_status_to_errno(status);
}

int hv_call_create_partition(
		u64 flags,
		struct hv_partition_creation_properties creation_properties,
		union hv_partition_isolation_properties isolation_properties,
		u64 *partition_id)
{
	struct hv_input_create_partition *input;
	struct hv_output_create_partition *output;
	u64 status;
	int ret;
	unsigned long irq_flags;

	do {
		local_irq_save(irq_flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		memset(input, 0, sizeof(*input));
		input->flags = flags;
		input->compatibility_version = HV_COMPATIBILITY_21_H2;

		memcpy(&input->partition_creation_properties, &creation_properties,
			sizeof(creation_properties));

		memcpy(&input->isolation_properties, &isolation_properties,
		       sizeof(isolation_properties));

		status = hv_do_hypercall(HVCALL_CREATE_PARTITION,
					 input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*partition_id = output->partition_id;
			else
				pr_err("%s: %s\n",
				       __func__, hv_status_to_string(status));
			local_irq_restore(irq_flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(irq_flags);
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    hv_current_partition_id, 1);
	} while (!ret);

	trace_mshv_hvcall_create_partition(status, (ret ? 0 : (*partition_id)), flags);

	return ret;
}

int hv_call_initialize_partition(u64 partition_id)
{
	struct hv_input_initialize_partition input;
	u64 status;
	int ret;

	input.partition_id = partition_id;

	ret = hv_call_deposit_pages(
				NUMA_NO_NODE,
				partition_id,
				HV_INIT_PARTITION_DEPOSIT_PAGES);
	if (ret)
		return ret;

	do {
		status = hv_do_fast_hypercall8(
				HVCALL_INITIALIZE_PARTITION,
				*(u64 *)&input);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n",
				       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	trace_mshv_hvcall_initialize_partition(status, partition_id);

	return ret;
}

int hv_call_finalize_partition(u64 partition_id)
{
	struct hv_input_finalize_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(
			HVCALL_FINALIZE_PARTITION,
			*(u64 *)&input);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	trace_mshv_hvcall_finalize_partition(status, partition_id);

	return hv_status_to_errno(status);
}

int hv_call_delete_partition(u64 partition_id)
{
	struct hv_input_delete_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(HVCALL_DELETE_PARTITION, *(u64 *)&input);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	trace_mshv_hvcall_delete_partition(status, partition_id);

	return hv_status_to_errno(status);
}

/* Ask the hypervisor to map guest ram pages or the guest mmio space */
static int hv_do_map_gpa_hcall(u64 partition_id, u64 gfn, u64 page_struct_count,
			       u32 flags, struct page **pages, u64 mmio_spa)
{
	struct hv_input_map_gpa_pages *input_page;
	u64 status, *pfnlist;
	unsigned long irq_flags, large_shift = 0;
	int ret = 0, done = 0;
	u64 page_count = page_struct_count;

	if (page_count == 0 || (pages && mmio_spa))
		return -EINVAL;

	if (flags & HV_MAP_GPA_LARGE_PAGE) {
		if (mmio_spa) {
			pr_err("%s: HV_MAP_GPA_LARGE_PAGE not supported with mmio\n",
			       __func__);
			return -EINVAL;
		}
		if (!HV_PAGE_COUNT_2M_ALIGNED(page_count)) {
			pr_err("%s: HV_MAP_GPA_LARGE_PAGE, but page_count %llx not aligned\n",
			       __func__, page_count);
			return -EINVAL;
		}
		large_shift = HV_HYP_LARGE_PAGE_SHIFT - HV_HYP_PAGE_SHIFT;
		page_count >>= large_shift;
	}

	while (done < page_count) {
		ulong i, completed, remain = page_count - done;
		int rep_count = min(remain, HV_MAP_GPA_BATCH_SIZE);

		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gfn + (done << large_shift);
		input_page->map_flags = flags;
		pfnlist = input_page->source_gpa_page_list;

		for (i = 0; i < rep_count; i++)
			if (flags & HV_MAP_GPA_NO_ACCESS) {
				pfnlist[i] = 0;
			} else if (pages) {
				u64 index = (done + i) << large_shift;

				if (index >= page_struct_count) {
					pr_err("%s: Bad index %lu\n",
					       __func__, i);
					ret = -EINVAL;
					break;
				}
				pfnlist[i] = page_to_pfn(pages[index]);
			} else {
				pfnlist[i] = mmio_spa + done + i;
			}
		if (ret)
			break;

		status = hv_do_rep_hypercall(HVCALL_MAP_GPA_PAGES, rep_count, 0,
					     input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id,
						    HV_MAP_GPA_DEPOSIT_PAGES);
			if (ret) {
				pr_err("%s: Unable to deposit pages 0x%llx\n",
				       __func__, status);
				break;
			}

		} else if (!hv_result_success(status)) {
			pr_err("%s: map pages failed %u/%llu. status:0x%llx %s\n",
			       __func__, done, page_count, status,
			       hv_status_to_string(hv_result(status)));
			ret = hv_status_to_errno(status);
			break;
		}

		done += completed;
	}

	if (ret && done) {
		u32 unmap_flags = 0;

		if (flags & HV_MAP_GPA_LARGE_PAGE)
			unmap_flags |= HV_UNMAP_GPA_LARGE_PAGE;
		hv_call_unmap_gpa_pages(partition_id, gfn, done, unmap_flags);
	}

	return ret;
}

/* Ask the hypervisor to map guest ram pages */
int hv_call_map_gpa_pages(u64 partition_id, u64 gpa_target, u64 page_count,
			  u32 flags, struct page **pages)
{
	return hv_do_map_gpa_hcall(partition_id, gpa_target, page_count,
				   flags, pages, 0);
}

/* Ask the hypervisor to map guest mmio space */
int hv_call_map_mmio_pages(u64 partition_id, u64 gfn, u64 mmio_spa, u64 numpgs)
{
	int i;
	u32 flags = HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE |
		    HV_MAP_GPA_NOT_CACHED;

	for (i = 0; i < numpgs; i++)
		if (page_is_ram(mmio_spa + i))
			return -EINVAL;

	return hv_do_map_gpa_hcall(partition_id, gfn, numpgs, flags, NULL,
				   mmio_spa);
}

int hv_call_unmap_gpa_pages(
		u64 partition_id,
		u64 gfn,
		u64 page_count_4k, u32 flags)
{
	struct hv_input_unmap_gpa_pages *input_page;
	u64 status, page_count = page_count_4k;
	unsigned long irq_flags, large_shift = 0;
	int ret = 0, done = 0;

	if (page_count == 0)
		return -EINVAL;

	if (flags & HV_UNMAP_GPA_LARGE_PAGE) {
		if (!HV_PAGE_COUNT_2M_ALIGNED(page_count)) {
			pr_err("%s: HV_UNMAP_GPA_LARGE_PAGE, but page_count %llx not aligned\n",
			       __func__, page_count);
			return -EINVAL;
		}
		large_shift = HV_HYP_LARGE_PAGE_SHIFT - HV_HYP_PAGE_SHIFT;
		page_count >>= large_shift;
	}

	while (done < page_count) {
		ulong completed, remain = page_count - done;
		int rep_count = min(remain, HV_MAP_GPA_BATCH_SIZE);

		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gfn + (done << large_shift);
		input_page->unmap_flags = flags;
		status = hv_do_rep_hypercall(
			HVCALL_UNMAP_GPA_PAGES, rep_count, 0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);
		if (!hv_result_success(status)) {
			pr_err("%s: unmap pages failed %u/%llu. status:0x%llx %s\n",
			       __func__, done, page_count, status,
			       hv_status_to_string(hv_result(status)));
			ret = hv_status_to_errno(status);
			break;
		}

		done += completed;
	}

	return ret;
}

int hv_call_get_gpa_access_states(
		u64 partition_id,
		u32 count,
		u64 gpa_base_pfn,
		union hv_gpa_page_access_state_flags state_flags,
		int *written_total,
		union hv_gpa_page_access_state *states)
{
	struct hv_input_get_gpa_pages_access_state *input_page;
	union hv_gpa_page_access_state *output_page;
	int completed = 0;
	unsigned long remaining = count;
	int rep_count, i;
	u64 status;
	unsigned long flags;

	*written_total = 0;
	while (remaining) {
		local_irq_save(flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input_page->partition_id = partition_id;
		input_page->hv_gpa_page_number = gpa_base_pfn + *written_total;
		input_page->flags = state_flags;
		rep_count = min(remaining, HV_GET_GPA_ACCESS_STATES_BATCH_SIZE);

		status = hv_do_rep_hypercall(HVCALL_GET_GPA_PAGES_ACCESS_STATES, rep_count,
					     0, input_page, output_page);
		if (!hv_result_success(status)) {
			pr_err("%s: completed %li out of %u, %s\n",
			       __func__,
			       count - remaining, count,
			       hv_status_to_string(status));
			local_irq_restore(flags);
			break;
		}
		completed = hv_repcomp(status);
		for (i = 0; i < completed; ++i)
			states[i].as_uint8 = output_page[i].as_uint8;

		states += completed;
		*written_total += completed;
		remaining -= completed;
		local_irq_restore(flags);
	}

	return hv_status_to_errno(status);
}

int hv_call_install_intercept(
		u64 partition_id,
		u32 access_type,
		enum hv_intercept_type intercept_type,
		union hv_intercept_parameters intercept_parameter)
{
	struct hv_input_install_intercept *input;
	unsigned long flags;
	u64 status;
	int ret;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		input->partition_id = partition_id;
		input->access_type = access_type;
		input->intercept_type = intercept_type;
		input->intercept_parameter = intercept_parameter;
		status = hv_do_hypercall(
				HVCALL_INSTALL_INTERCEPT, input, NULL);

		local_irq_restore(flags);
		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_assert_virtual_interrupt(
		u64 partition_id,
		u32 vector,
		u64 dest_addr,
		union hv_interrupt_control control)
{
	struct hv_input_assert_virtual_interrupt *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->vector = vector;
	input->dest_addr = dest_addr;
	input->control = control;
	status = hv_do_hypercall(HVCALL_ASSERT_VIRTUAL_INTERRUPT, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int hv_call_delete_vp(u64 partition_id, u32 vp_index)
{
	union hv_delete_vp input = { 0 };
	u64 status;

	input.partition_id = partition_id;
	input.vp_index = vp_index;

	status = hv_do_fast_hypercall16(HVCALL_DELETE_VP,
					input.as_uint64[0], input.as_uint64[1]);
	if (!hv_result_success(status)) {
		pr_err("%s: %s\n",
			__func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_delete_vp);

#ifdef HV_SUPPORTS_VP_STATE

int hv_call_get_vp_state(
		u32 vp_index,
		u64 partition_id,
		struct hv_vp_state_data state_data,
		/* Choose between pages and ret_output */
		u64 page_count,
		struct page **pages,
		union hv_output_get_vp_state *ret_output)
{
	struct hv_input_get_vp_state *input;
	union hv_output_get_vp_state *output;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;

	if (page_count > HV_GET_VP_STATE_BATCH_SIZE)
		return -EINVAL;

	if (!page_count && !ret_output)
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);
		memset(input, 0, sizeof(*input));
		memset(output, 0, sizeof(*output));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data = state_data;
		for (i = 0; i < page_count; i++)
			input->output_data_pfns[i] = page_to_pfn(pages[i]);

		control = (HVCALL_GET_VP_STATE) |
			  (page_count << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			else if (ret_output)
				memcpy(ret_output, output, sizeof(*output));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_set_vp_state(
		u32 vp_index,
		u64 partition_id,
		struct hv_vp_state_data state_data,
		/* Choose between pages and bytes */
		u64 page_count,
		struct page **pages,
		u32 num_bytes,
		u8 *bytes)
{
	struct hv_input_set_vp_state *input;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;
	u16 varhead_sz;

	if (page_count > HV_SET_VP_STATE_BATCH_SIZE)
		return -EINVAL;
	if (sizeof(*input) + num_bytes > HV_HYP_PAGE_SIZE)
		return -EINVAL;

	if (num_bytes)
		/* round up to 8 and divide by 8 */
		varhead_sz = (num_bytes + 7) >> 3;
	else if (page_count)
		varhead_sz = page_count;
	else
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data = state_data;
		if (num_bytes) {
			memcpy((u8 *)input->data, bytes, num_bytes);
		} else {
			for (i = 0; i < page_count; i++)
				input->data[i].pfns = page_to_pfn(pages[i]);
		}

		control = (HVCALL_SET_VP_STATE) |
			  (varhead_sz << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, NULL);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}

#endif

int hv_call_map_vp_state_page(u64 partition_id, u32 vp_index, u32 type,
				struct page **state_page)
{
	struct hv_input_map_vp_state_page *input;
	struct hv_output_map_vp_state_page *output;
	u64 status;
	int ret;
	unsigned long flags;

	do {
		local_irq_save(flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->type = type;

		status = hv_do_hypercall(HVCALL_MAP_VP_STATE_PAGE, input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*state_page = pfn_to_page(output->map_location);
			else
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}

		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	trace_mshv_hvcall_map_vp_state_page(status, partition_id, vp_index, type);

	return ret;
}

int hv_call_unmap_vp_state_page(u64 partition_id, u32 vp_index, u32 type)
{
	unsigned long flags;
	u64 status;
	struct hv_input_unmap_vp_state_page *input;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	memset(input, 0, sizeof(*input));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->type = type;

	status = hv_do_hypercall(HVCALL_UNMAP_VP_STATE_PAGE, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int hv_call_get_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 *property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_partition_property *input;
	struct hv_output_get_partition_property *output;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_PROPERTY, input,
			output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		local_irq_restore(flags);
		return hv_status_to_errno(status);
	}
	*property_value = output->property_value;

	local_irq_restore(flags);

	return 0;
}

int hv_call_set_partition_property(
	u64 partition_id, u64 property_code, u64 property_value,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data)
{
	u64 status;
	unsigned long flags;
	struct hv_input_set_partition_property *input;

	if (!completion_handler) {
		pr_err("%s: Missing completion handler for async set partition hypercall, property_code: %llu!\n",
		       __func__, property_code);
		return -EINVAL;
	}

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	input->property_value = property_value;
	status = hv_do_hypercall(HVCALL_SET_PARTITION_PROPERTY, input, NULL);
	local_irq_restore(flags);

	if (unlikely(status == HV_STATUS_CALL_PENDING))
		completion_handler(completion_data, &status);

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	trace_mshv_hvcall_set_partition_property(status, partition_id, property_code,
						property_value);

	return hv_status_to_errno(status);
}

int hv_call_translate_virtual_address(
		u32 vp_index,
		u64 partition_id,
		u64 flags,
		u64 gva,
		u64 *gpa,
		union hv_translate_gva_result *result)
{
	u64 status;
	unsigned long irq_flags;
	struct hv_input_translate_virtual_address *input;
	struct hv_output_translate_virtual_address *output;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->control_flags = flags;
	input->gva_page = gva >> HV_HYP_PAGE_SHIFT;

	status = hv_do_hypercall(HVCALL_TRANSLATE_VIRTUAL_ADDRESS, input, output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		goto out;
	}

	*result = output->translation_result;

	*gpa = (output->gpa_page << HV_HYP_PAGE_SHIFT) + /* pfn to gpa */
			((u64)gva & ~HV_HYP_PAGE_MASK);	 /* offset in gpa */

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}

int
hv_call_clear_virtual_interrupt(u64 partition_id)
{
	unsigned long flags;
	int status;

	local_irq_save(flags);
	status = hv_do_fast_hypercall8(HVCALL_CLEAR_VIRTUAL_INTERRUPT,
				       partition_id) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int
hv_call_create_port(u64 port_partition_id, union hv_port_id port_id,
		    u64 connection_partition_id,
		    struct hv_port_info *port_info,
		    u8 port_vtl, u8 min_connection_vtl, int node)
{
	struct hv_input_create_port *input;
	unsigned long flags;
	int ret = 0;
	int status;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));

		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->port_info = *port_info;
		input->port_vtl = port_vtl;
		input->min_connection_vtl = min_connection_vtl;
		input->proximity_domain_info = hv_numa_node_to_pxm_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;
		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				port_partition_id, 1);

	} while (!ret);

	return ret;
}

int
hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id)
{
	union hv_input_delete_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.port_partition_id = port_partition_id;
	input.port_id = port_id;
	status = hv_do_fast_hypercall16(HVCALL_DELETE_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int
hv_call_connect_port(u64 port_partition_id, union hv_port_id port_id,
		     u64 connection_partition_id,
		     union hv_connection_id connection_id,
		     struct hv_connection_info *connection_info,
		     u8 connection_vtl, int node)
{
	struct hv_input_connect_port *input;
	unsigned long flags;
	int ret = 0, status;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));
		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->connection_id = connection_id;
		input->connection_info = *connection_info;
		input->connection_vtl = connection_vtl;
		input->proximity_domain_info = hv_numa_node_to_pxm_info(node);
		status = hv_do_hypercall(HVCALL_CONNECT_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;

		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				connection_partition_id, 1);
	} while (!ret);

	return ret;
}

int
hv_call_disconnect_port(u64 connection_partition_id,
			union hv_connection_id connection_id)
{
	union hv_input_disconnect_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.connection_partition_id = connection_partition_id;
	input.connection_id = connection_id;
	input.is_doorbell = 1;
	status = hv_do_fast_hypercall16(HVCALL_DISCONNECT_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int
hv_call_notify_port_ring_empty(u32 sint_index)
{
	union hv_input_notify_port_ring_empty input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.sint_index = sint_index;
	status = hv_do_fast_hypercall8(HVCALL_NOTIFY_PORT_RING_EMPTY,
					input.as_uint64) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT

int hv_call_register_intercept_result(u32 vp_index,
				  u64 partition_id,
				  enum hv_intercept_type intercept_type,
				  union hv_register_intercept_result_parameters *params)
{
	u64 status;
	unsigned long flags;
	struct hv_input_register_intercept_result *in;
	int ret = 0;

	do {
		local_irq_save(flags);
		in = *this_cpu_ptr(hyperv_pcpu_input_arg);
		in->vp_index = vp_index;
		in->partition_id = partition_id;
		in->intercept_type = intercept_type;
		in->parameters = *params;

		status = hv_do_hypercall(HVCALL_REGISTER_INTERCEPT_RESULT, in, NULL);
		local_irq_restore(flags);

		if (hv_result_success(status))
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				partition_id, 1);
	} while (!ret);

	return ret;
}

#endif

int hv_call_signal_event_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u8 sint,
				u16 flag_number,
				u8 *newly_signaled)
{
	u64 status;
	unsigned long flags;
	struct hv_input_signal_event_direct *in;
	struct hv_output_signal_event_direct *out;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out = *this_cpu_ptr(hyperv_pcpu_output_arg);

	in->target_partition = partition_id;
	in->target_vp = vp_index;
	in->target_vtl = vtl;
	in->target_sint = sint;
	in->flag_number = flag_number;

	status = hv_do_hypercall(HVCALL_SIGNAL_EVENT_DIRECT, in, out);
	if (hv_result_success(status))
		*newly_signaled = out->newly_signaled;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}

int hv_call_post_message_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u32 sint_index,
				u8 *message)
{
	u64 status;
	unsigned long flags;
	struct hv_input_post_message_direct *in;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);

	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->vtl = vtl;
	in->sint_index = sint_index;
	memcpy(&in->message, message, HV_MESSAGE_SIZE);

	status = hv_do_hypercall(HVCALL_POST_MESSAGE_DIRECT, in, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}

int hv_call_get_vp_cpuid_values(u32 vp_index,
				u64 partition_id,
				union hv_get_vp_cpuid_values_flags values_flags,
				struct hv_cpuid_leaf_info *info,
				union hv_output_get_vp_cpuid_values *result)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_vp_cpuid_values *in;
	union hv_output_get_vp_cpuid_values *out;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(in, 0, sizeof(*in)+sizeof(*info));
	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->flags = values_flags;
	in->cpuid_leaf_info[0] = *info;

	status = hv_do_rep_hypercall(HVCALL_GET_VP_CPUID_VALUES, 1, 0, in, out);
	if (hv_result_success(status))
		*result = *out;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}

int hv_call_map_stat_page(enum hv_stats_object_type type,
		const union hv_stats_object_identity *identity,
		void **addr)
{
	unsigned long flags;
	struct hv_input_map_stats_page *input;
	struct hv_output_map_stats_page *output;
	u64 status, pfn;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	input->type = type;
	input->identity = *identity;

	status = hv_do_hypercall(HVCALL_MAP_STATS_PAGE, input, output);

	pfn = output->map_location;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	*addr = page_address(pfn_to_page(pfn));

	return 0;
}

int hv_call_unmap_stat_page(enum hv_stats_object_type type,
			    const union hv_stats_object_identity *identity)
{
	unsigned long flags;
	struct hv_input_unmap_stats_page *input;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	memset(input, 0, sizeof(*input));
	input->type = type;
	input->identity = *identity;

	status = hv_do_hypercall(HVCALL_UNMAP_STATS_PAGE, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}

int hv_call_modify_spa_host_access(u64 partition_id, struct page **pages,
				   u64 page_struct_count, u32 host_access,
				   u32 flags, u8 acquire)
{
	struct hv_input_modify_sparse_spa_page_host_access *input_page;
	u64 status;
	int done = 0;
	unsigned long irq_flags, large_shift = 0;
	u64 page_count = page_struct_count;
	u16 code = acquire ? HVCALL_ACQUIRE_SPARSE_SPA_PAGE_HOST_ACCESS :
			     HVCALL_RELEASE_SPARSE_SPA_PAGE_HOST_ACCESS;

	if (page_count == 0)
		return -EINVAL;

	if (flags & HV_MODIFY_SPA_PAGE_HOST_ACCESS_LARGE_PAGE) {
		if (!HV_PAGE_COUNT_2M_ALIGNED(page_count)) {
			pr_err("%s: HV_MODIFY_SPA_PAGE_HOST_ACCESS_LARGE_PAGE, but page_count %llx not aligned\n",
			       __func__, page_count);
			return -EINVAL;
		}
		large_shift = HV_HYP_LARGE_PAGE_SHIFT - HV_HYP_PAGE_SHIFT;
		page_count >>= large_shift;
	}

	while (done < page_count) {
		ulong i, completed, remain = page_count - done;
		int rep_count = min(
			remain,
			HV_MODIFY_SPARSE_SPA_PAGE_HOST_ACCESS_MAX_PAGE_COUNT);

		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		/*
		 * This is required to make sure that reserved field is set to
		 * zero, because MSHV has a check to make sure reserved bits are
		 * set to zero.
		 */
		memset(input_page, 0, sizeof(*input_page));
		/* Only set the partition id if you are making the pages exclusive */
		if (flags & HV_MODIFY_SPA_PAGE_HOST_ACCESS_MAKE_EXCLUSIVE)
			input_page->partition_id = partition_id;
		input_page->flags = flags;
		input_page->host_access = host_access;

		for (i = 0; i < rep_count; i++) {
			u64 index = (done + i) << large_shift;

			if (index >= page_struct_count) {
				pr_err("%s: Bad index %lu\n", __func__, i);
				return -EINVAL;
			}
			input_page->spa_page_list[i] =
						page_to_pfn(pages[index]);
		}

		status = hv_do_rep_hypercall(code, rep_count, 0, input_page,
					     NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);

		if (!hv_result_success(status)) {
			pr_err("%s: completed %u out of %llu, %s\n", __func__,
			       done, page_count,
			       hv_status_to_string(status));
			if (done)
				pr_err("%s: Partially succeeded; spa host access may be in invalid state",
				       __func__);
			return hv_status_to_errno(status);
		}

		done += completed;
	}

	return 0;
}

int hv_call_import_isolated_pages(
	u64 partition_id, u64 *pages, u64 num_pages,
	enum hv_isolated_page_type page_type,
	enum hv_isolated_page_size page_size,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data)
{
	struct hv_input_import_isolated_pages *input_page;
	u64 status;
	unsigned long remaining = num_pages;
	u64 completed;
	int rep_count;
	unsigned long irq_flags;
	u64 *gpa = pages;

	if (num_pages == 0)
		return -EINVAL;

	if (!completion_handler) {
		pr_err("%s: Missing completion handler for async import isolated pages hypercall, page_type: %u!\n",
		       __func__, page_type);
		return -EINVAL;
	}

	while (remaining) {
		rep_count = min(remaining, HV_ISOLATED_PAGE_BATCH_SIZE);

		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		input_page->partition_id = partition_id;
		input_page->page_type = page_type;
		input_page->page_size = page_size;
		memcpy(input_page->page_number, gpa, rep_count * sizeof(*gpa));

		status = hv_do_rep_hypercall(HVCALL_IMPORT_ISOLATED_PAGES,
					     rep_count, 0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);

		if (hv_result(status) == HV_STATUS_CALL_PENDING)
			completion_handler(completion_data, &status);

		if (!hv_result_success(status)) {
			pr_err("%s: completed %llu out of %llu, %s\n", __func__,
			       num_pages - remaining, num_pages,
			       hv_status_to_string(status));
			if (remaining < num_pages)
				pr_err("%s: Partially succeeded; gpa host access may be in invalid state",
				       __func__);
			return hv_status_to_errno(status);
		}

		gpa += completed;
		remaining -= completed;
	}

	return 0;
}

int hv_call_complete_isolated_import(
	u64 partition_id,
	union hv_partition_complete_isolated_import_data *import_data,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data)
{
	u64 status;
	unsigned long flags;
	struct hv_input_complete_isolated_import *in;

	if (!completion_handler) {
		pr_err("%s: Missing completion handler for async complete isolated import hypercall!\n",
		       __func__);
		return -EINVAL;
	}

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);

	in->partition_id = partition_id;
	memcpy(&in->import_data, import_data, sizeof(*import_data));

	status = hv_do_hypercall(HVCALL_COMPLETE_ISOLATED_IMPORT, in, NULL);
	local_irq_restore(flags);

	if (hv_result(status) == HV_STATUS_CALL_PENDING)
		completion_handler(completion_data, &status);

	if (!hv_result_success(status)) {
		pr_err("%s: status=%s, partition_id=%llu\n", __func__,
		       hv_status_to_string(status), partition_id);
		return hv_status_to_errno(status);
	}

	return 0;
}

int hv_call_read_gpa(
		u32 vp_index,
		u64 partition_id,
		union hv_access_gpa_control_flags flags,
		u64 gpa_base,
		u8 *data,
		u32 bytes_count,
		union hv_access_gpa_result *result)
{
	u64 status;
	unsigned long irq_flags;
	struct hv_input_read_gpa *input;
	struct hv_output_read_gpa *output;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->control_flags = flags;
	input->base_gpa = gpa_base;
	input->byte_count = bytes_count;

	status = hv_do_hypercall(HVCALL_READ_GPA, input, output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		goto out;
	}

	*result = output->access_result;

	memcpy(data, output->data, bytes_count);

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}
EXPORT_SYMBOL_GPL(hv_call_read_gpa);

int hv_call_write_gpa(
		u32 vp_index,
		u64 partition_id,
		union hv_access_gpa_control_flags flags,
		u64 gpa_base,
		u8 *data,
		u32 bytes_count,
		union hv_access_gpa_result *result)
{
	u64 status;
	unsigned long irq_flags;
	struct hv_input_write_gpa *input;
	struct hv_output_write_gpa *output;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->control_flags = flags;
	input->base_gpa = gpa_base;
	input->byte_count = bytes_count;
	memcpy(input->data, data, bytes_count);

	status = hv_do_hypercall(HVCALL_WRITE_GPA, input, output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		goto out;
	}

	*result = output->access_result;

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}

#ifdef HV_SUPPORTS_SEV_SNP_GUESTS
int hv_call_issue_psp_guest_request(
	u64 partition_id, u64 req_pfn, u64 rsp_pfn,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data)
{
	u64 status;
	unsigned long flags;
	struct hv_input_issue_psp_guest_request *in;

	if (!completion_handler) {
		pr_err("%s: Missing completion handler for issuing psp guest request hypercall!\n",
		       __func__);
		return -EINVAL;
	}

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);

	in->partition_id = partition_id;
	in->request_page = req_pfn;
	in->response_page = rsp_pfn;

	status = hv_do_hypercall(HVCALL_ISSUE_SNP_PSP_GUEST_REQUEST, in, NULL);
	local_irq_restore(flags);

	if (hv_result(status) == HV_STATUS_CALL_PENDING)
		completion_handler(completion_data, &status);

	if (!hv_result_success(status)) {
		pr_err("%s: status=%s, partition_id=%llu\n", __func__,
		       hv_status_to_string(status), partition_id);
		return hv_status_to_errno(status);
	}

	return 0;
}
#endif /* HV_SUPPORTS_SEV_SNP_GUESTS */
