/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 */

#ifndef _MSHV_H_
#define _MSHV_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <hyperv/hvhdk.h>
#include <uapi/linux/mshv.h>

#define mshv_field_nonzero(STRUCT, MEMBER) \
	memchr_inv(&((STRUCT).MEMBER), \
		   0, sizeof_field(typeof(STRUCT), MEMBER))

/*
 * Hyper-V hypercalls
 */

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id);
int hv_call_create_partition(
		u64 flags,
		struct hv_partition_creation_properties creation_properties,
		union hv_partition_isolation_properties isolation_properties,
		u64 *partition_id);
int hv_call_initialize_partition(u64 partition_id);
int hv_call_finalize_partition(u64 partition_id);
int hv_call_delete_partition(u64 partition_id);
int hv_call_map_mmio_pages(u64 partition_id, u64 gfn, u64 mmio_spa, u64 numpgs);
int hv_call_map_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags,
		struct page **pages);
int hv_call_unmap_gpa_pages(
		u64 partition_id,
		u64 gpa_target,
		u64 page_count, u32 flags);
int hv_call_delete_vp(u64 partition_id, u32 vp_index);
int hv_call_get_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		union hv_input_vtl input_vtl,
		struct hv_register_assoc *registers);
int hv_call_get_gpa_access_states(
		u64 partition_id,
		u32 count,
		u64 gpa_base_pfn,
		union hv_gpa_page_access_state_flags state_flags,
		int *written_total,
		union hv_gpa_page_access_state *states);

int hv_call_set_vp_registers(
		u32 vp_index,
		u64 partition_id,
		u16 count,
		union hv_input_vtl input_vtl,
		struct hv_register_assoc *registers);
int hv_call_install_intercept(u64 partition_id, u32 access_type,
		enum hv_intercept_type intercept_type,
		union hv_intercept_parameters intercept_parameter);
int hv_call_assert_virtual_interrupt(
		u64 partition_id,
		u32 vector,
		u64 dest_addr,
		union hv_interrupt_control control);
int hv_call_clear_virtual_interrupt(u64 partition_id);

#ifdef HV_SUPPORTS_VP_STATE
int hv_call_get_vp_state(
		u32 vp_index,
		u64 partition_id,
		struct hv_vp_state_data state_data,
		/* Choose between pages and ret_output */
		u64 page_count,
		struct page **pages,
		union hv_output_get_vp_state *ret_output);
int hv_call_set_vp_state(
		u32 vp_index,
		u64 partition_id,
		struct hv_vp_state_data state_data,
		/* Choose between pages and bytes */
		u64 page_count,
		struct page **pages,
		u32 num_bytes,
		u8 *bytes);
#endif

int hv_call_map_vp_state_page(u64 partition_id, u32 vp_index, u32 type,
				union hv_input_vtl input_vtl,
				struct page **state_page);
int hv_call_unmap_vp_state_page(u64 partition_id, u32 vp_index, u32 type,
				union hv_input_vtl input_vtl);
int hv_call_get_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 *property_value);
int hv_call_set_partition_property(
	u64 partition_id, u64 property_code, u64 property_value,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data);
int hv_call_translate_virtual_address(
		u32 vp_index,
		u64 partition_id,
		u64 flags,
		u64 gva,
		u64 *gpa,
		union hv_translate_gva_result *result);
int hv_call_get_vp_cpuid_values(
		u32 vp_index,
		u64 partition_id,
		union hv_get_vp_cpuid_values_flags values_flags,
		struct hv_cpuid_leaf_info *info,
		union hv_output_get_vp_cpuid_values *result);

int hv_call_create_port(u64 port_partition_id, union hv_port_id port_id,
			u64 connection_partition_id, struct hv_port_info *port_info,
			u8 port_vtl, u8 min_connection_vtl, int node);
int hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id);
int hv_call_connect_port(u64 port_partition_id, union hv_port_id port_id,
			 u64 connection_partition_id,
			 union hv_connection_id connection_id,
			 struct hv_connection_info *connection_info,
			 u8 connection_vtl, int node);
int hv_call_disconnect_port(u64 connection_partition_id,
			    union hv_connection_id connection_id);
int hv_call_notify_port_ring_empty(u32 sint_index);
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
int hv_call_register_intercept_result(u32 vp_index,
				  u64 partition_id,
				  enum hv_intercept_type intercept_type,
				  union hv_register_intercept_result_parameters *params);
#endif
int hv_call_signal_event_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u8 sint,
				u16 flag_number,
				u8* newly_signaled);
int hv_call_post_message_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u32 sint_index,
				u8* message);

int hv_call_map_stat_page(enum hv_stats_object_type type,
			  const union hv_stats_object_identity *identity,
			  void **addr);
int hv_call_unmap_stat_page(enum hv_stats_object_type type,
			    const union hv_stats_object_identity *identity);
int hv_call_modify_spa_host_access(u64 partition_id, struct page **page_list,
				   u64 spa_list_size, u32 host_access,
				   u32 flags, u8 acquire);
int hv_call_import_isolated_pages(
	u64 partition_id, u64 *pages, u64 num_pages,
	enum hv_isolated_page_type page_type,
	enum hv_isolated_page_size page_size,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data);
int hv_call_complete_isolated_import(
	u64 partition_id,
	union hv_partition_complete_isolated_import_data *import_data,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data);

int hv_call_read_gpa(u32 vp_index,
		u64 partition_id,
		union hv_access_gpa_control_flags flags,
		u64 gpa_base,
		u8 *data,
		u32 bytes_count,
		union hv_access_gpa_result *result);
int hv_call_write_gpa(u32 vp_index,
		u64 partition_id,
		union hv_access_gpa_control_flags flags,
		u64 gpa_base,
		u8 *data,
		u32 bytes_count,
		union hv_access_gpa_result *result);

#ifdef HV_SUPPORTS_SEV_SNP_GUESTS
int hv_call_issue_psp_guest_request(
	u64 partition_id, u64 req_pfn, u64 rsp_pfn,
	void (*completion_handler)(void * /* data */, u64 * /* status */),
	void *completion_data);
#endif /* HV_SUPPORTS_SEV_SNP_GUESTS */

int mshv_do_pre_guest_mode_work(ulong th_flags);

#if IS_ENABLED(CONFIG_MSHV_DIAG)
void mshv_trace_buffer_complete(const struct hv_eventlog_message_payload *msg);
#else
static inline void mshv_trace_buffer_complete(const struct hv_eventlog_message_payload *msg) {}
#endif /* CONFIG_MSHV_DIAG */

#endif /* _MSHV_H */
