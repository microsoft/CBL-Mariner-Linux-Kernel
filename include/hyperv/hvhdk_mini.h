/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Type definitions for the hypervisor host interface to kernel.
 */
#ifndef _UAPI_HV_HVHDK_MINI_H
#define _UAPI_HV_HVHDK_MINI_H

#include "hvgdk_mini.h"

#define HVHVK_MINI_VERSION		(25294)

/*
 * Doorbell connection_info flags.
 */
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_MASK  0x00000007
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_ANY   0x00000000
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_BYTE  0x00000001
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_WORD  0x00000002
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_DWORD 0x00000003
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_QWORD 0x00000004
#define HV_DOORBELL_FLAG_TRIGGER_ANY_VALUE  0x80000000

/* Each generic set contains 64 elements */
#define HV_GENERIC_SET_SHIFT		(6)
#define HV_GENERIC_SET_MASK		(63)

enum hv_generic_set_format {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};

enum hv_scheduler_type {
	HV_SCHEDULER_TYPE_LP = 1, /* Classic scheduler w/o SMT */
	HV_SCHEDULER_TYPE_LP_SMT = 2, /* Classic scheduler w/ SMT */
	HV_SCHEDULER_TYPE_CORE_SMT = 3, /* Core scheduler */
	HV_SCHEDULER_TYPE_ROOT = 4, /* Root / integrated scheduler */
	HV_SCHEDULER_TYPE_MAX
};

/* HV_STATS_AREA_TYPE */
enum hv_stats_area_type {
	HV_STATS_AREA_SELF = 0,
	HV_STATS_AREA_PARENT = 1,
	HV_STATS_AREA_INTERNAL = 2,
	HV_STATS_AREA_COUNT
};

enum hv_stats_object_type {
	HV_STATS_OBJECT_HYPERVISOR		= 0x00000001,
	HV_STATS_OBJECT_LOGICAL_PROCESSOR	= 0x00000002,
	HV_STATS_OBJECT_PARTITION		= 0x00010001,
	HV_STATS_OBJECT_VP			= 0x00010002
};

union hv_stats_object_identity {
	/* hv_stats_hypervisor */
	struct {
		u8 reserved[15];
		u8 stats_area_type;
	} __packed hv;

	/* hv_stats_logical_processor */
	struct {
		u32 lp_index;
		u8 reserved[11];
		u8 stats_area_type;
	} __packed lp;

	/* hv_stats_partition */
	struct {
		u64 partition_id;
		u8  reserved[7];
		u8  stats_area_type;
	} __packed partition;

	/* hv_stats_vp */
	struct {
		u64 partition_id;
		u32 vp_index;
		u16 flags;
		u8  reserved;
		u8  stats_area_type;
	} __packed vp;
};

enum hv_partition_property_code {
	/* Privilege properties */
	HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS			= 0x00010000,
	HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES		= 0x00010001,

	/* Scheduling properties */
	HV_PARTITION_PROPERTY_SUSPEND				= 0x00020000,
	HV_PARTITION_PROPERTY_CPU_RESERVE			= 0x00020001,
	HV_PARTITION_PROPERTY_CPU_CAP				= 0x00020002,
	HV_PARTITION_PROPERTY_CPU_WEIGHT			= 0x00020003,
	HV_PARTITION_PROPERTY_CPU_GROUP_ID			= 0x00020004,

	/* Time properties */
	HV_PARTITION_PROPERTY_TIME_FREEZE			= 0x00030003,
	HV_PARTITION_PROPERTY_REFERENCE_TIME			= 0x00030005,

	/* Debugging properties */
	HV_PARTITION_PROPERTY_DEBUG_CHANNEL_ID			= 0x00040000,

	/* Resource properties */
	HV_PARTITION_PROPERTY_VIRTUAL_TLB_PAGE_COUNT		= 0x00050000,
	HV_PARTITION_PROPERTY_VSM_CONFIG			= 0x00050001,
	HV_PARTITION_PROPERTY_ZERO_MEMORY_ON_RESET		= 0x00050002,
	HV_PARTITION_PROPERTY_PROCESSORS_PER_SOCKET		= 0x00050003,
	HV_PARTITION_PROPERTY_NESTED_TLB_SIZE			= 0x00050004,
	HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING		= 0x00050005,
	HV_PARTITION_PROPERTY_VSM_PERMISSIONS_DIRTY_SINCE_LAST_QUERY
								= 0x00050006,
	HV_PARTITION_PROPERTY_SGX_LAUNCH_CONTROL_CONFIG		= 0x00050007,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL0	= 0x00050008,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL1	= 0x00050009,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL2	= 0x0005000a,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL3	= 0x0005000b,
	HV_PARTITION_PROPERTY_ISOLATION_STATE			= 0x0005000c,
	HV_PARTITION_PROPERTY_ISOLATION_CONTROL			= 0x0005000d,
	HV_PARTITION_PROPERTY_ALLOCATION_ID			= 0x0005000e,
	HV_PARTITION_PROPERTY_MONITORING_ID			= 0x0005000f,
	HV_PARTITION_PROPERTY_IMPLEMENTED_PHYSICAL_ADDRESS_BITS	= 0x00050010,
	HV_PARTITION_PROPERTY_NON_ARCHITECTURAL_CORE_SHARING	= 0x00050011,
	HV_PARTITION_PROPERTY_HYPERCALL_DOORBELL_PAGE		= 0x00050012,
	HV_PARTITION_PROPERTY_ISOLATION_POLICY			= 0x00050014,
	HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION		= 0x00050017,
	HV_PARTITION_PROPERTY_SEV_VMGEXIT_OFFLOADS		= 0x00050022,
	HV_PARTITION_PROPERTY_PARTITION_DIAG_BUFFER_CONFIG	= 0x00050026,
	HV_PARTITION_PROPERTY_GICD_BASE_ADDRESS			= 0x00050028,
	HV_PARTITION_PROPERTY_GITS_TRANSLATER_BASE_ADDRESS	= 0x00050029,

	/* Compatibility properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VENDOR			= 0x00060000,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES_DEPRECATED	= 0x00060001,
	HV_PARTITION_PROPERTY_PROCESSOR_XSAVE_FEATURES		= 0x00060002,
	HV_PARTITION_PROPERTY_PROCESSOR_CL_FLUSH_SIZE		= 0x00060003,
	HV_PARTITION_PROPERTY_ENLIGHTENMENT_MODIFICATIONS	= 0x00060004,
	HV_PARTITION_PROPERTY_COMPATIBILITY_VERSION		= 0x00060005,
	HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH		= 0x00060006,
	HV_PARTITION_PROPERTY_XSAVE_STATES			= 0x00060007,
	HV_PARTITION_PROPERTY_MAX_XSAVE_DATA_SIZE		= 0x00060008,
	HV_PARTITION_PROPERTY_PROCESSOR_CLOCK_FREQUENCY		= 0x00060009,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES0		= 0x0006000a,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES1		= 0x0006000b,

	/* Guest software properties */
	HV_PARTITION_PROPERTY_GUEST_OS_ID			= 0x00070000,

	/* Nested virtualization properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VIRTUALIZATION_FEATURES	= 0x00080000,
};

enum hv_sleep_state {
	HV_SLEEP_STATE_S1 = 1,
	HV_SLEEP_STATE_S2 = 2,
	HV_SLEEP_STATE_S3 = 3,
	HV_SLEEP_STATE_S4 = 4,
	HV_SLEEP_STATE_S5 = 5,
	/*
	 * After hypervisor has reseived this, any follow up sleep
	 * state registration requests will be rejected.
	 */
	HV_SLEEP_STATE_LOCK = 6
};

struct hv_input_enter_sleep_state {	/* HV_INPUT_ENTER_SLEEP_STATE */
	u32 sleep_state;	/* enum hv_sleep_state */
} __packed;

enum hv_system_property {
	/* Add more values when needed */
	HV_SYSTEM_PROPERTY_SLEEP_STATE = 3,
	HV_SYSTEM_PROPERTY_SCHEDULER_TYPE = 15,
	HV_DYNAMIC_PROCESSOR_FEATURE_PROPERTY = 21,
	HV_SYSTEM_PROPERTY_DIAGOSTICS_LOG_BUFFERS = 28,
	HV_SYSTEM_PROPERTY_CRASHDUMPAREA = 47,
	HV_SYSTEM_PROPERTY_DEVIRT_TRAMP_PA = 52,
};

#define HV_PFN_RNG_PAGEBITS 24	/* HV_SPA_PAGE_RANGE_ADDITIONAL_PAGES_BITS */
union hv_pfn_range {		/* HV_SPA_PAGE_RANGE */
	u64 as_uint64;
	struct {
		/* 39:0: base pfn.  63:40: additional pages */
		u64 base_pfn : 64 - HV_PFN_RNG_PAGEBITS;
		u64 add_pfns : HV_PFN_RNG_PAGEBITS;
	} __packed;
};

struct hv_sleep_state_info {
	u32 sleep_state; /* enum hv_sleep_state */
	u8 pm1a_slp_typ;
	u8 pm1b_slp_typ;
} __packed;

enum hv_snp_status {
	HV_SNP_STATUS_NONE = 0,
	HV_SNP_STATUS_AVAILABLE = 1,
	HV_SNP_STATUS_INCOMPATIBLE = 2,
	HV_SNP_STATUS_PSP_UNAVAILABLE = 3,
	HV_SNP_STATUS_PSP_INIT_FAILED = 4,
	HV_SNP_STATUS_PSP_BAD_FW_VERSION = 5,
	HV_SNP_STATUS_BAD_CONFIGURATION = 6,
	HV_SNP_STATUS_PSP_FW_UPDATE_IN_PROGRESS = 7,
	HV_SNP_STATUS_PSP_RB_INIT_FAILED = 8,
	HV_SNP_STATUS_PSP_PLATFORM_STATUS_FAILED = 9,
	HV_SNP_STATUS_PSP_INIT_LATE_FAILED = 10,
};

enum hv_dynamic_processor_feature_property {
	/* Add more values when needed */
	HV_X64_DYNAMIC_PROCESSOR_FEATURE_MAX_ENCRYPTED_PARTITIONS = 13,
	HV_X64_DYNAMIC_PROCESSOR_FEATURE_SNP_STATUS = 16,
};

/* HV_PARTITION_DIAG_LOG_BUFFER_CONFIG */
union hv_partition_diag_log_buffer_config {
	struct {
		u32 buffer_count;
		u32 buffer_size_in_pages;
	} __packed;
	u64 as_uint64;
};

struct hv_input_get_system_property {
	u32 property_id; /* enum hv_system_property */
	u32 reserved;
	union {
		u64 as_uint64;
#if IS_ENABLED(CONFIG_X86)
		u32 hv_processor_feature; /* enum hv_dynamic_processor_feature_property */
#endif
		/* More fields to be filled in when needed */
	};
} __packed;

/* HV_SYSTEM_DIAG_LOG_BUFFER_CONFIG */
struct	hv_system_diag_log_buffer_config {
	u32 buffer_count;
	u32 buffer_size_in_pages;
} __packed;

struct hv_output_get_system_property { /* HV_OUTPUT_GET_SYSTEM_PROPERTY */
	union {
		u32 scheduler_type; /* HV_SCHEDULER_TYPE */
		struct hv_system_diag_log_buffer_config hv_diagbuf_info;
#if IS_ENABLED(CONFIG_X86)
		u64 hv_processor_feature_value;
#endif
		union hv_pfn_range hv_cda_info; /* CrashdumpAreaAddress */
		u64 hv_tramp_pa;		/* CrashdumpTrampolineAddress */
	};
} __packed;

struct hv_input_set_system_property {
	u32 property_id; /* enum hv_system_property */
	u32 reserved;
	union {
		/* More fields to be filled in when needed */
		struct hv_sleep_state_info set_sleep_state_info;
	};
} __packed;

struct hv_input_map_stats_page {
	u32 type; /* enum hv_stats_object_type */
	u32 padding;
	union hv_stats_object_identity identity;
} __packed;

struct hv_output_map_stats_page {
	u64 map_location;
} __packed;

struct hv_input_unmap_stats_page {
	u32 type; /* enum hv_stats_object_type */
	u32 padding;
	union hv_stats_object_identity identity;
} __packed;


struct hv_proximity_domain_flags {
	u32 proximity_preferred : 1;
	u32 reserved : 30;
	u32 proximity_info_valid : 1;
} __packed;

struct hv_proximity_domain_info {
	u32 domain_id;
	struct hv_proximity_domain_flags flags;
} __packed;

/* HvDepositMemory hypercall */
struct hv_deposit_memory {	/* HV_INPUT_DEPOSIT_MEMORY */
	u64 partition_id;
	u64 gpa_page_list[];
} __packed;

struct hv_input_withdraw_memory {
	u64 partition_id;
	struct hv_proximity_domain_info proximity_domain_info;
} __packed;

struct hv_output_withdraw_memory {
	/* Hack - compiler doesn't like empty array size
	 * in struct with no other members
	 */
	u64 gpa_page_list[0];
} __packed;

/* HV Map GPA (Guest Physical Address) Flags */
#define HV_MAP_GPA_PERMISSIONS_NONE	       0x0
#define HV_MAP_GPA_READABLE		       0x1
#define HV_MAP_GPA_WRITABLE		       0x2
#define HV_MAP_GPA_KERNEL_EXECUTABLE	       0x4
#define HV_MAP_GPA_USER_EXECUTABLE	       0x8
#define HV_MAP_GPA_EXECUTABLE		       0xC
#define HV_MAP_GPA_PERMISSIONS_MASK	       0xF
#define HV_MAP_GPA_ADJUSTABLE		    0x8000
#define HV_MAP_GPA_NO_ACCESS		   0x10000
#define HV_MAP_GPA_NOT_CACHED		  0x200000
#define HV_MAP_GPA_LARGE_PAGE		0x80000000

struct hv_input_map_gpa_pages {
	u64 target_partition_id;
	u64 target_gpa_base;
	u32 map_flags;
	u32 padding;
	u64 source_gpa_page_list[];
} __packed;

union hv_gpa_page_access_state_flags {
	struct {
		u64 clear_accessed : 1;
		u64 set_accessed : 1;
		u64 clear_dirty : 1;
		u64 set_dirty : 1;
		u64 reserved : 60;
	} __packed;
	u64 as_uint64;
};

struct hv_input_get_gpa_pages_access_state {
	u64  partition_id;
	union hv_gpa_page_access_state_flags flags;
	u64 hv_gpa_page_number;
} __packed;

union hv_gpa_page_access_state {
	struct {
		u8 accessed : 1;
		u8 dirty : 1;
		u8 reserved: 6;
	};
	u8 as_uint8;
} __packed;

union hv_snp_guest_policy {
	struct {
		u64 minor_version : 8;
		u64 major_version : 8;
		u64 smt_allowed : 1;
		u64 vmpls_required : 1;
		u64 migration_agent_allowed : 1;
		u64 debug_allowed : 1;
		u64 reserved : 44;
	} __packed;
	u64 as_uint64;
};

struct hv_snp_id_block {
	u8 launch_digest[48];
	u8 family_id[16];
	u8 image_id[16];
	u32 version;
	u32 guest_svn;
	union hv_snp_guest_policy policy;
} __packed;

struct hv_snp_id_auth_info {
	u32 id_key_algorithm;
	u32 auth_key_algorithm;
	u8 reserved0[56];
	u8 id_block_signature[512];
	u8 id_key[1028];
	u8 reserved1[60];
	u8 id_key_signature[512];
	u8 author_key[1028];
} __packed;

struct hv_psp_launch_finish_data {
	struct hv_snp_id_block id_block;
	struct hv_snp_id_auth_info id_auth_info;
	u8 host_data[32];
	u8 id_block_enabled;
	u8 author_key_enabled;
} __packed;

union hv_partition_complete_isolated_import_data {
	u64 reserved;
	struct hv_psp_launch_finish_data psp_parameters;
} __packed;

struct hv_input_complete_isolated_import {
	u64 partition_id;
	union hv_partition_complete_isolated_import_data import_data;
} __packed;

enum hv_crashdump_action {
	HV_CRASHDUMP_NONE = 0,
	HV_CRASHDUMP_SUSPEND_ALL_VPS,
	HV_CRASHDUMP_PREPARE_FOR_STATE_SAVE,
	HV_CRASHDUMP_STATE_SAVED,
	HV_CRASHDUMP_ENTRY,
};

struct hv_partition_event_root_crashdump_input {
	u32 crashdump_action; /* enum hv_crashdump_action */
} __packed;

struct hv_input_disable_hyp_ex {   /* HV_X64_INPUT_DISABLE_HYPERVISOR_EX */
	u64 rip;
	u64 arg;
} __packed;

struct hv_crashdump_area {	   /* HV_CRASHDUMP_AREA */
	u32 version;
	union {
		u32 flags_as_uint32;
		struct {
			u32 cda_valid : 1;
			u32 cda_unused : 31;
		} __packed;
	};
	/* more unused fields */
} __packed;

struct hv_partition_event_commit_processor_indices_input {
	u32 schedulable_processor_count;
} __packed;

union hv_partition_event_input {
	struct hv_partition_event_root_crashdump_input crashdump_input;
	struct hv_partition_event_commit_processor_indices_input
		commit_lp_indices_input;
};

enum hv_partition_event {
	HV_PARTITION_EVENT_DEBUG_DEVICE_AVAILABLE = 1,
	HV_PARTITION_EVENT_ROOT_CRASHDUMP = 2,
	HV_PARTITION_EVENT_ACPI_REENABLED = 3,
	HV_PARTITION_ALL_LOGICAL_PROCESSORS_STARTED = 4,
	HV_PARTITION_COMMIT_LP_INDICES = 5,
};

struct hv_input_notify_partition_event {
	u32 event; /* enum hv_partition_event */
	union hv_partition_event_input input;
} __packed;

struct hv_lp_startup_status {
	u64 hv_status;
	u64 substatus1;
	u64 substatus2;
	u64 substatus3;
	u64 substatus4;
	u64 substatus5;
	u64 substatus6;
} __packed;

struct hv_input_add_logical_processor {
	u32 lp_index;
	u32 apic_id;
	struct hv_proximity_domain_info proximity_domain_info;
} __packed;

struct hv_output_add_logical_processor {
	struct hv_lp_startup_status startup_status;
} __packed;

/* HV_INPUT_GET_LOGICAL_PROCESSOR_RUN_TIME */
struct hv_input_get_logical_processor_run_time {
	u32 lp_index;
} __packed;

/* HV_OUTPUT_GET_LOGICAL_PROCESSOR_RUN_TIME */
struct hv_output_get_logical_processor_run_time {
	u64 global_time;
	u64 local_run_time;
	u64 rsvdz0;
	u64 hypervisor_time;
} __packed;

enum {	/* HV_SUBNODE_TYPE */
	HvSubnodeAny = 0,
	HvSubnodeSocket,
	HvSubnodeCluster,
	HvSubnodeL3,
	HvSubnodeCount,
	HvSubnodeInvalid = -1
};

struct hv_create_vp {	/* HV_INPUT_CREATE_VP */
	u64 partition_id;
	u32 vp_index;
	u8 padding[3];
	u8 subnode_type;
	u64 subnode_id;
	struct hv_proximity_domain_info proximity_domain_info;
	u64 flags;
} __packed;

/* HV_INTERRUPT_TRIGGER_MODE */
enum hv_interrupt_trigger_mode {
	HV_INTERRUPT_TRIGGER_MODE_EDGE = 0,
	HV_INTERRUPT_TRIGGER_MODE_LEVEL = 1,
};

/* HV_DEVICE_INTERRUPT_DESCRIPTOR */
struct hv_device_interrupt_descriptor {
	u32 interrupt_type;
	u32 trigger_mode;
	u32 vector_count;
	u32 reserved;
	struct hv_device_interrupt_target target;
} __packed;

/* HV_INPUT_MAP_DEVICE_INTERRUPT */
struct hv_input_map_device_interrupt {
	u64 partition_id;
	u64 device_id;
	u32 flags;
	u32 base_irt_idx;
	struct hv_interrupt_entry logical_interrupt_entry;
	struct hv_device_interrupt_descriptor interrupt_descriptor;
} __packed;

/* HV_OUTPUT_MAP_DEVICE_INTERRUPT */
struct hv_output_map_device_interrupt {
	struct hv_interrupt_entry interrupt_entry;
} __packed;

/* HV_INPUT_UNMAP_DEVICE_INTERRUPT */
struct hv_input_unmap_device_interrupt {
	u64 partition_id;
	u64 device_id;
	struct hv_interrupt_entry interrupt_entry;
	u32 flags;
} __packed;

#define HV_SOURCE_SHADOW_NONE		    0x0
#define HV_SOURCE_SHADOW_BRIDGE_BUS_RANGE   0x1

struct hv_send_ipi_ex { /* HV_INPUT_SEND_SYNTHETIC_CLUSTER_IPI_EX */
	u32 vector;
	u32 reserved;
	struct hv_vpset vp_set;
} __packed;


union hv_attdev_flags {		/* HV_ATTACH_DEVICE_FLAGS */
	struct {
		u32 logical_id : 1;
		u32 resvd0 : 1;
		u32 ats_enabled : 1;
		u32 virt_func : 1;
		u32 shared_irq_child : 1;
		u32 virt_dev : 1;
		u32 ats_supported : 1;
		u32 small_irt : 1;
		u32 resvd : 24;
	} __packed;
	u32 as_uint32;
};

union hv_dev_pci_caps {		/* HV_DEVICE_PCI_CAPABILITIES */
	struct {
		u32 max_pasid_width : 5;
		u32 invalidate_qdepth : 5;
		u32 global_inval : 1;
		u32 prg_response_req : 1;
		u32 resvd : 20;
	} __packed;
	u32 as_uint32;
};

typedef u16 hv_pci_rid;		/* HV_PCI_RID */
typedef u16 hv_pci_segment;	/* HV_PCI_SEGMENT */
typedef u64 hv_logical_device_id;
union hv_pci_bdf {	/* HV_PCI_BDF */
	u16 as_uint16;

	struct {
		u8 function:3;
		u8 device:5;
		u8 bus;
	};
} __packed;

union hv_pci_bus_range {
	u16 as_uint16;

	struct {
		u8 subordinate_bus;
		u8 secondary_bus;
	};
} __packed;

enum hv_device_type {		/* HV_DEVICE_TYPE */
	HV_DEVICE_TYPE_LOGICAL = 0,
	HV_DEVICE_TYPE_PCI = 1,
	HV_DEVICE_TYPE_IOAPIC = 2,
	HV_DEVICE_TYPE_ACPI = 3,
};

union hv_device_id {		/* HV_DEVICE_ID */
	u64 as_uint64;

	struct {
		u64 reserved0:62;
		u64 device_type:2;
	};

	/* HV_DEVICE_TYPE_LOGICAL */
	struct {
		u64 id:62;
		u64 device_type:2;
	} logical;

	/* HV_DEVICE_TYPE_PCI */
	struct {
		union {
			hv_pci_rid rid;
			union hv_pci_bdf bdf;
		};

		hv_pci_segment segment;
		union hv_pci_bus_range shadow_bus_range;

		u16 phantom_function_bits:2;
		u16 source_shadow:1;

		u16 rsvdz0:11;
		u16 device_type:2;
	} pci;

	/* HV_DEVICE_TYPE_IOAPIC */
	struct {
		u8 ioapic_id;
		u8 rsvdz0;
		u16 rsvdz1;
		u16 rsvdz2;

		u16 rsvdz3:14;
		u16 device_type:2;
	} ioapic;

	/* HV_DEVICE_TYPE_ACPI */
	struct {
		u32 input_mapping_base;
		u32 input_mapping_count:30;
		u32 device_type:2;
	} acpi;
} __packed;

struct hv_input_attach_device {         /* HV_INPUT_ATTACH_DEVICE */
	u64 partition_id;
	union hv_device_id device_id;
	union hv_attdev_flags attdev_flags;
	u8  attdev_vtl;
	u8  rsvd0;
	u16 rsvd1;
	u64 logical_devid;
	union hv_dev_pci_caps dev_pcicaps;
	u16 pf_pci_rid;
	u16 resvd2;
} __packed;

struct hv_input_detach_device {		/* HV_INPUT_DETACH_DEVICE */
	u64 partition_id;
	u64 logical_devid;
} __packed;


/* 3 domain types: stage 1, stage 2, and SOC */
#define HV_DEVICE_DOMAIN_TYPE_S2  0 /* HV_DEVICE_DOMAIN_ID_TYPE_S2 */
#define HV_DEVICE_DOMAIN_TYPE_S1  1 /* HV_DEVICE_DOMAIN_ID_TYPE_S1 */
#define HV_DEVICE_DOMAIN_TYPE_SOC 2 /* HV_DEVICE_DOMAIN_ID_TYPE_SOC */

/* ID for stage 2 default domain and NULL domain */
#define HV_DEVICE_DOMAIN_ID_S2_DEFAULT 0
#define HV_DEVICE_DOMAIN_ID_S2_NULL    0xFFFFFFFFULL

union hv_device_domain_id {
	u64 as_uint64;
	struct {
		u32 type: 4;
		u32 reserved: 28;
		u32 id;
	};
} __packed;

struct hv_input_device_domain { /* HV_INPUT_DEVICE_DOMAIN */
	u64 partition_id;
	union hv_input_vtl owner_vtl;
	u8 padding[7];
	union hv_device_domain_id domain_id;
} __packed;

union hv_create_device_domain_flags {	/* HV_CREATE_DEVICE_DOMAIN_FLAGS */
	u32 as_uint32;
	struct {
		u32 forward_progress_required: 1;
		u32 inherit_owning_vtl: 1;
		u32 reserved: 30;
	} __packed;
} __packed;

struct hv_input_create_device_domain {	/* HV_INPUT_CREATE_DEVICE_DOMAIN */
	struct hv_input_device_domain device_domain;
	union hv_create_device_domain_flags create_device_domain_flags;
} __packed;

struct hv_input_delete_device_domain {	/* HV_INPUT_DELETE_DEVICE_DOMAIN */
	struct hv_input_device_domain device_domain;
} __packed;

struct hv_input_attach_device_domain {	/* HV_INPUT_ATTACH_DEVICE_DOMAIN */
	struct hv_input_device_domain device_domain;
	union hv_device_id device_id;
} __packed;

struct hv_input_detach_device_domain {	/* HV_INPUT_DETACH_DEVICE_DOMAIN */
	u64 partition_id;
	union hv_device_id device_id;
} __packed;

struct hv_input_map_device_gpa_pages {	/* HV_INPUT_MAP_DEVICE_GPA_PAGES */
	struct hv_input_device_domain device_domain;
	union hv_input_vtl target_vtl;
	u8 padding[3];
	u32 map_flags;
	u64 target_device_va_base;
	u64 gpa_page_list[];
} __packed;

struct hv_input_unmap_device_gpa_pages {  /* HV_INPUT_UNMAP_DEVICE_GPA_PAGES */
	struct hv_input_device_domain device_domain;
	u64 target_device_va_base;
} __packed;

#endif /* _UAPI_HV_HVHDK_MINI_H */
