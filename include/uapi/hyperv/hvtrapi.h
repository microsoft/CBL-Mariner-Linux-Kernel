/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Type definitions to access Diagnostic Events from hypervsior
 */
#ifndef _HV_HVTRAPI_H
#define _HV_HVTRAPI_H

#include <hyperv/hvgdk_mini.h>

#ifdef __KERNEL__

/* Max number of pages in MSHV's Diagnostic Buffers */
#define HV_MAX_PAGES_IN_DIAG 512  /* Non-HyperV code */

struct hv_input_map_eventlog_buffer { /* HV_INPUT_MAP_EVENTLOG_BUFFER */
	__u32 type; /* HV_EVENTLOG_TYPE */
	__u32 buffer_index;
} __packed;

struct hv_output_map_eventlog_buffer { /* HV_OUTPUT_MAP_EVENTLOG_BUFFER */
	__u64 gpa_numbers[HV_MAX_PAGES_IN_DIAG];
} __packed;

union hv_input_unmap_eventlog_buffer { /* HV_INPUT_UNMAP_EVENTLOG_BUFFER */
	__u64 as_uint64;
	struct {
		__u32 type; /* HV_EVENTLOG_TYPE */
		__u32 buffer_index;
	} __packed;
};

enum hv_eventlog_buffer_state { /* HV_EVENTLOG_BUFFER_STATE */
	HV_EVENT_LOG_BUFFER_STATE_STANDBY = 0,
	HV_EVENT_LOG_BUFFER_STATE_FREE = 1,
	HV_EVENT_LOG_BUFFER_STATE_IN_USE = 2,
	HV_EVENT_LOG_BUFFER_STATE_COMPLETE = 3,
	HV_EVENT_LOG_BUFFER_STATE_READY = 4,
};

struct hv_input_initialize_eventlog_buffer_group {
	struct hv_eventlog_init_type {
		__u16 type; /* enum hv_eventlog_type */
		__u16 mode; /* enum hv_eventlog_mode */
	} __packed init;
	__u32 maximum_buffer_count;
	__u32 buffer_size_in_bytes;
	__u32 threshold;
	__u32 time_basis; /* enum hv_eventlog_entry_time_basis */
	hv_nano100_time_t system_time;
} __packed;

union hv_input_finalize_eventlog_buffer_group {
	__u64 as_uint64;
	struct {
		__u32 type; /* enum hv_eventlog_type */
	} __packed;
};

union hv_input_create_eventlog_buffer {
	__u64 as_uint64[2];
	struct {
		__u32 type; /* enum hv_eventlog_type */
		__u32 buffer_index;
		struct hv_proximity_domain_info proximity_info;
	} __packed;
};

union hv_input_delete_eventlog_buffer {
	__u64 as_uint64;
	struct {
		__u32 type; /* enum hv_eventlog_type */
		__u32 buffer_index;
	} __packed;
};

union hv_input_eventlog_release_buffer {
	__u64 as_uint64;
	struct {
		__u32 type; /* enum hv_eventlog_type */
		__u32 buffer_index;
	} __packed;
};

union hv_eventlog_extended_trace_flags {
	__u64 as_uint64;
	struct {
		__u64 reserved1:8;
		__u64 id:8;
		__u64 reserved2:48;
	} __packed scenario;
	struct {
		__u64 reserved1:8;
		__u64 operation:8;
		__u64 reserved2:48;
	} __packed granular;
	struct {
		__u64 flags;
	} __packed legacy;
	struct {
		__u64 extended: 1;
		__u64 mode: 7;
		__u64 reserved1:56;
	} __packed common;
};

struct hv_eventlog_eventgroup_configuration {
	__u32 group_id;
	__u8 pad[2];
	__u16 event_count;
	__u8 event_id[256];
} __packed;

struct hv_input_eventlog_set_events {
	__u32 type; /* enum hv_eventlog_type */
	__u32 group_count;
	__u64 configuration_flags;
	struct hv_eventlog_eventgroup_configuration groups[2];
} __packed;

union hv_input_flush_eventlog_buffer {
	__u64 as_uint64;
	struct {
		__u32 type; /* enum hv_eventlog_type */
		__u32 buffer_index;
	} __packed;
};
#endif

struct hv_eventlog_entry_header { /* HV_EVENTLOG_ENTRY_HEADER */
	__u32 context;
	__u16 size;
	__u16 type;
	union {
		__u64 time_stamp;
		hv_nano100_time_t reference_time; /* HV_NANO100_TIME */
	};
} __attribute__((packed, aligned(sizeof(__u64))));

enum hv_eventlog_mode {
	HV_EVENT_LOG_MODE_REGULAR  = 0,
	HV_EVENT_LOG_MODE_CIRCULAR = 1,
	HV_EVENT_LOG_MODE_MAX      = 2
};

enum hv_eventlog_entry_time_basis {
	HV_EVENT_LOG_ENTRY_TIME_REFERENCE = 0,
	HV_EVENT_LOG_ENTRY_TIME_TSC       = 1,
	HV_EVENT_LOG_ENTRY_TIME_QPC       = 2,
	HV_EVENT_LOG_ENTRY_TIME_MAX       = 3
};

#define HV_TR_GROUP_BM		0x0000000000000100
#define HV_TR_GROUP_DM		0x0000000000000200
#define HV_TR_GROUP_HC		0x0000000000000400	/* Trace hypercalls. */
#define HV_TR_GROUP_IM		0x0000000000000800	/* Trace hypervisor intercepts. */
#define HV_TR_GROUP_IC		0x0000000000001000
#define HV_TR_GROUP_OB		0x0000000000002000
#define HV_TR_GROUP_PT		0x0000000000004000
#define HV_TR_GROUP_VP		0x0000000000008000
#define HV_TR_GROUP_SYNIC	0x0000000000010000	/* Trace SYNIC events. */
#define HV_TR_GROUP_SYNIC_TI	0x0000000000020000
#define HV_TR_GROUP_AM_GVA	0x0000000000040000
#define HV_TR_GROUP_AM		0x0000000000080000
#define HV_TR_GROUP_VAL		0x0000000000100000
#define HV_TR_GROUP_VM		0x0000000000200000
#define HV_TR_GROUP_SCH		0x0000000000400000
#define HV_TR_GROUP_TH		0x0000000000800000	/* Trace context switches. */
#define HV_TR_GROUP_TI		0x0000000001000000
#define HV_TR_GROUP_KE		0x0000000002000000	/* Trace hypervisor kernel events. */
#define HV_TR_GROUP_MM		0x0000000004000000
#define HV_TR_GROUP_PROFILER	0x0000000008000000
#define HV_TR_GROUP_USCH	0x0000000010000000
#define HV_TR_GROUP_GENERIC	0x0000000020000000

#define HV_TR_ALL_GROUPS	(HV_TR_GROUP_BM | HV_TR_GROUP_DM | \
				 HV_TR_GROUP_HC | HV_TR_GROUP_IM | \
				 HV_TR_GROUP_IC | HV_TR_GROUP_OB | \
				 HV_TR_GROUP_PT | HV_TR_GROUP_VP | \
				 HV_TR_GROUP_SYNIC | HV_TR_GROUP_SYNIC_TI | \
				 HV_TR_GROUP_AM_GVA | HV_TR_GROUP_AM | \
				 HV_TR_GROUP_VAL | HV_TR_GROUP_VM | \
				 HV_TR_GROUP_SCH | HV_TR_GROUP_TH | \
				 HV_TR_GROUP_TI | HV_TR_GROUP_KE | \
				 HV_TR_GROUP_MM | HV_TR_GROUP_PROFILER | \
				 HV_TR_GROUP_USCH | HV_TR_GROUP_GENERIC)

struct hv_eventlog_buffer_header {
	__u32 buffer_size;
	__u32 buffer_index;
	__u32 events_lost;
	__u32 reference_count;
	union {
		__u64 time_stamp;
		hv_nano100_time_t reference_time;
	};
	__u64 reserved1;
	__u64 reserved2;
	struct {
		__u16 logical_processor;
		__u16 logger_id;
	} __packed;
	__u32 buffer_state; /* enum hv_eventlog_buffer_state */
	__u32 next_buffer_offset;
	union {
		__u32 type; /* enum hv_eventlog_type */
		struct {
			__u16 buffer_flag;
			__u16 buffer_type;
		} __packed;
	};
	__u32 next_buffer_index;
	__u32 lp_sequence_number;
	__u32 reserved4[2];
} __packed;

#endif
