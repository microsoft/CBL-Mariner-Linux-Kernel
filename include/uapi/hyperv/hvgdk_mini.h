/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Type definitions for the hypervisor guest interface to kernel.
 */
#ifndef _UAPI_HV_HVGDK_MINI_H
#define _UAPI_HV_HVGDK_MINI_H

#include <linux/types.h>
#if defined(__KERNEL__)
#include <linux/bits.h>
#endif

#define HVGDK_MINI_H_VERSION		(25294)
typedef __u64 hv_nano100_time_t;	/* HV_NANO100_TIME */

struct hv_u128 {
	__u64 low_part;
	__u64 high_part;
} __packed;

/* NOTE: when adding below, update hv_status_to_string() */
#define HV_STATUS_SUCCESS			    0x0
#define HV_STATUS_INVALID_HYPERCALL_CODE	    0x2
#define HV_STATUS_INVALID_HYPERCALL_INPUT	    0x3
#define HV_STATUS_INVALID_ALIGNMENT		    0x4
#define HV_STATUS_INVALID_PARAMETER		    0x5
#define HV_STATUS_ACCESS_DENIED			    0x6
#define HV_STATUS_INVALID_PARTITION_STATE	    0x7
#define HV_STATUS_OPERATION_DENIED		    0x8
#define HV_STATUS_UNKNOWN_PROPERTY		    0x9
#define HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE	    0xA
#define HV_STATUS_INSUFFICIENT_MEMORY		    0xB
#define HV_STATUS_INVALID_PARTITION_ID		    0xD
#define HV_STATUS_INVALID_VP_INDEX		    0xE
#define HV_STATUS_NOT_FOUND			    0x10
#define HV_STATUS_INVALID_PORT_ID		    0x11
#define HV_STATUS_INVALID_CONNECTION_ID		    0x12
#define HV_STATUS_INSUFFICIENT_BUFFERS		    0x13
#define HV_STATUS_NOT_ACKNOWLEDGED		    0x14
#define HV_STATUS_INVALID_VP_STATE		    0x15
#define HV_STATUS_NO_RESOURCES			    0x1D
#define HV_STATUS_PROCESSOR_FEATURE_NOT_SUPPORTED   0x20
#define HV_STATUS_INVALID_LP_INDEX		    0x41
#define HV_STATUS_INVALID_REGISTER_VALUE	    0x50
#define HV_STATUS_OPERATION_FAILED		    0x71
#define HV_STATUS_TIME_OUT			    0x78
#define HV_STATUS_CALL_PENDING			    0x79
#define HV_STATUS_VTL_ALREADY_ENABLED		    0x86

/*
 * The Hyper-V TimeRefCount register and the TSC
 * page provide a guest VM clock with 100ns tick rate
 */
#define HV_CLOCK_HZ (NSEC_PER_SEC/100)


/* TODO not in hv headers */

#ifndef BIT
#define BIT(nr)				(1UL << (nr))
#endif

#define HV_LINUX_VENDOR_ID		0x8100
#define HV_HYP_PAGE_SHIFT		12
#define HV_HYP_PAGE_SIZE		BIT(HV_HYP_PAGE_SHIFT)
#define HV_HYP_PAGE_MASK		(~(HV_HYP_PAGE_SIZE - 1))
#define HV_HYP_LARGE_PAGE_SHIFT		21


#define HV_PARTITION_ID_INVALID		((__u64) 0)
#define HV_PARTITION_ID_SELF		((__u64)-1)


/* Hyper-V specific model specific registers (MSRs) */

#if defined(__x86_64__)
/* HV_X64_SYNTHETIC_MSR */
#define HV_X64_MSR_GUEST_OS_ID			0x40000000
#define HV_X64_MSR_HYPERCALL			0x40000001
#define HV_X64_MSR_VP_INDEX			0x40000002
#define HV_X64_MSR_RESET			0x40000003
#define HV_X64_MSR_VP_RUNTIME			0x40000010
#define HV_X64_MSR_TIME_REF_COUNT		0x40000020
#define HV_X64_MSR_REFERENCE_TSC		0x40000021
#define HV_X64_MSR_TSC_FREQUENCY		0x40000022
#define HV_X64_MSR_APIC_FREQUENCY		0x40000023

/* Define the virtual APIC registers */
#define HV_X64_MSR_EOI				0x40000070
#define HV_X64_MSR_ICR				0x40000071
#define HV_X64_MSR_TPR				0x40000072
#define HV_X64_MSR_VP_ASSIST_PAGE		0x40000073

/* Note: derived, not in hvgdk_mini.h */
#define HV_X64_MSR_VP_ASSIST_PAGE_ENABLE	0x00000001
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT	12
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK	\
		(~((1ull << HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT) - 1))

/* Define synthetic interrupt controller model specific registers. */
#define HV_X64_MSR_SCONTROL			0x40000080
#define HV_X64_MSR_SVERSION			0x40000081
#define HV_X64_MSR_SIEFP			0x40000082
#define HV_X64_MSR_SIMP				0x40000083
#define HV_X64_MSR_EOM				0x40000084
#define HV_X64_MSR_SIRBP			0x40000085
#define HV_X64_MSR_SINT0			0x40000090
#define HV_X64_MSR_SINT1			0x40000091
#define HV_X64_MSR_SINT2			0x40000092
#define HV_X64_MSR_SINT3			0x40000093
#define HV_X64_MSR_SINT4			0x40000094
#define HV_X64_MSR_SINT5			0x40000095
#define HV_X64_MSR_SINT6			0x40000096
#define HV_X64_MSR_SINT7			0x40000097
#define HV_X64_MSR_SINT8			0x40000098
#define HV_X64_MSR_SINT9			0x40000099
#define HV_X64_MSR_SINT10			0x4000009A
#define HV_X64_MSR_SINT11			0x4000009B
#define HV_X64_MSR_SINT12			0x4000009C
#define HV_X64_MSR_SINT13			0x4000009D
#define HV_X64_MSR_SINT14			0x4000009E
#define HV_X64_MSR_SINT15			0x4000009F

/* Define synthetic interrupt controller model specific registers for nested hypervisor */
#define HV_X64_MSR_NESTED_SCONTROL		0x40001080
#define HV_X64_MSR_NESTED_SVERSION		0x40001081
#define HV_X64_MSR_NESTED_SIEFP			0x40001082
#define HV_X64_MSR_NESTED_SIMP			0x40001083
#define HV_X64_MSR_NESTED_EOM			0x40001084
#define HV_X64_MSR_NESTED_SINT0			0x40001090

/*
 * Synthetic Timer MSRs. Four timers per vcpu.
 */
#define HV_X64_MSR_STIMER0_CONFIG		0x400000B0
#define HV_X64_MSR_STIMER0_COUNT		0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG		0x400000B2
#define HV_X64_MSR_STIMER1_COUNT		0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG		0x400000B4
#define HV_X64_MSR_STIMER2_COUNT		0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG		0x400000B6
#define HV_X64_MSR_STIMER3_COUNT		0x400000B7

/* Hyper-V guest idle MSR */
#define HV_X64_MSR_GUEST_IDLE			0x400000F0

/* Hyper-V guest crash notification MSR's */
#define HV_X64_MSR_CRASH_P0			0x40000100
#define HV_X64_MSR_CRASH_P1			0x40000101
#define HV_X64_MSR_CRASH_P2			0x40000102
#define HV_X64_MSR_CRASH_P3			0x40000103
#define HV_X64_MSR_CRASH_P4			0x40000104
#define HV_X64_MSR_CRASH_CTL			0x40000105
/* NOTE: derived, not in hvgdk_mini.h */
#define HV_X64_MSR_CRASH_PARAMS		\
		(1 + (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0))

#define HV_IPI_LOW_VECTOR	 0x10
#define HV_IPI_HIGH_VECTOR	 0xff

struct hv_reenlightenment_control {
	__u64 vector:8;
	__u64 reserved1:8;
	__u64 enabled:1;
	__u64 reserved2:15;
	__u64 target_vp:32;
}  __packed;

struct hv_tsc_emulation_status {	 /* HV_TSC_EMULATION_STATUS */
	__u64 inprogress:1;
	__u64 reserved:63;
} __packed;

struct hv_tsc_emulation_control {	 /* HV_TSC_INVARIANT_CONTROL */
	__u64 enabled:1;
	__u64 reserved:63;
} __packed;

/* TSC emulation after migration */
#define HV_X64_MSR_REENLIGHTENMENT_CONTROL	0x40000106
#define HV_X64_MSR_TSC_EMULATION_CONTROL	0x40000107
#define HV_X64_MSR_TSC_EMULATION_STATUS		0x40000108
#define HV_X64_MSR_TSC_INVARIANT_CONTROL	0x40000118
#define HV_EXPOSE_INVARIANT_TSC		BIT_ULL(0)

#endif /* __x86_64__ */

struct hv_get_partition_id {	 /* HV_OUTPUT_GET_PARTITION_ID */
	__u64 partition_id;
} __packed;

/* HV_CRASH_CTL_REG_CONTENTS */
#define HV_CRASH_CTL_CRASH_NOTIFY_MSG		 BIT_ULL(62)
#define HV_CRASH_CTL_CRASH_NOTIFY		 BIT_ULL(63)

union hv_reference_tsc_msr {
	__u64 as_uint64;
	struct {
		__u64 enable:1;
		__u64 reserved:11;
		__u64 pfn:52;
	} __packed;
};

/* The maximum number of sparse vCPU banks which can be encoded by 'struct hv_vpset' */
#define HV_MAX_SPARSE_VCPU_BANKS (64)
/* The number of vCPUs in one sparse bank */
#define HV_VCPUS_PER_SPARSE_BANK (64)

/* Some of Hyper-V structs do not use hv_vpset where linux uses them */
struct hv_vpset {	 /* HV_VP_SET */
	__u64 format;
	__u64 valid_bank_mask;
	__u64 bank_contents[];
} __packed;

/*
 * Version info reported by hypervisor
 * Changed to a union for convenience
 */
union hv_hypervisor_version_info {
	struct {
		__u32 build_number;

		__u32 minor_version : 16;
		__u32 major_version : 16;

		__u32 service_pack;

		__u32 service_number : 24;
		__u32 service_branch : 8;
	};
	struct {
		__u32 eax;
		__u32 ebx;
		__u32 ecx;
		__u32 edx;
	};
};

/* HV_CPUID_FUNCTION */
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS	0x40000000
#define HYPERV_CPUID_INTERFACE			0x40000001
#define HYPERV_CPUID_VERSION			0x40000002
#define HYPERV_CPUID_FEATURES			0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO		0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS		0x40000005
#define HYPERV_CPUID_CPU_MANAGEMENT_FEATURES	0x40000007
#define HYPERV_CPUID_NESTED_FEATURES		0x4000000A
#define HYPERV_CPUID_ISOLATION_CONFIG		0x4000000C

#define HYPERV_CPUID_VIRT_STACK_INTERFACE	 0x40000081
#define HYPERV_VS_INTERFACE_EAX_SIGNATURE	 0x31235356  /* "VS#1" */

#define HYPERV_CPUID_VIRT_STACK_PROPERTIES	 0x40000082
/* Support for the extended IOAPIC RTE format */
#define HYPERV_VS_PROPERTIES_EAX_EXTENDED_IOAPIC_RTE	 BIT(2)

#define HYPERV_HYPERVISOR_PRESENT_BIT		 0x80000000
#define HYPERV_CPUID_MIN			 0x40000005
#define HYPERV_CPUID_MAX			 0x4000ffff


/* HV_PARTITION_PRIVILEGE_MASK */
#define HV_MSR_VP_RUNTIME_AVAILABLE		BIT(0)
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		BIT(1)
#define HV_MSR_SYNIC_AVAILABLE			BIT(2)
#define HV_MSR_SYNTIMER_AVAILABLE		BIT(3)
#define HV_MSR_APIC_ACCESS_AVAILABLE		BIT(4)
#define HV_MSR_HYPERCALL_AVAILABLE		BIT(5)
#define HV_MSR_VP_INDEX_AVAILABLE		BIT(6)
#define HV_MSR_RESET_AVAILABLE			BIT(7)
#define HV_MSR_STAT_PAGES_AVAILABLE		BIT(8)
#define HV_MSR_REFERENCE_TSC_AVAILABLE		BIT(9)
#define HV_MSR_GUEST_IDLE_AVAILABLE		BIT(10)
#define HV_ACCESS_FREQUENCY_MSRS		BIT(11)
#define HV_ACCESS_REENLIGHTENMENT		BIT(13)
#define HV_ACCESS_TSC_INVARIANT			BIT(15)

/* HV_PARTITION_PRIVILEGE_MASK */
#define HV_CREATE_PARTITIONS			BIT(0)
#define HV_ACCESS_PARTITION_ID			BIT(1)
#define HV_ACCESS_MEMORY_POOL			BIT(2)
#define HV_ADJUST_MESSAGE_BUFFERS		BIT(3)
#define HV_POST_MESSAGES			BIT(4)
#define HV_SIGNAL_EVENTS			BIT(5)
#define HV_CREATE_PORT				BIT(6)
#define HV_CONNECT_PORT				BIT(7)
#define HV_ACCESS_STATS				BIT(8)
#define HV_DEBUGGING				BIT(11)
#define HV_CPU_MANAGEMENT			BIT(12)
#define HV_ENABLE_EXTENDED_HYPERCALLS		BIT(20)
#define HV_ISOLATION				BIT(22)

#if defined(__x86_64__)
/* HV_X64_HYPERVISOR_FEATURES (EDX) */
#define HV_X64_MWAIT_AVAILABLE				BIT(0)
#define HV_X64_GUEST_DEBUGGING_AVAILABLE		BIT(1)
#define HV_X64_PERF_MONITOR_AVAILABLE			BIT(2)
#define HV_X64_CPU_DYNAMIC_PARTITIONING_AVAILABLE	BIT(3)
#define HV_X64_HYPERCALL_XMM_INPUT_AVAILABLE		BIT(4)
#define HV_X64_GUEST_IDLE_STATE_AVAILABLE		BIT(5)
#define HV_FEATURE_FREQUENCY_MSRS_AVAILABLE		BIT(8)
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE		BIT(10)
#define HV_FEATURE_DEBUG_MSRS_AVAILABLE			BIT(11)
/*
 * Support for returning hypercall output block via XMM
 * registers is available
 */
#define HV_X64_HYPERCALL_XMM_OUTPUT_AVAILABLE		BIT(15)
/* stimer Direct Mode is available */
#define HV_STIMER_DIRECT_MODE_AVAILABLE			BIT(19)

#define HV_DEVICE_DOMAIN_AVAILABLE		BIT(24)
#define HV_S1_DEVICE_DOMAIN_AVAILABLE		BIT(25)

/* HV_X64_ENLIGHTENMENT_INFORMATION */
#define HV_X64_AS_SWITCH_RECOMMENDED			BIT(0)
#define HV_X64_LOCAL_TLB_FLUSH_RECOMMENDED		BIT(1)
#define HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED		BIT(2)
#define HV_X64_APIC_ACCESS_RECOMMENDED			BIT(3)
#define HV_X64_SYSTEM_RESET_RECOMMENDED			BIT(4)
#define HV_X64_RELAXED_TIMING_RECOMMENDED		BIT(5)
#define HV_DEPRECATING_AEOI_RECOMMENDED			BIT(9)
#define HV_X64_CLUSTER_IPI_RECOMMENDED			BIT(10)
#define HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED		BIT(11)
#define HV_X64_HYPERV_NESTED				BIT(12)
#define HV_X64_ENLIGHTENED_VMCS_RECOMMENDED		BIT(14)
#define HV_X64_USE_MMIO_HYPERCALLS			BIT(21)


/* HYPERV_CPUID_ISOLATION_CONFIG.EBX bits. */
#define HV_ISOLATION_TYPE				 GENMASK(3, 0)
#define HV_SHARED_GPA_BOUNDARY_ACTIVE			 BIT(5)
#define HV_SHARED_GPA_BOUNDARY_BITS			 GENMASK(11, 6)

/* HYPERV_CPUID_FEATURES.ECX bits. */
#define HV_VP_DISPATCH_INTERRUPT_INJECTION_AVAILABLE	BIT(9)

enum hv_isolation_type {
	HV_ISOLATION_TYPE_NONE	= 0,	/* HV_PARTITION_ISOLATION_TYPE_NONE */
	HV_ISOLATION_TYPE_VBS	= 1,
	HV_ISOLATION_TYPE_SNP	= 2,
	HV_ISOLATION_TYPE_TDX	= 3
};

union hv_x64_msr_hypercall_contents {
	__u64 as_uint64;
	struct {
		__u64 enable:1;
		__u64 reserved:11;
		__u64 guest_physical_address:52;
	} __packed;
};
#endif /* if defined(__x86_64__) */

#if defined(__aarch64__)
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE	BIT(8)
#define HV_STIMER_DIRECT_MODE_AVAILABLE		BIT(13)
#endif /* #if defined(__aarch64__) */

#if defined(__x86_64__)
#define HV_MAXIMUM_PROCESSORS	    2048
#else
#define HV_MAXIMUM_PROCESSORS	    320
#endif

#define HV_MAX_VP_INDEX			(HV_MAXIMUM_PROCESSORS - 1)
#define HV_VP_INDEX_SELF		((__u32)-2)
#define HV_ANY_VP			((__u32)-1)

union hv_vp_assist_msr_contents {	 /* HV_REGISTER_VP_ASSIST_PAGE */
	__u64 as_uint64;
	struct {
		__u64 enable:1;
		__u64 reserved:11;
		__u64 pfn:52;
	} __packed;
};

/* Declare the various hypercall operations. */
/* HV_CALL_CODE */
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE	0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST	0x0003
#define HVCALL_GET_LOGICAL_PROCESSOR_RUN_TIME	0x0004
#define HVCALL_NOTIFY_LONG_SPIN_WAIT		0x0008
#define HVCALL_SEND_IPI				0x000b
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX	0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX	0x0014
#define HVCALL_SEND_IPI_EX			0x0015
#define HVCALL_CREATE_PARTITION			0x0040
#define HVCALL_INITIALIZE_PARTITION		0x0041
#define HVCALL_FINALIZE_PARTITION		0x0042
#define HVCALL_DELETE_PARTITION			0x0043
#define HVCALL_GET_PARTITION_PROPERTY		0x0044
#define HVCALL_SET_PARTITION_PROPERTY		0x0045
#define HVCALL_GET_PARTITION_ID			0x0046
#define HVCALL_DEPOSIT_MEMORY			0x0048
#define HVCALL_WITHDRAW_MEMORY			0x0049
#define HVCALL_MAP_GPA_PAGES			0x004b
#define HVCALL_UNMAP_GPA_PAGES			0x004c
#define HVCALL_INSTALL_INTERCEPT		0x004d
#define HVCALL_CREATE_VP			0x004e
#define HVCALL_DELETE_VP			0x004f
#define HVCALL_GET_VP_REGISTERS			0x0050
#define HVCALL_SET_VP_REGISTERS			0x0051
#define HVCALL_TRANSLATE_VIRTUAL_ADDRESS	0x0052
#define HVCALL_READ_GPA			0x0053
#define HVCALL_WRITE_GPA		0x0054
#define HVCALL_CLEAR_VIRTUAL_INTERRUPT		0x0056
#define HVCALL_DELETE_PORT			0x0058
#define HVCALL_DISCONNECT_PORT			0x005b
#define HVCALL_POST_MESSAGE			0x005c
#define HVCALL_SIGNAL_EVENT			0x005d
#define HVCALL_INITIALIZE_EVENT_LOG_BUFFER_GROUP	0x0060
#define HVCALL_FINALIZE_EVENT_LOG_BUFFER_GROUP	0x0061
#define HVCALL_CREATE_EVENT_LOG_BUFFER		0x0062
#define HVCALL_DELETE_EVENT_LOG_BUFFER		0x0063
#define HVCALL_MAP_EVENT_LOG_BUFFER		0x0064
#define HVCALL_UNMAP_EVENT_LOG_BUFFER		0x0065
#define HVCALL_SET_EVENT_LOG_GROUP_SOURCES	0x0066
#define HVCALL_RELEASE_EVENT_LOG_BUFFER		0x0067
#define HVCALL_FLUSH_EVENT_LOG_BUFFER		0x0068
#define HVCALL_POST_DEBUG_DATA			0x0069
#define HVCALL_RETRIEVE_DEBUG_DATA		0x006a
#define HVCALL_RESET_DEBUG_SESSION		0x006b
#define HVCALL_MAP_STATS_PAGE			0x006c
#define HVCALL_UNMAP_STATS_PAGE			0x006d
#define HVCALL_SET_SYSTEM_PROPERTY		0x006f
#define HVCALL_ADD_LOGICAL_PROCESSOR		0x0076
#define HVCALL_GET_SYSTEM_PROPERTY		0x007b
#define HVCALL_MAP_DEVICE_INTERRUPT		0x007c
#define HVCALL_UNMAP_DEVICE_INTERRUPT		0x007d
#define HVCALL_RETARGET_INTERRUPT		0x007e
#define HVCALL_ATTACH_DEVICE			0x0082
#define HVCALL_DETACH_DEVICE			0x0083
#define HVCALL_ENTER_SLEEP_STATE		0x0084
#define HVCALL_NOTIFY_PARTITION_EVENT		0x0087
#define HVCALL_NOTIFY_PORT_RING_EMPTY		0x008b
#define HVCALL_REGISTER_INTERCEPT_RESULT	0x0091
#define HVCALL_ASSERT_VIRTUAL_INTERRUPT		0x0094
#define HVCALL_CREATE_PORT			0x0095
#define HVCALL_CONNECT_PORT			0x0096
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE 0x00af
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_LIST 0x00b0
#define HVCALL_CREATE_DEVICE_DOMAIN		0x00b1
#define HVCALL_ATTACH_DEVICE_DOMAIN		0x00b2
#define HVCALL_MAP_DEVICE_GPA_PAGES		0x00b3
#define HVCALL_UNMAP_DEVICE_GPA_PAGES		0x00b4
#define HVCALL_SIGNAL_EVENT_DIRECT		0x00c0
#define HVCALL_POST_MESSAGE_DIRECT		0x00c1
#define HVCALL_DISPATCH_VP			0x00c2
#define HVCALL_DETACH_DEVICE_DOMAIN		0x00c4
#define HVCALL_DELETE_DEVICE_DOMAIN		0x00c5
#define HVCALL_QUERY_DEVICE_DOMAIN		0x00c6
#define HVCALL_MAP_SPARSE_DEVICE_GPA_PAGES	0x00c7
#define HVCALL_UNMAP_SPARSE_DEVICE_GPA_PAGES	0x00c8
#define HVCALL_GET_GPA_PAGES_ACCESS_STATES	 0x00c9
#define HVCALL_CONFIGURE_DEVICE_DOMAIN		0x00ce
#define HVCALL_FLUSH_DEVICE_DOMAIN		0x00d0
#define HVCALL_ACQUIRE_SPARSE_SPA_PAGE_HOST_ACCESS	0x00d7
#define HVCALL_RELEASE_SPARSE_SPA_PAGE_HOST_ACCESS	0x00d8
#define HVCALL_MAP_VP_STATE_PAGE			0x00e1
#define HVCALL_UNMAP_VP_STATE_PAGE		0x00e2
#define HVCALL_GET_VP_STATE				0x00e3
#define HVCALL_SET_VP_STATE				0x00e4
#define HVCALL_IMPORT_ISOLATED_PAGES		0x00ef
#define HVCALL_COMPLETE_ISOLATED_IMPORT		0x00f1
#define HVCALL_ISSUE_SNP_PSP_GUEST_REQUEST	0x00f2
#define HVCALL_GET_VP_CPUID_VALUES		0x00f4
#define HVCALL_LOG_HYPERVISOR_SYSTEM_CONFIG	0x00f8
#define HVCALL_MMIO_READ			0x0106
#define HVCALL_MMIO_WRITE			0x0107
#define HVCALL_DISABLE_HYP_EX			0x010f

/*
 * Some macros - i.e. GENMASK_ULL and BIT_ULL - are not currently supported by
 * userspace rust bindings generation tool.
 * As the below are not currently needed in userspace, don't export them and
 * avoid the issue altogether for now.
 */
#if defined(__KERNEL__)

/* HV_HYPERCALL_INPUT */
#define HV_HYPERCALL_RESULT_MASK	GENMASK_ULL(15, 0)
#define HV_HYPERCALL_FAST_BIT		BIT(16)
#define HV_HYPERCALL_VARHEAD_OFFSET	17
#define HV_HYPERCALL_NESTED		BIT(31)
#define HV_HYPERCALL_REP_COMP_OFFSET	32
#define HV_HYPERCALL_REP_COMP_1		BIT_ULL(32)
#define HV_HYPERCALL_REP_COMP_MASK	GENMASK_ULL(43, 32)
#define HV_HYPERCALL_REP_START_OFFSET	48
#define HV_HYPERCALL_REP_START_MASK	GENMASK_ULL(59, 48)

#endif /* __KERNEL__ */

/* HvFlushGuestPhysicalAddressSpace hypercalls */
struct hv_guest_mapping_flush {
	__u64 address_space;
	__u64 flags;
} __packed;

/*
 *  HV_MAX_FLUSH_PAGES = "additional_pages" + 1. It's limited
 *  by the bitwidth of "additional_pages" in union hv_gpa_page_range.
 */
#define HV_MAX_FLUSH_PAGES (2048)
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_2MB		0
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_1GB		1

#define HV_FLUSH_ALL_PROCESSORS		 BIT(0)
#define HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES	 BIT(1)
#define HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY	 BIT(2)
#define HV_FLUSH_USE_EXTENDED_RANGE_FORMAT	 BIT(3)

/* HvFlushGuestPhysicalAddressList, HvExtCallMemoryHeatHint hypercall */
union hv_gpa_page_range {
	__u64 address_space;
	struct {
		__u64 additional_pages:11;
		__u64 largepage:1;
		__u64 basepfn:52;
	} page;
	struct {
		__u64 reserved:12;
		__u64 page_size:1;
		__u64 reserved1:8;
		__u64 base_large_pfn:43;
	};
};

#if defined(__KERNEL__)
/*
 * All input flush parameters should be in single page. The max flush
 * count is equal with how many entries of union hv_gpa_page_range can
 * be populated into the input parameter page.
 */
#define HV_MAX_FLUSH_REP_COUNT ((HV_HYP_PAGE_SIZE - 2 * sizeof(__u64)) / \
				sizeof(union hv_gpa_page_range))

struct hv_guest_mapping_flush_list {
	__u64 address_space;
	__u64 flags;
	union hv_gpa_page_range gpa_list[HV_MAX_FLUSH_REP_COUNT];
};

struct hv_tlb_flush {	 /* HV_INPUT_FLUSH_VIRTUAL_ADDRESS_LIST */
	__u64 address_space;
	__u64 flags;
	__u64 processor_mask;
	__u64 gva_list[];
} __packed;

/* HvFlushVirtualAddressSpaceEx, HvFlushVirtualAddressListEx hypercalls */
struct hv_tlb_flush_ex {
	__u64 address_space;
	__u64 flags;
	struct hv_vpset hv_vp_set;
	__u64 gva_list[];
} __packed;

struct ms_hyperv_tsc_page {	 /* HV_REFERENCE_TSC_PAGE */
	volatile __u32 tsc_sequence;
	__u32 reserved1;
	volatile __u64 tsc_scale;
	volatile __s64 tsc_offset;
} __packed;

#endif /* __KERNEL__ */

/* Define the number of synthetic interrupt sources. */
#define HV_SYNIC_SINT_COUNT (16)

/* Hyper-V defined statically assigned SINTs */
#define HV_SYNIC_INTERCEPTION_SINT_INDEX 0x00000000
#define HV_SYNIC_IOMMU_FAULT_SINT_INDEX  0x00000001
#define HV_SYNIC_VMBUS_SINT_INDEX	 0x00000002
#define HV_SYNIC_HAL_HV_TIMER_SINT_INDEX 0x00000003
#define HV_SYNIC_HVL_SHARED_SINT_INDEX	 0x00000004
#define HV_SYNIC_FIRST_UNUSED_SINT_INDEX 0x00000005

/* mshv assigned SINT for doorbell */
#define HV_SYNIC_DOORBELL_SINT_INDEX	 HV_SYNIC_FIRST_UNUSED_SINT_INDEX

#define HV_INTERRUPT_VECTOR_NONE 0xFFFFFFFF

enum hv_interrupt_type {
#if defined(__aarch64__)
	HV_ARM64_INTERRUPT_TYPE_FIXED		= 0x0000,
	HV_ARM64_INTERRUPT_TYPE_MAXIMUM		= 0x0008,
#else
	HV_X64_INTERRUPT_TYPE_FIXED		= 0x0000,
	HV_X64_INTERRUPT_TYPE_LOWESTPRIORITY	= 0x0001,
	HV_X64_INTERRUPT_TYPE_SMI		= 0x0002,
	HV_X64_INTERRUPT_TYPE_REMOTEREAD	= 0x0003,
	HV_X64_INTERRUPT_TYPE_NMI		= 0x0004,
	HV_X64_INTERRUPT_TYPE_INIT		= 0x0005,
	HV_X64_INTERRUPT_TYPE_SIPI		= 0x0006,
	HV_X64_INTERRUPT_TYPE_EXTINT		= 0x0007,
	HV_X64_INTERRUPT_TYPE_LOCALINT0		= 0x0008,
	HV_X64_INTERRUPT_TYPE_LOCALINT1		= 0x0009,
	HV_X64_INTERRUPT_TYPE_MAXIMUM		= 0x000A,
#endif
};

/* Define synthetic interrupt source. */
union hv_synic_sint {
	__u64 as_uint64;
	struct {
		__u64 vector : 8;
		__u64 reserved1 : 8;
		__u64 masked : 1;
		__u64 auto_eoi : 1;
		__u64 polling : 1;
		__u64 as_intercept : 1;
		__u64 proxy : 1;
		__u64 reserved2 : 43;
	} __packed;
};


union hv_x64_xsave_xfem_register {
	__u64 as_uint64;
	struct {
		__u32 low_uint32;
		__u32 high_uint32;
	} __packed;
	struct {
		__u64 legacy_x87 : 1;
		__u64 legacy_sse : 1;
		__u64 avx : 1;
		__u64 mpx_bndreg : 1;
		__u64 mpx_bndcsr : 1;
		__u64 avx_512_op_mask : 1;
		__u64 avx_512_zmmhi : 1;
		__u64 avx_512_zmm16_31 : 1;
		__u64 rsvd8_9 : 2;
		__u64 pasid : 1;
		__u64 cet_u : 1;
		__u64 cet_s : 1;
		__u64 rsvd13_16 : 4;
		__u64 xtile_cfg : 1;
		__u64 xtile_data : 1;
		__u64 rsvd19_63 : 45;
	} __packed;
};

/* Synthetic timer configuration */
union hv_stimer_config {	 /* HV_X64_MSR_STIMER_CONFIG_CONTENTS */
	__u64 as_uint64;
	struct {
		__u64 enable:1;
		__u64 periodic:1;
		__u64 lazy:1;
		__u64 auto_enable:1;
		__u64 apic_vector:8;
		__u64 direct_mode:1;
		__u64 reserved_z0:3;
		__u64 sintx:4;
		__u64 reserved_z1:44;
	} __packed;
};

/* Define the number of synthetic timers */
#define HV_SYNIC_STIMER_COUNT	(4)

/* Define port identifier type. */
union hv_port_id {
	__u32 as__u32;
	struct {
		__u32 id : 24;
		__u32 reserved : 8;
	} __packed u; // TODO remove this u
};

#define HV_MESSAGE_SIZE			(256)
#define HV_MESSAGE_PAYLOAD_BYTE_COUNT	(240)
#define HV_MESSAGE_PAYLOAD_QWORD_COUNT	(30)

/* Define hypervisor message types. */
enum hv_message_type {
	HVMSG_NONE				= 0x00000000,

	/* Memory access messages. */
	HVMSG_UNMAPPED_GPA			= 0x80000000,
	HVMSG_GPA_INTERCEPT			= 0x80000001,
	HVMSG_UNACCEPTED_GPA			= 0x80000003,
	HVMSG_GPA_ATTRIBUTE_INTERCEPT		= 0x80000004,

	/* Timer notification messages. */
	HVMSG_TIMER_EXPIRED			= 0x80000010,

	/* Error messages. */
	HVMSG_INVALID_VP_REGISTER_VALUE		= 0x80000020,
	HVMSG_UNRECOVERABLE_EXCEPTION		= 0x80000021,
	HVMSG_UNSUPPORTED_FEATURE		= 0x80000022,

	/*
	 * Opaque intercept message. The original intercept message is only
	 * accessible from the mapped intercept message page.
	 */
	HVMSG_OPAQUE_INTERCEPT			= 0x8000003F,

	/* Trace buffer complete messages. */
	HVMSG_EVENTLOG_BUFFERCOMPLETE		= 0x80000040,

	/* Hypercall intercept */
	HVMSG_HYPERCALL_INTERCEPT		= 0x80000050,

	/* SynIC intercepts */
	HVMSG_SYNIC_EVENT_INTERCEPT		= 0x80000060,
	HVMSG_SYNIC_SINT_INTERCEPT		= 0x80000061,
	HVMSG_SYNIC_SINT_DELIVERABLE	= 0x80000062,

	/* Async call completion intercept */
	HVMSG_ASYNC_CALL_COMPLETION		= 0x80000070,

	/* Root scheduler messages */
	HVMSG_SCHEDULER_VP_SIGNAL_BITSET	= 0x80000100,
	HVMSG_SCHEDULER_VP_SIGNAL_PAIR		= 0x80000101,

	/* Platform-specific processor intercept messages. */
	HVMSG_X64_IO_PORT_INTERCEPT		= 0x80010000,
	HVMSG_X64_MSR_INTERCEPT			= 0x80010001,
	HVMSG_X64_CPUID_INTERCEPT		= 0x80010002,
	HVMSG_X64_EXCEPTION_INTERCEPT		= 0x80010003,
	HVMSG_X64_APIC_EOI			= 0x80010004,
	HVMSG_X64_LEGACY_FP_ERROR		= 0x80010005,
	HVMSG_X64_IOMMU_PRQ			= 0x80010006,
	HVMSG_X64_HALT				= 0x80010007,
	HVMSG_X64_INTERRUPTION_DELIVERABLE	= 0x80010008,
	HVMSG_X64_SIPI_INTERCEPT		= 0x80010009,
	HVMSG_X64_SEV_VMGEXIT_INTERCEPT	= 0x80010013,
};

/* Define the format of the SIMP register */
union hv_synic_simp {
	__u64 as_uint64;
	struct {
		__u64 simp_enabled : 1;
		__u64 preserved : 11;
		__u64 base_simp_gpa : 52;
	} __packed;
};

union hv_message_flags {
	__u8 asu8;
	struct {
		__u8 msg_pending : 1;
		__u8 reserved : 7;
	} __packed;
};

struct hv_message_header {
	__u32 message_type;
	__u8 payload_size;
	union hv_message_flags message_flags;
	__u8 reserved[2];
	union {
		__u64 sender;
		union hv_port_id port;
	};
} __packed;

/*
 * Message format for notifications delivered via
 * intercept message(as_intercept=1)
 */
struct hv_notification_message_payload {
	__u32 sint_index;
} __packed;

struct hv_message {
	struct hv_message_header header;
	union {
		__u64 payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
	} u;
} __packed;

/* Define the synthetic interrupt message page layout. */
struct hv_message_page {
	struct hv_message sint_message[HV_SYNIC_SINT_COUNT];
} __packed;

struct hv_x64_segment_register {
	__u64 base;
	__u32 limit;
	__u16 selector;
	union {
		struct {
			__u16 segment_type : 4;
			__u16 non_system_segment : 1;
			__u16 descriptor_privilege_level : 2;
			__u16 present : 1;
			__u16 reserved : 4;
			__u16 available : 1;
			__u16 _long : 1;
			__u16 _default : 1;
			__u16 granularity : 1;
		} __packed;
		__u16 attributes;
	};
} __packed;

struct hv_x64_table_register {
	__u16 pad[3];
	__u16 limit;
	__u64 base;
} __packed;

union hv_x64_fp_control_status_register {
	struct hv_u128 as_uint128;
	struct {
		__u16 fp_control;
		__u16 fp_status;
		__u8 fp_tag;
		__u8 reserved;
		__u16 last_fp_op;
		union {
			/* long mode */
			__u64 last_fp_rip;
			/* 32 bit mode */
			struct {
				__u32 last_fp_eip;
				__u16 last_fp_cs;
				__u16 padding;
			} __packed;
		};
	} __packed;
} __packed;

union hv_x64_xmm_control_status_register {
	struct hv_u128 as_uint128;
	struct {
		union {
			/* long mode */
			__u64 last_fp_rdp;
			/* 32 bit mode */
			struct {
				__u32 last_fp_dp;
				__u16 last_fp_ds;
				__u16 padding;
			} __packed;
		};
		__u32 xmm_status_control;
		__u32 xmm_status_control_mask;
	} __packed;
} __packed;

union hv_x64_fp_register {
	struct hv_u128 as_uint128;
	struct {
		__u64 mantissa;
		__u64 biased_exponent : 15;
		__u64 sign : 1;
		__u64 reserved : 48;
	} __packed;
} __packed;

union hv_x64_msr_npiep_config_contents {
	__u64 as_uint64;
	struct {
		/*
		 * These bits enable instruction execution prevention for
		 * specific instructions.
		 */
		__u64 prevents_gdt : 1;
		__u64 prevents_idt : 1;
		__u64 prevents_ldt : 1;
		__u64 prevents_tr : 1;

		/* The reserved bits must always be 0. */
		__u64 reserved : 60;
	} __packed;
};

union hv_input_vtl {
	__u8 as_uint8;
	struct {
		__u8 target_vtl : 4;
		__u8 use_target_vtl : 1;
		__u8 reserved_z : 3;
	};
} __packed;

/* Note: not in hvgdk_mini.h */
#if defined(__x86_64__)
#define HV_SUPPORTS_REGISTER_DELIVERABILITY_NOTIFICATIONS
#endif

union hv_register_vsm_partition_config {
	__u64 as_u64;
	struct {
		__u64 enable_vtl_protection : 1;
		__u64 default_vtl_protection_mask : 4;
		__u64 zero_memory_on_reset : 1;
		__u64 deny_lower_vtl_startup : 1;
		__u64 intercept_acceptance : 1;
		__u64 intercept_enable_vtl_protection : 1;
		__u64 intercept_vp_startup : 1;
		__u64 intercept_cpuid_unimplemented : 1;
		__u64 intercept_unrecoverable_exception : 1;
		__u64 intercept_page : 1;
		__u64 intercept_restore_partition_time: 1;
		__u64 intercept_not_present: 1;
		__u64 mbz : 49;
	};
};

struct hv_nested_enlightenments_control {
	struct {
		__u32 directhypercall : 1;
		__u32 reserved : 31;
	} __packed features;
	struct {
		__u32 inter_partition_comm : 1;
		__u32 reserved : 31;
	} __packed hypercall_controls;
} __packed;

/* Define virtual processor assist page structure. */
struct hv_vp_assist_page {
	__u32 apic_assist;
	__u32 reserved1;
	__u32 vtl_entry_reason;
	__u32 vtl_reserved;
	__u64 vtl_ret_x64rax;
	__u64 vtl_ret_x64rcx;
	struct hv_nested_enlightenments_control nested_control;
	__u8 enlighten_vmentry;
	__u8 reserved2[7];
	__u64 current_nested_vmcs;
	__u8 synthetic_time_unhalted_timer_expired;
	__u8 reserved3[7];
	__u8 virtualization_fault_information[40];
	__u8 reserved4[8];
	__u8 intercept_message[256];
	__u8 vtl_ret_actions[256];
} __packed;

enum hv_register_name {
	/* Suspend Registers */
	HV_REGISTER_EXPLICIT_SUSPEND		= 0x00000000,
	HV_REGISTER_INTERCEPT_SUSPEND		= 0x00000001,
	HV_REGISTER_INSTRUCTION_EMULATION_HINTS	= 0x00000002,
	HV_REGISTER_DISPATCH_SUSPEND		= 0x00000003,
	HV_REGISTER_INTERNAL_ACTIVITY_STATE	= 0x00000004,

	/* Version */
	HV_REGISTER_HYPERVISOR_VERSION	= 0x00000100, /* 128-bit result same as CPUID 0x40000002 */

	/* Feature Access (registers are 128 bits) - same as CPUID 0x40000003 - 0x4000000B */
	HV_REGISTER_PRIVILEGES_AND_FEATURES_INFO	= 0x00000200,
	HV_REGISTER_FEATURES_INFO			= 0x00000201,
	HV_REGISTER_IMPLEMENTATION_LIMITS_INFO		= 0x00000202,
	HV_REGISTER_HARDWARE_FEATURES_INFO		= 0x00000203,
	HV_REGISTER_CPU_MANAGEMENT_FEATURES_INFO	= 0x00000204,
	HV_REGISTER_SVM_FEATURES_INFO			= 0x00000205,
	HV_REGISTER_SKIP_LEVEL_FEATURES_INFO		= 0x00000206,
	HV_REGISTER_NESTED_VIRT_FEATURES_INFO		= 0x00000207,
	HV_REGISTER_IPT_FEATURES_INFO			= 0x00000208,

	/* Guest Crash Registers */
	HV_REGISTER_GUEST_CRASH_P0	= 0x00000210,
	HV_REGISTER_GUEST_CRASH_P1	= 0x00000211,
	HV_REGISTER_GUEST_CRASH_P2	= 0x00000212,
	HV_REGISTER_GUEST_CRASH_P3	= 0x00000213,
	HV_REGISTER_GUEST_CRASH_P4	= 0x00000214,
	HV_REGISTER_GUEST_CRASH_CTL	= 0x00000215,

	/* Power State Configuration */
	HV_REGISTER_POWER_STATE_CONFIG_C1	= 0x00000220,
	HV_REGISTER_POWER_STATE_TRIGGER_C1	= 0x00000221,
	HV_REGISTER_POWER_STATE_CONFIG_C2	= 0x00000222,
	HV_REGISTER_POWER_STATE_TRIGGER_C2	= 0x00000223,
	HV_REGISTER_POWER_STATE_CONFIG_C3	= 0x00000224,
	HV_REGISTER_POWER_STATE_TRIGGER_C3	= 0x00000225,

	/* Frequency Registers */
	HV_REGISTER_PROCESSOR_CLOCK_FREQUENCY	= 0x00000240,
	HV_REGISTER_INTERRUPT_CLOCK_FREQUENCY	= 0x00000241,

	/* Idle Register */
	HV_REGISTER_GUEST_IDLE	= 0x00000250,

	/* Guest Debug */
	HV_REGISTER_DEBUG_DEVICE_OPTIONS	= 0x00000260,

	/* Memory Zeroing Conrol Register */
	HV_REGISTER_MEMORY_ZEROING_CONTROL	= 0x00000270,

	/* Pending Event Register */
	HV_REGISTER_PENDING_EVENT0	= 0x00010004,
	HV_REGISTER_PENDING_EVENT1	= 0x00010005,
	HV_REGISTER_DELIVERABILITY_NOTIFICATIONS	= 0x00010006,

	/* Misc */
	HV_REGISTER_VP_RUNTIME			= 0x00090000,
	HV_REGISTER_GUEST_OS_ID			= 0x00090002,
	HV_REGISTER_VP_INDEX			= 0x00090003,
	HV_REGISTER_TIME_REF_COUNT		= 0x00090004,
	HV_REGISTER_CPU_MANAGEMENT_VERSION	= 0x00090007,
	HV_REGISTER_VP_ASSIST_PAGE		= 0x00090013,
	HV_REGISTER_VP_ROOT_SIGNAL_COUNT	= 0x00090014,
	HV_REGISTER_REFERENCE_TSC		= 0x00090017,

	/* Performance statistics Registers */
	HV_REGISTER_STATS_PARTITION_RETAIL	= 0x00090020,
	HV_REGISTER_STATS_PARTITION_INTERNAL	= 0x00090021,
	HV_REGISTER_STATS_VP_RETAIL		= 0x00090022,
	HV_REGISTER_STATS_VP_INTERNAL		= 0x00090023,

	HV_REGISTER_NESTED_VP_INDEX	= 0x00091003,

	/* Hypervisor-defined Registers (Synic) */
	HV_REGISTER_SINT0	= 0x000A0000,
	HV_REGISTER_SINT1	= 0x000A0001,
	HV_REGISTER_SINT2	= 0x000A0002,
	HV_REGISTER_SINT3	= 0x000A0003,
	HV_REGISTER_SINT4	= 0x000A0004,
	HV_REGISTER_SINT5	= 0x000A0005,
	HV_REGISTER_SINT6	= 0x000A0006,
	HV_REGISTER_SINT7	= 0x000A0007,
	HV_REGISTER_SINT8	= 0x000A0008,
	HV_REGISTER_SINT9	= 0x000A0009,
	HV_REGISTER_SINT10	= 0x000A000A,
	HV_REGISTER_SINT11	= 0x000A000B,
	HV_REGISTER_SINT12	= 0x000A000C,
	HV_REGISTER_SINT13	= 0x000A000D,
	HV_REGISTER_SINT14	= 0x000A000E,
	HV_REGISTER_SINT15	= 0x000A000F,
	HV_REGISTER_SCONTROL	= 0x000A0010,
	HV_REGISTER_SVERSION	= 0x000A0011,
	HV_REGISTER_SIEFP	= 0x000A0012,
	HV_REGISTER_SIMP	= 0x000A0013,
	HV_REGISTER_EOM		= 0x000A0014,
	HV_REGISTER_SIRBP	= 0x000A0015,

	HV_REGISTER_NESTED_SINT0	= 0x000A1000,
	HV_REGISTER_NESTED_SINT1	= 0x000A1001,
	HV_REGISTER_NESTED_SINT2	= 0x000A1002,
	HV_REGISTER_NESTED_SINT3	= 0x000A1003,
	HV_REGISTER_NESTED_SINT4	= 0x000A1004,
	HV_REGISTER_NESTED_SINT5	= 0x000A1005,
	HV_REGISTER_NESTED_SINT6	= 0x000A1006,
	HV_REGISTER_NESTED_SINT7	= 0x000A1007,
	HV_REGISTER_NESTED_SINT8	= 0x000A1008,
	HV_REGISTER_NESTED_SINT9	= 0x000A1009,
	HV_REGISTER_NESTED_SINT10	= 0x000A100A,
	HV_REGISTER_NESTED_SINT11	= 0x000A100B,
	HV_REGISTER_NESTED_SINT12	= 0x000A100C,
	HV_REGISTER_NESTED_SINT13	= 0x000A100D,
	HV_REGISTER_NESTED_SINT14	= 0x000A100E,
	HV_REGISTER_NESTED_SINT15	= 0x000A100F,
	HV_REGISTER_NESTED_SCONTROL	= 0x000A1010,
	HV_REGISTER_NESTED_SVERSION	= 0x000A1011,
	HV_REGISTER_NESTED_SIFP		= 0x000A1012,
	HV_REGISTER_NESTED_SIPP		= 0x000A1013,
	HV_REGISTER_NESTED_EOM		= 0x000A1014,
	HV_REGISTER_NESTED_SIRBP	= 0x000a1015,


	/* Hypervisor-defined Registers (Synthetic Timers) */
	HV_REGISTER_STIMER0_CONFIG		= 0x000B0000,
	HV_REGISTER_STIMER0_COUNT		= 0x000B0001,
	HV_REGISTER_STIMER1_CONFIG		= 0x000B0002,
	HV_REGISTER_STIMER1_COUNT		= 0x000B0003,
	HV_REGISTER_STIMER2_CONFIG		= 0x000B0004,
	HV_REGISTER_STIMER2_COUNT		= 0x000B0005,
	HV_REGISTER_STIMER3_CONFIG		= 0x000B0006,
	HV_REGISTER_STIMER3_COUNT		= 0x000B0007,
	HV_REGISTER_STIME_UNHALTED_TIMER_CONFIG	= 0x000B0100,
	HV_REGISTER_STIME_UNHALTED_TIMER_COUNT	= 0x000b0101,

	/* Synthetic VSM registers */

	/* 0x000D0000-1 are available for future use. */
	HV_REGISTER_VSM_CODE_PAGE_OFFSETS	= 0x000D0002,
	HV_REGISTER_VSM_VP_STATUS		= 0x000D0003,
	HV_REGISTER_VSM_PARTITION_STATUS	= 0x000D0004,
	HV_REGISTER_VSM_VINA			= 0x000D0005,
	HV_REGISTER_VSM_CAPABILITIES		= 0x000D0006,
	HV_REGISTER_VSM_PARTITION_CONFIG	= 0x000D0007,

	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0	= 0x000D0010,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL1	= 0x000D0011,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL2	= 0x000D0012,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL3	= 0x000D0013,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL4	= 0x000D0014,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL5	= 0x000D0015,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL6	= 0x000D0016,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL7	= 0x000D0017,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL8	= 0x000D0018,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL9	= 0x000D0019,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL10	= 0x000D001A,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL11	= 0x000D001B,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL12	= 0x000D001C,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL13	= 0x000D001D,
	HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14	= 0x000D001E,

	HV_REGISTER_VSM_VP_WAIT_FOR_TLB_LOCK	= 0x000D0020,

	HV_REGISTER_ISOLATION_CAPABILITIES	= 0x000D0100,

#if defined(__x86_64__)
	/* Pending Interruption Register */
	HV_REGISTER_PENDING_INTERRUPTION		= 0x00010002,

	/* Interrupt State register */
	HV_REGISTER_INTERRUPT_STATE			= 0x00010003,

	/* Interruptible notification register */
	HV_X64_REGISTER_DELIVERABILITY_NOTIFICATIONS	= 0x00010006,

	/* Pending debug exceptions register */
	HV_X64_REGISTER_PENDING_DEBUG_EXCEPTION		= 0x00010007,

	/* X64 User-Mode Registers */
	HV_X64_REGISTER_RAX	= 0x00020000,
	HV_X64_REGISTER_RCX	= 0x00020001,
	HV_X64_REGISTER_RDX	= 0x00020002,
	HV_X64_REGISTER_RBX	= 0x00020003,
	HV_X64_REGISTER_RSP	= 0x00020004,
	HV_X64_REGISTER_RBP	= 0x00020005,
	HV_X64_REGISTER_RSI	= 0x00020006,
	HV_X64_REGISTER_RDI	= 0x00020007,
	HV_X64_REGISTER_R8	= 0x00020008,
	HV_X64_REGISTER_R9	= 0x00020009,
	HV_X64_REGISTER_R10	= 0x0002000A,
	HV_X64_REGISTER_R11	= 0x0002000B,
	HV_X64_REGISTER_R12	= 0x0002000C,
	HV_X64_REGISTER_R13	= 0x0002000D,
	HV_X64_REGISTER_R14	= 0x0002000E,
	HV_X64_REGISTER_R15	= 0x0002000F,
	HV_X64_REGISTER_RIP	= 0x00020010,
	HV_X64_REGISTER_RFLAGS	= 0x00020011,

	/* X64 Floating Point and Vector Registers */
	HV_X64_REGISTER_XMM0			= 0x00030000,
	HV_X64_REGISTER_XMM1			= 0x00030001,
	HV_X64_REGISTER_XMM2			= 0x00030002,
	HV_X64_REGISTER_XMM3			= 0x00030003,
	HV_X64_REGISTER_XMM4			= 0x00030004,
	HV_X64_REGISTER_XMM5			= 0x00030005,
	HV_X64_REGISTER_XMM6			= 0x00030006,
	HV_X64_REGISTER_XMM7			= 0x00030007,
	HV_X64_REGISTER_XMM8			= 0x00030008,
	HV_X64_REGISTER_XMM9			= 0x00030009,
	HV_X64_REGISTER_XMM10			= 0x0003000A,
	HV_X64_REGISTER_XMM11			= 0x0003000B,
	HV_X64_REGISTER_XMM12			= 0x0003000C,
	HV_X64_REGISTER_XMM13			= 0x0003000D,
	HV_X64_REGISTER_XMM14			= 0x0003000E,
	HV_X64_REGISTER_XMM15			= 0x0003000F,
	HV_X64_REGISTER_FP_MMX0			= 0x00030010,
	HV_X64_REGISTER_FP_MMX1			= 0x00030011,
	HV_X64_REGISTER_FP_MMX2			= 0x00030012,
	HV_X64_REGISTER_FP_MMX3			= 0x00030013,
	HV_X64_REGISTER_FP_MMX4			= 0x00030014,
	HV_X64_REGISTER_FP_MMX5			= 0x00030015,
	HV_X64_REGISTER_FP_MMX6			= 0x00030016,
	HV_X64_REGISTER_FP_MMX7			= 0x00030017,
	HV_X64_REGISTER_FP_CONTROL_STATUS	= 0x00030018,
	HV_X64_REGISTER_XMM_CONTROL_STATUS	= 0x00030019,

	/* X64 Control Registers */
	HV_X64_REGISTER_CR0	= 0x00040000,
	HV_X64_REGISTER_CR2	= 0x00040001,
	HV_X64_REGISTER_CR3	= 0x00040002,
	HV_X64_REGISTER_CR4	= 0x00040003,
	HV_X64_REGISTER_CR8	= 0x00040004,
	HV_X64_REGISTER_XFEM	= 0x00040005,

	/* X64 Intermediate Control Registers */
	HV_X64_REGISTER_INTERMEDIATE_CR0	= 0x00041000,
	HV_X64_REGISTER_INTERMEDIATE_CR4	= 0x00041003,
	HV_X64_REGISTER_INTERMEDIATE_CR8	= 0x00041004,

	/* X64 Debug Registers */
	HV_X64_REGISTER_DR0	= 0x00050000,
	HV_X64_REGISTER_DR1	= 0x00050001,
	HV_X64_REGISTER_DR2	= 0x00050002,
	HV_X64_REGISTER_DR3	= 0x00050003,
	HV_X64_REGISTER_DR6	= 0x00050004,
	HV_X64_REGISTER_DR7	= 0x00050005,

	/* X64 Segment Registers */
	HV_X64_REGISTER_ES	= 0x00060000,
	HV_X64_REGISTER_CS	= 0x00060001,
	HV_X64_REGISTER_SS	= 0x00060002,
	HV_X64_REGISTER_DS	= 0x00060003,
	HV_X64_REGISTER_FS	= 0x00060004,
	HV_X64_REGISTER_GS	= 0x00060005,
	HV_X64_REGISTER_LDTR	= 0x00060006,
	HV_X64_REGISTER_TR	= 0x00060007,

	/* X64 Table Registers */
	HV_X64_REGISTER_IDTR	= 0x00070000,
	HV_X64_REGISTER_GDTR	= 0x00070001,

	/* X64 Virtualized MSRs */
	HV_X64_REGISTER_TSC		= 0x00080000,
	HV_X64_REGISTER_EFER		= 0x00080001,
	HV_X64_REGISTER_KERNEL_GS_BASE	= 0x00080002,
	HV_X64_REGISTER_APIC_BASE	= 0x00080003,
	HV_X64_REGISTER_PAT		= 0x00080004,
	HV_X64_REGISTER_SYSENTER_CS	= 0x00080005,
	HV_X64_REGISTER_SYSENTER_EIP	= 0x00080006,
	HV_X64_REGISTER_SYSENTER_ESP	= 0x00080007,
	HV_X64_REGISTER_STAR		= 0x00080008,
	HV_X64_REGISTER_LSTAR		= 0x00080009,
	HV_X64_REGISTER_CSTAR		= 0x0008000A,
	HV_X64_REGISTER_SFMASK		= 0x0008000B,
	HV_X64_REGISTER_INITIAL_APIC_ID	= 0x0008000C,

	/* X64 Cache control MSRs */
	HV_X64_REGISTER_MSR_MTRR_CAP		= 0x0008000D,
	HV_X64_REGISTER_MSR_MTRR_DEF_TYPE	= 0x0008000E,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0	= 0x00080010,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1	= 0x00080011,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2	= 0x00080012,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3	= 0x00080013,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4	= 0x00080014,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5	= 0x00080015,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6	= 0x00080016,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7	= 0x00080017,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8	= 0x00080018,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9	= 0x00080019,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA	= 0x0008001A,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB	= 0x0008001B,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC	= 0x0008001C,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASED	= 0x0008001D,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE	= 0x0008001E,
	HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF	= 0x0008001F,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0	= 0x00080040,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1	= 0x00080041,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2	= 0x00080042,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3	= 0x00080043,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4	= 0x00080044,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5	= 0x00080045,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6	= 0x00080046,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7	= 0x00080047,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8	= 0x00080048,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9	= 0x00080049,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA	= 0x0008004A,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB	= 0x0008004B,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC	= 0x0008004C,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD	= 0x0008004D,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE	= 0x0008004E,
	HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF	= 0x0008004F,
	HV_X64_REGISTER_MSR_MTRR_FIX64K00000	= 0x00080070,
	HV_X64_REGISTER_MSR_MTRR_FIX16K80000	= 0x00080071,
	HV_X64_REGISTER_MSR_MTRR_FIX16KA0000	= 0x00080072,
	HV_X64_REGISTER_MSR_MTRR_FIX4KC0000	= 0x00080073,
	HV_X64_REGISTER_MSR_MTRR_FIX4KC8000	= 0x00080074,
	HV_X64_REGISTER_MSR_MTRR_FIX4KD0000	= 0x00080075,
	HV_X64_REGISTER_MSR_MTRR_FIX4KD8000	= 0x00080076,
	HV_X64_REGISTER_MSR_MTRR_FIX4KE0000	= 0x00080077,
	HV_X64_REGISTER_MSR_MTRR_FIX4KE8000	= 0x00080078,
	HV_X64_REGISTER_MSR_MTRR_FIX4KF0000	= 0x00080079,
	HV_X64_REGISTER_MSR_MTRR_FIX4KF8000	= 0x0008007A,

	HV_X64_REGISTER_TSC_AUX		= 0x0008007B,
	HV_X64_REGISTER_BNDCFGS		= 0x0008007C,
	HV_X64_REGISTER_DEBUG_CTL	= 0x0008007D,

	/* Available */
	HV_X64_REGISTER_AVAILABLE0008007E	= 0x0008007E,
	HV_X64_REGISTER_AVAILABLE0008007F	= 0x0008007F,

	HV_X64_REGISTER_SGX_LAUNCH_CONTROL0	= 0x00080080,
	HV_X64_REGISTER_SGX_LAUNCH_CONTROL1	= 0x00080081,
	HV_X64_REGISTER_SGX_LAUNCH_CONTROL2	= 0x00080082,
	HV_X64_REGISTER_SGX_LAUNCH_CONTROL3	= 0x00080083,
	HV_X64_REGISTER_SPEC_CTRL		= 0x00080084,
	HV_X64_REGISTER_PRED_CMD		= 0x00080085,
	HV_X64_REGISTER_VIRT_SPEC_CTRL		= 0x00080086,
	HV_X64_REGISTER_TSC_ADJUST		= 0x00080096,

	/* Other MSRs */
	HV_X64_REGISTER_MSR_IA32_MISC_ENABLE		= 0x000800A0,
	HV_X64_REGISTER_IA32_FEATURE_CONTROL		= 0x000800A1,
	HV_X64_REGISTER_IA32_VMX_BASIC			= 0x000800A2,
	HV_X64_REGISTER_IA32_VMX_PINBASED_CTLS		= 0x000800A3,
	HV_X64_REGISTER_IA32_VMX_PROCBASED_CTLS		= 0x000800A4,
	HV_X64_REGISTER_IA32_VMX_EXIT_CTLS		= 0x000800A5,
	HV_X64_REGISTER_IA32_VMX_ENTRY_CTLS		= 0x000800A6,
	HV_X64_REGISTER_IA32_VMX_MISC			= 0x000800A7,
	HV_X64_REGISTER_IA32_VMX_CR0_FIXED0		= 0x000800A8,
	HV_X64_REGISTER_IA32_VMX_CR0_FIXED1		= 0x000800A9,
	HV_X64_REGISTER_IA32_VMX_CR4_FIXED0		= 0x000800AA,
	HV_X64_REGISTER_IA32_VMX_CR4_FIXED1		= 0x000800AB,
	HV_X64_REGISTER_IA32_VMX_VMCS_ENUM		= 0x000800AC,
	HV_X64_REGISTER_IA32_VMX_PROCBASED_CTLS2	= 0x000800AD,
	HV_X64_REGISTER_IA32_VMX_EPT_VPID_CAP		= 0x000800AE,
	HV_X64_REGISTER_IA32_VMX_TRUE_PINBASED_CTLS	= 0x000800AF,
	HV_X64_REGISTER_IA32_VMX_TRUE_PROCBASED_CTLS	= 0x000800B0,
	HV_X64_REGISTER_IA32_VMX_TRUE_EXIT_CTLS		= 0x000800B1,
	HV_X64_REGISTER_IA32_VMX_TRUE_ENTRY_CTLS	= 0x000800B2,

	/* Performance monitoring MSRs */
	HV_X64_REGISTER_PERF_GLOBAL_CTRL	= 0x00081000,
	HV_X64_REGISTER_PERF_GLOBAL_STATUS	= 0x00081001,
	HV_X64_REGISTER_PERF_GLOBAL_IN_USE	= 0x00081002,
	HV_X64_REGISTER_FIXED_CTR_CTRL		= 0x00081003,
	HV_X64_REGISTER_DS_AREA			= 0x00081004,
	HV_X64_REGISTER_PEBS_ENABLE		= 0x00081005,
	HV_X64_REGISTER_PEBS_LD_LAT		= 0x00081006,
	HV_X64_REGISTER_PEBS_FRONTEND		= 0x00081007,
	HV_X64_REGISTER_PERF_EVT_SEL0		= 0x00081100,
	HV_X64_REGISTER_PMC0			= 0x00081200,
	HV_X64_REGISTER_FIXED_CTR0		= 0x00081300,

	HV_X64_REGISTER_LBR_TOS		= 0x00082000,
	HV_X64_REGISTER_LBR_SELECT	= 0x00082001,
	HV_X64_REGISTER_LER_FROM_LIP	= 0x00082002,
	HV_X64_REGISTER_LER_TO_LIP	= 0x00082003,
	HV_X64_REGISTER_LBR_FROM0	= 0x00082100,
	HV_X64_REGISTER_LBR_TO0		= 0x00082200,
	HV_X64_REGISTER_LBR_INFO0	= 0x00083300,

	/* Intel processor trace MSRs */
	HV_X64_REGISTER_RTIT_CTL		= 0x00081008,
	HV_X64_REGISTER_RTIT_STATUS		= 0x00081009,
	HV_X64_REGISTER_RTIT_OUTPUT_BASE	= 0x0008100A,
	HV_X64_REGISTER_RTIT_OUTPUT_MASK_PTRS	= 0x0008100B,
	HV_X64_REGISTER_RTIT_CR3_MATCH		= 0x0008100C,
	HV_X64_REGISTER_RTIT_ADDR0A		= 0x00081400,

	/* RtitAddr0A/B - RtitAddr3A/B occupy 0x00081400-0x00081407. */

	/* X64 Apic registers. These match the equivalent x2APIC MSR offsets. */
	HV_X64_REGISTER_APIC_ID		= 0x00084802,
	HV_X64_REGISTER_APIC_VERSION	= 0x00084803,

	/* Hypervisor-defined registers (Misc) */
	HV_X64_REGISTER_HYPERCALL	= 0x00090001,

	/* X64 Virtual APIC registers synthetic MSRs */
	HV_X64_REGISTER_SYNTHETIC_EOI	= 0x00090010,
	HV_X64_REGISTER_SYNTHETIC_ICR	= 0x00090011,
	HV_X64_REGISTER_SYNTHETIC_TPR	= 0x00090012,

	HV_X64_REGISTER_REG_PAGE	= 0x0009001C,
	HV_X64_REGISTER_GHCB		= 0x00090019,

	/* Partition Timer Assist Registers */
	HV_X64_REGISTER_EMULATED_TIMER_PERIOD	= 0x00090030,
	HV_X64_REGISTER_EMULATED_TIMER_CONTROL	= 0x00090031,
	HV_X64_REGISTER_PM_TIMER_ASSIST		= 0x00090032,

	/* AMD SEV SNP configuration register */
	HV_X64_REGISTER_SEV_CONTROL		= 0x00090040,
	HV_X64_REGISTER_SEV_GHCB_GPA		= 0x00090041,
	HV_X64_REGISTER_SEV_DOORBELL_GPA	= 0x00090042,

	/* Intercept Control Registers */
	HV_X64_REGISTER_CR_INTERCEPT_CONTROL			= 0x000E0000,
	HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK			= 0x000E0001,
	HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK			= 0x000E0002,
	HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK	= 0x000E0003,

#elif defined(__aarch64__)
	/* TODO */
#endif
};


/*
 * Arch compatibility regs for use with hv_set/get_register
 * NOTE: not really in hyperv headers
 */
#if defined(__x86_64__)

/*
 * To support arch-generic code calling hv_set/get_register:
 * - On x86, HV_MSR_ indicates an MSR accessed via rdmsrl/wrmsrl
 * - On ARM, HV_MSR_ indicates a VP register accessed via hypercall
 */
#define HV_MSR_CRASH_P0		(HV_X64_MSR_CRASH_P0)
#define HV_MSR_CRASH_P1		(HV_X64_MSR_CRASH_P1)
#define HV_MSR_CRASH_P2		(HV_X64_MSR_CRASH_P2)
#define HV_MSR_CRASH_P3		(HV_X64_MSR_CRASH_P3)
#define HV_MSR_CRASH_P4		(HV_X64_MSR_CRASH_P4)
#define HV_MSR_CRASH_CTL	(HV_X64_MSR_CRASH_CTL)

#define HV_MSR_VP_INDEX		(HV_X64_MSR_VP_INDEX)
#define HV_MSR_TIME_REF_COUNT	(HV_X64_MSR_TIME_REF_COUNT)
#define HV_MSR_REFERENCE_TSC	(HV_X64_MSR_REFERENCE_TSC)

#define HV_MSR_SINT0		(HV_X64_MSR_SINT0)
#define HV_MSR_SVERSION		(HV_X64_MSR_SVERSION)
#define HV_MSR_SCONTROL		(HV_X64_MSR_SCONTROL)
#define HV_MSR_SIEFP		(HV_X64_MSR_SIEFP)
#define HV_MSR_SIMP		(HV_X64_MSR_SIMP)
#define HV_MSR_EOM		(HV_X64_MSR_EOM)
#define HV_MSR_SIRBP		(HV_X64_MSR_SIRBP)

#define HV_MSR_NESTED_SCONTROL	(HV_X64_MSR_NESTED_SCONTROL)
#define HV_MSR_NESTED_SVERSION	(HV_X64_MSR_NESTED_SVERSION)
#define HV_MSR_NESTED_SIEFP	(HV_X64_MSR_NESTED_SIEFP)
#define HV_MSR_NESTED_SIMP	(HV_X64_MSR_NESTED_SIMP)
#define HV_MSR_NESTED_EOM	(HV_X64_MSR_NESTED_EOM)
#define HV_MSR_NESTED_SINT0	(HV_X64_MSR_NESTED_SINT0)

#define HV_MSR_STIMER0_CONFIG	(HV_X64_MSR_STIMER0_CONFIG)
#define HV_MSR_STIMER0_COUNT	(HV_X64_MSR_STIMER0_COUNT)

/* x86 supports nested virtualization */
#define HV_SUPPORTS_NESTED

#else /* __x86_64__ */

#define HV_MSR_CRASH_P0		(HV_REGISTER_GUEST_CRASH_P0)
#define HV_MSR_CRASH_P1		(HV_REGISTER_GUEST_CRASH_P1)
#define HV_MSR_CRASH_P2		(HV_REGISTER_GUEST_CRASH_P2)
#define HV_MSR_CRASH_P3		(HV_REGISTER_GUEST_CRASH_P3)
#define HV_MSR_CRASH_P4		(HV_REGISTER_GUEST_CRASH_P4)
#define HV_MSR_CRASH_CTL	(HV_REGISTER_GUEST_CRASH_CTL)

#define HV_MSR_VP_INDEX		(HV_REGISTER_VP_INDEX)
#define HV_MSR_TIME_REF_COUNT	(HV_REGISTER_TIME_REF_COUNT)
#define HV_MSR_REFERENCE_TSC	(HV_REGISTER_REFERENCE_TSC)

#define HV_MSR_SINT0		(HV_REGISTER_SINT0)
#define HV_MSR_SCONTROL		(HV_REGISTER_SCONTROL)
#define HV_MSR_SIEFP		(HV_REGISTER_SIEFP)
#define HV_MSR_SIMP		(HV_REGISTER_SIMP)
#define HV_MSR_EOM		(HV_REGISTER_EOM)
#define HV_MSR_SIRBP		(HV_REGISTER_SIRBP)

#define HV_MSR_STIMER0_CONFIG	(HV_REGISTER_STIMER0_CONFIG)
#define HV_MSR_STIMER0_COUNT	(HV_REGISTER_STIMER0_COUNT)

#endif

/* General Hypervisor Register Content Definitions */

union hv_explicit_suspend_register {
	__u64 as_uint64;
	struct {
		__u64 suspended : 1;
		__u64 reserved : 63;
	} __packed;
};

union hv_intercept_suspend_register {
	__u64 as_uint64;
	struct {
		__u64 suspended : 1;
		__u64 reserved : 63;
	} __packed;
};

union hv_dispatch_suspend_register {
	__u64 as_uint64;
	struct {
		__u64 suspended : 1;
		__u64 reserved : 63;
	} __packed;
};

union hv_internal_activity_register {
	__u64 as_uint64;

	struct {
		__u64 startup_suspend : 1;
		__u64 halt_suspend : 1;
		__u64 idle_suspend : 1;
		__u64 rsvd_z : 61;
	} __packed;
};

union hv_x64_interrupt_state_register {
	__u64 as_uint64;
	struct {
		__u64 interrupt_shadow : 1;
		__u64 nmi_masked : 1;
		__u64 reserved : 62;
	} __packed;
};

#if defined(__aarch64__)
/* HvGetVpRegisters returns an array of these output elements */
struct hv_get_vp_registers_output {
	union {
		struct {
			__u32 a;
			__u32 b;
			__u32 c;
			__u32 d;
		} as32 __packed;
		struct {
			__u64 low;
			__u64 high;
		} as64 __packed;
	};
};

#define HV_ARM64_PENDING_EVENT_HEADER \
	__u8 event_pending : 1; \
	__u8 event_type : 3; \
	__u8 reserved : 4

union hv_arm64_pending_synthetic_exception_event {
	__u64 as_uint64[2];
	struct {
		HV_ARM64_PENDING_EVENT_HEADER;

		__u32 exception_type;
		__u64 context;
	} __packed;
};

union hv_arm64_interrupt_state_register {
	__u64 as_uint64;
	struct {
		__u64 interrupt_shadow : 1;
		__u64 reserved : 63;
	} __packed;
};

enum hv_arm64_pending_interruption_type {
	HV_ARM64_PENDING_INTERRUPT = 0,
	HV_ARM64_PENDING_EXCEPTION = 1
};

union hv_arm64_pending_interruption_register {
	__u64 as_uint64;
	struct {
		__u64 interruption_pending : 1;
		__u64 interruption_type : 1;
		__u64 reserved : 30;
		__u64 error_code : 32;
	} __packed;
};

#else /* defined(__aarch64__) */

union hv_x64_pending_exception_event {
	__u64 as_uint64[2];
	struct {
		__u32 event_pending : 1;
		__u32 event_type : 3;
		__u32 reserved0 : 4;
		__u32 deliver_error_code : 1;
		__u32 reserved1 : 7;
		__u32 vector : 16;
		__u32 error_code;
		__u64 exception_parameter;
	} __packed;
};

union hv_x64_pending_virtualization_fault_event {
	__u64 as_uint64[2];
	struct {
		__u32 event_pending : 1;
		__u32 event_type : 3;
		__u32 reserved0 : 4;
		__u32 reserved1 : 8;
		__u32 parameter0 : 16;
		__u32 code;
		__u64 parameter1;
	} __packed;
};

// bunch of stuff in between

union hv_x64_pending_interruption_register {
	__u64 as_uint64;
	struct {
		__u32 interruption_pending : 1;
		__u32 interruption_type : 3;
		__u32 deliver_error_code : 1;
		__u32 instruction_length : 4;
		__u32 nested_event : 1;
		__u32 reserved : 6;
		__u32 interruption_vector : 16;
		__u32 error_code;
	} __packed;
};

#define HV_SUPPORTS_SEV_SNP_GUESTS

union hv_x64_register_sev_control {
	__u64 as_uint64;
	struct {
		__u64 enable_encrypted_state : 1;
		__u64 reserved_z : 11;
		__u64 vmsa_gpa_page_number : 52;
	} __packed;
};

#endif /* defined(__aarch64__) */

union hv_register_value {
	struct hv_u128 reg128;
	__u64 reg64;
	__u32 reg32;
	__u16 reg16;
	__u8 reg8;

#if defined(__x86_64__)
	union hv_x64_fp_register fp;
	union hv_x64_fp_control_status_register fp_control_status;
	union hv_x64_xmm_control_status_register xmm_control_status;
	struct hv_x64_segment_register segment;
	struct hv_x64_table_register table;
#endif
	union hv_explicit_suspend_register explicit_suspend;
	union hv_intercept_suspend_register intercept_suspend;
	union hv_dispatch_suspend_register dispatch_suspend;
	union hv_internal_activity_register internal_activity;
#if defined(__x86_64__)
	union hv_x64_interrupt_state_register interrupt_state;
	union hv_x64_pending_interruption_register pending_interruption;
	union hv_x64_msr_npiep_config_contents npiep_config;
	union hv_x64_pending_exception_event pending_exception_event;
	union hv_x64_pending_virtualization_fault_event
		pending_virtualization_fault_event;
	union hv_x64_register_sev_control sev_control;
#elif defined(__aarch64__)
	union hv_arm64_pending_interruption_register pending_interruption;
	union hv_arm64_interrupt_state_register interrupt_state;
	union hv_arm64_pending_synthetic_exception_event
		pending_synthetic_exception_event;
#endif
};

struct hv_register_assoc {
	__u32 name;			/* enum hv_register_name */
	__u32 reserved1;
	__u64 reserved2;
	union hv_register_value value;
} __packed;

struct hv_input_get_vp_registers {
	__u64 partition_id;
	__u32 vp_index;
	union hv_input_vtl input_vtl;
	__u8  rsvd_z8;
	__u16 rsvd_z16;
	__u32 names[];
} __packed;

struct hv_input_set_vp_registers {
	__u64 partition_id;
	__u32 vp_index;
	union hv_input_vtl input_vtl;
	__u8  rsvd_z8;
	__u16 rsvd_z16;
	struct hv_register_assoc elements[];
} __packed;

#define HV_UNMAP_GPA_LARGE_PAGE		0x2

/* HvCallSendSyntheticClusterIpi hypercall */
struct hv_send_ipi {	 /* HV_INPUT_SEND_SYNTHETIC_CLUSTER_IPI */
	__u32 vector;
	__u32 reserved;
	__u64 cpu_mask;
} __packed;

#if defined(__KERNEL__)
#if defined(__x86_64__)
union hv_msi_address_register { /* HV_MSI_ADDRESS */
	__u32 as_uint32;
	struct {
		__u32 reserved1:2;
		__u32 destination_mode:1;
		__u32 redirection_hint:1;
		__u32 reserved2:8;
		__u32 destination_id:8;
		__u32 msi_base:12;
	};
} __packed;

union hv_msi_data_register {	 /* HV_MSI_ENTRY.Data */
	__u32 as_uint32;
	struct {
		__u32 vector:8;
		__u32 delivery_mode:3;
		__u32 reserved1:3;
		__u32 level_assert:1;
		__u32 trigger_mode:1;
		__u32 reserved2:16;
	};
} __packed;

union hv_msi_entry {	 /* HV_MSI_ENTRY */

	__u64 as_uint64;
	struct {
		union hv_msi_address_register address;
		union hv_msi_data_register data;
	} __packed;
};

#elif defined(__aarch64__)

union hv_msi_entry {
	__u64 as_uint64[2];
	struct {
		__u64 address;
		__u32 data;
		__u32 reserved;
	} __packed;
};
#endif

union hv_ioapic_rte {
	__u64 as_uint64;

	struct {
		__u32 vector:8;
		__u32 delivery_mode:3;
		__u32 destination_mode:1;
		__u32 delivery_status:1;
		__u32 interrupt_polarity:1;
		__u32 remote_irr:1;
		__u32 trigger_mode:1;
		__u32 interrupt_mask:1;
		__u32 reserved1:15;

		__u32 reserved2:24;
		__u32 destination_id:8;
	};

	struct {
		__u32 low_uint32;
		__u32 high_uint32;
	};
} __packed;

enum hv_interrupt_source {	 /* HV_INTERRUPT_SOURCE */
	HV_INTERRUPT_SOURCE_MSI = 1, /* MSI and MSI-X */
	HV_INTERRUPT_SOURCE_IOAPIC,
};

struct hv_interrupt_entry {	 /* HV_INTERRUPT_ENTRY */
	__u32 source;
	__u32 reserved1;
	union {
		union hv_msi_entry msi_entry;
		union hv_ioapic_rte ioapic_rte;
	};
} __packed;

#define HV_DEVICE_INTERRUPT_TARGET_MULTICAST		1
#define HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET	2

struct hv_device_interrupt_target {	 /* HV_DEVICE_INTERRUPT_TARGET */
	__u32 vector;
	__u32 flags;		/* HV_DEVICE_INTERRUPT_TARGET_* above */
	union {
		__u64 vp_mask;
		struct hv_vpset vp_set;
	};
} __packed;

struct hv_retarget_device_interrupt {	 /* HV_INPUT_RETARGET_DEVICE_INTERRUPT */
	__u64 partition_id;		/* use "self" */
	__u64 device_id;
	struct hv_interrupt_entry int_entry;
	__u64 reserved2;
	struct hv_device_interrupt_target int_target;
} __packed __aligned(8);

#endif /* __KERNEL__ */

enum hv_intercept_type {
#if defined(__x86_64__)
	HV_INTERCEPT_TYPE_X64_IO_PORT			= 0X00000000,
	HV_INTERCEPT_TYPE_X64_MSR			= 0X00000001,
	HV_INTERCEPT_TYPE_X64_CPUID			= 0X00000002,
#endif
	HV_INTERCEPT_TYPE_EXCEPTION			= 0X00000003,
	/* Used to be HV_INTERCEPT_TYPE_REGISTER */
	HV_INTERCEPT_TYPE_RESERVED0			= 0X00000004,
	HV_INTERCEPT_TYPE_MMIO				= 0X00000005,
#if defined(__x86_64__)
	HV_INTERCEPT_TYPE_X64_GLOBAL_CPUID		= 0X00000006,
	HV_INTERCEPT_TYPE_X64_APIC_SMI			= 0X00000007,
#endif
	HV_INTERCEPT_TYPE_HYPERCALL			= 0X00000008,
#if defined(__x86_64__)
	HV_INTERCEPT_TYPE_X64_APIC_INIT_SIPI		= 0X00000009,
	HV_INTERCEPT_MC_UPDATE_PATCH_LEVEL_MSR_READ	= 0X0000000A,
	HV_INTERCEPT_TYPE_X64_APIC_WRITE		= 0X0000000B,
	HV_INTERCEPT_TYPE_X64_MSR_INDEX			= 0X0000000C,
#endif
	HV_INTERCEPT_TYPE_MAX,
	HV_INTERCEPT_TYPE_INVALID			= 0XFFFFFFFF,
};

union hv_intercept_parameters {
	/*  HV_INTERCEPT_PARAMETERS is defined to be an 8-byte field. */
	__u64 as_uint64;
#if defined(__x86_64__)
	/* HV_INTERCEPT_TYPE_X64_IO_PORT */
	__u16 io_port;
	/* HV_INTERCEPT_TYPE_X64_CPUID */
	__u32 cpuid_index;
	/* HV_INTERCEPT_TYPE_X64_APIC_WRITE */
	__u32 apic_write_mask;
	/* HV_INTERCEPT_TYPE_EXCEPTION */
	__u16 exception_vector;
	/* HV_INTERCEPT_TYPE_X64_MSR_INDEX */
	__u32 msr_index;
#endif
	/* N.B. Other intercept types do not have any parameters. */
};

/* Access types for the install intercept hypercall parameter */
#define HV_INTERCEPT_ACCESS_MASK_NONE		0x00
#define HV_INTERCEPT_ACCESS_MASK_READ		0X01
#define HV_INTERCEPT_ACCESS_MASK_WRITE		0x02
#define HV_INTERCEPT_ACCESS_MASK_EXECUTE	0x04

struct hv_input_install_intercept {
	__u64 partition_id;
	__u32 access_type;	/* mask */
	__u32 intercept_type;	/* hv_intercept_type */
	union hv_intercept_parameters intercept_parameter;
} __packed;

/* Data structures for HVCALL_MMIO_READ and HVCALL_MMIO_WRITE */
#define HV_HYPERCALL_MMIO_MAX_DATA_LENGTH 64

struct hv_mmio_read_input { /* HV_INPUT_MEMORY_MAPPED_IO_READ */
	__u64 gpa;
	__u32 size;
	__u32 reserved;
} __packed;

struct hv_mmio_read_output {
	__u8 data[HV_HYPERCALL_MMIO_MAX_DATA_LENGTH];
} __packed;

struct hv_mmio_write_input {
	__u64 gpa;
	__u32 size;
	__u32 reserved;
	__u8 data[HV_HYPERCALL_MMIO_MAX_DATA_LENGTH];
} __packed;

enum hv_eventlog_type { /* HV_EVENTLOG_TYPE */
	HV_EVENT_LOG_TYPE_GLOBAL_SYSTEM_EVENTS	= 0x00000000,
	HV_EVENT_LOG_TYPE_LOCAL_DIAGNOSTICS	= 0x00000001,
	HV_EVENT_LOG_TYPE_SYSTEM_DIAGNOSTICS	= 0x00000002,
};

union hv_x64_register_sev_ghcb {
	__u64 as_uint64;
	struct {
		__u64 enabled:1;
		__u64 reservedz:11;
		__u64 page_number:52;
	} __packed;
};

union hv_x64_register_sev_hv_doorbell {
	__u64 as_uint64;
	struct {
		__u64 enabled:1;
		__u64 reservedz:11;
		__u64 page_number:52;
	} __packed;
};

/* Values for intercept_access_type field */
#define HV_INTERCEPT_ACCESS_READ 0
#define HV_INTERCEPT_ACCESS_WRITE 1
#define HV_INTERCEPT_ACCESS_EXECUTE 2

#endif /* _UAPI_HV_HVGDK_MINI_H */
