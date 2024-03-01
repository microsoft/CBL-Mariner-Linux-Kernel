/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file contains definitions from Hyper-V Hypervisor Top-Level Functional
 * Specification (TLFS):
 * https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
 */

#ifndef _ASM_GENERIC_HYPERV_TLFS_H
#define _ASM_GENERIC_HYPERV_TLFS_H

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/time64.h>

/*
 * While not explicitly listed in the TLFS, Hyper-V always runs with a page size
 * of 4096. These definitions are used when communicating with Hyper-V using
 * guest physical pages and guest physical page addresses, since the guest page
 * size may not be 4096 on all architectures.
 */
#define HV_HYP_PAGE_SHIFT      12
#define HV_HYP_PAGE_SIZE       BIT(HV_HYP_PAGE_SHIFT)
#define HV_HYP_PAGE_MASK       (~(HV_HYP_PAGE_SIZE - 1))

/*
 * Hyper-V provides two categories of flags relevant to guest VMs.  The
 * "Features" category indicates specific functionality that is available
 * to guests on this particular instance of Hyper-V. The "Features"
 * are presented in four groups, each of which is 32 bits. The group A
 * and B definitions are common across architectures and are listed here.
 * However, not all flags are relevant on all architectures.
 *
 * Groups C and D vary across architectures and are listed in the
 * architecture specific portion of hyperv-tlfs.h. Some of these flags exist
 * on multiple architectures, but the bit positions are different so they
 * cannot appear in the generic portion of hyperv-tlfs.h.
 *
 * The "Enlightenments" category provides recommendations on whether to use
 * specific enlightenments that are available. The Enlighenments are a single
 * group of 32 bits, but they vary across architectures and are listed in
 * the architecture specific portion of hyperv-tlfs.h.
 */

/*
 * Group A Features.
 */

/* VP Runtime register available */
#define HV_MSR_VP_RUNTIME_AVAILABLE		BIT(0)
/* Partition Reference Counter available*/
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		BIT(1)
/* Basic SynIC register available */
#define HV_MSR_SYNIC_AVAILABLE			BIT(2)
/* Synthetic Timer registers available */
#define HV_MSR_SYNTIMER_AVAILABLE		BIT(3)
/* Virtual APIC assist and VP assist page registers available */
#define HV_MSR_APIC_ACCESS_AVAILABLE		BIT(4)
/* Hypercall and Guest OS ID registers available*/
#define HV_MSR_HYPERCALL_AVAILABLE		BIT(5)
/* Access virtual processor index register available*/
#define HV_MSR_VP_INDEX_AVAILABLE		BIT(6)
/* Virtual system reset register available*/
#define HV_MSR_RESET_AVAILABLE			BIT(7)
/* Access statistics page registers available */
#define HV_MSR_STAT_PAGES_AVAILABLE		BIT(8)
/* Partition reference TSC register is available */
#define HV_MSR_REFERENCE_TSC_AVAILABLE		BIT(9)
/* Partition Guest IDLE register is available */
#define HV_MSR_GUEST_IDLE_AVAILABLE		BIT(10)
/* Partition local APIC and TSC frequency registers available */
#define HV_ACCESS_FREQUENCY_MSRS		BIT(11)
/* AccessReenlightenmentControls privilege */
#define HV_ACCESS_REENLIGHTENMENT		BIT(13)
/* AccessTscInvariantControls privilege */
#define HV_ACCESS_TSC_INVARIANT			BIT(15)

/*
 * Group B features.
 */
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

/*
 * Group D features
 */
#define HV_DEVICE_DOMAIN_AVAILABLE		BIT(24)
#define HV_S1_DEVICE_DOMAIN_AVAILABLE		BIT(25)


/*
 * TSC page layout.
 */
struct ms_hyperv_tsc_page {
	volatile u32 tsc_sequence;
	u32 reserved1;
	volatile u64 tsc_scale;
	volatile s64 tsc_offset;
} __packed;

union hv_reference_tsc_msr {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:11;
		u64 pfn:52;
	} __packed;
};

/*
 * The guest OS needs to register the guest ID with the hypervisor.
 * The guest ID is a 64 bit entity and the structure of this ID is
 * specified in the Hyper-V specification:
 *
 * msdn.microsoft.com/en-us/library/windows/hardware/ff542653%28v=vs.85%29.aspx
 *
 * While the current guideline does not specify how Linux guest ID(s)
 * need to be generated, our plan is to publish the guidelines for
 * Linux and other guest operating systems that currently are hosted
 * on Hyper-V. The implementation here conforms to this yet
 * unpublished guidelines.
 *
 *
 * Bit(s)
 * 63 - Indicates if the OS is Open Source or not; 1 is Open Source
 * 62:56 - Os Type; Linux is 0x100
 * 55:48 - Distro specific identification
 * 47:16 - Linux kernel version number
 * 15:0  - Distro specific identification
 *
 *
 */

#define HV_LINUX_VENDOR_ID              0x8100

/*
 * Crash notification flags.
 */
#define HV_CRASH_CTL_CRASH_NOTIFY_MSG		BIT_ULL(62)
#define HV_CRASH_CTL_CRASH_NOTIFY		BIT_ULL(63)

/* Declare the various hypercall operations. */
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE	0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST	0x0003
#define HVCALL_ENABLE_VP_VTL			0x000f
#define HVCALL_NOTIFY_LONG_SPIN_WAIT		0x0008
#define HVCALL_SEND_IPI				0x000b
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX	0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX	0x0014
#define HVCALL_SEND_IPI_EX			0x0015
#define HVCALL_GET_PARTITION_ID			0x0046
#define HVCALL_DEPOSIT_MEMORY			0x0048
#define HVCALL_CREATE_VP			0x004e
#define HVCALL_GET_VP_REGISTERS			0x0050
#define HVCALL_SET_VP_REGISTERS			0x0051
#define HVCALL_POST_MESSAGE			0x005c
#define HVCALL_SIGNAL_EVENT			0x005d
#define HVCALL_POST_DEBUG_DATA			0x0069
#define HVCALL_RETRIEVE_DEBUG_DATA		0x006a
#define HVCALL_RESET_DEBUG_SESSION		0x006b
#define HVCALL_ADD_LOGICAL_PROCESSOR		0x0076
#define HVCALL_MAP_DEVICE_INTERRUPT		0x007c
#define HVCALL_UNMAP_DEVICE_INTERRUPT		0x007d
#define HVCALL_RETARGET_INTERRUPT		0x007e
#define HVCALL_START_VP				0x0099
#define HVCALL_GET_VP_ID_FROM_APIC_ID		0x009a
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE 0x00af
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_LIST 0x00b0
#define HVCALL_MODIFY_SPARSE_GPA_PAGE_HOST_VISIBILITY 0x00db
#define HVCALL_CREATE_DEVICE_DOMAIN		0x00b1
#define HVCALL_ATTACH_DEVICE_DOMAIN		0x00b2
#define HVCALL_MAP_DEVICE_GPA_PAGES		0x00b3
#define HVCALL_UNMAP_DEVICE_GPA_PAGES		0x00b4
#define HVCALL_DETACH_DEVICE_DOMAIN		0x00c4
#define HVCALL_DELETE_DEVICE_DOMAIN		0x00c5
#define HVCALL_QUERY_DEVICE_DOMAIN		0x00c6
#define HVCALL_MAP_SPARSE_DEVICE_GPA_PAGES	0x00c7
#define HVCALL_UNMAP_SPARSE_DEVICE_GPA_PAGES	0x00c8
#define HVCALL_CONFIGURE_DEVICE_DOMAIN		0x00ce
#define HVCALL_FLUSH_DEVICE_DOMAIN		0x00d0
#define HVCALL_MAP_VP_STATE_PAGE		0x00e1
#define HVCALL_GET_VP_STATE			0x00e3
#define HVCALL_SET_VP_STATE			0x00e4

#define HVCALL_MMIO_READ			0x0106
#define HVCALL_MMIO_WRITE			0x0107

/* Extended hypercalls */
#define HV_EXT_CALL_QUERY_CAPABILITIES		0x8001
#define HV_EXT_CALL_MEMORY_HEAT_HINT		0x8003

#define HV_FLUSH_ALL_PROCESSORS			BIT(0)
#define HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES	BIT(1)
#define HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY	BIT(2)
#define HV_FLUSH_USE_EXTENDED_RANGE_FORMAT	BIT(3)

/* Extended capability bits */
#define HV_EXT_CAPABILITY_MEMORY_COLD_DISCARD_HINT BIT(8)

enum HV_GENERIC_SET_FORMAT {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};

#define HV_PARTITION_ID_SELF		((u64)-1)
#define HV_VP_INDEX_SELF		((u32)-2)

#define HV_HYPERCALL_RESULT_MASK	GENMASK_ULL(15, 0)
#define HV_HYPERCALL_FAST_BIT		BIT(16)
#define HV_HYPERCALL_VARHEAD_OFFSET	17
#define HV_HYPERCALL_VARHEAD_MASK	GENMASK_ULL(26, 17)
#define HV_HYPERCALL_RSVD0_MASK		GENMASK_ULL(31, 27)
#define HV_HYPERCALL_NESTED		BIT_ULL(31)
#define HV_HYPERCALL_REP_COMP_OFFSET	32
#define HV_HYPERCALL_REP_COMP_1		BIT_ULL(32)
#define HV_HYPERCALL_REP_COMP_MASK	GENMASK_ULL(43, 32)
#define HV_HYPERCALL_RSVD1_MASK		GENMASK_ULL(47, 44)
#define HV_HYPERCALL_REP_START_OFFSET	48
#define HV_HYPERCALL_REP_START_MASK	GENMASK_ULL(59, 48)
#define HV_HYPERCALL_RSVD2_MASK		GENMASK_ULL(63, 60)
#define HV_HYPERCALL_RSVD_MASK		(HV_HYPERCALL_RSVD0_MASK | \
					 HV_HYPERCALL_RSVD1_MASK | \
					 HV_HYPERCALL_RSVD2_MASK)

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

/* Define the number of synthetic interrupt sources. */
#define HV_SYNIC_SINT_COUNT		(16)
/* Define the expected SynIC version. */
#define HV_SYNIC_VERSION_1		(0x1)
/* Valid SynIC vectors are 16-255. */
#define HV_SYNIC_FIRST_VALID_VECTOR	(16)

#define HV_SYNIC_CONTROL_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIMP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIEFP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SINT_MASKED		(1ULL << 16)
#define HV_SYNIC_SINT_AUTO_EOI		(1ULL << 17)
#define HV_SYNIC_SINT_VECTOR_MASK	(0xFF)

#define HV_SYNIC_STIMER_COUNT		(4)

/* Define synthetic interrupt controller message constants. */
#define HV_MESSAGE_SIZE			(256)
#define HV_MESSAGE_PAYLOAD_BYTE_COUNT	(240)
#define HV_MESSAGE_PAYLOAD_QWORD_COUNT	(30)

/*
 * Define hypervisor message types. Some of the message types
 * are x86/x64 specific, but there's no good way to separate
 * them out into the arch-specific version of hyperv-tlfs.h
 * because C doesn't provide a way to extend enum types.
 * Keeping them all in the arch neutral hyperv-tlfs.h seems
 * the least messy compromise.
 */
enum hv_message_type {
	HVMSG_NONE			= 0x00000000,

	/* Memory access messages. */
	HVMSG_UNMAPPED_GPA		= 0x80000000,
	HVMSG_GPA_INTERCEPT		= 0x80000001,

	/* Timer notification messages. */
	HVMSG_TIMER_EXPIRED		= 0x80000010,

	/* Error messages. */
	HVMSG_INVALID_VP_REGISTER_VALUE	= 0x80000020,
	HVMSG_UNRECOVERABLE_EXCEPTION	= 0x80000021,
	HVMSG_UNSUPPORTED_FEATURE	= 0x80000022,

	/* Trace buffer complete messages. */
	HVMSG_EVENTLOG_BUFFERCOMPLETE	= 0x80000040,

	/* Platform-specific processor intercept messages. */
	HVMSG_X64_IOPORT_INTERCEPT	= 0x80010000,
	HVMSG_X64_MSR_INTERCEPT		= 0x80010001,
	HVMSG_X64_CPUID_INTERCEPT	= 0x80010002,
	HVMSG_X64_EXCEPTION_INTERCEPT	= 0x80010003,
	HVMSG_X64_APIC_EOI		= 0x80010004,
	HVMSG_X64_LEGACY_FP_ERROR	= 0x80010005
};

/* Define synthetic interrupt controller message flags. */
union hv_message_flags {
	__u8 asu8;
	struct {
		__u8 msg_pending:1;
		__u8 reserved:7;
	} __packed;
};

/* Define port identifier type. */
union hv_port_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	} __packed u;
};

/* Define synthetic interrupt controller message header. */
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

/* Define synthetic interrupt controller message format. */
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

/* Define timer message payload structure. */
struct hv_timer_message_payload {
	__u32 timer_index;
	__u32 reserved;
	__u64 expiration_time;	/* When the timer expired */
	__u64 delivery_time;	/* When the message was delivered */
} __packed;

/*
 * Synthetic timer configuration.
 */
union hv_stimer_config {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 periodic:1;
		u64 lazy:1;
		u64 auto_enable:1;
		u64 apic_vector:8;
		u64 direct_mode:1;
		u64 reserved_z0:3;
		u64 sintx:4;
		u64 reserved_z1:44;
	} __packed;
};

/* Define synthetic interrupt controller flag constants. */
#define HV_EVENT_FLAGS_COUNT        (256 * 8)
#define HV_EVENT_FLAGS_BYTE_COUNT   (256)
#define HV_EVENT_FLAGS32_COUNT  (256 / sizeof(__u32))

/* linux side we create long version of flags to use long bit ops on flags */
#define HV_EVENT_FLAGS_UL_COUNT  (256 / sizeof(ulong))

/* Define the synthetic interrupt controller event flags format. */
union hv_synic_event_flags {
	unsigned char flags8[HV_EVENT_FLAGS_BYTE_COUNT];
	__u32 flags32[HV_EVENT_FLAGS32_COUNT];
	ulong ulflags[HV_EVENT_FLAGS_UL_COUNT];  /* linux only */
};

/* Define SynIC control register. */
union hv_synic_scontrol {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:63;
	} __packed;
};

/* Define synthetic interrupt source. */
union hv_synic_sint {
	u64 as_uint64;
	struct {
		u64 vector:8;
		u64 reserved1:8;
		u64 masked:1;
		u64 auto_eoi:1;
		u64 polling:1;
		u64 reserved2:45;
	} __packed;
};

/* Define the format of the SIMP register */
union hv_synic_simp {
	u64 as_uint64;
	struct {
		u64 simp_enabled:1;
		u64 preserved:11;
		u64 base_simp_gpa:52;
	} __packed;
};

/* Define the format of the SIEFP register */
union hv_synic_siefp {
	u64 as_uint64;
	struct {
		u64 siefp_enabled:1;
		u64 preserved:11;
		u64 base_siefp_gpa:52;
	} __packed;
};

struct hv_vpset {
	u64 format;
	u64 valid_bank_mask;
	u64 bank_contents[];
} __packed;

/* The maximum number of sparse vCPU banks which can be encoded by 'struct hv_vpset' */
#define HV_MAX_SPARSE_VCPU_BANKS (64)
/* The number of vCPUs in one sparse bank */
#define HV_VCPUS_PER_SPARSE_BANK (64)

/* HvCallSendSyntheticClusterIpi hypercall */
struct hv_send_ipi {
	u32 vector;
	u32 reserved;
	u64 cpu_mask;
} __packed;

/* HvCallSendSyntheticClusterIpiEx hypercall */
struct hv_send_ipi_ex {
	u32 vector;
	u32 reserved;
	struct hv_vpset vp_set;
} __packed;

/* HvFlushGuestPhysicalAddressSpace hypercalls */
struct hv_guest_mapping_flush {
	u64 address_space;
	u64 flags;
} __packed;

/*
 *  HV_MAX_FLUSH_PAGES = "additional_pages" + 1. It's limited
 *  by the bitwidth of "additional_pages" in union hv_gpa_page_range.
 */
#define HV_MAX_FLUSH_PAGES (2048)
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_2MB		0
#define HV_GPA_PAGE_RANGE_PAGE_SIZE_1GB		1

/* HvFlushGuestPhysicalAddressList, HvExtCallMemoryHeatHint hypercall */
union hv_gpa_page_range {
	u64 address_space;
	struct {
		u64 additional_pages:11;
		u64 largepage:1;
		u64 basepfn:52;
	} page;
	struct {
		u64 reserved:12;
		u64 page_size:1;
		u64 reserved1:8;
		u64 base_large_pfn:43;
	};
};

/*
 * All input flush parameters should be in single page. The max flush
 * count is equal with how many entries of union hv_gpa_page_range can
 * be populated into the input parameter page.
 */
#define HV_MAX_FLUSH_REP_COUNT ((HV_HYP_PAGE_SIZE - 2 * sizeof(u64)) /	\
				sizeof(union hv_gpa_page_range))

/* HvFlushGuestPhysicalAddressList hypercall */
struct hv_guest_mapping_flush_list {
	u64 address_space;
	u64 flags;
	union hv_gpa_page_range gpa_list[HV_MAX_FLUSH_REP_COUNT];
};

/* HvFlushVirtualAddressSpace, HvFlushVirtualAddressList hypercalls */
struct hv_tlb_flush {
	u64 address_space;
	u64 flags;
	u64 processor_mask;
	u64 gva_list[];
} __packed;

/* HvFlushVirtualAddressSpaceEx, HvFlushVirtualAddressListEx hypercalls */
struct hv_tlb_flush_ex {
	u64 address_space;
	u64 flags;
	struct hv_vpset hv_vp_set;
	u64 gva_list[];
} __packed;

/* HvGetPartitionId hypercall (output only) */
struct hv_get_partition_id {
	u64 partition_id;
} __packed;

/* HvDepositMemory hypercall */
struct hv_deposit_memory {
	u64 partition_id;
	u64 gpa_page_list[];
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

struct hv_lp_startup_status {
	u64 hv_status;
	u64 substatus1;
	u64 substatus2;
	u64 substatus3;
	u64 substatus4;
	u64 substatus5;
	u64 substatus6;
} __packed;

/* HvAddLogicalProcessor hypercall */
struct hv_input_add_logical_processor {
	u32 lp_index;
	u32 apic_id;
	struct hv_proximity_domain_info proximity_domain_info;
} __packed;

struct hv_output_add_logical_processor {
	struct hv_lp_startup_status startup_status;
} __packed;

enum HV_SUBNODE_TYPE
{
    HvSubnodeAny = 0,
    HvSubnodeSocket = 1,
    HvSubnodeAmdNode = 2,
    HvSubnodeL3 = 3,
    HvSubnodeCount = 4,
    HvSubnodeInvalid = -1
};

/* HvCreateVp hypercall */
struct hv_create_vp {
	u64 partition_id;
	u32 vp_index;
	u8 padding[3];
	u8 subnode_type;
	u64 subnode_id;
	struct hv_proximity_domain_info proximity_domain_info;
	u64 flags;
} __packed;

enum hv_interrupt_source {
	HV_INTERRUPT_SOURCE_MSI = 1, /* MSI and MSI-X */
	HV_INTERRUPT_SOURCE_IOAPIC,
};

union hv_ioapic_rte {
	u64 as_uint64;

	struct {
		u32 vector:8;
		u32 delivery_mode:3;
		u32 destination_mode:1;
		u32 delivery_status:1;
		u32 interrupt_polarity:1;
		u32 remote_irr:1;
		u32 trigger_mode:1;
		u32 interrupt_mask:1;
		u32 reserved1:15;

		u32 reserved2:24;
		u32 destination_id:8;
	};

	struct {
		u32 low_uint32;
		u32 high_uint32;
	};
} __packed;

struct hv_interrupt_entry {
	u32 source;
	u32 reserved1;
	union {
		union hv_msi_entry msi_entry;
		union hv_ioapic_rte ioapic_rte;
	};
} __packed;

/*
 * flags for hv_device_interrupt_target.flags
 */
#define HV_DEVICE_INTERRUPT_TARGET_MULTICAST		1
#define HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET	2

struct hv_device_interrupt_target {
	u32 vector;
	u32 flags;
	union {
		u64 vp_mask;
		struct hv_vpset vp_set;
	};
} __packed;

struct hv_retarget_device_interrupt {
	u64 partition_id;		/* use "self" */
	u64 device_id;
	struct hv_interrupt_entry int_entry;
	u64 reserved2;
	struct hv_device_interrupt_target int_target;
} __packed __aligned(8);

/*
 * These Hyper-V registers provide information equivalent to the CPUID
 * instruction on x86/x64.
 */
#define HV_REGISTER_HYPERVISOR_VERSION		 0x00000100 /*CPUID 0x40000002 */
#define HV_REGISTER_PRIVILEGES_AND_FEATURES_INFO 0x00000200 /*CPUID 0x40000003 */
#define HV_REGISTER_FEATURES_INFO		 0x00000201 /*CPUID 0x40000004 */

/*
 * Synthetic register definitions equivalent to MSRs on x86/x64
 */
#define HV_REGISTER_GUEST_CRASH_P0	0x00000210
#define HV_REGISTER_GUEST_CRASH_P1	0x00000211
#define HV_REGISTER_GUEST_CRASH_P2	0x00000212
#define HV_REGISTER_GUEST_CRASH_P3	0x00000213
#define HV_REGISTER_GUEST_CRASH_P4	0x00000214
#define HV_REGISTER_GUEST_CRASH_CTL	0x00000215

#define HV_REGISTER_GUEST_OS_ID		0x00090002
#define HV_REGISTER_VP_INDEX		0x00090003
#define HV_REGISTER_TIME_REF_COUNT	0x00090004
#define HV_REGISTER_REFERENCE_TSC	0x00090017

#define HV_REGISTER_SINT0		0x000A0000
#define HV_REGISTER_SCONTROL		0x000A0010
#define HV_REGISTER_SIEFP		0x000A0012
#define HV_REGISTER_SIMP		0x000A0013
#define HV_REGISTER_EOM			0x000A0014

#define HV_REGISTER_STIMER0_CONFIG	0x000B0000
#define HV_REGISTER_STIMER0_COUNT	0x000B0001

/* HvGetVpRegisters hypercall input with variable size reg name list*/
struct hv_get_vp_registers_input {
	struct {
		u64 partitionid;
		u32 vpindex;
		u8  inputvtl;
		u8  padding[3];
	} header;
	struct input {
		u32 name0;
		u32 name1;
	} element[];
} __packed;

/* HvGetVpRegisters returns an array of these output elements */
struct hv_get_vp_registers_output {
	union {
		struct {
			u32 a;
			u32 b;
			u32 c;
			u32 d;
		} as32 __packed;
		struct {
			u64 low;
			u64 high;
		} as64 __packed;
	};
};

/* HvSetVpRegisters hypercall with variable size reg name/value list*/
struct hv_set_vp_registers_input {
	struct {
		u64 partitionid;
		u32 vpindex;
		u8  inputvtl;
		u8  padding[3];
	} header;
	struct {
		u32 name;
		u32 padding1;
		u64 padding2;
		u64 valuelow;
		u64 valuehigh;
	} element[];
} __packed;

enum hv_device_type {
	HV_DEVICE_TYPE_LOGICAL = 0,
	HV_DEVICE_TYPE_PCI = 1,
	HV_DEVICE_TYPE_IOAPIC = 2,
	HV_DEVICE_TYPE_ACPI = 3,
};

typedef u16 hv_pci_rid;
typedef u16 hv_pci_segment;
typedef u64 hv_logical_device_id;
union hv_pci_bdf {
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

union hv_device_id {
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

enum hv_interrupt_trigger_mode {
	HV_INTERRUPT_TRIGGER_MODE_EDGE = 0,
	HV_INTERRUPT_TRIGGER_MODE_LEVEL = 1,
};

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

#define HV_SOURCE_SHADOW_NONE               0x0
#define HV_SOURCE_SHADOW_BRIDGE_BUS_RANGE   0x1

/*
 * Version info reported by hypervisor
 */
union hv_hypervisor_version_info {
	struct {
		u32 build_number;

		u32 minor_version : 16;
		u32 major_version : 16;

		u32 service_pack;

		u32 service_number : 24;
		u32 service_branch : 8;
	};
	struct {
		u32 eax;
		u32 ebx;
		u32 ecx;
		u32 edx;
	};
};

/*
 * The whole argument should fit in a page to be able to pass to the hypervisor
 * in one hypercall.
 */
#define HV_MEMORY_HINT_MAX_GPA_PAGE_RANGES  \
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_memory_hint)) / \
		sizeof(union hv_gpa_page_range))

/* HvExtCallMemoryHeatHint hypercall */
#define HV_EXT_MEMORY_HEAT_HINT_TYPE_COLD_DISCARD	2
struct hv_memory_hint {
	u64 heat_type:2;
	u64 reserved:62;
	union hv_gpa_page_range ranges[];
} __packed;

/* Data structures for HVCALL_MMIO_READ and HVCALL_MMIO_WRITE */
#define HV_HYPERCALL_MMIO_MAX_DATA_LENGTH 64

struct hv_mmio_read_input { /* HV_INPUT_MEMORY_MAPPED_IO_READ */
	u64 gpa;
	u32 size;
	u32 reserved;
} __packed;

struct hv_mmio_read_output {
	u8 data[HV_HYPERCALL_MMIO_MAX_DATA_LENGTH];
} __packed;

struct hv_mmio_write_input {
	u64 gpa;
	u32 size;
	u32 reserved;
	u8 data[HV_HYPERCALL_MMIO_MAX_DATA_LENGTH];
} __packed;

/* Device domain types */
#define HV_DEVICE_DOMAIN_TYPE_S2  0 /* Stage 2 domain */
#define HV_DEVICE_DOMAIN_TYPE_S1  1 /* Stage 1 domain */
#define HV_DEVICE_DOMAIN_TYPE_SOC 2 /* SOC domain */

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

struct hv_input_device_domain {
	u64 partition_id;
	union hv_input_vtl owner_vtl;
	u8 padding[7];
	union hv_device_domain_id domain_id;
} __packed;

union hv_create_device_domain_flags {
	u32 as_uint32;
	struct {
		u32 forward_progress_required: 1;
		u32 inherit_owning_vtl: 1;
		u32 reserved: 30;
	};
} __packed;

struct hv_input_create_device_domain {
	struct hv_input_device_domain device_domain;
	union hv_create_device_domain_flags create_device_domain_flags;
} __packed;

struct hv_input_delete_device_domain {
	struct hv_input_device_domain device_domain;
} __packed;

struct hv_input_attach_device_domain {
	struct hv_input_device_domain device_domain;
	union hv_device_id device_id;
} __packed;

struct hv_input_detach_device_domain {
	u64 partition_id;
	union hv_device_id device_id;
} __packed;

struct hv_input_map_device_gpa_pages {
	struct hv_input_device_domain device_domain;
	union hv_input_vtl target_vtl;
	u8 padding[3];
	u32 map_flags;
	u64 target_device_va_base;
	u64 gpa_page_list[];
} __packed;

struct hv_input_unmap_device_gpa_pages {
	struct hv_input_device_domain device_domain;
	u64 target_device_va_base;
} __packed;

struct hv_input_query_device_domain {
	struct hv_input_device_domain device_domain;
	u64 target_device_va_list[];
} __packed;

struct hv_device_va_mapping {
	u64 target_device_va;
	u64 gpa_page_number;
} __packed;

struct hv_input_map_sparse_device_gpa_pages {
	struct hv_input_device_domain device_domain;
	union hv_input_vtl target_vtl;
	u32 map_flags;
	struct hv_device_va_mapping page_list[];
} __packed;

struct hv_input_unmap_sparse_device_gpa_pages {
	struct hv_input_device_domain device_domain;
	u64 target_device_va_list[];
} __packed;

struct hv_device_domain_settings_x64 {
	struct {
		/*
		 * Enable translations. If not enabled, all transaction bypass
		 * S1 translations.
		 */
		u64 translation_enabled: 1;
		u64 reserved: 63;
	} flags;
	/* Page attribute table */
	u64 pat;
	/* Address of translation table */
	u64 page_table_root;
} __packed;

struct hv_device_domain_settings {
	union {
		struct hv_device_domain_settings_x64 x64;
		/* ARM TBD */
	};
} __packed;

struct hv_input_configure_device_domain {
	struct hv_input_device_domain device_domain;
	struct hv_device_domain_settings settings;
} __packed;

/* HV Map GPA (Guest Physical Address) Flags */
#define HV_MAP_GPA_READABLE		0x1
#define HV_MAP_GPA_WRITABLE		0x2

/* Define connection identifier type. */
union hv_connection_id {
	u32 asu32;
	struct {
		u32 id:24;
		u32 reserved:8;
	} u;
};

#endif
