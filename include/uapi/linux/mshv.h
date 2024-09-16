/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interfaces for /dev/mshv* devices and derived fds
 * Includes:
 * - VMM APIs for parent (nested/baremetal root, L1VH) partition APIs
 * - VMM APIs for VTL0 APIs
 * - Debug and performance metrics APIs
 *
 * This file is divided into sections containing data structures and IOCTLs for
 * a particular set of related devices or derived file descriptors.
 *
 * The IOCTL definitions are at the end of each section. They are grouped by
 * device/fd, so that new IOCTLs can easily be added with a monotonically
 * increasing number.
 */
#ifndef _UAPI_LINUX_MSHV_H
#define _UAPI_LINUX_MSHV_H

#include <linux/types.h>

/*
 * This IOCTL number is reserved for use by mshv drivers in ioctl-number.rst.
 * It is not necessary to use any other IOCTL number in this file.
 */
#define MSHV_IOCTL	0xB8

/*************************************************************************
 * This section contains data structures that depend on hvhdk.h, or are
 * superceded by making a generic hypercall via MSHV_ROOT_HVCALL.
 * Group them here independently to easily remove later.
 *
 * IOCTL definitions using these remain grouped with the others for that
 * device/fd so they remain in context and don't collide.
 *
 * TODO: Remove this section when no longer needed
 *************************************************************************
 */

#define MSHV_VP_MAX_REGISTERS	128

struct mshv_vp_registers {
	int count; /* at most MSHV_VP_MAX_REGISTERS */
	struct hv_register_assoc *regs;
};

struct mshv_install_intercept {
	__u32 access_type_mask;
	enum hv_intercept_type intercept_type;
	union hv_intercept_parameters intercept_parameter;
};

struct mshv_assert_interrupt {
	union hv_interrupt_control control;
	__u64 dest_addr;
	__u32 vector;
	__u32 rsvd;
};

struct mshv_partition_property {
	enum hv_partition_property_code property_code;
	__u64 property_value;
};

struct mshv_translate_gva {
	__u64 gva;
	__u64 flags;
	union hv_translate_gva_result *result;
	__u64 *gpa;
};

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
struct mshv_register_intercept_result {
	__u32 intercept_type; /* enum hv_intercept_type */
	union hv_register_intercept_result_parameters parameters;
};
#endif

struct mshv_signal_event_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 flag;
	/* output */
	__u8 newly_signaled;
};

struct mshv_post_message_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 length;
	__u8 __user const *message;
};

struct mshv_register_deliverabilty_notifications {
	__u32 vp;
	__u32 pad;
	__u64 flag;
};

struct mshv_get_vp_cpuid_values {
	__u32 function;
	__u32 index;
	__u64 xfem;
	__u64 xss;
	/* output */
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct mshv_read_write_gpa {
	__u64 base_gpa;
	__u32 byte_count;
	__u32 flags;
	__u8 data[HV_READ_WRITE_GPA_MAX_SIZE];
};

struct mshv_sev_snp_ap_create {
	__u64 vp_id;
	__u64 vmsa_gpa;
};

struct mshv_issue_psp_guest_request {
	__u64 req_gpa;
	__u64 rsp_gpa;
};

struct mshv_complete_isolated_import {
	union hv_partition_complete_isolated_import_data import_data;
};

/*
 *******************************************
 * Entry point to main VMM APIs: /dev/mshv *
 *******************************************
 */

enum {
	MSHV_VTL_CAP_BIT_REGISTER_PAGE,
	MSHV_VTL_CAP_BIT_RETURN_ACTION,
	MSHV_VTL_CAP_BIT_DR6_SHARED,
	MSHV_VTL_CAP_BIT_COUNT,
};
#define MSHV_VTL_CAP_MASK ((1 << MSHV_CAP_BIT_COUNT) - 1)

/**
 * struct mshv_vtl_capabilities - arguments for MSHV_GET_VTL_CAPS
 * @bits: in: MBZ
 *	  out: bitmask of MSHV_VTL_CAP_BIT << 1
 */
struct mshv_vtl_capabilities {
	__u64 bits;
};

enum {
	MSHV_PT_BIT_LAPIC,
	MSHV_PT_BIT_X2APIC,
	MSHV_PT_BIT_GPA_SUPER_PAGES,
	MSHV_PT_BIT_COUNT,
};
#define MSHV_PT_FLAGS_MASK ((1 << MSHV_PT_BIT_COUNT) - 1)

enum {
	MSHV_PT_ISOLATION_NONE,
	MSHV_PT_ISOLATION_SNP,
	MSHV_PT_ISOLATION_COUNT,
};

/**
 * struct mshv_create_partition - arguments for MSHV_CREATE_PARTITION
 * @pt_flags: Bitmask of 1 << MSHV_PT_BIT_*
 * @pt_isolation: MSHV_PT_ISOLATION_*
 *
 * Returns a file descriptor to act as a handle to a guest partition.
 * At this point the partition is not yet initialized in the hypervisor.
 * Some operations must be done with the partition in this state, e.g. setting
 * so-called "early" partition properties. The partition can then be
 * initialized with MSHV_INITIALIZE_PARTITION.
 */
struct mshv_create_partition {
	__u64 pt_flags;
	__u64 pt_isolation;
};

/* /dev/mshv */
#define MSHV_CREATE_PARTITION	_IOW(MSHV_IOCTL, 0x00, struct mshv_create_partition)
/* Start nr again from 0x00 - mshv_vtl ioctls won't collide with mshv_root */
#define MSHV_CREATE_VTL		_IO(MSHV_IOCTL, 0x00)
#define MSHV_GET_VTL_CAPS	_IOR(MSHV_IOCTL, 0x01, struct mshv_vtl_capabilities)

/*
 ************************
 * Child partition APIs *
 ************************
 */

struct mshv_create_vp {
	__u32 vp_index;
};

enum {
	MSHV_SET_MEM_BIT_WRITABLE,
	MSHV_SET_MEM_BIT_EXECUTABLE,
	MSHV_SET_MEM_BIT_UNMAP,
	MSHV_SET_MEM_BIT_COUNT
};
#define MSHV_SET_MEM_FLAGS_MASK ((1 << MSHV_SET_MEM_BIT_COUNT) - 1)

/**
 * struct mshv_user_mem_region - arguments for MSHV_SET_GUEST_MEMORY
 * @size: Size of the memory region (bytes). Must be aligned to PAGE_SIZE
 * @guest_pfn: Base guest page number to map
 * @userspace_addr: Base address of userspace memory. Must be aligned to
 *                  PAGE_SIZE
 * @flags: Bitmask of 1 << MSHV_SET_MEM_BIT_*. If (1 << MSHV_SET_MEM_BIT_UNMAP)
 *         is set, ignore other bits.
 * @rsvd: MBZ
 *
 * Map or unmap a region of userspace memory to Guest Physical Addresses (GPA).
 * Mappings can't overlap in GPA space or userspace.
 * To unmap, these fields must match an existing mapping.
 */
struct mshv_user_mem_region {
	__u64 size;
	__u64 guest_pfn;
	__u64 userspace_addr;
	__u8 flags;
	__u8 rsvd[7];
};

enum {
	MSHV_IRQFD_BIT_DEASSIGN,
	MSHV_IRQFD_BIT_RESAMPLE,
	MSHV_IRQFD_BIT_COUNT,
};
#define MSHV_IRQFD_FLAGS_MASK	((1 << MSHV_IRQFD_BIT_COUNT) - 1)

struct mshv_user_irqfd {
	__s32 fd;
	__s32 resamplefd;
	__u32 gsi;
	__u32 flags;
};

enum {
	MSHV_IOEVENTFD_BIT_DATAMATCH,
	MSHV_IOEVENTFD_BIT_PIO,
	MSHV_IOEVENTFD_BIT_DEASSIGN,
	MSHV_IOEVENTFD_BIT_COUNT,
};
#define MSHV_IOEVENTFD_FLAGS_MASK	((1 << MSHV_IOEVENTFD_BIT_COUNT) - 1)

struct mshv_user_ioeventfd {
	__u64 datamatch;
	__u64 addr;	   /* legal pio/mmio address */
	__u32 len;	   /* 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;
	__u8  rsvd[4];
};

struct mshv_user_irq_entry {
	__u32 gsi;
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
};

struct mshv_user_irq_table {
	__u32 nr;
	__u32 rsvd; /* MBZ */
	struct mshv_user_irq_entry entries[0];
};

enum {
	MSHV_GPAP_ACCESS_TYPE_ACCESSED = 0,
	MSHV_GPAP_ACCESS_TYPE_DIRTY,
	MSHV_GPAP_ACCESS_TYPE_COUNT		/* Count of enum members */
};

enum {
	MSHV_GPAP_ACCESS_OP_NOOP = 0,
	MSHV_GPAP_ACCESS_OP_CLEAR,
	MSHV_GPAP_ACCESS_OP_SET,
	MSHV_GPAP_ACCESS_OP_COUNT		/* Count of enum members */
};

/**
 * struct mshv_gpap_access_bitmap - arguments for MSHV_GET_GPAP_ACCESS_BITMAP
 * @access_type: MSHV_GPAP_ACCESS_TYPE_* - The type of access to record in the
 *               bitmap
 * @access_op: MSHV_GPAP_ACCESS_OP_* - Allows an optional clear or set of all
 *             the access states in the range, after retrieving the current
 *             states.
 * @rsvd: MBZ
 * @page_count: in: number of pages
 *              out: on error, number of states successfully written to bitmap
 * @gpap_base: Base gpa page number
 * @bitmap_ptr: Output buffer for bitmap, at least (page_count + 7) / 8 bytes
 *
 * Retrieve a bitmap of either ACCESSED or DIRTY bits for a given range of guest
 * memory, and optionally clear or set the bits.
 */
struct mshv_gpap_access_bitmap {
	__u8 access_type;
	__u8 access_op;
	__u8 rsvd[6];
	__u64 page_count;
	__u64 gpap_base;
	__u64 bitmap_ptr;
};

/* Subsection - SEV/SNP data structures */
enum {
	MSHV_GPA_HOST_ACCESS_BIT_ACQUIRE = 0,
	MSHV_GPA_HOST_ACCESS_BIT_READABLE,
	MSHV_GPA_HOST_ACCESS_BIT_WRITABLE,
	MSHV_GPA_HOST_ACCESS_BIT_LARGE_PAGE,
	MSHV_GPA_HOST_ACCESS_BIT_COUNT		/* Count of enum members */
};
#define MSHV_GPA_HOST_ACCESS_FLAGS_MASK \
	((1 << MSHV_GPA_HOST_ACCESS_BIT_COUNT) - 1)

/**
 * struct mshv_modify_gpa_host_access - args for MSHV_MODIFY_GPA_HOST_ACCESS
 * @flags: Bitmask of 1 << MSHV_GPA_HOST_ACCESS_BIT_*
 * @rsvd: MBZ
 * @page_count: Number of pages in guest_pfns
 * @guest_pfns: Variable length array of guest page numbers
 */
struct mshv_modify_gpa_host_access {
	__u8 flags;
	__u8 rsvd[7];
	__u64 page_count;
	__u64 guest_pfns[];
};

enum {
	MSHV_ISOLATED_PAGE_NORMAL = 0,
	MSHV_ISOLATED_PAGE_VMSA,
	MSHV_ISOLATED_PAGE_ZERO,
	MSHV_ISOLATED_PAGE_UNMEASURED,
	MSHV_ISOLATED_PAGE_SECRETS,
	MSHV_ISOLATED_PAGE_CPUID,
	MSHV_ISOLATED_PAGE_COUNT		/* Count of enum members */
};

/**
 * struct mshv_import_isolated_pages - args for MSHV_IMPORT_ISOLATED_PAGES
 * @page_type: MSHV_ISOLATED_PAGE_*
 * @rsvd: MBZ
 * @page_count: Number of pages in guest_pfns
 * @guest_pfns: Variable length array of guest page numbers
 *
 * Must use 4KiB pages
 */
struct mshv_import_isolated_pages {
	__u8 page_type;
	__u8 rsvd[7];
	__u64 page_count;
	__u64 guest_pfns[];
};

/**
 * struct mshv_root_hvcall - arguments for MSHV_ROOT_HVCALL
 * @code: Hypercall code (HVCALL_*)
 * @reps: in: Rep count ('repcount')
 *	  out: Reps completed ('repcomp'). MBZ unless rep hvcall
 * @in_sz: Size of input incl rep data. <= HV_HYP_PAGE_SIZE
 * @out_sz: Size of output buffer. <= HV_HYP_PAGE_SIZE. MBZ if out_ptr is 0
 * @status: in: MBZ
 *	    out: HV_STATUS_* from hypercall
 * @rsvd: MBZ
 * @in_ptr: Input data buffer (struct hv_input_*). If used with partition or
 *	    vp fd, partition id field is added by kernel.
 * @out_ptr: Output data buffer (optional)
 */
struct mshv_root_hvcall {
	__u16 code;
	__u16 reps;
	__u16 in_sz;
	__u16 out_sz;
	__u16 status;
	__u8 rsvd[6];
	__u64 in_ptr;
	__u64 out_ptr;
};

/* Partition fds created with MSHV_CREATE_PARTITION */
#define MSHV_INITIALIZE_PARTITION	_IO(MSHV_IOCTL, 0x00)
#define MSHV_CREATE_VP			_IOW(MSHV_IOCTL, 0x01, struct mshv_create_vp)
#define MSHV_SET_GUEST_MEMORY		_IOW(MSHV_IOCTL, 0x02, struct mshv_user_mem_region)
#define MSHV_IRQFD			_IOW(MSHV_IOCTL, 0x03, struct mshv_user_irqfd)
#define MSHV_IOEVENTFD			_IOW(MSHV_IOCTL, 0x04, struct mshv_user_ioeventfd)
#define MSHV_SET_MSI_ROUTING		_IOW(MSHV_IOCTL, 0x05, struct mshv_user_irq_table)
#define MSHV_GET_GPAP_ACCESS_BITMAP	_IOWR(MSHV_IOCTL, 0x06, struct mshv_gpap_access_bitmap)
/* Generic hypercall */
#define MSHV_ROOT_HVCALL		_IOWR(MSHV_IOCTL, 0x07, struct mshv_root_hvcall)
/* Experimental */
#define MSHV_CREATE_DEVICE		_IOWR(MSHV_IOCTL, 0x08, struct mshv_create_device)
/* SEV/SNP-related partition IOCTLs */
#define MSHV_MODIFY_GPA_HOST_ACCESS	_IOW(MSHV_IOCTL, 0x09, struct mshv_modify_gpa_host_access)
#define MSHV_IMPORT_ISOLATED_PAGES	_IOW(MSHV_IOCTL, 0x0A, struct mshv_import_isolated_pages)
/* TODO: Remove the following. They are replaceable with MSHV_ROOT_HVCALL */
#define MSHV_INSTALL_INTERCEPT		_IOW(MSHV_IOCTL, 0xF0, struct mshv_install_intercept)
#define MSHV_ASSERT_INTERRUPT		_IOW(MSHV_IOCTL, 0xF1, struct mshv_assert_interrupt)
#define MSHV_SET_PARTITION_PROPERTY	_IOW(MSHV_IOCTL, 0xF2, struct mshv_partition_property)
#define MSHV_GET_PARTITION_PROPERTY	_IOWR(MSHV_IOCTL, 0xF3, struct mshv_partition_property)
#define MSHV_COMPLETE_ISOLATED_IMPORT	_IOW(MSHV_IOCTL, 0xF4, struct mshv_complete_isolated_import)
#define MSHV_ISSUE_PSP_GUEST_REQUEST	_IOW(MSHV_IOCTL, 0xF5, struct mshv_issue_psp_guest_request)
#define MSHV_SEV_SNP_AP_CREATE		_IOW(MSHV_IOCTL, 0xF6, struct mshv_sev_snp_ap_create)
#define MSHV_SIGNAL_EVENT_DIRECT	_IOWR(MSHV_IOCTL, 0xF7, struct mshv_signal_event_direct)
#define MSHV_POST_MESSAGE_DIRECT	_IOW(MSHV_IOCTL, 0xF8, struct mshv_post_message_direct)
#define MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS \
					_IOW(MSHV_IOCTL, 0xF9, \
					     struct mshv_register_deliverabilty_notifications)

/*
 ********************************
 * VP APIs for child partitions *
 ********************************
 */

#define MSHV_RUN_VP_BUF_SZ 256

/*
 * Map various VP state pages to userspace.
 * Multiply the offset by PAGE_SIZE before being passed as the 'offset'
 * argument to mmap().
 * e.g.
 * void *reg_page = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
 *                       MAP_SHARED, vp_fd,
 *                       MSHV_VP_MMAP_OFFSET_REGISTERS * PAGE_SIZE);
 */
enum mshv_hv_vp_state_page_type {
	MSHV_VP_MMAP_OFFSET_REGISTERS,
	MSHV_VP_MMAP_OFFSET_INTERCEPT_MESSAGE,
	MSHV_VP_MMAP_OFFSET_GHCB,
	MSHV_VP_MMAP_OFFSET_COUNT
};

struct mshv_run_vp {
	__u8 msg_buf[MSHV_RUN_VP_BUF_SZ];
};

#ifdef HV_SUPPORTS_VP_STATE

enum {
	MSHV_VP_STATE_LAPIC = 0,
	MSHV_VP_STATE_XSAVE, /* XSAVE data in compacted form */
	MSHV_VP_STATE_SIMP,
	MSHV_VP_STATE_SIEFP,
	MSHV_VP_STATE_SYNTHETIC_TIMERS,
	MSHV_VP_STATE_COUNT,
};

struct mshv_get_set_vp_state {
	__u8 type;	/* MSHV_VP_STATE_* */
	__u8 rsvd[3];	/* MBZ */
	__u32 buf_sz;	/* in - 4k page-aligned size of buffer.
			 * out - actual size of data.
			 * On EINVAL, check this to see if buffer was too small
			 */
	__u64 buf_ptr;	/* 4k page-aligned data buffer. */
};

#endif

/* VP fds created with MSHV_CREATE_VP */
#define MSHV_RUN_VP			_IOR(MSHV_IOCTL, 0x00, struct mshv_run_vp)
#ifdef HV_SUPPORTS_VP_STATE
#define MSHV_GET_VP_STATE		_IOWR(MSHV_IOCTL, 0x01, struct mshv_get_set_vp_state)
#define MSHV_SET_VP_STATE		_IOWR(MSHV_IOCTL, 0x02, struct mshv_get_set_vp_state)
#endif
/*
 * Generic hypercall
 * Defined above in partition IOCTLs, avoid redefining it here
 * #define MSHV_ROOT_HVCALL			_IOWR(MSHV_IOCTL, 0x07, struct mshv_root_hvcall)
 */
/* TODO: Remove the following. They are replaceable with MSHV_ROOT_HVCALL */
#define MSHV_GET_VP_REGISTERS		_IOWR(MSHV_IOCTL, 0xF0, struct mshv_vp_registers)
#define MSHV_SET_VP_REGISTERS		_IOW(MSHV_IOCTL, 0xF1, struct mshv_vp_registers)
#define MSHV_TRANSLATE_GVA		_IOWR(MSHV_IOCTL, 0xF2, struct mshv_translate_gva)
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
#define MSHV_VP_REGISTER_INTERCEPT_RESULT \
					_IOW(MSHV_IOCTL, 0xF3, \
					     struct mshv_register_intercept_result)
#endif
#define MSHV_GET_VP_CPUID_VALUES	_IOWR(MSHV_IOCTL, 0xF4, struct mshv_get_vp_cpuid_values)
#define MSHV_READ_GPA			_IOWR(MSHV_IOCTL, 0xF5, struct mshv_read_write_gpa)
#define MSHV_WRITE_GPA			_IOW(MSHV_IOCTL, 0xF6, struct mshv_read_write_gpa)

/*
 **************************
 * Passthrough device API *
 **************************
 */

#define MSHV_CREATE_DEVICE_TEST		1

struct mshv_create_device {
	__u32	type;	/* in: MSHV_DEV_TYPE_xxx */
	__u32	fd;	/* out: device handle */
	__u32	flags;	/* in: MSHV_CREATE_DEVICE_xxx */
};

#define MSHV_DEV_VFIO_FILE		1
#define MSHV_DEV_VFIO_FILE_ADD	1
#define MSHV_DEV_VFIO_FILE_DEL	2

enum mshv_device_type {
	MSHV_DEV_TYPE_VFIO,
#define MSHV_DEV_TYPE_VFIO		MSHV_DEV_TYPE_VFIO
	MSHV_DEV_TYPE_MAX,
};

struct mshv_device_attr {
	__u32	flags;		/* no flags currently defined */
	__u32	group;		/* device-defined */
	__u64	attr;		/* group-defined */
	__u64	addr;		/* userspace address of attr data */
};

/* Device fds created with MSHV_CREATE_DEVICE */
#define MSHV_SET_DEVICE_ATTR	_IOW(MSHV_IOCTL, 0x00, struct mshv_device_attr)
#define MSHV_GET_DEVICE_ATTR	_IOW(MSHV_IOCTL, 0x01, struct mshv_device_attr)
#define MSHV_HAS_DEVICE_ATTR	_IOW(MSHV_IOCTL, 0x02, struct mshv_device_attr)

/*
 ***********************
 * Diag and trace APIs *
 ***********************
 */

/* TODO: remove and use MSHV_IOCTL */
#define MSHV_DIAG_IOCTL		0xB9
/* TODO: remove and use MSHV_IOCTL */
#define MSHV_TRACE_IOCTL	0xBA

struct mshv_trace_config {
	__u32 mode; /* enum hv_eventlog_mode */
	__u32 max_buffers_count;
	__u32 pages_per_buffer;
	__u32 buffers_threshold;
	__u32 time_basis; /* enum hv_eventlog_entry_time_basis */
	__u64 system_time;
};

/* /dev/mshv_diag device */
#define MSHV_GET_TRACE_FD				\
		_IO(MSHV_DIAG_IOCTL, HV_EVENT_LOG_TYPE_LOCAL_DIAGNOSTICS)
#define MSHV_GET_DIAGLOG_FD				\
		_IO(MSHV_DIAG_IOCTL, HV_EVENT_LOG_TYPE_SYSTEM_DIAGNOSTICS)

/* Trace fd created with MSHV_GET_TRACE_FD */
#define MSHV_TRACE_STATE_CREATE		_IOW(MSHV_TRACE_IOCTL, 0x0, \
					     struct mshv_trace_config)
#define MSHV_TRACE_STATE_INFO		_IOR(MSHV_TRACE_IOCTL, 0x1, \
					     struct mshv_trace_config)
#define MSHV_TRACE_STATE_DESTROY	_IO(MSHV_TRACE_IOCTL, 0x2)
#define MSHV_TRACE_STATE_ATTACH		_IO(MSHV_TRACE_IOCTL, 0x3)
#define MSHV_TRACE_STATE_DETACH		_IO(MSHV_TRACE_IOCTL, 0x4)
#define MSHV_TRACE_START		_IO(MSHV_TRACE_IOCTL, 0x5)
#define MSHV_TRACE_STOP			_IO(MSHV_TRACE_IOCTL, 0x6)

/*
 ************
 * VTL APIs *
 ************
 */

/* vtl fd created with MSHV_CREATE_VTL */
#define MSHV_VTL_ADD_VTL0_MEMORY	_IOW(MSHV_IOCTL, 0x21, struct mshv_ram_disposition)
#define MSHV_VTL_SET_POLL_FILE		_IOW(MSHV_IOCTL, 0x25, struct mshv_set_poll_file)
#define MSHV_VTL_RETURN_TO_LOWER_VTL	_IO(MSHV_IOCTL, 0x27)

/* /dev/mshv_sint */
#define MSHV_SINT_SIGNAL_EVENT		_IOW(MSHV_IOCTL, 0x22, struct mshv_signal_event)
#define MSHV_SINT_POST_MESSAGE		_IOW(MSHV_IOCTL, 0x23, struct mshv_sint_post_msg)
#define MSHV_SINT_SET_EVENTFD		_IOW(MSHV_IOCTL, 0x24, struct mshv_set_eventfd)

/* /dev/mshv_hvcall */
#define MSHV_HVCALL_SETUP		_IOW(MSHV_IOCTL, 0x1E, struct mshv_hvcall_setup)
#define MSHV_HVCALL			_IOWR(MSHV_IOCTL, 0x1F, struct mshv_hvcall)

#endif
