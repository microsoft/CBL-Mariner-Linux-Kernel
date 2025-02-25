// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tick.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/cpuhotplug.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/key.h>
#include <keys/system_keyring.h>
#include <keys/asymmetric-type.h>
#include <crypto/pkcs7.h>
#include <linux/heki.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/mem_attr.h>
#include "../../kernel/module/internal.h"
#include <asm/mshyperv.h>
#include <asm/fpu/api.h>
#include <asm/cpu.h>
#include <asm/mpspec.h>
#include <asm/bootparam.h>
#include <asm/e820/types.h>
#include "hv_vsm.h"

#define HV_VTL1_IOCTL	0xE1
#define HV_RETURN_TO_LOWER_VTL    _IO(HV_VTL1_IOCTL, 0)

#define VTL_ENTRY_REASON_LOWER_VTL_CALL     0x1
#define VTL_ENTRY_REASON_INTERRUPT          0x2

#define HV_PAGE_ACCESS_NONE		0x0
#define HV_PAGE_READABLE		0x1
#define HV_PAGE_WRITABLE		0x2
#define HV_PAGE_KERNEL_EXECUTABLE	0x4
#define HV_PAGE_USER_EXECUTABLE		0x8
#define HV_PAGE_EXECUTABLE		(HV_PAGE_KERNEL_EXECUTABLE | HV_PAGE_USER_EXECUTABLE)
#define HV_PAGE_FULL_ACCESS		(HV_PAGE_READABLE | HV_PAGE_WRITABLE | HV_PAGE_EXECUTABLE)

/* Compute the address of the page at the given index with the given base */
#define VSM_PAGE_AT(addr, idx)  ((addr) + (idx) * PAGE_SIZE)
/* Compute the page frame number (PFN) from a page address */
#define VSM_PAGE_TO_PFN(addr)  ((addr) >> PAGE_SHIFT)

#define CR4_PIN_MASK	~((u64)(X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_VMXE))
#define CR0_PIN_MASK	((u64)(X86_CR0_PE | X86_CR0_WP | X86_CR0_PG))
#define DEFAULT_REG_PIN_MASK	((u64)-1)

bool vtl0_end_of_boot;

struct hv_intercept_message_header {
	u32 vp_index;
	u8 instruction_length;
	u8 intercept_access_type;
	/* ToDo: Define union for this */
	u16 execution_state;
	struct hv_x64_segment_register cs_segment;
	u64 rip;
	u64 rflags;
} __packed;

union hv_register_access_info {
	u64 reg_value_low;
	u64 reg_value_high;
	u32 reg_name;
	u64 src_addr;
	u64 dest_addr;
} __packed;

union hv_memory_access_info {
	u8 as_u8;
	struct {
		u8 gva_valid : 1;
		u8 gva_gpa_valid : 1;
		u8 hypercall_op_pending : 1;
		u8 tlb_blocked : 1;
		u8 supervisor_shadow_stack : 1;
		u8 verify_page_wr : 1;
		u8 reserved : 2;
	};
} __packed;

struct hv_intercept_message {
	struct hv_intercept_message_header hdr;
	u8 is_memory_op;
	u8 reserved_0;
	u16 reserved_1;
	u32 reg_name;
	union hv_register_access_info info;
} __packed;

struct hv_msr_intercept_message {
	struct hv_intercept_message_header hdr;
	u32 msr;
	u32 reserved_0;
	u64 rdx;
	u64 rax;
} __packed;

struct hv_mem_intercept_message {
	struct hv_intercept_message_header hdr;
	u32 cache_type;
	u8 instruction_byte_count;
	union hv_memory_access_info info;
	u8 tpr_priority;
	u8 reserved;
	u64 gva;
	u64 gpa;
	u8 instr_bytes[16];
} __packed;

extern struct boot_params boot_params;

union hv_register_vsm_vp_secure_vtl_config {
	u64 as_u64;
	struct {
		u64 mbec_enabled : 1;
		u64 tlb_locked : 1;
		u64 reserved: 62;
	};
};

struct hv_vtl_cpu_context {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 cr2;
	struct fxregs_state fx_state;
};

struct hv_vsm_per_cpu {
	struct hv_vtl_cpu_context cpu_context;
	struct hv_vtlcall_param vtl_params;
	struct task_struct *vsm_task;
	struct tasklet_struct handle_intercept;
	void *synic_message_page;
//	void *synic_event_page;
	u64 cr0_saved;
	u64 cr4_saved;
	u64 msr_lstar_saved;
	u64 msr_cstar_saved;
	u64 msr_star_saved;
	u64 msr_apic_base_saved;
	u64 msr_efer_saved;
	u64 msr_sysenter_cs_saved;
	u64 msr_sysenter_eip_saved;
	u64 msr_sysenter_esp_saved;
	u64 msr_sfmask_saved;
	/* Shut down tick when exiting VTL1 */
	bool suppress_tick;
	/* CPU should stay in VTL1 and not exit to VTL0 even if idle is invoked */
	bool stay_in_vtl1;
	bool vtl1_enabled;
	bool vtl1_booted;
};

static DEFINE_PER_CPU(struct hv_vsm_per_cpu, vsm_per_cpu);

struct vtl0 {
	struct heki_mem mem[HEKI_KDATA_MAX];
	struct key *trusted_keys;
	struct mutex lock;
	struct list_head modules;
	struct load_info info;
	long token;
	struct heki_mod *hmod;
} vtl0;

struct hv_input_modify_vtl_protection_mask {
	u64 partition_id;
	u32 map_flags;
	union hv_input_vtl target_vtl;
	u8 reserved8_z;
	u16 reserved16_z;

	__aligned(8) u64 gpa_page_list[];
};

static int hv_vsm_get_vtl0_register(u32 reg_name, u64 *result)
{
	u8 input_vtl = 0x1 << 4;

	return __hv_vsm_get_register(reg_name, result, input_vtl);
}

static int hv_vsm_set_vtl0_register(u32 reg_name, u64 value)
{
	u8 input_vtl = 0x1 << 4;

	return __hv_vsm_set_register(reg_name, value, input_vtl);
}

static int mshv_vsm_enable_aps(unsigned int cpu_present_mask_pfn)
{
	unsigned int cpu, total_cpus_enabled = 0;
	struct hv_vsm_per_cpu *per_cpu;
	const struct cpumask *cpu_present_vtl0;
	struct page *cpu_present_page;
	void *cpu_present_data = NULL;
	int ret;

	/* Validate cpu_present_mask_pfn parameter */
	cpu_present_page = pfn_to_page(cpu_present_mask_pfn);
	cpu_present_data = vmap(&cpu_present_page, 1, VM_MAP, PAGE_KERNEL);
	if (!cpu_present_data) {
		pr_err("%s: Could not map shared page", __func__);
		return -EINVAL;
	}
	cpu_present_vtl0 = (struct cpumask *)cpu_present_data;

	/* Loop through VTL0's present CPUs and make them present in VTL1 as well */
	for_each_cpu(cpu, cpu_present_vtl0) {
		if (!cpu_possible(cpu)) {
			pr_err("%s: CPU%u cannot be enabled because CPU%u is not possible",
			       __func__, cpu, cpu);
			ret = -EINVAL;
			goto out;
		}

		if (!(cpu_present(cpu))) {
			ret = generic_processor_info(cpu);

			if (ret != cpu) {
				pr_err("%s: Failed adding CPU%u. Error code: %d",
				       __func__, cpu, ret);
				ret = -EINVAL;
				goto out;
			}

			ret = arch_register_cpu(cpu);

			if (ret) {
				pr_err("%s: Failed registering CPU%u. Error code: %d",
				       __func__, cpu, ret);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	/* Loop through present Processors and enable VTL1 in each one */
	for_each_present_cpu(cpu) {
		/*
		 * Skip enabling of VTL1 for boot processor as it is already enabled by
		 * VTL0 and boot completed
		 */
		if (cpu_online(cpu))
			continue;
		per_cpu = per_cpu_ptr(&vsm_per_cpu, cpu);
		if (per_cpu->vtl1_enabled) {
			pr_info("%s: CPU%u is already enabled for VTL1. Will skip to next CPU",
				__func__, cpu);
			continue;
		}

		ret = hv_secure_vtl_enable_secondary_cpu((u32)cpu);

		if (ret) {
			pr_err("%s: Failed to enable VTL1 for CPU%u", __func__, cpu);
			goto out;
		}

		per_cpu->vtl1_enabled = true;
		total_cpus_enabled++;
	}

	pr_debug("%s: Enabled %u CPUs", __func__, total_cpus_enabled);
out:
	vunmap(cpu_present_data);
	return ret;
}

/*
 * This placeholder are overridden by arch specific code to allow setting up
 * of interrupt handler for secure interrupts and intercepts
 */
void __weak hv_setup_vsm_handler(void (*handler)(void))
{
}

static void mshv_vsm_isr(void)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);
	void *synic_message_page;
	struct hv_message *msg;
	u32 message_type;

	synic_message_page = per_cpu->synic_message_page;
	if (unlikely(!synic_message_page)) {
		pr_err("%s Error!!\n\n", __func__);
		return;
	}

	msg = (struct hv_message *)synic_message_page + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	message_type = READ_ONCE(msg->header.message_type);

	if (message_type == HVMSG_NONE)
		return;

	per_cpu->stay_in_vtl1 = true;
	tasklet_schedule(&per_cpu->handle_intercept);
}

static void __raise_vtl0_gp_fault(void)
{
	union hv_x64_pending_exception_event exception;
	int ret;

	exception.as_uint64[0] = 0;
	exception.event_pending = 0x1;
	exception.event_type = 0;
	exception.deliver_error_code = 1;
	exception.vector = 0xd;
	exception.error_code = 0;

	ret = hv_vsm_set_vtl0_register(HV_REGISTER_PENDING_EVENT0, exception.as_uint64[0]);
	if (ret)
		pr_err("%s: Error raising GP exception in VTL0\n", __func__);
}

static void __increment_vtl0_rip(struct hv_intercept_message_header *msg_hdr)
{
	u64 vtl0_rip;
	int ret;

	vtl0_rip = msg_hdr->rip + msg_hdr->instruction_length;

	ret = hv_vsm_set_vtl0_register(HV_X64_REGISTER_RIP, vtl0_rip);
	if (ret)
		pr_err("%s: Error advancing instruction pointer of VTL0\n", __func__);
}

static void mshv_vsm_handle_intercept(unsigned long data)
{
	struct hv_vsm_per_cpu *per_cpu = (void *)data;
	void *page_addr = per_cpu->synic_message_page;
	struct hv_message *msg = (struct hv_message *)page_addr + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	struct hv_intercept_message_header *intercept_msg_hdr;
	u64 value, mask, allowed_value;
	u32 reg_name, message_type;
	bool raise_fault = false;

	pr_info("%s: cpu%d\n", __func__, smp_processor_id());
	message_type = READ_ONCE(msg->header.message_type);
	if (message_type == HVMSG_NONE)
		/* We should not be here. Message corruption?? */
		goto clear_event;

	/* We handle only register and msr intercepts now */
	if (message_type == HVMSG_X64_REGISTER_INTERCEPT) {
		struct hv_intercept_message *intercept_msg =
			(struct hv_intercept_message *)msg->u.payload;

		reg_name = intercept_msg->reg_name;
		value = intercept_msg->info.reg_value_low;
		intercept_msg_hdr = &intercept_msg->hdr;
		pr_err("%s: Register intercept on cpu%d, reg:0x%x, value:0x%llx\n",
		       __func__, smp_processor_id(), reg_name, value);
	} else if (message_type == HVMSG_X64_MSR_INTERCEPT) {
		struct hv_msr_intercept_message *msr_intercept_msg =
			(struct hv_msr_intercept_message *)msg->u.payload;

		reg_name = msr_intercept_msg->msr;
		value = (msr_intercept_msg->rdx << 32) | (msr_intercept_msg->rax & 0xFFFFFFFF);
		intercept_msg_hdr = &msr_intercept_msg->hdr;
		pr_err("%s: MSR intercept on cpu%d, reg:0x%x, value:0x%llx\n",
		       __func__, smp_processor_id(), reg_name, value);
	} else if (message_type == HVMSG_GPA_INTERCEPT) {
		struct hv_mem_intercept_message *mem_intercept_msg =
			(struct hv_mem_intercept_message *)msg->u.payload;

		intercept_msg_hdr = &mem_intercept_msg->hdr;
		raise_fault = true;
		pr_err("%s: Memory intercept on cpu%d, gpa:0x%llx\n",
		       __func__, smp_processor_id(), mem_intercept_msg->gpa);
		goto out;
	} else {
		goto clear_event;
	}

	switch (reg_name) {
	case HV_X64_REGISTER_CR0:
		allowed_value = per_cpu->cr0_saved;
		mask = CR0_PIN_MASK;
		break;
	case HV_X64_REGISTER_CR4:
		allowed_value = per_cpu->cr4_saved;
		mask = CR4_PIN_MASK;
		break;
	case HV_X64_REGISTER_GDTR:
	case HV_X64_REGISTER_IDTR:
	case HV_X64_REGISTER_LDTR:
	case HV_X64_REGISTER_TR:
		raise_fault = true;
		break;
	case MSR_LSTAR:
		reg_name = HV_X64_REGISTER_LSTAR;
		allowed_value = per_cpu->msr_lstar_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_STAR:
		reg_name = HV_X64_REGISTER_STAR;
		allowed_value = per_cpu->msr_star_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_CSTAR:
		reg_name = HV_X64_REGISTER_CSTAR;
		allowed_value = per_cpu->msr_cstar_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_IA32_APICBASE:
		reg_name = HV_X64_REGISTER_APIC_BASE;
		allowed_value = per_cpu->msr_apic_base_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_EFER:
		reg_name = HV_X64_REGISTER_EFER;
		allowed_value = per_cpu->msr_efer_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_IA32_SYSENTER_CS:
		reg_name = HV_X64_REGISTER_SYSENTER_CS;
		allowed_value = per_cpu->msr_sysenter_cs_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_IA32_SYSENTER_ESP:
		reg_name = HV_X64_REGISTER_SYSENTER_ESP;
		allowed_value = per_cpu->msr_sysenter_esp_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_IA32_SYSENTER_EIP:
		reg_name = HV_X64_REGISTER_SYSENTER_EIP;
		allowed_value = per_cpu->msr_sysenter_eip_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	case MSR_SYSCALL_MASK:
		reg_name = HV_X64_REGISTER_SFMASK;
		allowed_value = per_cpu->msr_sfmask_saved;
		mask = DEFAULT_REG_PIN_MASK;
		break;
	default:
		/* We should not be here. Do nothing */
		goto out;
	}

	if (!raise_fault) {
		if ((value & mask) == allowed_value) {
			if (hv_vsm_set_vtl0_register(reg_name, value))
				pr_err("%s: Error writing into register 0x%x of VTL0\n",
				       __func__, reg_name);
		} else {
			raise_fault = true;
		}
	}

out:
	if (raise_fault)
		__raise_vtl0_gp_fault();
	else
		__increment_vtl0_rip(intercept_msg_hdr);

clear_event:
	vmbus_signal_eom(msg, message_type);
	/* Should interrupts be disabled ?? */
	per_cpu->stay_in_vtl1 = false;
}

static int hv_modify_vtl_protection_mask(u64 start, u64 number_of_pages, u32 page_access)
{
	struct hv_input_modify_vtl_protection_mask *hvin;
	u64 status, pages_processed, total_pages_processed;
	unsigned long flags;
	size_t max_pages_per_request;
	int i;

	/* Check parameters */
	if (number_of_pages <= 0 || number_of_pages >= UINT_MAX)
		return -EINVAL;

	pr_debug("%s start = 0x%llx, page_count = %lld, perm = 0x%x\n",
		 __func__, start, number_of_pages, page_access);

	/* Compute the maximum number of pages that can be processed in one go */
	max_pages_per_request = (PAGE_SIZE - sizeof(*hvin)) / sizeof(u64);

	/* Disable interrupts */
	local_irq_save(flags);

	/* Acquire the input page */
	hvin = (struct hv_input_modify_vtl_protection_mask *)(*this_cpu_ptr(hyperv_pcpu_input_arg));
	memset(hvin, 0, sizeof(*hvin));

	/* Fill in the hypercall parameters */
	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl.as_uint8 = 1;
	hvin->map_flags = page_access;

	/*
	 * Batch-process pages based on the maximum number of pages that can be
	 * processed in a single hypercall
	 */
	pages_processed = 0;
	total_pages_processed = 0;

	while (total_pages_processed < number_of_pages) {
		for (i = 0; ((i < max_pages_per_request) &&
			     ((total_pages_processed + i) < number_of_pages)); i++)
			hvin->gpa_page_list[i] =
				VSM_PAGE_TO_PFN(VSM_PAGE_AT(start, total_pages_processed + i));

		/* Perform the hypercall */
		status = hv_do_rep_hypercall(HVCALL_MODIFY_VTL_PROTECTION_MASK, i, 0, hvin, NULL);

		/*
		 * Update page accounting for the next iteration, if any
		 * N.B.: pages_processed is correct even if Hyper-V returned an error.
		 */
		pages_processed = hv_repcomp(status);
		total_pages_processed += pages_processed;

		/* See how things went */
		if (!hv_result_success(status))
			break;
	}

	/* Enable interrupts */
	local_irq_restore(flags);
	/* Done */
	return hv_result(status);
}

/*
 * VTL0 passes kernel data structures to VTL1. Each kernel data structure is
 * assigned a unique identifier. That identifier is specified in the
 * attributes field. All of the ranges that contain a single kernel data
 * structure must be virtually contiguous and in the correct order. Check for
 * for that.
 */
static bool vsm_contiguous(struct heki_range *ranges, unsigned long nranges)
{
	struct heki_range *range = ranges;
	struct heki_range *erange = ranges + nranges;
	unsigned long attributes;
	unsigned long eva;

	while (range < erange) {
		attributes = range->attributes;
		eva = range->va;
		while (range < erange && range->attributes == attributes) {
			if (eva != range->va)
				return false;
			eva = range->va + (range->epa - range->pa);
			range++;
		}
	}
	return true;
}

static int cmp_ranges(const void *a, const void *b)
{
	const struct heki_range *ra = (const struct heki_range *) a;
	const struct heki_range *rb = (const struct heki_range *) b;

	/* Sort on attributes first, then on VA. */
	if (ra->attributes > rb->attributes)
		return 1;
	if (ra->attributes < rb->attributes)
		return -1;
	if (ra->va > rb->va)
		return 1;
	if (ra->va < rb->va)
		return -1;
	return 0;
}

/* Read in guest ranges. */
static struct heki_range *__vsm_read_ranges(u64 pa, unsigned long nranges,
					    bool need_sort)
{
	struct heki_page *heki_page;
	struct heki_range *ranges;
	struct page *page;
	unsigned long max_nranges, cur_nranges;
	size_t size;
	unsigned long n;

	if (pa & (PAGE_SIZE - 1)) {
		pr_warn("heki: list %llx not page aligned\n", pa);
		return NULL;
	}

	ranges = vmalloc(sizeof(*ranges) * nranges);
	if (!ranges) {
		pr_warn("heki: Can't allocate %ld ranges\n", nranges);
		return NULL;
	}

	max_nranges = (PAGE_SIZE - sizeof(*heki_page)) / sizeof(*ranges);

	for (n = 0; n < nranges; n += cur_nranges) {
		page = pfn_to_page(pa >> PAGE_SHIFT);
		heki_page = vmap(&page, 1, VM_MAP, PAGE_KERNEL);

		cur_nranges = heki_page->nranges;
		pa = heki_page->next_pa;

		if (cur_nranges > max_nranges || cur_nranges > (nranges - n)) {
			pr_warn("%s: Too many ranges\n", __func__);
			vfree(ranges);
			return NULL;
		}

		size = cur_nranges * sizeof(*ranges);
		memcpy(&ranges[n], heki_page->ranges, size);

		vunmap(heki_page);
	}

	if (need_sort) {
		/* Sort the ranges in ascending <type, VA> order. */
		sort(ranges, nranges, sizeof(*ranges), cmp_ranges, NULL);

		/* Check contiguity for each type. */
		if (!vsm_contiguous(ranges, nranges)) {
			vfree(ranges);
			return NULL;
		}
	}
	return ranges;
}

/*
 * Module sections are reconstructed in VTL1 and compared with VTL0 module
 * sections. Mapping the module sections in VTL1 at the same addresses as
 * in VTL0 makes symbol resolutions and relocations during reconstruction
 * simpler. We call this identity mapping.
 */
static int vsm_id_map(struct heki_mem *mem)
{
	unsigned long npages = mem->size >> PAGE_SHIFT;
	struct page **pages;
	int i, err = 0;

	pages = kzalloc(sizeof(*pages) * npages, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	/* Allocate pages. */
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i]) {
			err = -ENOMEM;
			goto free_pages;
		}
	}

	/* Map the pages into VTL1 at the same address as VTL0. */
	err = vmap_range(mem->ranges->va, mem->ranges->va + mem->size, pages);
	if (!err) {
		mem->pages = pages;
		return 0;
	}

free_pages:
	pr_warn("%s: Identity mapping failed.\n", __func__);
	for (i--; i >= 0; i--)
		__free_page(pages[i]);
	kfree(pages);
	return err;
}

static void vsm_id_unmap(struct heki_mem *mem)
{
	unsigned long i, npages;

	if (!mem->pages || mem->retain)
		return;

	vunmap_range(mem->ranges->va, mem->ranges->va + mem->size);

	npages = mem->size >> PAGE_SHIFT;
	for (i = 0; i < npages; i++)
		__free_page(mem->pages[i]);
	kfree(mem->pages);
	mem->pages = NULL;
}

/*
 * Each heki_mem instance describes a single VTL0 kernel data structure.
 * Map the data structure into VTL1 address space.
 */
static int vsm_map(struct heki_mem *mem)
{
	struct heki_range *ranges = mem->ranges;
	unsigned long nranges = mem->nranges;
	struct heki_range *range;
	struct page **pages;
	unsigned long npages;
	u64 spa, epa, pa;
	int i, p;

	mem->offset = ranges[0].va & (PAGE_SIZE - 1);

	/* Count the number of pages. */
	npages = 0;
	for (i = 0; i < nranges; i++) {
		range = &ranges[i];

		spa = ALIGN_DOWN(range->pa, PAGE_SIZE);
		epa = ALIGN(range->epa, PAGE_SIZE);
		npages += (epa - spa) >> PAGE_SHIFT;
	}

	/* Allocate an array of page struct pointers. */
	pages = kzalloc(sizeof(*pages) * npages, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	/* Get the page structure pointers. */
	for (p = 0, i = 0; i < nranges; i++) {
		range = &ranges[i];

		spa = ALIGN_DOWN(range->pa, PAGE_SIZE);
		epa = ALIGN(range->epa, PAGE_SIZE);
		for (pa = spa; pa < epa; pa += PAGE_SIZE, p++)
			pages[p] = pfn_to_page(pa >> PAGE_SHIFT);
		mem->size += range->epa - range->pa;
	}

	/* Map the pages into VTL1. */
	mem->va = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	kfree(pages);

	if (!mem->va)
		return -ENOMEM;

	mem->va += mem->offset;
	return 0;
}

static void vsm_unmap(struct heki_mem *mem)
{
	vsm_id_unmap(mem);

	if (!mem->va)
		return;

	mem->va -= mem->offset;
	vunmap(mem->va);
	mem->va = NULL;
}

static void vsm_unmap_all(struct heki_mem *mems, unsigned long nmems);

/*
 * A number of VTL0 kernel data structures can be passed to VTL1 in a single
 * call. Map all of them into VTL1 address space.
 */
static int vsm_map_all(struct heki_range *ranges, unsigned long nranges,
		       struct heki_mem *mems, unsigned long nmems)
{
	struct heki_range *range;
	struct heki_mem *mem;
	long id = -1;
	int i, ret;

	memset(mems, 0, sizeof(*mem) * nmems);

	/*
	 * The attributes field contains an identifier that identifies a VTL0
	 * kernel data structure. Collect the ranges of each VTL0 kernel data
	 * structure into its own mem.
	 */
	for (i = 0; i < nranges; i++) {
		range = &ranges[i];

		if (id == range->attributes) {
			mem->nranges++;
		} else {
			id = range->attributes;
			if (id >= nmems) {
				pr_warn("%s: Illegal ID %lx\n", __func__, id);
				return -EINVAL;
			}

			mem = &mems[id];
			if (mem->nranges) {
				pr_warn("%s: ID %lx repeated\n", __func__, id);
				return -EINVAL;
			}
			mem->ranges = range;
			mem->nranges = 1;
		}
	}

	/* Map the data structures. */
	for (id = 0; id < nmems; id++) {
		mem = &mems[id];
		if (!mem->nranges)
			continue;

		ret = vsm_map(mem);
		if (ret) {
			vsm_unmap_all(mems, nmems);
			return ret;
		}
	}
	return 0;
}

static void vsm_unmap_all(struct heki_mem *mems, unsigned long nmems)
{
	struct heki_mem *mem;
	int id;

	for (id = 0; id < nmems; id++) {
		mem = &mems[id];
		if (mem->nranges)
			vsm_unmap(mem);
	}
}

static int mshv_vsm_protect_memory(u64 pa, unsigned long nranges)
{
	struct heki_range *ranges, *range;
	unsigned long attributes, n;
	u32 permissions;
	int i, err = 0;

	/* No need to sort the ranges. */
	ranges = __vsm_read_ranges(pa, nranges, false);
	if (!ranges)
		return -EINVAL;

	/* Check all parameters before setting any permissions. */
	for (i = 0; i < nranges; i++) {
		range = &ranges[i];

		if (!PAGE_ALIGNED(range->va)) {
			pr_warn("%s: GVA not aligned: %lx\n",
				__func__, range->va);
			err = -EINVAL;
			goto out;
		}
		if (!PAGE_ALIGNED(range->pa)) {
			pr_warn("%s: GPA not aligned: %llx\n",
				__func__, range->pa);
			err = -EINVAL;
			goto out;
		}
		if (!PAGE_ALIGNED(range->epa)) {
			pr_warn("%s: GPA not aligned: %llx\n",
				__func__, range->epa);
			err = -EINVAL;
			goto out;
		}

		attributes = range->attributes;
		if (!attributes || (attributes & ~MEM_ATTR_PROT)) {
			err = -EINVAL;
			goto out;
		}
	}

	/* Walk the ranges, apply the permissions for each guest page. */
	for (i = 0; i < nranges; i++) {
		range = &ranges[i];
		attributes = range->attributes;

		permissions = 0;
		if (attributes & MEM_ATTR_READ) {
			permissions |= (HV_PAGE_READABLE |
					HV_PAGE_USER_EXECUTABLE);
		}
		if (attributes & MEM_ATTR_WRITE)
			permissions |= HV_PAGE_WRITABLE;
		if (attributes & MEM_ATTR_EXEC)
			permissions |= HV_PAGE_EXECUTABLE;

		n = (range->epa - range->pa) >> PAGE_SHIFT;
		err = hv_modify_vtl_protection_mask(range->pa, n, permissions);
		if (err) {
			pr_err("%s: failed pa=0x%llx, nranges=%lu, perm=0x%x\n",
			       __func__, range->pa, n, permissions);
			goto out;
		}
	}
out:
	vfree(ranges);
	return err;
}

static void __save_vtl0_registers(void)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);
	u64 result;

	hv_vsm_get_vtl0_register(HV_X64_REGISTER_CR0, &result);
	per_cpu->cr0_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_CR4, &result);
	per_cpu->cr4_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_LSTAR, &result);
	per_cpu->msr_lstar_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_STAR, &result);
	per_cpu->msr_star_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_CSTAR, &result);
	per_cpu->msr_cstar_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_APIC_BASE, &result);
	per_cpu->msr_apic_base_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_EFER, &result);
	per_cpu->msr_efer_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_SYSENTER_CS, &result);
	per_cpu->msr_sysenter_cs_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_SYSENTER_ESP, &result);
	per_cpu->msr_sysenter_esp_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_SYSENTER_EIP, &result);
	per_cpu->msr_sysenter_eip_saved = result;
	hv_vsm_get_vtl0_register(HV_X64_REGISTER_SFMASK, &result);
	per_cpu->msr_sfmask_saved = result;
}

static int mshv_vsm_lock_regs(void)
{
	union hv_register_cr_intercept_control ctrl;
	int ret;

	ctrl.as_uint64 = 0;
	ctrl.cr0_write = 1;
	ctrl.cr4_write = 1;
	ctrl.gdtr_write = 1;
	ctrl.idtr_write = 1;
	ctrl.ldtr_write = 1;
	ctrl.tr_write = 1;
	ctrl.msr_lstar_write = 1;
	ctrl.msr_star_write = 1;
	ctrl.msr_cstar_write = 1;
	ctrl.apic_base_msr_write = 1;
	ctrl.msr_efer_write = 1;
	ctrl.msr_sysenter_cs_write = 1;
	ctrl.msr_sysenter_eip_write = 1;
	ctrl.msr_sysenter_esp_write = 1;
	ctrl.msr_sfmask_write = 1;

	__save_vtl0_registers();

	ret = hv_vsm_set_register(HV_X64_REGISTER_CR_INTERCEPT_CONTROL, ctrl.as_uint64);
	if (ret)
		return ret;

	ret = hv_vsm_set_register(HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK, (u64)CR4_PIN_MASK);
	if (ret)
		return ret;

	ret = hv_vsm_set_register(HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK, (u64)CR0_PIN_MASK);
	return ret;
}

int x509_load_certificate_list(const u8 cert_list[],
			       const unsigned long list_size,
			       const struct key *keyring);

int restrict_link_by_trusted(struct key *dest_keyring, const struct key_type *type,
			     const union key_payload *payload, struct key *restrict_key)
{
	/* Only keys vouched for by vtl0.trusted_keys can be added */
	return restrict_link_by_signature(dest_keyring, type, payload, vtl0.trusted_keys);
}

static int mshv_vsm_create_trusted_keys(void)
{
	struct heki_mem *mem = &vtl0.mem[HEKI_MODULE_CERTS];
	void *certs = mem->va;
	unsigned long certs_size = mem->size;
	struct key_restriction *restriction;
	int ret = 0;

	if (vtl0.trusted_keys) {
		/* Can only load this once. */
		pr_warn("%s: Certificates already loaded\n", __func__);
		ret = -EINVAL;
		goto unmap;
	}

	restriction = kzalloc(sizeof(*restriction), GFP_KERNEL);
	if (!restriction) {
		pr_warn("Can't allocate secondary trusted keyring restriction\n");
		ret = -ENOMEM;
		goto unmap;
	}
	restriction->check = restrict_link_by_trusted;

	vtl0.trusted_keys =
		keyring_alloc(".guest_trusted_keys",
			      GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
				  KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH |
				  KEY_USR_WRITE),
			      KEY_ALLOC_NOT_IN_QUOTA,
			      restriction, NULL);
	if (!vtl0.trusted_keys) {
		pr_warn("%s: Could not allocate trusted keyring\n", __func__);
		ret = -ENOMEM;
		goto unmap;
	}

	/* Populate a trusted keyring with VTL0 module certificates. */
	ret = x509_load_certificate_list(certs, certs_size, vtl0.trusted_keys);
	if (ret) {
		pr_warn("%s: Can't populate trusted keyring\n", __func__);
		key_put(vtl0.trusted_keys);
		vtl0.trusted_keys = NULL;
	} else {
		pr_debug("%s: Created trusted keys\n", __func__);
	}

unmap:
	vsm_unmap(mem);
	return ret;
}

static int mshv_vsm_save_secondary_key(u64 pa, unsigned long nranges)
{
	struct heki_range *ranges;
	struct heki_mem mem;
	void *key_data;
	size_t key_data_size;
	key_ref_t key_ref;
	int ret = 0;

	if (!vtl0.trusted_keys) {
		pr_warn("%s: VTL0 trusted keyring not initialized\n", __func__);
		return -EINVAL;
	}

	ranges = __vsm_read_ranges(pa, nranges, true);
	if (!ranges) {
		pr_warn("Failed to read ranges\n");
		return -ENOMEM;
	}

	memset(&mem, 0, sizeof(mem));
	mem.ranges = ranges;
	mem.nranges = nranges;

	ret = vsm_map(&mem);
	if (ret) {
		pr_info("Failed to map ranges\n");
		goto free_ranges;
	}

	key_data = mem.va;
	key_data_size = mem.size;

	key_ref = key_create_or_update(make_key_ref(vtl0.trusted_keys, true), "asymmetric", NULL,
				       key_data, key_data_size, KEY_PERM_UNDEF, KEY_ALLOC_IN_QUOTA);

	if (IS_ERR(key_ref)) {
		pr_warn("Failed to add secondary key: %ld", PTR_ERR(key_ref));
		ret = PTR_ERR(key_ref);
	} else {
		pr_info("Added secondary key: %d, %s\n",
			key_ref_to_ptr(key_ref)->serial, key_ref_to_ptr(key_ref)->description);
		key_ref_put(key_ref);
	}

	vsm_unmap(&mem);
free_ranges:
	vfree(ranges);
	return ret;
}

static void *vsm_vtl0_va_to_vtl1_va(struct heki_mem *mem, void *va)
{
	void *vtl0_va = (void *)mem->ranges->va;
	unsigned long offset;

	if (va >= vtl0_va && va < (vtl0_va + mem->size)) {
		offset = va - vtl0_va;
		return mem->va + offset;
	}
	return NULL;
}

static void *vsm_vtl1_va_to_vtl0_va(struct heki_mem *mem, void *va)
{
	void *vtl0_va = (void *)mem->ranges->va;
	unsigned long offset;

	if (va >= mem->va && va < (mem->va + mem->size)) {
		offset = va - mem->va;
		return vtl0_va + offset;
	}
	return NULL;
}

static int mshv_vsm_get_kinfo(void)
{
	struct heki_mem *data_mem = &vtl0.mem[HEKI_KERNEL_DATA];
	struct heki_mem *info_mem = &vtl0.mem[HEKI_KERNEL_INFO];
	struct heki_kinfo *kinfo = info_mem->va;
	unsigned long nsyms;

	/*
	 * Convert VTL0 addresses to VTL1 addresses so we can access the
	 * symbol tables.
	 */
	nsyms = kinfo->ksymtab_end - kinfo->ksymtab_start;
	kinfo->ksymtab_start = vsm_vtl0_va_to_vtl1_va(data_mem, kinfo->ksymtab_start);
	kinfo->ksymtab_end = kinfo->ksymtab_start + nsyms;

	nsyms = kinfo->ksymtab_gpl_end - kinfo->ksymtab_gpl_start;
	kinfo->ksymtab_gpl_start = vsm_vtl0_va_to_vtl1_va(data_mem, kinfo->ksymtab_gpl_start);
	kinfo->ksymtab_gpl_end = kinfo->ksymtab_gpl_start + nsyms;

	return 0;
}

static int mshv_vsm_load_kdata(u64 pa, unsigned long nranges)
{
	struct heki_range *ranges;
	int ret;

	ranges = __vsm_read_ranges(pa, nranges, true);
	if (!ranges)
		return -ENOMEM;

	ret = vsm_map_all(ranges, nranges, vtl0.mem, HEKI_KDATA_MAX);
	if (ret)
		goto free_ranges;

	ret =  mshv_vsm_create_trusted_keys();
	if (ret)
		goto free_ranges;

	ret = mshv_vsm_get_kinfo();

free_ranges:
	return ret;
}

void module_id_unmap(struct heki_mod *hmod);

/*
 * Module contents are reconstructed in VTL1 when a module is loaded in VTL0.
 * Part of this is symbol resolution and module relocation. This is simpler
 * to do if we map the module copy in VTL1 at the same exact addresses as the
 * original module in VTL0.
 */
int module_id_map(struct heki_mod *hmod)
{
	struct module_memory *mod_mem;
	int err;

	for_each_mod_mem_type(type) {
		if (!hmod->mem[type].size)
			continue;

		err = vsm_id_map(&hmod->mem[type]);
		if (err)
			goto unmap;
	}

	for_each_mod_mem_type(type) {
		if (!hmod->mem[type].size)
			continue;

		mod_mem = &hmod->mod->mem[type];
		mod_mem->base = (void *)hmod->mem[type].ranges->va;
		memset(mod_mem->base, 0, hmod->mem[type].size);
		/*
		 * Initialize the size to 0 here. layout_sections() will
		 * add section sizes to the size field.
		 */
		mod_mem->size = 0;
	}

	return 0;
unmap:
	module_id_unmap(hmod);
	return err;
}

void module_id_unmap(struct heki_mod *hmod)
{
	for_each_mod_mem_type(type) {
		if (!hmod->mem[type].size)
			continue;
		vsm_id_unmap(&hmod->mem[type]);
	}
}

static int vsm_set_module_permissions(struct heki_mod *hmod, int type,
				      unsigned long attributes, bool free)
{
	struct heki_mem *mem = &hmod->mem[type];
	unsigned long permissions;
	struct heki_range *range;
	int i, n, err = 0;

	if (!mem->nranges)
		return 0;

	for (i = 0; i < mem->nranges; i++) {
		range = &mem->ranges[i];

		permissions = 0;
		if (attributes & MEM_ATTR_READ) {
			permissions |= (HV_PAGE_READABLE |
					HV_PAGE_USER_EXECUTABLE);
		}
		if (attributes & MEM_ATTR_WRITE)
			permissions |= HV_PAGE_WRITABLE;
		if (attributes & MEM_ATTR_EXEC)
			permissions |= HV_PAGE_EXECUTABLE;

		n = (range->epa - range->pa) >> PAGE_SHIFT;
		err = hv_modify_vtl_protection_mask(range->pa, n, permissions);
		if (err) {
			pr_warn("%s: %s: Didn't set permissions for type %d\n",
				__func__, hmod->name, type);
			break;
		}
	}

	if (free && !mem->retain) {
		mem->ranges = NULL;
		mem->nranges = 0;
	}

	return err;
}

static int vsm_set_guest_module_permissions(struct heki_mod *hmod)
{
	unsigned long permissions;
	int err = 0;

	for_each_mod_mem_type(type) {
		switch (type) {
		case MOD_TEXT:
			permissions = MEM_ATTR_READ | MEM_ATTR_EXEC;
			break;
		case MOD_DATA:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		case MOD_RODATA:
			permissions = MEM_ATTR_READ;
			break;
		case MOD_RO_AFTER_INIT:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		case MOD_INIT_TEXT:
			permissions = MEM_ATTR_READ | MEM_ATTR_EXEC;
			break;
		case MOD_INIT_DATA:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		case MOD_INIT_RODATA:
			permissions = MEM_ATTR_READ;
			break;
		default:
			continue;
		}

		err = vsm_set_module_permissions(hmod, type, permissions, false);
		if (err)
			break;
	}
	return err;
}

static int vsm_free_guest_module_init(long token)
{
	struct heki_mod *hmod;
	bool found;
	unsigned long permissions;
	int err = 0;

	mutex_lock(&vtl0.lock);

	found = false;
	list_for_each_entry(hmod, &vtl0.modules, node) {
		if (hmod->token == token) {
			found = true;
			break;
		}
	}

	if (!found) {
		/* Silently ignore the request. */
		goto unlock;
	}

	for_each_mod_mem_type(type) {
		bool free = true;

		switch (type) {
		case MOD_RO_AFTER_INIT:
			permissions = MEM_ATTR_READ;
			free = false;
			break;
		case MOD_INIT_TEXT:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		case MOD_INIT_DATA:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		case MOD_INIT_RODATA:
			permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
			break;
		default:
			continue;
		}

		err = vsm_set_module_permissions(hmod, type, permissions, free);
		if (err)
			break;
	}
unlock:
	mutex_unlock(&vtl0.lock);
	return err;
}

static void vsm_resolve_func(char *name, Elf64_Sym *sym);

static long mshv_vsm_validate_guest_module(u64 pa, unsigned long nranges,
					   int flags)
{
	struct load_info *info = &vtl0.info;
	struct heki_mem *info_mem;
	struct heki_mod *hmod;
	struct heki_range *ranges;
	long err = 0;

	if (!vtl0.trusted_keys) {
		pr_warn("%s: No trusted keys present!\n", __func__);
		return -EINVAL;
	}

	/* Read the module content ranges. */
	ranges = __vsm_read_ranges(pa, nranges, true);
	if (!ranges) {
		pr_warn("%s: Could not allocate ranges!\n", __func__);
		return -ENOMEM;
	}

	mutex_lock(&vtl0.lock);

	memset(info, 0, sizeof(*info));

	/* Allocate a heki module structure. */
	hmod = kzalloc(sizeof(*hmod), GFP_KERNEL);
	if (!hmod) {
		pr_warn("%s: Could not allocate heki module\n", __func__);
		err = -ENOMEM;
		goto unlock;
	}
	vtl0.hmod = hmod;

	err = vsm_map_all(ranges, nranges, hmod->mem, MOD_ELF + 1);
	if (err) {
		pr_warn("%s: Could not map module sections\n", __func__);
		goto unmap;
	}

	/* Load the module ELF buffer and trusted keys. */
	info_mem = &hmod->mem[MOD_ELF];
	info->hdr = info_mem->va;
	info->len = info_mem->size;
	info->trusted_keys = vtl0.trusted_keys;

	/* Load kinfo for post-relocation fixes. */
	current->kinfo = vtl0.mem[HEKI_KERNEL_INFO].va;

	/*
	 * The ELF buffer will be used to construct a copy of the guest module
	 * in the host. The trusted keys will be used to verify the signature
	 * of the guest module. After the copy is created, it will be compared
	 * with the module contents passed by the guest to validate them.
	 */
	err = validate_guest_module(info, flags, hmod, vsm_resolve_func);
	if (err) {
		pr_warn("%s: Load guest module failed\n", __func__);
		err = -EINVAL;
		goto unmap;
	}

	/* Set permissions for all module sections in the EPT. */
	strscpy(hmod->name, info->name, MODULE_NAME_LEN);
	hmod->ranges = ranges;

	err = vsm_set_guest_module_permissions(hmod);
	if (err) {
		pr_warn("%s: Could not set module permissions\n", __func__);
		goto unmap;
	}

	/*
	 * Add the guest module to a modules list and assign an
	 * authentication token for it. Return the token.
	 */
	hmod->token = ++vtl0.token;
	list_add(&hmod->node, &vtl0.modules);
	err = hmod->token;

	/*
	 * We want to retain the following until module unload.
	 *	MOD_DATA	contains the module structure (hmod->mod).
	 */
	hmod->mem[MOD_DATA].retain = true;
	hmod->mem[MOD_RODATA].retain = true;
unmap:
	current->kinfo = NULL;
	/* Free everything that we don't need beyond this point. */
	vsm_unmap_all(hmod->mem, MOD_ELF + 1);
	if (err < 0)
		kfree(hmod);
unlock:
	mutex_unlock(&vtl0.lock);

	if (err < 0)
		vfree(ranges);
	return err;
}

static int vsm_cmp_func(const void *name, const void *ksym)
{
	return strcmp(name, kernel_symbol_name(ksym));
}

static void vsm_resolve_func(char *name, Elf64_Sym *sym)
{
	struct heki_kinfo *kinfo = vtl0.mem[HEKI_KERNEL_INFO].va;
	struct kernel_symbol *ksym;
	struct heki_mod *hmod;
	struct heki_mem *mem;
	struct module *mod = NULL;
	void *addr;
	int offset;

	/* Search the kernel symbol tables. */
	mem = &vtl0.mem[HEKI_KERNEL_DATA];

	ksym = bsearch(name, kinfo->ksymtab_start,
		       kinfo->ksymtab_end - kinfo->ksymtab_start,
		       sizeof(struct kernel_symbol), vsm_cmp_func);
	if (ksym)
		goto found;

	ksym = bsearch(name, kinfo->ksymtab_gpl_start,
		       kinfo->ksymtab_gpl_end - kinfo->ksymtab_gpl_start,
		       sizeof(struct kernel_symbol), vsm_cmp_func);
	if (ksym)
		goto found;

	/* Search the symbol tables of other modules. */
	list_for_each_entry(hmod, &vtl0.modules, node) {
		mem = &hmod->mem[MOD_RODATA];
		mod = hmod->mod;

		ksym = bsearch(name, mod->syms, mod->num_syms,
			       sizeof(struct kernel_symbol), vsm_cmp_func);
		if (ksym)
			goto found;

		ksym = bsearch(name, mod->gpl_syms, mod->num_gpl_syms,
			       sizeof(struct kernel_symbol), vsm_cmp_func);
		if (ksym)
			goto found;
	}
	return;
found:
	offset = ksym->value_offset;
	addr = &ksym->value_offset;
	if (!mod) {
		/*
		 * Modules are mapped in VTL1 at the same addresses as the
		 * corresponding modules in VTL0. So, there is no need to
		 * translate for modules.
		 */
		addr = vsm_vtl1_va_to_vtl0_va(mem, addr);
	}
	sym->st_value = (unsigned long)addr + offset;
}

static int vsm_unload_guest_module(long token)
{
	struct heki_mod *hmod;
	bool found;
	unsigned long permissions;

	mutex_lock(&vtl0.lock);

	found = false;
	list_for_each_entry(hmod, &vtl0.modules, node) {
		if (hmod->token == token) {
			found = true;
			break;
		}
	}

	if (!found) {
		/* Silently ignore the request. */
		goto unlock;
	}

	for_each_mod_mem_type(type) {
		permissions = MEM_ATTR_READ | MEM_ATTR_WRITE;
		vsm_set_module_permissions(hmod, type, permissions, true);
	}

	list_del(&hmod->node);

	hmod->mem[MOD_DATA].retain = false;
	hmod->mem[MOD_RODATA].retain = false;
	vsm_unmap_all(hmod->mem, MOD_ELF + 1);

	vfree(hmod->ranges);
	kfree(hmod);
unlock:
	mutex_unlock(&vtl0.lock);
	return 0;
}

/********************** Boot Secondary CPUs **********************/
static int mshv_vsm_boot_aps(unsigned int cpu_online_mask_pfn,
							unsigned int boot_signal_pfn)
{
	unsigned int cpu, present = num_present_cpus(), online = num_online_cpus(),
		total_cpus_booted = 0;
	struct hv_vsm_per_cpu *per_cpu;
	const struct cpumask *cpu_online_vtl0;
	struct page *boot_signal_page, *cpu_online_page;
	void *boot_signal_data = NULL, *cpu_online_data = NULL;
	cpumask_var_t cpu_online_diff;
	int status = 0;

	if (!(present - online)) {
		pr_debug("%s: VTL1 kernel has no present CPUs that are not already online.\n", __func__);
		return -EINVAL;
	}

	per_cpu = this_cpu_ptr(&vsm_per_cpu);
	per_cpu->stay_in_vtl1 = true;
	/* Validate boot_signal_pfn parameter */
	boot_signal_page = pfn_to_page(boot_signal_pfn);
	boot_signal_data = vmap(&boot_signal_page, 1, VM_MAP, PAGE_KERNEL);
	if (!boot_signal_data) {
		pr_err("%s: Could not map shared page", __func__);
		status = -EINVAL;
		goto out;
	}

	status = hv_secure_vtl_init_boot_signal_page(boot_signal_data);
	if (status) {
		pr_err("%s: Could not initialize boot_signal", __func__);
		goto unmap_signal;
	}

	/* Validate cpu_online_mask_pfn parameter */
	cpu_online_page = pfn_to_page(cpu_online_mask_pfn);
	cpu_online_data = vmap(&cpu_online_page, 1, VM_MAP, PAGE_KERNEL);
	if (!cpu_online_data) {
		pr_err("%s: Could not map shared page", __func__);
		status = -EINVAL;
		goto unmap_signal;
	}
	cpu_online_vtl0 = (struct cpumask *)cpu_online_data;

	/* Find VTL0's Online CPUs that are not already online in VTL1 */
	if (!alloc_cpumask_var(&cpu_online_diff, GFP_KERNEL)) {
		pr_err("%s: Error allocating cpu_online_diff", __func__);
		status = -ENOMEM;
		goto unmap_online;
	}
	status = cpumask_andnot(cpu_online_diff, cpu_online_vtl0, cpu_online_mask);
	if (!status) {
		pr_err("%s: Error computing cpumask_andnot()", __func__);
		goto free_cpumask;
	}

	/* Loop through VTL0's online CPUs that are not already online in VTL1
	 * and bring them online
	 */
	for_each_cpu(cpu, cpu_online_diff) {
		if (!cpu_present(cpu)) {
			pr_err("%s: Cannot bring up CPU%u because CPU%u is not present",
			       __func__, cpu, cpu);
			status = -EINVAL;
			goto free_cpumask;
		}

		per_cpu = per_cpu_ptr(&vsm_per_cpu, cpu);

		if (!(per_cpu->vtl1_enabled)) {
			pr_err("%s: Cannot bring up CPU%u because CPU%u is not enabled for VTL1",
			       __func__, cpu, cpu);
			status = -EINVAL;
			goto free_cpumask;
		}

		per_cpu->vtl1_booted = 0;
		pr_debug("%s: Bringing up CPU%u", __func__, cpu);

		/* Bring up AP */
		status = cpu_device_up(get_cpu_device(cpu));
		if (status) {
			pr_err("%s: Failed to Boot CPU%u", __func__, cpu);
			goto free_cpumask;
		}

		total_cpus_booted++;
	}

	/* Loop through newly booted CPUs and disable tick when exiting VTL1 */
	for_each_cpu(cpu, cpu_online_diff) {
		per_cpu = per_cpu_ptr(&vsm_per_cpu, cpu);

		while (!(per_cpu->vtl1_booted));
		per_cpu->suppress_tick = true;
	}

	pr_debug("%s: Booted %u CPUs", __func__, total_cpus_booted);

free_cpumask:
	free_cpumask_var(cpu_online_diff);
unmap_online:
	vunmap(cpu_online_data);
unmap_signal:
	vunmap(boot_signal_data);
out:
	per_cpu = this_cpu_ptr(&vsm_per_cpu);
	per_cpu->stay_in_vtl1 = false;
	return status;
}

/* DO NOT MODIFY THIS FUNCTION WITHOUT DISASSEMBLING AND SEEING WHAT IS GOING ON */
static void __mshv_vsm_vtl_return(void)
{
	register struct hv_vtl_cpu_context *cpu_context asm ("rcx");
	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");
	register u64 r12 asm("r12");
	register u64 r13 asm("r13");
	register u64 r14 asm("r14");
	register u64 r15 asm("r15");
	register u64 hcall_addr asm ("rax");
	struct hv_vp_assist_page *hvp;

	hcall_addr = (u64)((u8 *)hv_hypercall_pg + vsm_code_page_offsets.vtl_return_offset);
	/*
	 * All VTL0 registers are saved and restored. The only exception for now is VTL0
	 * rax and rcx. This is a non-issue if the entry reason is HvVtlEntryVtlCall since VTL0
	 * will take care of saving an restoring rax and rcx. However if the entry reason is
	 * HvVtlEntryInterrupt, VTL0 rax and rcx are lost. Only way to fix this is to implement
	 * the jump into hypercall page for return to VTL0. The first part before vmcall restores
	 * all VTL0 registers and the part after vmcall saves. For registers r8-r15 the compiler
	 * translates the following c code into write of value in cpu_context->r# to actual cpu
	 * register r# prior to vmcall and save the content of cpu register r# into cpu_context->r#
	 * post vmcall.
	 *		 register u64 r# asm("r#");
	 *		 r# = cpu_context->r#;
	 *		 asm __volatile(some instruction
	 *				some instruction
	 *				vmcall
	 *				some instruction
	 *				some instruction
	 *				: +r(r#)
	 *				:
	 *				:);
	 *		cpu_context->r# = r#;
	 * For registers rdx, rbx, rdi and rsi the complier again translates the following c code
	 * into restoring and saving of these registers from/to corresponding cpu_context-># across
	 * the vmcall.
	 *		 asm __volatile(some instruction
	 *				some instruction
	 *				vmcall
	 *				some instruction
	 *				some instruction
	 *				: "+d"(cpu_context->rdx), "+b"(cpu_context->rbx),
	 *				  "+S"(cpu_context->rsi), "+D"(cpu_context->rdi)
	 *				:
	 *				:);
	 * rbp alone requires explicit restore and save which is performed in the inline
	 * assembly code below.
	 *
	 * Regarding VTL1 registers only VTL1 rbp and rcx are saved and restored. rcx is
	 * saved and restored so as to preserve pointer to cpu_context across vmcall. rbp
	 * is weird since sometimes it gets used before the exit of __mshv_vsm_vtl_return
	 * and not saving and restoring can lead to crashes
	 * There is very little happening in this function post vmcall, just minimal saving
	 * of VTL0 context into cpu_context which is stored in rax. Technically no other
	 * VTL1 register gets used in this function post vmcall. As per x64 function calling
	 * conventions registers rbx, rbp and r12-r15 are callee saved and hence the compiler
	 * automatically saves and restores them across the boundary of a function call i.e.
	 * when __mshv_vsm_vtl_return exits these registers are restored. Rest of the registers
	 * are caller saved and the caller of __mshv_vsm_vtl_return takes care of saving and
	 * restoring. Thus no other VTL1 register needs explicit saving and restoring.
	 */
	cpu_context = &this_cpu_ptr(&vsm_per_cpu)->cpu_context;
	hvp = hv_vp_assist_page[smp_processor_id()];

	hvp->vtl_ret_x64rax = cpu_context->rax;
	hvp->vtl_ret_x64rcx = cpu_context->rcx;

	asm __volatile__("pushq %%rbp\n"	// Save VTL1 rbp
			 "pushq %%rcx\n"	// Push VTL1 rax i.e. save *cpu_context
			 :
			 : "c"(cpu_context)
			 : );
	r8 = cpu_context->r8;
	r9 = cpu_context->r9;
	r10 = cpu_context->r10;
	r11 = cpu_context->r11;
	r12 = cpu_context->r12;
	r13 = cpu_context->r13;
	r14 = cpu_context->r14;
	r15 = cpu_context->r15;
	asm __volatile__("movq %0, %%rbp\n"	// Load rbp with saved VTL0 rbp
			 "xorl  %%ecx, %%ecx\n"	// Load return kind into rcx.
			 CALL_NOSPEC		// VTL call
			 "pushq %%rax\n"	// Push VTL0 rax into stack
			 "pushq %%rcx\n"	// Push VTL0 rcx into stack to align at 16 bytes
			 "movq 16(%%rsp), %%rcx\n" // Restore rax to *cpu_context
			 "movq %%rbp, %0\n"	// Save VTL0 rbp
			 "popq %1\n"	// Save VTL0 rcx
			 "popq %2\n"	// Save VTL0 rax
			 "movq 8(%%rsp), %%rbp\n"	// Restore VTL1 rbp
			 "addq $16, %%rsp\n"	// Restore VTL1 stack to prior condition
			 : "+m"(cpu_context->rbp), "=m"(cpu_context->rcx), "=m"(cpu_context->rax),
			   "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11), "+r"(r12), "+r"(r13),
			   "+r"(r14), "+r"(r15), "+d"(cpu_context->rdx), "+b"(cpu_context->rbx),
			   "+S"(cpu_context->rsi), "+D"(cpu_context->rdi)
			 : THUNK_TARGET(hcall_addr)
			 : "memory", "cc");
	cpu_context->r8 = r8;
	cpu_context->r9 = r9;
	cpu_context->r10 = r10;
	cpu_context->r11 = r11;
	cpu_context->r12 = r12;
	cpu_context->r13 = r13;
	cpu_context->r14 = r14;
	cpu_context->r15 = r15;
}

static void mshv_vsm_vtl_idle(void)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	if (!per_cpu->vsm_task)
		goto out;

	if (task_is_running(per_cpu->vsm_task) || !(per_cpu->vtl1_booted) || per_cpu->stay_in_vtl1)
		goto out;

	if (per_cpu->suppress_tick)
		tick_suspend_local();

	kernel_fpu_begin_mask(0);
	__mshv_vsm_vtl_return();

	kernel_fpu_end();
	per_cpu = this_cpu_ptr(&vsm_per_cpu);
	if (per_cpu->suppress_tick)
		tick_resume_local();
	wake_up_process(per_cpu->vsm_task);

out:
	raw_local_irq_enable();
}

static void mshv_vsm_handle_entry(struct hv_vtlcall_param *_vtl_params)
{
	int status = -EINVAL;

	switch (_vtl_params->a0) {
	case VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL:
		pr_debug("%s : VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL\n", __func__);
		status = mshv_vsm_enable_aps(_vtl_params->a1);
		break;
	case VSM_VTL_CALL_FUNC_ID_BOOT_APS:
		pr_debug("%s : VSM_VTL_CALL_FUNC_ID_BOOT_APS\n", __func__);
		status = mshv_vsm_boot_aps(_vtl_params->a1, _vtl_params->a2);
		break;
	case VSM_VTL_CALL_FUNC_ID_LOCK_REGS:
		pr_debug("%s : VSM_LOCK_REGS\n", __func__);
		if (!vtl0_end_of_boot)
			status = mshv_vsm_lock_regs();
		break;
	case VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT:
		pr_debug("%s: VSM_SIGNAL_END_OF_BOOT\n", __func__);
		vtl0_end_of_boot = true;
		status = 0;
		break;
	case VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY:
		pr_debug("%s : VSM_PROTECT_MEMORY\n", __func__);
		if (!vtl0_end_of_boot)
			status = mshv_vsm_protect_memory(_vtl_params->a1, _vtl_params->a2);
		break;
	case VSM_VTL_CALL_FUNC_ID_LOAD_KDATA:
		pr_debug("%s : VSM_LOAD_KDATA\n", __func__);
		if (!vtl0_end_of_boot)
			status = mshv_vsm_load_kdata(_vtl_params->a1, _vtl_params->a2);
		break;
	case VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE:
		pr_debug("%s : VSM_VALIDATE_MODULE\n", __func__);
		status = mshv_vsm_validate_guest_module(_vtl_params->a1,
							_vtl_params->a2,
							_vtl_params->a3);
		break;
	case VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT:
		pr_debug("%s : VSM_FREE_MODULE_INIT\n", __func__);
		status = vsm_free_guest_module_init(_vtl_params->a1);
		break;
	case VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE:
		pr_debug("%s : VSM_UNLOAD_MODULE\n", __func__);
		status = vsm_unload_guest_module(_vtl_params->a1);
		break;
	case VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY:
		pr_debug("%s : VSM_COPY_SECONDARY_KEY\n", __func__);
		status = mshv_vsm_save_secondary_key(_vtl_params->a1, _vtl_params->a2);
		break;
	default:
		pr_err("%s: Wrong Command:0x%llx sent into VTL1\n", __func__, _vtl_params->a0);
		break;
	}
	if (status < 0)
		pr_err("%s: func id:0x%llx failed\n", __func__, _vtl_params->a0);
	else
		pr_debug("%s: func id:0x%llx is ok\n", __func__, _vtl_params->a0);
	_vtl_params->a3 = status;
}

static int mshv_vsm_vtl_task(void *unused)
{
	struct hv_vp_assist_page *hvp;
	struct hv_vsm_per_cpu *per_cpu;
	struct hv_vtl_cpu_context *cpu_context;
	struct hv_vtlcall_param *vtl_params;

	while (true) {
		hvp = hv_vp_assist_page[smp_processor_id()];
		switch (hvp->vtl_entry_reason) {
		case VTL_ENTRY_REASON_LOWER_VTL_CALL:
			/*
			 *  VTL0 can pass four arguments to VTL1 in registers rdi,
			 *  rsi, rdx and r8 respectively. r8 is also used to pass
			 *  success or failure back to VTL0. Copy these arguments
			 *  to vtl_params structure on entry. Copy vtl_params
			 *  out to cpu_context on vtl exit so that _mshv_vtl_return
			 *  populates these registers with return values from vtl1.
			 */
			per_cpu = this_cpu_ptr(&vsm_per_cpu);
			cpu_context = &per_cpu->cpu_context;
			vtl_params = &per_cpu->vtl_params;

			vtl_params->a0 = cpu_context->rdi;
			vtl_params->a1 = cpu_context->rsi;
			vtl_params->a2 = cpu_context->rdx;
			vtl_params->a3 = cpu_context->r8;

			pr_debug("CPU%u: MSHV_ENTRY_REASON_LOWER_VTL_CALL\n", smp_processor_id());
			mshv_vsm_handle_entry(vtl_params);

			cpu_context->rdi = vtl_params->a0;
			cpu_context->rsi = vtl_params->a1;
			cpu_context->rdx = vtl_params->a2;
			cpu_context->r8 =  vtl_params->a3;
			break;
		case VTL_ENTRY_REASON_INTERRUPT:
			/* ToDo: Some kind of refcounting here */
			break;
		default:
			pr_err("CPU%u: Unknown entry reason: %d",
			       smp_processor_id(), hvp->vtl_entry_reason);
			break;
		}
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return 0;
}

static void mshv_vsm_set_secure_config_vtl0(void)
{
	union hv_register_vsm_vp_secure_vtl_config vsm_vp_secure_vtl_config;

	vsm_vp_secure_vtl_config.as_u64 = 0;
	vsm_vp_secure_vtl_config.mbec_enabled = 1;
	vsm_vp_secure_vtl_config.tlb_locked = 0;
	vsm_vp_secure_vtl_config.reserved = 0;

	hv_vsm_set_register(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, vsm_vp_secure_vtl_config.as_u64);
}

static int mshv_vsm_configure_partition(void)
{
	union hv_register_vsm_partition_config config;

	config.as_u64 = 0;
	config.default_vtl_protection_mask = HV_PAGE_FULL_ACCESS;
	config.enable_vtl_protection = 1;
//	config.zero_memory_on_reset = 1;
//	config.intercept_vp_startup = 1;
//	config.intercept_cpuid_unimplemented = 1;

//	if (mshv_vsm_capabilities.intercept_page_available) {
//		pr_debug("%s: using intercept page", __func__);
//		config.intercept_page = 1;
//	}

	return hv_vsm_set_register(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64);
}

static u64 mshv_vsm_get_msr(unsigned int reg)
{
	if (hv_parent_partition())
		return hv_get_non_nested_msr(reg);
	return hv_get_msr(reg);
}

static void mshv_vsm_set_msr(unsigned int reg, u64 value)
{
	if (hv_parent_partition())
		hv_set_non_nested_msr(reg, value);
	else
		hv_set_msr(reg, value);
}

static int mshv_vsm_per_cpu_synic_init(unsigned int cpu)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);
	union hv_synic_simp simp;
	union hv_synic_sint sint;
	union hv_synic_scontrol sctrl;

	simp.as_uint64 = mshv_vsm_get_msr(HV_MSR_SIMP);
	if (hv_parent_partition()) {
		/* Setup the Synic's message page */
		per_cpu->synic_message_page = memremap(simp.base_simp_gpa << HV_HYP_PAGE_SHIFT,
				HV_HYP_PAGE_SIZE, MEMREMAP_WB);
		if (!per_cpu->synic_message_page) {
			pr_err("%s: SIMP memremap failed\n", __func__);
			return -EFAULT;
		}
	} else {
		per_cpu->synic_message_page = (void *)get_zeroed_page(GFP_ATOMIC);
		if (!per_cpu->synic_message_page) {
			pr_err("%s: Unable to allocate SYNIC message page\n", __func__);
			return -ENOMEM;
		}
		simp.base_simp_gpa = virt_to_phys(per_cpu->synic_message_page) >> HV_HYP_PAGE_SHIFT;
	}
	simp.simp_enabled = 1;
	mshv_vsm_set_msr(HV_MSR_SIMP, simp.as_uint64);

#ifdef HYPERVISOR_CALLBACK_VECTOR
	/* Enable intercepts */
	sint.as_uint64 = mshv_vsm_get_msr(HV_MSR_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX);
	sint.vector = HYPERVISOR_CALLBACK_VECTOR;
	sint.masked = false;
	sint.auto_eoi = hv_recommend_using_aeoi();
	mshv_vsm_set_msr(HV_MSR_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX,
			 sint.as_uint64);
#endif

	/* Enable the global synic bit */
	sctrl.as_uint64 = mshv_vsm_get_msr(HV_MSR_SCONTROL);
	sctrl.enable = 1;
	mshv_vsm_set_msr(HV_MSR_SCONTROL, sctrl.as_uint64);

	return 0;
}

static int mshv_vsm_per_cpu_init(unsigned int cpu)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	memset(per_cpu, 0, sizeof(*per_cpu));

	per_cpu->vsm_task = kthread_create(mshv_vsm_vtl_task, NULL, "vsm_task");
	kthread_bind(per_cpu->vsm_task, cpu);

	mshv_vsm_set_secure_config_vtl0();

	/* Enable tasklet to handle the intercepts */
	tasklet_init(&per_cpu->handle_intercept, mshv_vsm_handle_intercept,
		     (unsigned long)per_cpu);

	if (mshv_vsm_per_cpu_synic_init(cpu)) {
		pr_err("%s: Could not init synic for cpu%d\n", __func__, cpu);
		tasklet_kill(&per_cpu->handle_intercept);
	}

	per_cpu->vtl1_booted = true;
	return 0;
}

static bool enable_ioctl = true;
static long mshv_vsm_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret = 0;
	struct hv_vsm_per_cpu *per_cpu;

	switch (ioctl) {
	case HV_RETURN_TO_LOWER_VTL:
		if (enable_ioctl) {
			enable_ioctl = false; // IOCTL is used only once

			/*
			 * Schedule the main kthread that will deal with entry/exit from VTL1 and
			 * put the init process to sleep.
			 */
			per_cpu = this_cpu_ptr(&vsm_per_cpu);
			per_cpu->suppress_tick = true;
			hv_vtl_set_idle(mshv_vsm_vtl_idle);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
		}
		break;
	default:
		pr_err("%s: invalid vtl ioctl: %#x\n", __func__, ioctl);
		ret = -ENOTTY;
	}

	return ret;
}

static const struct file_operations mshv_vtl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mshv_vsm_vtl_ioctl,
};

static struct miscdevice mshv_vsm_dev = {
	.name = "mshv_vsm_dev",
	.nodename = "mshv_vsm_dev",
	.fops = &mshv_vtl_fops,
	.mode = 0400,
	.minor = MISC_DYNAMIC_MINOR,
};

static int __init mshv_vtl1_init(void)
{
	int i, ret = 0;
	struct boot_e820_entry *e820_table;
	u32 permissions = 0;

	ret = misc_register(&mshv_vsm_dev);

	if (ret) {
		pr_err("VSM: Could not register mshv_vsm_vtl_ioctl\n");
		return ret;
	}

	if (mshv_vsm_configure_partition()) {
		pr_emerg("%s: VSM configuration failed !!\n", __func__);
		return -EPERM;
	}

	if (hv_vsm_get_code_page_offsets()) {
		pr_emerg("%s: FATAL: Could not retrieve vsm page offsets.Cannot return to VTL0\n",
			 __func__);
		return -EINVAL;
	}

	/* Initialize hyper-v per cpu context */
	// ToDo: Introduce clean up function
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "hyperv/vsm:init",
				mshv_vsm_per_cpu_init, NULL);
	if (ret < 0)
		return ret;

	/* ToDo : per-cpu interrupt enabling for supported architectures like arm64 */
	hv_setup_vsm_handler(mshv_vsm_isr);

	/* Protect VTL1 memory from VTL0 */
	e820_table = boot_params.e820_table;
	permissions = HV_PAGE_ACCESS_NONE;

	for (i = 0; i < E820_MAX_ENTRIES_ZEROPAGE; i++) {
		if (e820_table[i].type == E820_TYPE_RAM) {
			u64 start, end, page_count;

			start = e820_table[i].addr;
			end = e820_table[i].addr + e820_table[i].size;
			pr_debug("VSM: Protect VTL1 memory region 0x%llx:0x%llx", start, end);

			page_count = e820_table[i].size / PAGE_SIZE;
			ret = hv_modify_vtl_protection_mask(start, page_count, permissions);
			if (ret)
				pr_err("Could not protect VTL1 mem addr:0x%llx, pg_count 0x%llx",
				       start, page_count);
		}
	}

	mutex_init(&vtl0.lock);
	INIT_LIST_HEAD(&vtl0.modules);
	/*
	 * Reserve the module area so that when a VTL0 module is sent to VTL1,
	 * we can map the module sections to the same exact addresses as in
	 * VTL0.
	 */
	if (!ret && !get_module_vm_area(HEKI_MODULE_RESERVE_SIZE))
		ret = -ENOMEM;

	return ret;
}

static void __exit mshv_vtl1_exit(void)
{
	misc_deregister(&mshv_vsm_dev);
	pr_info("mshv_vsm_dev device unregistered\n");
}

module_init(mshv_vtl1_init);
module_exit(mshv_vtl1_exit);
