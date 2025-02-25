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
	/* Shut down tick when exiting VTL1 */
	bool suppress_tick;
	/* CPU should stay in VTL1 and not exit to VTL0 even if idle is invoked */
	bool stay_in_vtl1;
	bool vtl1_enabled;
	bool vtl1_booted;
};

static DEFINE_PER_CPU(struct hv_vsm_per_cpu, vsm_per_cpu);

struct hv_input_modify_vtl_protection_mask {
	u64 partition_id;
	u32 map_flags;
	union hv_input_vtl target_vtl;
	u8 reserved8_z;
	u16 reserved16_z;

	__aligned(8) u64 gpa_page_list[];
};

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

	while (true) {
		hvp = hv_vp_assist_page[smp_processor_id()];
		switch (hvp->vtl_entry_reason) {
		case VTL_ENTRY_REASON_LOWER_VTL_CALL:
			struct hv_vsm_per_cpu *per_cpu;
			struct hv_vtl_cpu_context *cpu_context;
			struct hv_vtlcall_param *vtl_params;

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

static int mshv_vsm_per_cpu_init(unsigned int cpu)
{
	struct hv_vsm_per_cpu *per_cpu = this_cpu_ptr(&vsm_per_cpu);

	memset(per_cpu, 0, sizeof(*per_cpu));

	per_cpu->vsm_task = kthread_create(mshv_vsm_vtl_task, NULL, "vsm_task");
	kthread_bind(per_cpu->vsm_task, cpu);

	mshv_vsm_set_secure_config_vtl0();

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

	return ret;
}

static void __exit mshv_vtl1_exit(void)
{
	misc_deregister(&mshv_vsm_dev);
	pr_info("mshv_vsm_dev device unregistered\n");
}

module_init(mshv_vtl1_init);
module_exit(mshv_vtl1_exit);
