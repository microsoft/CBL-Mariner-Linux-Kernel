// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <asm/apic.h>
#include <asm/boot.h>
#include <asm/desc.h>
#include <asm/i8259.h>
#include <asm/mshyperv.h>
#include <asm/realmode.h>
#include <../kernel/smpboot.h>

#define HV_SECURE_VTL_BOOT_TOKEN 0xDC

extern struct boot_params boot_params;
static struct real_mode_header hv_vtl_real_mode_header;
static u8 *hv_secure_vtl_boot_signal;

static bool __init hv_vtl_msi_ext_dest_id(void)
{
	return true;
}

#ifdef CONFIG_HV_SECURE_VTL
static void __init hv_vtl1_apic_intr_mode_select(void)
{
	apic_intr_mode = APIC_SYMMETRIC_IO;
}
#endif

void __init hv_vtl_init_platform(void)
{
	pr_info("Linux runs in Hyper-V Virtual Trust Level\n");

	x86_platform.realmode_reserve = x86_init_noop;
	x86_platform.realmode_init = x86_init_noop;
#ifdef CONFIG_HV_SECURE_VTL
	x86_init.irqs.intr_mode_select = hv_vtl1_apic_intr_mode_select;
#endif
	x86_init.irqs.pre_vector_init = x86_init_noop;
	x86_init.timers.timer_init = x86_init_noop;
	x86_init.resources.probe_roms = x86_init_noop;

	/* Avoid searching for BIOS MP tables */
	x86_init.mpparse.find_smp_config = x86_init_noop;
	x86_init.mpparse.get_smp_config = x86_init_uint_noop;

	x86_platform.get_wallclock = get_rtc_noop;
	x86_platform.set_wallclock = set_rtc_noop;
	x86_platform.get_nmi_reason = hv_get_nmi_reason;

	x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
	x86_platform.legacy.rtc = 0;
	x86_platform.legacy.warm_reset = 0;
	x86_platform.legacy.reserve_bios_regions = 0;
	x86_platform.legacy.devices.pnpbios = 0;

	x86_init.hyper.msi_ext_dest_id = hv_vtl_msi_ext_dest_id;
}

static inline u64 hv_vtl_system_desc_base(struct ldttss_desc *desc)
{
	return ((u64)desc->base3 << 32) | ((u64)desc->base2 << 24) |
		(desc->base1 << 16) | desc->base0;
}

static inline u32 hv_vtl_system_desc_limit(struct ldttss_desc *desc)
{
	return ((u32)desc->limit1 << 16) | (u32)desc->limit0;
}

typedef void (*secondary_startup_64_fn)(void*, void*);
static void hv_vtl_ap_entry(void)
{
	((secondary_startup_64_fn)secondary_startup_64)(&boot_params, &boot_params);
}

static int __hv_vtl_enable_vcpu(struct hv_enable_vp_vtl *input)
{
	u64 status;
	int ret = 0;
	unsigned long irq_flags;

	local_irq_save(irq_flags);

	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, input, NULL);

	if (!hv_result_success(status) &&
	    hv_result(status) != HV_STATUS_VTL_ALREADY_ENABLED) {
		pr_err("HVCALL_ENABLE_VP_VTL failed for VP : %d ! [Err: %#llx\n]",
		       input->vp_index, status);
		ret = -EINVAL;
	}

	local_irq_restore(irq_flags);
	return ret;
}

static void hv_vtl_populate_vp_context(struct hv_enable_vp_vtl *input, u32 target_vp_index, int cpu)
{
	struct desc_ptr gdt_ptr;
	struct desc_ptr idt_ptr;

	struct ldttss_desc *tss;
	struct ldttss_desc *ldt;
	struct desc_struct *gdt;

	struct task_struct *idle = idle_thread_get(cpu);
	u64 rsp = (unsigned long)idle->thread.sp;

	u64 rip = (u64)&hv_vtl_ap_entry;

	native_store_gdt(&gdt_ptr);
	store_idt(&idt_ptr);

	gdt = (struct desc_struct *)((void *)(gdt_ptr.address));
	tss = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);
	ldt = (struct ldttss_desc *)(gdt + GDT_ENTRY_LDT);


	/*
	 * The x86_64 Linux kernel follows the 16-bit -> 32-bit -> 64-bit
	 * mode transition sequence after waking up an AP with SIPI whose
	 * vector points to the 16-bit AP startup trampoline code. Here in
	 * VTL2, we can't perform that sequence as the AP has to start in
	 * the 64-bit mode.
	 *
	 * To make this happen, we tell the hypervisor to load a valid 64-bit
	 * context (most of which is just magic numbers from the CPU manual)
	 * so that AP jumps right to the 64-bit entry of the kernel, and the
	 * control registers are loaded with values that let the AP fetch the
	 * code and data and carry on with work it gets assigned.
	 */

	input->vp_context.rip = rip;
	input->vp_context.rsp = rsp;
	input->vp_context.rflags = 0x0000000000000002;
	input->vp_context.efer = __rdmsr(MSR_EFER);
	input->vp_context.cr0 = native_read_cr0();
	input->vp_context.cr3 = __native_read_cr3();
	input->vp_context.cr4 = native_read_cr4();
	input->vp_context.msr_cr_pat = __rdmsr(MSR_IA32_CR_PAT);
	input->vp_context.idtr.limit = idt_ptr.size;
	input->vp_context.idtr.base = idt_ptr.address;
	input->vp_context.gdtr.limit = gdt_ptr.size;
	input->vp_context.gdtr.base = gdt_ptr.address;

	/* Non-system desc (64bit), long, code, present */
	input->vp_context.cs.selector = __KERNEL_CS;
	input->vp_context.cs.base = 0;
	input->vp_context.cs.limit = 0xffffffff;
	input->vp_context.cs.attributes = 0xa09b;
	/* Non-system desc (64bit), data, present, granularity, default */
	input->vp_context.ss.selector = __KERNEL_DS;
	input->vp_context.ss.base = 0;
	input->vp_context.ss.limit = 0xffffffff;
	input->vp_context.ss.attributes = 0xc093;

	/* System desc (128bit), present, LDT */
	input->vp_context.ldtr.selector = GDT_ENTRY_LDT * 8;
	input->vp_context.ldtr.base = hv_vtl_system_desc_base(ldt);
	input->vp_context.ldtr.limit = hv_vtl_system_desc_limit(ldt);
	input->vp_context.ldtr.attributes = 0x82;

	/* System desc (128bit), present, TSS, 0x8b - busy, 0x89 -- default */
	input->vp_context.tr.selector = GDT_ENTRY_TSS * 8;
	input->vp_context.tr.base = hv_vtl_system_desc_base(tss);
	input->vp_context.tr.limit = hv_vtl_system_desc_limit(tss);
	input->vp_context.tr.attributes = 0x8b;
}

static int hv_vtl1_wakeup_secondary_cpu(int apicid, unsigned long start_eip)
{
	WRITE_ONCE(hv_secure_vtl_boot_signal[apicid], HV_SECURE_VTL_BOOT_TOKEN);
	return 0;
}

int hv_secure_vtl_init_boot_signal_page(void *shared_data)
{
	if (!shared_data)
		return -EINVAL;

	hv_secure_vtl_boot_signal = (u8 *)shared_data;
	/* VTL 0 sets the boot signal for cpu 0 and sends the page across. */
	if (hv_secure_vtl_boot_signal[0] != HV_SECURE_VTL_BOOT_TOKEN)
		return -EINVAL;
	else
		return 0;
}

static int hv_vtl_bringup_vcpu(u32 target_vp_index, int cpu, u64 eip_ignored)
{
	u64 status;
	int ret = 0;
	unsigned long irq_flags;
	struct hv_enable_vp_vtl *input;

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = target_vp_index;
	input->target_vtl.target_vtl = HV_VTL_MGMT;
	hv_vtl_populate_vp_context(input, target_vp_index, cpu);

	ret = __hv_vtl_enable_vcpu(input);

	if (ret)
		return ret;

	local_irq_save(irq_flags);
	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);

	if (!hv_result_success(status)) {
		pr_err("HVCALL_START_VP failed for VP : %d ! [Err: %#llx]\n",
		       target_vp_index, status);
		ret = -EINVAL;
	}
	local_irq_restore(irq_flags);

	return ret;
}

static int hv_vtl_apicid_to_vp_id(u32 apic_id)
{
	u64 control;
	u64 status;
	unsigned long irq_flags;
	struct hv_get_vp_from_apic_id_in *input;
	u32 *output, ret;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->apic_ids[0] = apic_id;

	output = (u32 *)input;

	control = HV_HYPERCALL_REP_COMP_1 | HVCALL_GET_VP_ID_FROM_APIC_ID;
	status = hv_do_hypercall(control, input, output);
	ret = output[0];

	local_irq_restore(irq_flags);

	if (!hv_result_success(status)) {
		pr_err("failed to get vp id from apic id %d, status %#llx\n",
		       apic_id, status);
		return -EINVAL;
	}

	return ret;
}

static int hv_vtl_wakeup_secondary_cpu(int apicid, unsigned long start_eip)
{
	int vp_id, cpu;

	/* Find the logical CPU for the APIC ID */
	for_each_present_cpu(cpu) {
		if (arch_match_cpu_phys_id(cpu, apicid))
			break;
	}
	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	pr_debug("Bringing up CPU with APIC ID %d in VTL2...\n", apicid);
	vp_id = hv_vtl_apicid_to_vp_id(apicid);

	if (vp_id < 0) {
		pr_err("Couldn't find CPU with APIC ID %d\n", apicid);
		return -EINVAL;
	}
	if (vp_id > ms_hyperv.max_vp_index) {
		pr_err("Invalid CPU id %d for APIC ID %d\n", vp_id, apicid);
		return -EINVAL;
	}

	return hv_vtl_bringup_vcpu(vp_id, cpu, start_eip);
}

int hv_secure_vtl_enable_secondary_cpu(u32 target_vp_index)
{
	struct hv_enable_vp_vtl *input;

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = target_vp_index;
	input->target_vtl.target_vtl = HV_VTL_SECURE;
	hv_vtl_populate_vp_context(input, target_vp_index, target_vp_index);

	return  __hv_vtl_enable_vcpu(input);
}

int __init hv_vtl_early_init(u8 vtl)
{
	/*
	 * `boot_cpu_has` returns the runtime feature support,
	 * and here is the earliest it can be used.
	 */
	if (cpu_feature_enabled(X86_FEATURE_XSAVE))
		panic("XSAVE has to be disabled as it is not supported by this module.\n"
			  "Please add 'noxsave' to the kernel command line.\n");

	 /* We should not be here. We do not support VTLs higher than 2 */
	if (vtl > HV_VTL_MGMT)
		panic("Booting in unsupported VTL\n");

	real_mode_header = &hv_vtl_real_mode_header;

	if (vtl == HV_VTL_SECURE)
		apic_update_callback(wakeup_secondary_cpu_64, hv_vtl1_wakeup_secondary_cpu);

	if (vtl == HV_VTL_MGMT)
		apic_update_callback(wakeup_secondary_cpu_64, hv_vtl_wakeup_secondary_cpu);

	return 0;
}
