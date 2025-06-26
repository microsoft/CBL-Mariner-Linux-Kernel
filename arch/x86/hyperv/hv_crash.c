// SPDX-License-Identifier: GPL-2.0-only
/*
 * X86 specific Hyper-V kdump/crash related code.
 *
 * Copyright (C) 2023, Microsoft, Inc.
 *
 * This module implements kdump kexec and crash collection support in both
 * cases of mshv crash and linux crash.
 */
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/panic.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/mshyperv.h>
#include <asm/nmi.h>
#include <asm/idtentry.h>
#include <asm/reboot.h>
#include <asm/intel_pt.h>

int hv_crash_enabled;
EXPORT_SYMBOL_GPL(hv_crash_enabled);

struct hv_crash_ctxt {
	ulong rsp;
	ulong cr0;
	ulong cr2;
	ulong cr4;
	ulong cr8;

	u16 cs;
	u16 ss;
	u16 ds;
	u16 es;
	u16 fs;
	u16 gs;

	u16 gdt_fill;
	struct desc_ptr gdtr;
	char idt_fill[6];
	struct desc_ptr idtr;

	u64 gsbase;
	u64 efer;
	u64 pat;
};
static struct hv_crash_ctxt hv_crash_ctxt;

/* Shared hypervisor page that contains crash dump area we peek into.
 * NB: windbg looks for "hv_cda" symbol
 */
static struct hv_crashdump_area *hv_cda;

#if CONFIG_PGTABLE_LEVELS > 4
#define HV_CRASH_PT_PGS 5
BUILD_BUG_ON_MSG(1, "FIXME: pgtable levels greater than 4\n");
#else
#define HV_CRASH_PT_PGS 4
#endif

static u32 hv_tramp32_cr3, trampoline_pa, trampoline_arg;
static atomic_t crash_cpus_wait;
static void *hv_crash_ptpgs[HV_CRASH_PT_PGS];
static int hv_has_crashed, lx_has_crashed;

/* This cannot be inlined as it needs stack */
static noinline __noclone void hv_crash_restore_tss(void)
{
	load_TR_desc();
}

/* This cannot be inlined as it needs stack */
static noinline void hv_crash_clear_knpt(void)
{
	pgd_t *pgd;
	p4d_t *p4d;

	/* clear so it's not confusing to someone looking at the core */
	pgd = pgd_offset_k(trampoline_pa);
	p4d = p4d_offset(pgd, trampoline_pa);
	native_p4d_clear(p4d);
}

/*
 * This is the C entry point from the asm glue code after the devirt hypercall.
 * We enter here in IA32-e long mode, ie, full 64bit mode running on kernel
 * page tables with our below 4G page identity mapped, but using a temporary
 * GDT. ds/fs/gs/es are null. ss is not usable. bp is null. stack is not
 * available. We restore kernel GDT, and rest of the context, and continue
 * to kexec.
 */
static asmlinkage void __noreturn hv_crash_c_entry(void)
{
	struct hv_crash_ctxt *ctxt = &hv_crash_ctxt;

	/* first thing, restore kernel gdt */
	native_load_gdt(&ctxt->gdtr);

	asm volatile("movw %%ax, %%ss" : : "a"(ctxt->ss));
	asm volatile("movq %0, %%rsp" : : "m"(ctxt->rsp));

	asm volatile("movw %%ax, %%ds" : : "a"(ctxt->ds));
	asm volatile("movw %%ax, %%es" : : "a"(ctxt->es));
	asm volatile("movw %%ax, %%fs" : : "a"(ctxt->fs));
	asm volatile("movw %%ax, %%gs" : : "a"(ctxt->gs));

	native_wrmsrl(MSR_IA32_CR_PAT, ctxt->pat);
	asm volatile("movq %0, %%cr0" : : "r"(ctxt->cr0));

	asm volatile("movq %0, %%cr8" : : "r"(ctxt->cr8));
	asm volatile("movq %0, %%cr4" : : "r"(ctxt->cr4));
	asm volatile("movq %0, %%cr2" : : "r"(ctxt->cr4));

	native_load_idt(&ctxt->idtr);
	native_wrmsrl(MSR_GS_BASE, ctxt->gsbase);
	native_wrmsrl(MSR_EFER, ctxt->efer);

	/* restore the original kernel CS now via far return */
	asm volatile("movzwq %0, %%rax\n\t"
		     "pushq %%rax\n\t"
		     "pushq $1f\n\t"
		     "lretq\n\t"
		     "1:nop\n\t" : : "m"(ctxt->cs) : "rax");

	/* We are in asmlinkage without stack frame, hence make a C function
	 * call which can buy stack frame to restore the tss or clear PT entry.
	 */
	hv_crash_restore_tss();
	hv_crash_clear_knpt();

	/* we are now fully in devirtualized normal kernel mode */
	__crash_kexec(NULL);

	BUG();
}
/* Tell gcc we are using lretq long jump in the above function intentionally */
STACK_FRAME_NON_STANDARD(hv_crash_c_entry);

static void hv_mark_tss_not_busy(void)
{
	struct desc_struct *desc = get_current_gdt_rw();
	tss_desc tss;

	memcpy(&tss, &desc[GDT_ENTRY_TSS], sizeof(tss_desc));
	tss.type = 0x9;        /* available 64-bit TSS. 0xB is busy TSS */
	write_gdt_entry(desc, GDT_ENTRY_TSS, &tss, DESC_TSS);
}

/* Save essential context */
static void hv_hvcrash_ctxt_save(void)
{
	struct hv_crash_ctxt *ctxt = &hv_crash_ctxt;

	asm volatile("movq %%rsp,%0" : "=m"(ctxt->rsp));

	ctxt->cr0 = native_read_cr0();
	ctxt->cr4 = native_read_cr4();

	asm volatile("movq %%cr2, %0" : "=a"(ctxt->cr2));
	asm volatile("movq %%cr8, %0" : "=a"(ctxt->cr8));

	asm volatile("movl %%cs, %%eax" : "=a"(ctxt->cs));
	asm volatile("movl %%ss, %%eax" : "=a"(ctxt->ss));
	asm volatile("movl %%ds, %%eax" : "=a"(ctxt->ds));
	asm volatile("movl %%es, %%eax" : "=a"(ctxt->es));
	asm volatile("movl %%fs, %%eax" : "=a"(ctxt->fs));
	asm volatile("movl %%gs, %%eax" : "=a"(ctxt->gs));

	native_store_gdt(&ctxt->gdtr);
	store_idt(&ctxt->idtr);

	ctxt->gsbase = __rdmsr(MSR_GS_BASE);
	ctxt->efer = __rdmsr(MSR_EFER);
	ctxt->pat = __rdmsr(MSR_IA32_CR_PAT);
}

/* Add trampoline page to the kernel pagetable for transition to kernel PT */
static void hv_crash_fixup_knpt(void)
{
	pgd_t *pgd;
	p4d_t *p4d;

	pgd = pgd_offset_k(trampoline_pa);
	p4d = p4d_offset(pgd, trampoline_pa);

	p4d_populate(&init_mm, p4d, (pud_t *)hv_crash_ptpgs[1]);
	p4d->pgd.pgd = p4d->pgd.pgd & ~(_PAGE_NX);    /* disable no execute */
}

/*
 * Now that all cpus are in nmi and spinning, we notify the hyp that dom0 has
 * crashed and will collect core. This will cause the hyp to quiesce and
 * suspend all VPs. While not strictly necessary, it aids in better state
 * collection on the hypervisor side.
 */
static void hv_notify_prepare_hyp(void)
{
	u64 status;
	struct hv_input_notify_partition_event *input;
	struct hv_partition_event_root_crashdump_input *cda;

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	cda = &input->input.crashdump_input;
	memset(input, 0, sizeof(*input));
	input->event = HV_PARTITION_EVENT_ROOT_CRASHDUMP;

	cda->crashdump_action = HV_CRASHDUMP_ENTRY;
	status = hv_do_hypercall(HVCALL_NOTIFY_PARTITION_EVENT, input, NULL);
	if (!hv_result_success(status))
		return;

	cda->crashdump_action = HV_CRASHDUMP_SUSPEND_ALL_VPS;
	status = hv_do_hypercall(HVCALL_NOTIFY_PARTITION_EVENT, input, NULL);
}

/*
 * Common function for all cpus before devirtualization.
 *
 * Hypervisor crash: all cpus get here in nmi context.
 * Linux crash: the panicing cpu gets here at base level, all others in nmi
 *		context. Note, panicing cpu may not be the bsp.
 *
 * The function is not inlined so it will show on the stack. It is named so
 * because the crash cmd looks for certain well known function names on the
 * stack before looking into the cpu saved note in the elf section, and
 * that work is currently incomplete.
 *
 * Notes:
 *  Hypervisor crash:
 *    - the hypervisor is in a very restrictive mode at this point and any
 *	vmexit it cannot handle would result in reboot. For example, console
 *	output from here would result in synic ipi hcall, which would result
 *	in reboot. So, no mumbo jumbo, just get to kexec as quickly as possible.
 *
 *  Devirtualization is supported from the bsp only.
 */
static noinline __noclone void crash_nmi_callback(struct pt_regs *regs)
{
	struct hv_input_disable_hyp_ex *input;
	u64 status;
	int msecs = 1000, ccpu = safe_smp_processor_id();

	if (ccpu == 0) {
		/* crash_save_cpu() will be done in the kexec path */
		cpu_emergency_stop_pt();	/* disable performance trace */
		atomic_inc(&crash_cpus_wait);
	} else {
		crash_save_cpu(regs, ccpu);
		cpu_emergency_stop_pt();	/* disable performance trace */
		atomic_inc(&crash_cpus_wait);
		for (;;);			/* cause no vmexits */
	}

	while (atomic_read(&crash_cpus_wait) < num_online_cpus() && msecs--)
		mdelay(1);

	stop_nmi();
	if (!hv_has_crashed)
		hv_notify_prepare_hyp();

	if (crashing_cpu == -1)
		crashing_cpu = ccpu;		/* crash cmd uses this */

	hv_hvcrash_ctxt_save();
	hv_mark_tss_not_busy();
	hv_crash_fixup_knpt();

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->rip = trampoline_pa;
	input->arg = trampoline_arg;

	status = hv_do_hypercall(HVCALL_DISABLE_HYP_EX, input, NULL);
	if (!hv_result_success(status)) {
		pr_emerg("%s: %s\n", __func__, hv_status_to_string(status));
		pr_emerg("Hyper-V: disable hyp failed. kexec not possible\n");
	}

	native_wrmsrl(HV_X64_MSR_RESET, 1);    /* get hv to reboot */
}

/*
 * generic nmi callback handler: could be called without any crash also.
 *  hv crash: hypervisor injects nmi's into all cpus
 *  lx crash: panicing cpu sends nmi to all but self via crash_stop_other_cpus
 */
static int hv_crash_nmi_local(unsigned int cmd, struct pt_regs *regs)
{
	int ccpu = safe_smp_processor_id();

	if (!hv_has_crashed && hv_cda && hv_cda->cda_valid)
		hv_has_crashed = 1;

	if (!hv_has_crashed && !lx_has_crashed)
		return NMI_DONE;	/* ignore the nmi */

	if (hv_has_crashed && !hv_crash_enabled) {
		if (ccpu == 0) {
			pr_emerg("Hyper-V: crashcore collect not setup. Reboot\n");
			native_wrmsrl(HV_X64_MSR_RESET, 1);	/* reboot */
		} else
			for (;;)
				cpu_relax();
	}

	crash_nmi_callback(regs);
	return NMI_DONE;
}

/*
 * hv_crash_stop_other_cpus() == smp_ops.crash_stop_other_cpus
 *
 * On normal linux panic, this is called twice: first from panic and then again
 * from native_machine_crash_shutdown.
 *
 * In case of mshv, 3 ways to get here:
 *  1. hv crash (only bsp will get here):
 *	BSP : nmi callback -> DisableHv -> hv_crash_asm32 -> hv_crash_c_entry
 *		  -> __crash_kexec -> native_machine_crash_shutdown
 *		  -> crash_smp_send_stop -> smp_ops.crash_stop_other_cpus
 *  2. linux panic:
 *	panic cpu x: panic() -> crash_smp_send_stop
 *			 -> smp_ops.crash_stop_other_cpus
 *   OR
 *	bsp: native_machine_crash_shutdown -> crash_smp_send_stop
 *
 * NB: noclone and non standard stack because of call to crash_setup_regs().
 */
static void __noclone hv_crash_stop_other_cpus(void)
{
	static int crash_stop_done;
	struct pt_regs lregs;
	int ccpu = safe_smp_processor_id();

	if (hv_has_crashed)
		return;		/* all cpus already in nmi handler path */

	if (crash_stop_done)
		return;
	crash_stop_done = 1;

	/* linux has crashed: hv is healthy, we can ipi safely */
	lx_has_crashed = 1;
	wmb();			/* nmi handlers looks at lx_has_crashed */

	apic->send_IPI_allbutself(NMI_VECTOR);

	if (crashing_cpu == -1)
		crashing_cpu = ccpu;		/* crash cmd uses this */

	/* crash_setup_regs() happens in kexec also, but for the kexec cpu which
	 * is the bsp. We could be here on non-bsp cpu, collect regs if so.
	 */
	if (ccpu)
		crash_setup_regs(&lregs, NULL);

	crash_nmi_callback(&lregs);
}
STACK_FRAME_NON_STANDARD(hv_crash_stop_other_cpus);

/* This GDT is accessed in IA32-e compat mode which uses 32bits addresses */
struct hv_gdtr32 {
	u16 fill;
	u16 limit;
	u32 address;
} __packed;

/* We need a CS with L bit to goto IA32-e long mode from 32bit compat mode */
struct hv_crash_trgdt {
	u64 null;	/* index 0, selector 0, null selector */
	u64 cs64;	/* index 1, selector 8, cs64 selector */
} __packed;

/* No stack, so jump via far ptr in memory to load the 64bit CS */
struct hv_cs_jmptgt {
	u32 address;
	u16 csval;
	u16 fill;
} __packed;

/* This trampoline data is copied onto the trampoline page after the asm code */
struct hv_crash_trdata {
	u64 tramp32_cr3;
	u64 kernel_cr3;
	struct hv_gdtr32 gdtr32;
	struct hv_crash_trgdt trgdt;
	struct hv_cs_jmptgt cs_jmptgt;
	u64 c_entry_addr;
} __packed;

/*
 * Setup a temporary gdt to allow the asm code to switch to the long mode.
 * Since the asm code is relocated/copied to a below 4G page, it cannot use rip
 * relative addressing, hence, we must use trampoline_pa here. Also save
 * other jmp and C entry targets for same reasons.
 */
static void hv_crash_setup_trdata(u64 trampoline_va)
{
	int size, offs;
	void *dest;
	struct hv_crash_trdata *trdata;

	/* These must match exactly the ones in the corresponding asm file */
	BUILD_BUG_ON(offsetof(struct hv_crash_trdata, tramp32_cr3) != 0);
	BUILD_BUG_ON(offsetof(struct hv_crash_trdata, kernel_cr3) != 8);
	BUILD_BUG_ON(offsetof(struct hv_crash_trdata, gdtr32.limit) != 18);
	BUILD_BUG_ON(offsetof(struct hv_crash_trdata, cs_jmptgt.address) != 40);

	size = &hv_crash_asm32_end - &hv_crash_asm32;
	dest = (void *)trampoline_va;
	memcpy(dest, &hv_crash_asm32, size);

	BUG_ON(size + sizeof(struct hv_crash_trdata) > PAGE_SIZE);

	dest += size;
	dest = (void *)round_up((ulong)dest, 16);
	size = sizeof(struct hv_crash_trdata);

	trdata = (struct hv_crash_trdata *)dest;
	trdata->tramp32_cr3 = hv_tramp32_cr3;

	/* Note, when restoring X86_CR4_PCIDE, cr3[11:0] must be zero */
	trdata->kernel_cr3 = __sme_pa(init_mm.pgd);

	trdata->gdtr32.limit = sizeof(struct hv_crash_trgdt);
	trdata->gdtr32.address = trampoline_pa +
				   (ulong)&trdata->trgdt - trampoline_va;

	 /* base:0 limit:0xfffff type:b dpl:0 P:1 L:1 D:0 avl:0 G:1 */
	trdata->trgdt.cs64 = 0x00af9a000000ffff;

	trdata->cs_jmptgt.csval = 0x8;
	offs = (ulong)&hv_crash_asm64_lbl - (ulong)&hv_crash_asm32;
	trdata->cs_jmptgt.address = trampoline_pa + offs;

	trdata->c_entry_addr = (u64)&hv_crash_c_entry;

	memcpy(dest, trdata, sizeof(struct hv_crash_trdata));
	trampoline_arg = trampoline_pa + (ulong)dest - trampoline_va;
}

/*
 * Build trampoline 32bit page table for transition from long-mode non-paging
 * to long-mode paging. This transition needs pagetables below 4G, hence this.
 */
static void hv_crash_build_trpt(void)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	u64 pa, addr = trampoline_pa;

	/* see MAX_ASID_AVAILABLE in tlb.c: "PCID 0 is reserved for use by
	 * non-PCID-aware users". Build cr3 with pcid 0
	 */
	hv_tramp32_cr3 = __sme_pa(hv_crash_ptpgs[0]);

	p4d = hv_crash_ptpgs[0] + pgd_index(addr) * sizeof(p4d);
	pa = virt_to_phys(hv_crash_ptpgs[1]);
	set_p4d(p4d, __p4d(_PAGE_TABLE | pa));
	p4d->pgd.pgd &= ~(_PAGE_NX);	/* disable no execute */

	pud = hv_crash_ptpgs[1] + pud_index(addr) * sizeof(pud);
	pa = virt_to_phys(hv_crash_ptpgs[2]);
	set_pud(pud, __pud(_PAGE_TABLE | pa));

	pmd = hv_crash_ptpgs[2] + pmd_index(addr) * sizeof(pmd);
	pa = virt_to_phys(hv_crash_ptpgs[3]);
	set_pmd(pmd, __pmd(_PAGE_TABLE | pa));

	pte = hv_crash_ptpgs[3] + pte_index(addr) * sizeof(pte);
	set_pte(pte, pfn_pte(addr >> PAGE_SHIFT, PAGE_KERNEL_EXEC));
}

/*
 * Setup trampoline for devirtualization:
 *  - a page below 4G, ie 32bit addr containing asm glue code that mshv jmps to
 *    in protected mode.
 *  - 4 pages for a temporary page table that asm code uses to turn paging on
 *  - a temporary gdt to use in the compat mode.
 */
static int hv_crash_trampoline_setup(void)
{
	int i;
	struct page *page;
	u64 trampoline_va;
	gfp_t flags32 = GFP_KERNEL | GFP_DMA32 | __GFP_ZERO;

	/* page containing 32bit trampoline assembly code + hv_crash_trdata */
	page = alloc_page(flags32);
	if (page == NULL) {
		pr_err("%s: failed to alloc asm stub page\n", __func__);
		return -1;
	}

	trampoline_va = (u64)page_to_virt(page);
	trampoline_pa = (u32)page_to_phys(page);

	page = alloc_pages(flags32, 2);        /* alloc 2^2 pages */
	if (page == NULL) {
		pr_err("%s: failed to alloc pt pages\n", __func__);
		free_page(trampoline_va);
		return -1;
	}
	for (i = 0; i < 4; i++, page++)
		hv_crash_ptpgs[i] = page_to_virt(page);

	hv_crash_build_trpt();
	hv_crash_setup_trdata(trampoline_va);

	return 0;
}

static bool hv_supports_devirt(void)
{
	union hv_hypervisor_version_info version_info;

	if (hv_get_hypervisor_version(&version_info))
		return false;

	if (version_info.major_version < 10)
		return false;
	else if (version_info.major_version == 10) {
		if (version_info.build_number < 27562)
			return false;
	}

	return true;
}

/* Do the setup for kdump kexec to collect core when running as mshv root */
void hv_root_crash_init(void)
{
	int rc;
	struct hv_input_get_system_property *input;
	struct hv_output_get_system_property *output;
	unsigned long flags;
	u64 status;
	union hv_pfn_range cda_info;

	crash_kexec_post_notifiers = true;

	if (!hv_supports_devirt())
		goto err_out;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));
	input->property_id = HV_SYSTEM_PROPERTY_CRASHDUMPAREA;

	status = hv_do_hypercall(HVCALL_GET_SYSTEM_PROPERTY, input, output);
	if (!hv_result_success(status))
		goto prop_err_out;

	cda_info.as_uint64 = output->hv_cda_info.as_uint64;
	local_irq_restore(flags);

	hv_cda = phys_to_virt(cda_info.base_pfn << PAGE_SHIFT);

	rc = hv_crash_trampoline_setup();
	if (rc)
		goto err_out;

	register_nmi_handler(NMI_LOCAL, hv_crash_nmi_local, NMI_FLAG_FIRST,
			     "hv_crash_nmi");

	smp_ops.crash_stop_other_cpus = hv_crash_stop_other_cpus;

	hv_crash_enabled = 1;
	pr_info("Hyper-V: linux and hv kdump support enabled\n");

	return;

prop_err_out:
	local_irq_restore(flags);
	pr_err("Hyper-V: %s: property:%d %s\n", __func__, input->property_id,
	       hv_status_to_string(status));
err_out:
	pr_err("Hyper-V: only linux (but not hv) kdump support enabled\n");
}

