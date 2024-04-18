// SPDX-License-Identifier: GPL-2.0-only
/*
 * HyperV  Detection code.
 *
 * Copyright (C) 2010, Novell, Inc.
 * Author : K. Y. Srinivasan <ksrinivasan@novell.com>
 */

#include <linux/types.h>
#include <linux/time.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/efi.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kexec.h>
#include <linux/random.h>
#include <linux/memblock.h>
#include <linux/crash_dump.h>
#include <asm/processor.h>
#include <asm/hypervisor.h>
#include <asm/mshyperv.h>
#include <asm/desc.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/i8259.h>
#include <asm/apic.h>
#include <asm/timer.h>
#include <asm/reboot.h>
#include <asm/nmi.h>
#include <clocksource/hyperv_timer.h>
#include <asm/numa.h>
#include <asm/svm.h>
#include <asm/e820/api.h>

/* Linux partition type: guest, root or l1vh */
enum hv_partition_type hv_current_partition;
/* Is Linux running on nested Microsoft Hypervisor */
bool hv_nested;
struct ms_hyperv_info ms_hyperv;
bool mshv_loader_new;

/* Used in modules via hv_do_hypercall(): see arch/x86/include/asm/mshyperv.h */
bool hyperv_paravisor_present __ro_after_init;
EXPORT_SYMBOL_GPL(hyperv_paravisor_present);

static bool hv_minroot_nodes_defined __initdata;
static nodemask_t hv_minroot_nodes __initdata;

static int hv_lp_to_cpu[NR_CPUS] __initdata;
/* CPUs that don't have a root VP on them. */
static struct cpumask root_vps_absent_mask __initdata;

static struct {
	bool is_valid;
	int vps_per_node[MAX_NUMNODES];
} minroot_cfg;

#if IS_ENABLED(CONFIG_HYPERV)
static inline unsigned int hv_get_nested_msr(unsigned int reg)
{
	if (hv_is_sint_msr(reg))
		return reg - HV_X64_MSR_SINT0 + HV_X64_MSR_NESTED_SINT0;

	switch (reg) {
	case HV_X64_MSR_SIMP:
		return HV_X64_MSR_NESTED_SIMP;
	case HV_X64_MSR_SIEFP:
		return HV_X64_MSR_NESTED_SIEFP;
	case HV_X64_MSR_SVERSION:
		return HV_X64_MSR_NESTED_SVERSION;
	case HV_X64_MSR_SCONTROL:
		return HV_X64_MSR_NESTED_SCONTROL;
	case HV_X64_MSR_EOM:
		return HV_X64_MSR_NESTED_EOM;
	default:
		return reg;
	}
}

u64 hv_get_non_nested_msr(unsigned int reg)
{
	u64 value;

	if (hv_is_synic_msr(reg) && ms_hyperv.paravisor_present)
		hv_ivm_msr_read(reg, &value);
	else
		rdmsrl(reg, value);
	return value;
}
EXPORT_SYMBOL_GPL(hv_get_non_nested_msr);

void hv_set_non_nested_msr(unsigned int reg, u64 value)
{
	if (hv_is_synic_msr(reg) && ms_hyperv.paravisor_present) {
		hv_ivm_msr_write(reg, value);

		/* Write proxy bit via wrmsl instruction */
		if (hv_is_sint_msr(reg))
			wrmsrl(reg, value | 1 << 20);
	} else {
		wrmsrl(reg, value);
	}
}
EXPORT_SYMBOL_GPL(hv_set_non_nested_msr);

u64 hv_get_msr(unsigned int reg)
{
	if (hv_nested)
		reg = hv_get_nested_msr(reg);

	return hv_get_non_nested_msr(reg);
}
EXPORT_SYMBOL_GPL(hv_get_msr);

void hv_set_msr(unsigned int reg, u64 value)
{
	if (hv_nested)
		reg = hv_get_nested_msr(reg);

	hv_set_non_nested_msr(reg, value);
}
EXPORT_SYMBOL_GPL(hv_set_msr);

static void (*mshv_handler)(void);
static void (*vmbus_handler)(void);
static void (*hv_stimer0_handler)(void);
static void (*hv_kexec_handler)(void);
static void (*hv_crash_handler)(struct pt_regs *regs);

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_callback)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);
	if (mshv_handler)
		mshv_handler();

	if (vmbus_handler)
		vmbus_handler();

	if (ms_hyperv.hints & HV_DEPRECATING_AEOI_RECOMMENDED)
		apic_eoi();

	set_irq_regs(old_regs);
}

DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_nested_vmbus_intr)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);
	if (vmbus_handler)
		vmbus_handler();

	if (ms_hyperv.hints & HV_DEPRECATING_AEOI_RECOMMENDED)
		apic_eoi();

	set_irq_regs(old_regs);
}

void hv_setup_mshv_handler(void (*handler)(void))
{
	mshv_handler = handler;
}

void hv_setup_vmbus_handler(void (*handler)(void))
{
	vmbus_handler = handler;
}

void hv_remove_vmbus_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	vmbus_handler = NULL;
}

/*
 * Routines to do per-architecture handling of stimer0
 * interrupts when in Direct Mode
 */
DEFINE_IDTENTRY_SYSVEC(sysvec_hyperv_stimer0)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(hyperv_stimer0_count);
	if (hv_stimer0_handler)
		hv_stimer0_handler();
	add_interrupt_randomness(HYPERV_STIMER0_VECTOR);
	apic_eoi();

	set_irq_regs(old_regs);
}

/* For x86/x64, override weak placeholders in hyperv_timer.c */
void hv_setup_stimer0_handler(void (*handler)(void))
{
	hv_stimer0_handler = handler;
}

void hv_remove_stimer0_handler(void)
{
	/* We have no way to deallocate the interrupt gate */
	hv_stimer0_handler = NULL;
}

void hv_setup_kexec_handler(void (*handler)(void))
{
	hv_kexec_handler = handler;
}

void hv_remove_kexec_handler(void)
{
	hv_kexec_handler = NULL;
}

void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
	hv_crash_handler = handler;
}

void hv_remove_crash_handler(void)
{
	hv_crash_handler = NULL;
}

#ifdef CONFIG_KEXEC_CORE
static void hv_machine_shutdown(void)
{
	if (kexec_in_progress) {
		hv_stimer_global_cleanup();

		if (hv_kexec_handler)
			hv_kexec_handler();
	}

	/*
	 * Call hv_cpu_die() on all the CPUs, otherwise later the hypervisor
	 * corrupts the old VP Assist Pages and can crash the kexec kernel.
	 */
	if (kexec_in_progress)
		cpuhp_remove_state(CPUHP_AP_HYPERV_ONLINE);

	/* The function calls stop_other_cpus(). */
	native_machine_shutdown();

	/* Disable the hypercall page when there is only 1 active CPU. */
	if (kexec_in_progress)
		hyperv_cleanup();
}

static void hv_guest_crash_shutdown(struct pt_regs *regs)
{
	if (hv_crash_handler)
		hv_crash_handler(regs);

	/* The function calls crash_smp_send_stop(). */
	native_machine_crash_shutdown(regs);

	/* Disable the hypercall page when there is only 1 active CPU. */
	hyperv_cleanup();
}
#endif /* CONFIG_KEXEC_CORE */

static u64 hv_ref_counter_at_suspend;
static void (*old_save_sched_clock_state)(void);
static void (*old_restore_sched_clock_state)(void);

/*
 * Hyper-V clock counter resets during hibernation. Save and restore clock
 * offset during suspend/resume, while also considering the time passed
 * before suspend. This is to make sure that sched_clock using hv tsc page
 * based clocksource, proceeds from where it left off during suspend and
 * it shows correct time for the timestamps of kernel messages after resume.
 */
static void save_hv_clock_tsc_state(void)
{
	hv_ref_counter_at_suspend = hv_read_reference_counter();
}

static void restore_hv_clock_tsc_state(void)
{
	/*
	 * Adjust the offsets used by hv tsc clocksource to
	 * account for the time spent before hibernation.
	 * adjusted value = reference counter (time) at suspend
	 *                - reference counter (time) now.
	 */
	hv_adj_sched_clock_offset(hv_ref_counter_at_suspend - hv_read_reference_counter());
}

/*
 * Functions to override save_sched_clock_state and restore_sched_clock_state
 * functions of x86_platform. The Hyper-V clock counter is reset during
 * suspend-resume and the offset used to measure time needs to be
 * corrected, post resume.
 */
static void hv_save_sched_clock_state(void)
{
	old_save_sched_clock_state();
	save_hv_clock_tsc_state();
}

static void hv_restore_sched_clock_state(void)
{
	restore_hv_clock_tsc_state();
	old_restore_sched_clock_state();
}

static void __init x86_setup_ops_for_tsc_pg_clock(void)
{
	if (!(ms_hyperv.features & HV_MSR_REFERENCE_TSC_AVAILABLE))
		return;

	old_save_sched_clock_state = x86_platform.save_sched_clock_state;
	x86_platform.save_sched_clock_state = hv_save_sched_clock_state;

	old_restore_sched_clock_state = x86_platform.restore_sched_clock_state;
	x86_platform.restore_sched_clock_state = hv_restore_sched_clock_state;
}
#endif /* CONFIG_HYPERV */

static uint32_t  __init ms_hyperv_platform(void)
{
	u32 eax;
	u32 hyp_signature[3];

	if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return 0;

	cpuid(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS,
	      &eax, &hyp_signature[0], &hyp_signature[1], &hyp_signature[2]);

	if (eax < HYPERV_CPUID_MIN || eax > HYPERV_CPUID_MAX ||
	    memcmp("Microsoft Hv", hyp_signature, 12))
		return 0;

	/* HYPERCALL and VP_INDEX MSRs are mandatory for all features. */
	eax = cpuid_eax(HYPERV_CPUID_FEATURES);
	if (!(eax & HV_MSR_HYPERCALL_AVAILABLE)) {
		pr_warn("x86/hyperv: HYPERCALL MSR not available.\n");
		return 0;
	}
	if (!(eax & HV_MSR_VP_INDEX_AVAILABLE)) {
		pr_warn("x86/hyperv: VP_INDEX MSR not available.\n");
		return 0;
	}

	return HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS;
}

#ifdef CONFIG_X86_LOCAL_APIC
/*
 * Prior to WS2016 Debug-VM sends NMIs to all CPUs which makes
 * it difficult to process CHANNELMSG_UNLOAD in case of crash. Handle
 * unknown NMI on the first CPU which gets it.
 */
static int hv_nmi_unknown(unsigned int val, struct pt_regs *regs)
{
	static atomic_t nmi_cpu = ATOMIC_INIT(-1);

	if (!unknown_nmi_panic)
		return NMI_DONE;

	if (atomic_cmpxchg(&nmi_cpu, -1, raw_smp_processor_id()) != -1)
		return NMI_HANDLED;

	return NMI_DONE;
}
#endif

static unsigned long hv_get_tsc_khz(void)
{
	unsigned long freq;

	rdmsrl(HV_X64_MSR_TSC_FREQUENCY, freq);

	return freq / 1000;
}

static int __init hv_parse_root_vp_nodes(char *arg)
{
	char *tok;
	int node, ret;

	if (strcmp(arg, "all") == 0) {
		nodes_setall(hv_minroot_nodes);
	} else {
		while ((tok = strsep(&arg, ",")) != NULL) {
			ret = kstrtoint(tok, 10, &node);
			if (ret) {
				pr_warn("Hyper-V: invalid format for hv_minroot_nodes: %s\n",
						arg);
				return 0;

			}

			if (!node_possible(node)) {
				pr_warn("Hyper-V: ignoring invalid node %u specified in hv_minroot_nodes.\n",
						node);
				continue;
			}

			node_set(node, hv_minroot_nodes);
		}
	}

	if (nodes_weight(hv_minroot_nodes) > 0)
		hv_minroot_nodes_defined = true;

	return 0;
}
early_param("hv_minroot_nodes", hv_parse_root_vp_nodes);

#if defined(CONFIG_SMP) && IS_ENABLED(CONFIG_HYPERV)
static void __init hv_smp_prepare_boot_cpu(void)
{
	native_smp_prepare_boot_cpu();
#if defined(CONFIG_X86_64) && defined(CONFIG_PARAVIRT_SPINLOCKS)
	hv_init_spinlocks();
#endif
}

static int apicids[NR_CPUS] __initdata;

/* find the next smallest apicid in the unsorted array of size NR_CPUS */
static int __init next_smallest_apicid(int apicids[], int curr, int *cpu)
{
	int i, found = INT_MAX;

	for (i = 0; i < NR_CPUS; i++) {
		if (apicids[i] <= curr)
			continue;

		if (apicids[i] < found) {
			found = apicids[i];
			*cpu = i;
		}
	}

	return found;
}

static void __init prepare_minroot_cfg(unsigned int max_cpus)
{
	unsigned int node, num_nodes;
	unsigned int present_cpus = num_present_cpus();

	if (max_cpus >= present_cpus)
		return;

	if (max_cpus % smp_num_siblings != 0) {
		pr_warn("Hyper-V: minroot: number of root VPs should be a multiple of threads per core\n");
		goto invalid_config;
	}

	num_nodes = num_online_nodes();

	/*
	 * If the hv_root_vp_nodes option is specified, spread the root VPs
	 * evenly across the specified nodes. Otherwise, fill up nodes in order
	 * until we run out of root VPs.
	 */
	if (hv_minroot_nodes_defined) {
		int vps_per_node;
		int bsp_node = numa_cpu_node(raw_smp_processor_id());

		if (bsp_node == NUMA_NO_NODE)
			bsp_node = 0;

		if (!node_isset(bsp_node, hv_minroot_nodes)) {
			pr_warn("Hyper-V: minroot: hv_minroot_nodes must contain BSP's node\n");
			goto invalid_config;
		}

		nodes_and(hv_minroot_nodes, hv_minroot_nodes, node_online_map);

		num_nodes = nodes_weight(hv_minroot_nodes);
		vps_per_node = max_cpus / num_nodes;
		if (vps_per_node % smp_num_siblings != 0) {
			pr_warn("Hyper-V: minroot: number of root VPs per node should be a multiple of threads per core\n");
			goto invalid_config;
		}

		for_each_online_node(node) {
			if (!node_isset(node, hv_minroot_nodes))
				continue;

			minroot_cfg.vps_per_node[node] = vps_per_node;
		}
	} else {
		int remaining = max_cpus;
		int cpus_per_node = present_cpus / num_nodes;

		for_each_online_node(node) {
			minroot_cfg.vps_per_node[node] =
					min(remaining, cpus_per_node);

			if (minroot_cfg.vps_per_node[node]
					% smp_num_siblings != 0) {
				pr_warn("Hyper-V: minroot: number of root VPs in a node should be a multiple of threads per core\n");
				goto invalid_config;
			}

			remaining -= minroot_cfg.vps_per_node[node];

			if (!remaining)
				break;
		}
	}

	minroot_cfg.is_valid = true;
	return;

invalid_config:
	pr_warn("Hyper-V: invalid minroot configuration. Ignoring.\n");
}

static bool __init root_vp_allowed_on_node(int node)
{
	if (!hv_minroot_nodes_defined)
		return true;

	return node_isset(node, hv_minroot_nodes);
}

static bool __init can_create_root_vp(int cpu, int *vps_added)
{
	int node;

	if (!minroot_cfg.is_valid)
		return true;

	node = numa_cpu_node(cpu);
	if (node == NUMA_NO_NODE)
		node = 0;

	return root_vp_allowed_on_node(node)
		&& vps_added[node] < minroot_cfg.vps_per_node[node];
}

static void __init hv_create_root_vps(unsigned int max_cpus, bool kexec)
{
	unsigned int present_cpus = num_present_cpus();
	unsigned int lpidx, vpidx, node;
	int *vps_added;
	int ret;

	prepare_minroot_cfg(max_cpus);

	if (minroot_cfg.is_valid)
		pr_info("Hyper-V: booting in minroot configuration");

	vps_added = kcalloc(num_online_nodes(), sizeof(*vps_added), GFP_KERNEL);
	BUG_ON(!vps_added);

	vpidx = 1;
	vps_added[0] = 1;
	for (lpidx = 1; lpidx < present_cpus; ++lpidx) {
		int cpu = hv_lp_to_cpu[lpidx];

		node = numa_cpu_node(cpu);
		if (node == NUMA_NO_NODE)
			node = 0;

		if (!can_create_root_vp(cpu, vps_added)) {
			/*
			 * As per the provided minroot config, we can't create a
			 * root VP on this CPU. Mark it as not-present so that
			 * the core boot code doesn't try to bring it online
			 * (which will fail). Later in smp_cpus_done(), we will
			 * set it as present so as to reflect the actual state
			 * of the system: these CPUs exist but are offline.
			 */
			cpumask_set_cpu(cpu, &root_vps_absent_mask);
			set_cpu_present(cpu, false);
			continue;
		}

		if (!kexec) {
			/*
			 * hv_call_create_vp() uses the node number to construct
			 * hv_proximity_domain_info which is an input to the
			 * create VP hypercall. However, when creating root VPs,
			 * the hypervisor ignores the proximity domain info and
			 * instead uses the LP index to figure out NUMA node
			 * info. So, we can simply pass NUMA_NO_NODE here.
			 */
			/* params: node num, domid, vp index, lp index */
			ret = hv_call_create_vp(NUMA_NO_NODE,
					hv_current_partition_id, vpidx, lpidx);
			BUG_ON(ret);
		}

		++vpidx;
		++vps_added[node];
	}
}

/*
 * On a 4 core, single node, with HT, linux numbers cpus as:
 *     [0]c0 ht0   [1]c1 ht0   [2]c2 ht0   [3]c3 ht0
 *     [4]c0 ht1   [5]c1 ht1   [6]c2 ht1   [7]c3 ht1
 *
 * On a 4 core, two nodes, with HT, linux numbers cpus as:
 *     [0]n0 c0 h0    [1]n1 c0 ht0  [2]n0 c3 ht0 ......
 *
 * MSHV wants vcpus/vpidxs: [0]c0 ht0, [1]c0 ht1, [2]c1 ht0, [3]c1 ht1 ....
 * for the default core scheduler. classic scheduler doesn't care.
 * The requirement means linux cpu numbers and vcpu index won't
 * match. The driver uses hv_vp_index[] for that indirection.
 *
 * Other requirements are:
 *  - LPs must be added in only lpindex order, with any lapic ids for any lp
 *  - VPs can be created in any vp index order as long as the HT siblings
 *    match.
 *
 * To achieve above, we add LPs in order of apic ids.
 */
static void __init hv_smp_prepare_cpus(unsigned int max_cpus)
{
#ifdef CONFIG_X86_64
	s16 node;
	int i, lpidx, ret, cpu, ccpu = raw_smp_processor_id();
	bool kexec = false;
#endif
	native_smp_prepare_cpus(max_cpus);

	/*
	 *  Override wakeup_secondary_cpu_64 callback for SEV-SNP
	 *  enlightened guest.
	 */
	if (!ms_hyperv.paravisor_present && hv_isolation_type_snp()) {
		apic->wakeup_secondary_cpu_64 = hv_snp_boot_ap;
		return;
	}

	/* If AP LPs exist, we are in kexec kernel and VPs already exist */
	if (num_present_cpus() == 1)
		return;

#ifdef CONFIG_X86_64
	BUG_ON(ccpu != 0);

	/* If AP LPs exist, we are in kexec kernel and VPs already exist */
	if (hv_lp_exists(1))
		kexec = true;

	for (i = 0; i < NR_CPUS; i++)
		apicids[i] = INT_MAX;

	for_each_present_cpu(i) {
		if (i == 0)
			continue;

		BUG_ON(cpu_physical_id(i) == INT_MAX);
		apicids[i] = cpu_physical_id(i);
	}

	i = next_smallest_apicid(apicids, 0, &cpu);

	for (lpidx = 1; i != INT_MAX; lpidx++) {
		node = __apicid_to_node[i];
		if (node == NUMA_NO_NODE)
			node = 0;

		if (!kexec) {
			/* params: node num, lp index, apic id */
			ret = hv_call_add_logical_proc(node, lpidx, i);
			BUG_ON(ret);
		}

		hv_lp_to_cpu[lpidx] = cpu;

		i = next_smallest_apicid(apicids, i, &cpu);
	}

	/*
	 * We should only call this hypercall once we have added all the logical
	 * processors to the root partition.
	 *
	 * This is a strict requirement for CVM because without this hypercall
	 * MSHV won't expose support for launching SEV-SNP enabled guest.
	 *
	 * We can also invoke this hypercall for non-CVM usecase as well. There
	 * is no side effect because of this hypercall.
	 */
	if (!kexec) {
		ret = hv_call_notify_all_processors_started();
		WARN_ON(ret);
	}

	hv_create_root_vps(max_cpus, kexec);

#endif /* #ifdef CONFIG_X86_64 */
}

static void __init hv_smp_cpus_done(unsigned int max_cpus)
{
#ifdef CONFIG_X86_64
	unsigned int cpu;

	/* see the comment in hv_create_root_vps(). */
	if (minroot_cfg.is_valid) {
		for_each_cpu(cpu, &root_vps_absent_mask)
			set_cpu_present(cpu, true);
	}
#endif

	native_smp_cpus_done(max_cpus);
}
#endif /* #if defined(CONFIG_SMP) && IS_ENABLED(CONFIG_HYPERV) */

/*
 * When a fully enlightened TDX VM runs on Hyper-V, the firmware sets the
 * HW_REDUCED flag: refer to acpi_tb_create_local_fadt(). Consequently ttyS0
 * interrupts can't work because request_irq() -> ... -> irq_to_desc() returns
 * NULL for ttyS0. This happens because mp_config_acpi_legacy_irqs() sees a
 * nr_legacy_irqs() of 0, so it doesn't initialize the array 'mp_irqs[]', and
 * later setup_IO_APIC_irqs() -> find_irq_entry() fails to find the legacy irqs
 * from the array and hence doesn't create the necessary irq description info.
 *
 * Clone arch/x86/kernel/acpi/boot.c: acpi_generic_reduced_hw_init() here,
 * except don't change 'legacy_pic', which keeps its default value
 * 'default_legacy_pic'. This way, mp_config_acpi_legacy_irqs() sees a non-zero
 * nr_legacy_irqs() and eventually serial console interrupts works properly.
 */
static void __init reduced_hw_init(void)
{
	x86_init.timers.timer_init	= x86_init_noop;
	x86_init.irqs.pre_vector_init	= x86_init_noop;
}

int hv_get_hypervisor_version(union hv_hypervisor_version_info *info)
{
	unsigned int hv_max_functions;

	hv_max_functions = cpuid_eax(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
	if (hv_max_functions < HYPERV_CPUID_VERSION) {
		pr_err("%s: Could not detect Hyper-V version\n", __func__);
		return -ENODEV;
	}

	cpuid(HYPERV_CPUID_VERSION, &info->eax, &info->ebx, &info->ecx, &info->edx);

	return 0;
}
EXPORT_SYMBOL_GPL(hv_get_hypervisor_version);

static void __init __maybe_unused hv_preset_lpj(void)
{
	unsigned long khz;
	u64 lpj;

	if (!x86_platform.calibrate_tsc)
		return;

	khz = x86_platform.calibrate_tsc();

	lpj = ((u64)khz * 1000);
	do_div(lpj, HZ);
	preset_lpj = lpj;
}

#define HV_MAX_RESVD_RANGES 32
static int hv_resvd_ranges[HV_MAX_RESVD_RANGES] = {
					[0 ... HV_MAX_RESVD_RANGES-1] = -1};
static struct resource hv_mshv_res[HV_MAX_RESVD_RANGES];
static u32 ranges_nr;

/*
 * Parse "hyperv_resvd_new=<size>!<address>,<size>!<address>,...", specifying a
 * list of memory ranges that are reserved by the loader for the hypervisor.
 */
static int __init hv_parse_hyperv_resvd_new(char *arg)
{
	unsigned long long region_start, region_sz;
	int i = 0;
	char *curr = arg;

	mshv_loader_new = true;

	if (is_kdump_kernel())
		return 0;

	while (*curr != 0) {
		region_sz = simple_strtoull(curr, &curr, 16);
		if (!region_sz) {
			pr_err("Hyper-V: invalid format for hyperv_resvd_new: %s\n", arg);
			BUG();
		}

		if (*curr != '!') {
			pr_err("Hyper-V: invalid format for hyperv_resvd_new: %s\n", arg);
			BUG();
		}

		++curr;

		region_start = simple_strtoull(curr, &curr, 16);
		if (region_start == 0) {
			pr_err("Hyper-V: invalid format for hyperv_resvd_new: %s\n", arg);
			BUG();
		}

		memblock_reserve(region_start, region_sz);

		hv_mshv_res[i].name = "Hypervisor Code and Data";
		hv_mshv_res[i].flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
		hv_mshv_res[i].start = region_start;
		hv_mshv_res[i].end = region_start + region_sz - 1;

		if (*curr == ',')
			++curr;

		++i;
	}

	ranges_nr = i;

	return 0;
}
early_param("hyperv_resvd_new", hv_parse_hyperv_resvd_new);

/*
 * Parse eg "hyperv_resvd=3,7,20" where 3, 7, and 20 are indexes into the e820
 * table for ranges that are reserved by the loader for the hypervisor
 */
static int __init hv_parse_hyperv_resvd(char *arg)
{
	int idx, max = ARRAY_SIZE(hv_resvd_ranges);
	int i = 0;

	mshv_loader_new = false;

	if (is_kdump_kernel())
		return 0;

	if (hv_resvd_ranges[0] != -1) {
		pr_err("Hyper-V: multile hyperv_resvd not supported\n");
		return 0;
	}

	while (get_option(&arg, &idx)) {
		if (i >= max) {
			pr_err("Hyper-V: resvd ranges tbl full %d\n", idx);
			break;
		}

		hv_resvd_ranges[i++] = idx;
	}

	return 0;
}
early_param("hyperv_resvd", hv_parse_hyperv_resvd);

/*
 * Reserve memory that the hypervisor is using early on. The ranges are marked
 * reserved by a custom bootloader, change that to usable and reserve that
 * range. Note, the bootloader sanitizes the e820 before passing on here.
 */
static void __init hv_resv_mshv_memory(void)
{
	u64 start, end, size;
	int i, idx, max = ARRAY_SIZE(hv_resvd_ranges);

	for (i = 0; i < max && hv_resvd_ranges[i] != -1; i++) {

		idx = hv_resvd_ranges[i];
		if (idx < 0 || idx >= e820_table->nr_entries) {
			pr_info("Hyper-V: invalid resvd idx %d\n", idx);
			continue;
		}

		start = e820_table->entries[idx].addr;
		size = e820_table->entries[idx].size;
		end = start + size - 1;

		memblock_reserve(start, size);
		e820_table->entries[idx].type = E820_TYPE_RAM;
		pr_info("Hyper-V reserve [mem %#018Lx-%#018Lx]\n", start, end);

		hv_mshv_res[i].name = "Hypervisor Code and Data";
		hv_mshv_res[i].flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
		hv_mshv_res[i].start = start;
		hv_mshv_res[i].end = end;
	}
}

/*
 * Log memory ranges that the hypervisor uses. The ranges are marked
 * by a custom bootloader.
 */
static void __init hv_dump_mshv_memory(void)
{
	u64 start, end;
	int i;

	for (i = 0; i < ranges_nr; i++) {
		start = hv_mshv_res[i].start;
		end = hv_mshv_res[i].end;
		pr_info("Hyper-V reserve [mem %#018Lx-%#018Lx]\n", start, end);
	}
}

/* this cannot be done during platform init, hence called from hyperv_init() */
void __init hv_mark_resources(void)
{
	int i, max = ARRAY_SIZE(hv_mshv_res);

	for (i = 0; i < max && hv_mshv_res[i].end; i++)
		insert_resource(&iomem_resource, &hv_mshv_res[i]);
}

static void __init ms_hyperv_init_platform(void)
{
	int hv_max_functions_eax;

#ifdef CONFIG_PARAVIRT
	pv_info.name = "Hyper-V";
#endif

	/*
	 * Extract the features and hints
	 */
	ms_hyperv.features = cpuid_eax(HYPERV_CPUID_FEATURES);
	ms_hyperv.priv_high = cpuid_ebx(HYPERV_CPUID_FEATURES);
	ms_hyperv.ext_features = cpuid_ecx(HYPERV_CPUID_FEATURES);
	ms_hyperv.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
	ms_hyperv.hints    = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

	hv_max_functions_eax = cpuid_eax(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, ext 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high,
		ms_hyperv.ext_features, ms_hyperv.hints,
		ms_hyperv.misc_features);

	ms_hyperv.max_vp_index = cpuid_eax(HYPERV_CPUID_IMPLEMENT_LIMITS);
	ms_hyperv.max_lp_index = cpuid_ebx(HYPERV_CPUID_IMPLEMENT_LIMITS);

	pr_debug("Hyper-V: max %u virtual processors, %u logical processors\n",
		 ms_hyperv.max_vp_index, ms_hyperv.max_lp_index);

	hv_identify_partition_type();

	if (hv_root_partition()) {
		/* very first thing, reserve/log exclusive hypervisor memory */
		if (mshv_loader_new)
			hv_dump_mshv_memory();
		else
			hv_resv_mshv_memory();
	}

	if (ms_hyperv.hints & HV_X64_HYPERV_NESTED) {
		hv_nested = true;
		pr_info("Hyper-V: running on a nested hypervisor\n");
	}

	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		x86_platform.calibrate_tsc = hv_get_tsc_khz;
		x86_platform.calibrate_cpu = hv_get_tsc_khz;
		setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);
	}

	if (ms_hyperv.priv_high & HV_ISOLATION) {
		ms_hyperv.isolation_config_a = cpuid_eax(HYPERV_CPUID_ISOLATION_CONFIG);
		ms_hyperv.isolation_config_b = cpuid_ebx(HYPERV_CPUID_ISOLATION_CONFIG);

		if (ms_hyperv.shared_gpa_boundary_active)
			ms_hyperv.shared_gpa_boundary =
				BIT_ULL(ms_hyperv.shared_gpa_boundary_bits);

		hyperv_paravisor_present = !!ms_hyperv.paravisor_present;

		pr_info("Hyper-V: Isolation Config: Group A 0x%x, Group B 0x%x\n",
			ms_hyperv.isolation_config_a, ms_hyperv.isolation_config_b);


		if (hv_get_isolation_type() == HV_ISOLATION_TYPE_SNP) {
			static_branch_enable(&isolation_type_snp);
		} else if (hv_get_isolation_type() == HV_ISOLATION_TYPE_TDX) {
			static_branch_enable(&isolation_type_tdx);

			/* A TDX VM must use x2APIC and doesn't use lazy EOI. */
			ms_hyperv.hints &= ~HV_X64_APIC_ACCESS_RECOMMENDED;

			if (!ms_hyperv.paravisor_present) {
				/* To be supported: more work is required.  */
				ms_hyperv.features &= ~HV_MSR_REFERENCE_TSC_AVAILABLE;

				/* HV_MSR_CRASH_CTL is unsupported. */
				ms_hyperv.misc_features &= ~HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE;

				/* Don't trust Hyper-V's TLB-flushing hypercalls. */
				ms_hyperv.hints &= ~HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED;

				x86_init.acpi.reduced_hw_early_init = reduced_hw_init;
			}
		}
	}

	if (hv_max_functions_eax >= HYPERV_CPUID_NESTED_FEATURES) {
		ms_hyperv.nested_features =
			cpuid_eax(HYPERV_CPUID_NESTED_FEATURES);
		pr_info("Hyper-V: Nested features: 0x%x\n",
			ms_hyperv.nested_features);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	if (ms_hyperv.features & HV_ACCESS_FREQUENCY_MSRS &&
	    ms_hyperv.misc_features & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE) {
		/*
		 * Get the APIC frequency.
		 */
		u64	hv_lapic_frequency;

		rdmsrl(HV_X64_MSR_APIC_FREQUENCY, hv_lapic_frequency);
		hv_lapic_frequency = div_u64(hv_lapic_frequency, HZ);
		lapic_timer_period = hv_lapic_frequency;
		pr_info("Hyper-V: LAPIC Timer Frequency: %#x\n",
			lapic_timer_period);
	}

	register_nmi_handler(NMI_UNKNOWN, hv_nmi_unknown, NMI_FLAG_FIRST,
			     "hv_nmi_unknown");
#endif

#ifdef CONFIG_X86_IO_APIC
	no_timer_check = 1;
#endif

#if IS_ENABLED(CONFIG_HYPERV) && defined(CONFIG_KEXEC_CORE)
	machine_ops.shutdown = hv_machine_shutdown;
	if (!hv_root_partition())
		machine_ops.crash_shutdown = hv_guest_crash_shutdown;
#endif
	if (ms_hyperv.features & HV_ACCESS_TSC_INVARIANT) {
		/*
		 * Writing to synthetic MSR 0x40000118 updates/changes the
		 * guest visible CPUIDs. Setting bit 0 of this MSR  enables
		 * guests to report invariant TSC feature through CPUID
		 * instruction, CPUID 0x800000007/EDX, bit 8. See code in
		 * early_init_intel() where this bit is examined. The
		 * setting of this MSR bit should happen before init_intel()
		 * is called.
		 */
		wrmsrl(HV_X64_MSR_TSC_INVARIANT_CONTROL, HV_EXPOSE_INVARIANT_TSC);
		setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);
	}

	/*
	 * Generation 2 instances don't support reading the NMI status from
	 * 0x61 port.
	 */
	if (efi_enabled(EFI_BOOT))
		x86_platform.get_nmi_reason = hv_get_nmi_reason;

#if IS_ENABLED(CONFIG_HYPERV)
	if ((hv_get_isolation_type() == HV_ISOLATION_TYPE_VBS) ||
	    ms_hyperv.paravisor_present)
		hv_vtom_init();
	/*
	 * Setup the hook to get control post apic initialization.
	 */
	x86_platform.apic_post_init = hyperv_init;
	hyperv_setup_mmu_ops();
	/* Setup the IDT for hypervisor callback */
	alloc_intr_gate(HYPERVISOR_CALLBACK_VECTOR, asm_sysvec_hyperv_callback);

	/* Setup the IDT for reenlightenment notifications */
	if (ms_hyperv.features & HV_ACCESS_REENLIGHTENMENT) {
		alloc_intr_gate(HYPERV_REENLIGHTENMENT_VECTOR,
				asm_sysvec_hyperv_reenlightenment);
	}

	/* Setup the IDT for stimer0 */
	if (ms_hyperv.misc_features & HV_STIMER_DIRECT_MODE_AVAILABLE) {
		alloc_intr_gate(HYPERV_STIMER0_VECTOR,
				asm_sysvec_hyperv_stimer0);
	}

# ifdef CONFIG_SMP
	smp_ops.smp_prepare_boot_cpu = hv_smp_prepare_boot_cpu;
	if (hv_root_partition() ||
	    (!ms_hyperv.paravisor_present && hv_isolation_type_snp()))
		smp_ops.smp_prepare_cpus = hv_smp_prepare_cpus;

	if (hv_root_partition())
		smp_ops.smp_cpus_done = hv_smp_cpus_done;
# endif

	/*
	 * Hyper-V doesn't provide irq remapping for IO-APIC. To enable x2apic,
	 * set x2apic destination mode to physical mode when x2apic is available
	 * and Hyper-V IOMMU driver makes sure cpus assigned with IO-APIC irqs
	 * have 8-bit APIC id.
	 */
# ifdef CONFIG_X86_X2APIC
	if (x2apic_supported())
		x2apic_phys = 1;
# endif

	/* Register Hyper-V specific clocksource */
	hv_init_clocksource();
	x86_setup_ops_for_tsc_pg_clock();
	hv_vtl_init_platform();

	/*
	 * Preset lpj to make calibrate_delay a no-op, which is turn helps to
	 * speed up secondary cores initialization.
	 */
	hv_preset_lpj();
#endif
	/*
	 * TSC should be marked as unstable only after Hyper-V
	 * clocksource has been initialized. This ensures that the
	 * stability of the sched_clock is not altered.
	 */
	if (!(ms_hyperv.features & HV_ACCESS_TSC_INVARIANT))
		mark_tsc_unstable("running on Hyper-V");

	hardlockup_detector_disable();
}

static bool __init ms_hyperv_x2apic_available(void)
{
	return x2apic_supported();
}

/*
 * If ms_hyperv_msi_ext_dest_id() returns true, hyperv_prepare_irq_remapping()
 * returns -ENODEV and the Hyper-V IOMMU driver is not used; instead, the
 * generic support of the 15-bit APIC ID is used: see __irq_msi_compose_msg().
 *
 * Note: for a VM on Hyper-V, the I/O-APIC is the only device which
 * (logically) generates MSIs directly to the system APIC irq domain.
 * There is no HPET, and PCI MSI/MSI-X interrupts are remapped by the
 * pci-hyperv host bridge.
 *
 * Note: for a Hyper-V root partition, this will always return false.
 * The hypervisor doesn't expose these HYPERV_CPUID_VIRT_STACK_* cpuids by
 * default, they are implemented as intercepts by the Windows Hyper-V stack.
 * Even a nested root partition (L2 root) will not get them because the
 * nested (L1) hypervisor filters them out.
 */
static bool __init ms_hyperv_msi_ext_dest_id(void)
{
	u32 eax;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_INTERFACE);
	if (eax != HYPERV_VS_INTERFACE_EAX_SIGNATURE)
		return false;

	eax = cpuid_eax(HYPERV_CPUID_VIRT_STACK_PROPERTIES);
	return eax & HYPERV_VS_PROPERTIES_EAX_EXTENDED_IOAPIC_RTE;
}

#ifdef CONFIG_AMD_MEM_ENCRYPT
static void hv_sev_es_hcall_prepare(struct ghcb *ghcb, struct pt_regs *regs)
{
	/* RAX and CPL are already in the GHCB */
	ghcb_set_rcx(ghcb, regs->cx);
	ghcb_set_rdx(ghcb, regs->dx);
	ghcb_set_r8(ghcb, regs->r8);
}

static bool hv_sev_es_hcall_finish(struct ghcb *ghcb, struct pt_regs *regs)
{
	/* No checking of the return state needed */
	return true;
}
#endif

const __initconst struct hypervisor_x86 x86_hyper_ms_hyperv = {
	.name			= "Microsoft Hyper-V",
	.detect			= ms_hyperv_platform,
	.type			= X86_HYPER_MS_HYPERV,
	.init.x2apic_available	= ms_hyperv_x2apic_available,
	.init.msi_ext_dest_id	= ms_hyperv_msi_ext_dest_id,
	.init.init_platform	= ms_hyperv_init_platform,
#ifdef CONFIG_AMD_MEM_ENCRYPT
	.runtime.sev_es_hcall_prepare = hv_sev_es_hcall_prepare,
	.runtime.sev_es_hcall_finish = hv_sev_es_hcall_finish,
#endif
};
