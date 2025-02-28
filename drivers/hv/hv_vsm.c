// SPDX-License-Identifier: GPL-2.0-only
/*
 * VSM framework that enables VTL1, loads secure kernel and boots VTL1.
 *
 * Copyright © 2024 Microsoft Corporation
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/heki.h>

#include <hyperv/hvgdk_mini.h>
#include <hyperv/hv_vsm.h>

#include <asm/mshyperv.h>

#include "mshv.h"
#include "hv_vsm.h"

/*
 * This function expects the upper VTL to preserve all registers except
 * those used by the VTL calling convention ABI (%rdi, %rsi, %rdx, %r8).
 *
 * VTL1 reliance means the Linux x86_64 ABI (%rbx, %r12, %r13, %r14, %r15)
 * must be restored by the caller during bootstrapping when VTL1 is not
 * operational.
 *
 * The %rcx register must be explicitly preserved as it is clobbered,
 * causing issues if this function is inlined. %rax is not restored by the
 * upper VTL (passed via the assist page) but is unused and can be ignored.
 *
 * This function preserves the args variable on the stack as it is passed
 * via a scratch register and clobbered.
 *
 * Microsoft Hypervisor preserves %rsp during VTL switches.
 */
void __hv_vsm_vtlcall(struct hv_vtlcall_param *args)
{
	register u64 r8 asm("r8");
	u64 hcall_addr;

	hcall_addr = (u64)((u8 *)hv_hypercall_pg + vsm_code_page_offsets.vtl_call_offset);
	r8 = args->a3;

	asm volatile (
	/* Push args to stack as %rcx is not preserved across a VTL call */
		"pushq %[args]\n"
	/* Make rcx 0 */
		"xorl	%%ecx, %%ecx\n"
	/* VTL call */
		CALL_NOSPEC
	/* Restore args from stack */
		"popq %[args]\n"
		: "+D"(args->a0), "+S"(args->a1),
		  "+d"(args->a2), "+r"(r8)
		: [thunk_target]"a"(hcall_addr), [args]"r"(args)
	/* See the comment above the function why %rcx if here */
		: "cc", "memory", "rcx");

	args->a3 = r8;
}

static int hv_vsm_vtlcall(struct hv_vtlcall_param *args)
{
	unsigned long flags = 0;

	local_irq_save(flags);
	__hv_vsm_vtlcall(args);
	local_irq_restore(flags);

	return (int)args->a3;
}

static int hv_vsm_lock_crs(void)
{
	cpumask_var_t orig_mask;
	struct hv_vtlcall_param args = {0};
	int cpu, ret = 0;

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_LOCK_REGS;

	if (!alloc_cpumask_var(&orig_mask, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out;
	}
	cpumask_copy(orig_mask, &current->cpus_mask);
	/*
	 * ToDo: Spin off separate threads on each cpu to do this.
	 * Should be better from a performance point of view.
	 * Irrespective this thread should wait until all cpus have locked
	 * the registers
	 */
	for_each_online_cpu(cpu) {
		set_cpus_allowed_ptr(current, cpumask_of(cpu));
		ret = hv_vsm_vtlcall(&args);
		if (ret) {
			pr_err("%s: Unable to lock registers for cpu%d..Aborting\n",
			       __func__, cpu);
			break;
		}
	}
	set_cpus_allowed_ptr(current, orig_mask);
	free_cpumask_var(orig_mask);

out:
	return ret;
}

static int hv_vsm_signal_end_of_boot(void)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT;
	return hv_vsm_vtlcall(&args);
}

static int hv_vsm_protect_memory(phys_addr_t pa, unsigned long nranges)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success || !hv_vsm_mbec_enabled)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY;
	args.a1 = pa;
	args.a2 = nranges;
	return hv_vsm_vtlcall(&args);
}

static int hv_vsm_load_kdata(phys_addr_t pa, unsigned long nranges)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA;
	args.a1 = pa;
	args.a2 = nranges;
	return hv_vsm_vtlcall(&args);
}

static long hv_vsm_validate_module(phys_addr_t pa, unsigned long nranges,
				   unsigned long flags)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE;
	args.a1 = pa;
	args.a2 = nranges;
	args.a3 = flags;
	return hv_vsm_vtlcall(&args);
}

static int hv_vsm_free_module_init(long token)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT;
	args.a1 = token;
	return hv_vsm_vtlcall(&args);
}

static int hv_vsm_unload_module(long token)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE;
	args.a1 = token;
	return hv_vsm_vtlcall(&args);
}

static int hv_vsm_copy_secondary_key(phys_addr_t pa, unsigned long nranges)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -EINVAL;

	args.a0 = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY;
	args.a1 = pa;
	args.a2 = nranges;

	return hv_vsm_vtlcall(&args);
}

#ifdef CONFIG_KEXEC_FILE

static int hv_vsm_kexec_validate(phys_addr_t pa, unsigned long nranges,
				 bool crash)
{
	struct hv_vtlcall_param args = {0};

	if (!hv_vsm_boot_success)
		return -ENOTSUPP;

	args.a0 = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE;
	args.a1 = pa;
	args.a2 = nranges;
	args.a3 = crash;

	return hv_vsm_vtlcall(&args);
}

#endif

static struct heki_hypervisor hyperv_heki_hypervisor = {
	.lock_crs = hv_vsm_lock_crs,
	.finish_boot = hv_vsm_signal_end_of_boot,
	.protect_memory = hv_vsm_protect_memory,
	.load_kdata = hv_vsm_load_kdata,
	.validate_module = hv_vsm_validate_module,
	.free_module_init = hv_vsm_free_module_init,
	.unload_module = hv_vsm_unload_module,
	.copy_secondary_key = hv_vsm_copy_secondary_key,
#ifdef CONFIG_KEXEC_FILE
	.kexec_validate = hv_vsm_kexec_validate,
#endif
};

int __init hv_vsm_init_heki(void)
{
	if (hv_vsm_boot_success)
		heki_register_hypervisor(&hyperv_heki_hypervisor);

	return 0;
}

static int __init vsm_arch_has_vsm_access(void)
{
	if (!(ms_hyperv.features & HV_MSR_SYNIC_AVAILABLE))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VSM))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VP_REGS))
		return false;
	return true;
}

static int __init vsm_get_max_vtl(int *max_vtl)
{
	struct hv_register_assoc reg = {
		.name = HV_REGISTER_VSM_PARTITION_STATUS,
	};
	union hv_input_vtl input_vtl = {
		.as_uint8 = 0,
	};
	int err;

	err = hv_call_get_vp_registers(HV_VP_INDEX_SELF,
				       HV_PARTITION_ID_SELF,
				       1, input_vtl, &reg);
	if (err)
		return err;

	*max_vtl = reg.value.vsm_partition_status.max_vtl;

	return 0;
}

int __init vsm_init(void)
{
	int max_vtl;

	if (!vsm_arch_has_vsm_access())
		return 0;

	if (vsm_get_max_vtl(&max_vtl))
		return 0;

	if (max_vtl == 0)
		return 0;

	return hv_vsm_boot_init();
}
