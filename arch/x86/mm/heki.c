// SPDX-License-Identifier: GPL-2.0
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Arch specific.
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/mem_attr.h>

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

static unsigned long kernel_va;
static unsigned long kernel_end;
static unsigned long direct_map_va;
static unsigned long direct_map_end;

void heki_arch_init(void)
{
	struct heki_args args = {};

	size_t direct_map_size;

	if (pgtable_l5_enabled()) {
		kernel_va = 0xff00000000000000UL;
		kernel_end = 0xffffffffffe00000UL;
		direct_map_size = 0xff91000000000000UL - 0xff11000000000000UL;
	} else {
		kernel_va = 0xffff800000000000UL;
		kernel_end = 0xffffffffffe00000UL;
		direct_map_size = 0xffffc88000000000UL - 0xffff888000000000UL;
	}
	direct_map_va = PAGE_OFFSET;
	direct_map_end = direct_map_va + direct_map_size;

	mutex_lock(&heki.lock);

	xa_init(&args.permissions);

	/*
	 * Walk all the kernel mappings and record the permissions for each
	 * physical page. If there are multiple mappings to a page, the
	 * permissions must be ORed.
	 */
	heki_init_perm(kernel_va, direct_map_va, &args);
	heki_init_perm(direct_map_end, kernel_end, &args);

	xa_destroy(&args.permissions);

	mutex_unlock(&heki.lock);
}

unsigned long heki_flags_to_permissions(unsigned long flags)
{
	unsigned long permissions;

	permissions = MEM_ATTR_READ | MEM_ATTR_EXEC;
	if (flags & _PAGE_RW)
		permissions |= MEM_ATTR_WRITE;
	if (flags & _PAGE_NX)
		permissions &= ~MEM_ATTR_EXEC;

	return permissions;
}
