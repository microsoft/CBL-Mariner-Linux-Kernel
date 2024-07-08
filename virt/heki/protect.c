// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Protect kernel mappings.
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/mem_attr.h>
#include <linux/xarray.h>

#include "common.h"

static void heki_init_perm_cb(struct heki_args *args)
{
	unsigned long va;
	phys_addr_t pa, pa_end;
	unsigned long pfn, perm, cur_perm;

	if (!pfn_valid(args->pa >> PAGE_SHIFT))
		return;

	perm = heki_flags_to_permissions(args->flags);

	/* Walk the leaf entries and record page permissions for each page. */
	pa_end = args->pa + args->size;
	for (pa = args->pa, va = args->va; pa < pa_end;
	     pa += PAGE_SIZE, va += PAGE_SIZE) {

		pfn = pa >> PAGE_SHIFT;
		cur_perm = (unsigned long) xa_load(&args->permissions, pfn);
		if (cur_perm)
			perm |= cur_perm;
		xa_store(&args->permissions, pfn, (void *) perm, GFP_KERNEL);
	}
}

/* Find the mappings in the given range and initialize permissions for them. */
void heki_init_perm(unsigned long va, unsigned long end, struct heki_args *args)
{
	va = ALIGN_DOWN(va, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	heki_walk(va, end, heki_init_perm_cb, args);
}
