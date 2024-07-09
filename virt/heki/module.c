// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Authentication
 *
 * Copyright © 2024 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

extern __initconst const u8 system_certificate_list[];
extern __initconst const unsigned long module_cert_size;

static u8 *heki_module_certs;
static unsigned long heki_module_cert_size;

static int __init heki_copy_module_certs(void)
{
	heki_module_certs = vmalloc(module_cert_size);
	if (!heki_module_certs) {
		pr_warn("Failed to alloc module certificates.\n");
		return -ENOMEM;
	}
	heki_module_cert_size = module_cert_size;

	/*
	 * Copy the module certificates because they will be freed at
	 * the end of init.
	 */
	memcpy(heki_module_certs, system_certificate_list, module_cert_size);
	return 0;
}
core_initcall(heki_copy_module_certs);

static void heki_get_ranges(struct heki_args *args)
{
	phys_addr_t pa, pa_end, pa_next;
	unsigned long va, va_end, va_next;

	if (!pfn_valid(args->pa >> PAGE_SHIFT))
		return;

	va_end = args->va + args->size;
	pa_end = args->pa + args->size;
	for (va = args->va, pa = args->pa;
	     pa < pa_end;
	     va = va_next, pa = pa_next) {
		va_next = (va & PAGE_MASK) + PAGE_SIZE;
		pa_next = (pa & PAGE_MASK) + PAGE_SIZE;
		if (pa_next > pa_end) {
			va_next = va_end;
			pa_next = pa_end;
		}
		heki_add_range(args, va, pa, pa_next);
	}
}

void heki_load_kdata(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_args args = {};

	if (!hypervisor || !heki_module_certs)
		return;

	mutex_lock(&heki.lock);

	args.attributes = HEKI_MODULE_CERTS;
	heki_walk((unsigned long)heki_module_certs,
		  (unsigned long)heki_module_certs + heki_module_cert_size,
		  heki_get_ranges, &args);

	if (hypervisor->load_kdata(args.head_pa, args.nranges))
		pr_warn("Failed to load kernel data.\n");
	else
		pr_warn("Loaded kernel data\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);
	vfree(heki_module_certs);
}
