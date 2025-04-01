// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;
struct heki heki;

/*
 * Must be called after mark_readonly().
 */
void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int ret;

	if (!heki_enabled || !heki.hypervisor)
		return;

	/* Locks control registers so a compromised guest cannot change them. */
	if (hypervisor->lock_crs)
		ret = hypervisor->lock_crs();

	if (ret)
		pr_warn("Unable to lock down control registers\n");
	else
		pr_warn("Control registers locked\n");

	mutex_init(&heki.lock);
	heki_arch_init();
	heki_load_kdata();

	/*
	 * Signal end of kernel boot.
	 * This means all boot time lvbs protections are in place and protections on
	 * many of the resources cannot be altered now.
	 */
	if (hypervisor->finish_boot)
		hypervisor->finish_boot();
}

void heki_register_hypervisor(struct heki_hypervisor *hypervisor)
{
	heki.hypervisor = hypervisor;
}

static int __init heki_parse_config(char *str)
{
	if (kstrtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);

void heki_get_ranges(struct heki_args *args)
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
