/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	/* Lock control registers. */
	int (*lock_crs)(void);

	/* Signal end of kernel boot */
	int (*finish_boot)(void);
};

#ifdef CONFIG_HEKI
/*
 * The kernel page table is walked to locate kernel mappings. For each
 * mapping, a callback function is called. The table walker passes information
 * about the mapping to the callback using this structure.
 */
struct heki_args {
	/* Information passed by the table walker to the callback. */
	unsigned long va;
	phys_addr_t pa;
	size_t size;
	unsigned long flags;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(struct heki_args *args);

void heki_late_init(void);
void heki_register_hypervisor(struct heki_hypervisor *hypervisor);

#else /* !CONFIG_HEKI */

static inline void heki_late_init(void)
{
}

static void heki_register_hypervisor(struct heki_hypervisor *hypervisor) { }

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
