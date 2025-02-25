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
#include <linux/mm.h>
#include <linux/xarray.h>

/*
 * This structure contains a guest physical range and its attributes (e.g.,
 * permissions (RWX)).
 */
struct heki_range {
	unsigned long va;
	phys_addr_t pa;
	phys_addr_t epa;
	unsigned long attributes;
};

/*
 * Guest ranges are passed to the VMM or hypervisor so they can be authenticated
 * and their permissions can be set in the host page table. When an array of
 * these is passed to the Hypervisor or VMM, the array must be in physically
 * contiguous memory.
 *
 * This struct occupies one page. In each page, an array of guest ranges can
 * be passed. A guest request to the VMM/Hypervisor may contain a list of
 * these structs (linked by "next_pa").
 */
struct heki_page {
	struct heki_page *next;
	phys_addr_t next_pa;
	unsigned long nranges;
	struct heki_range ranges[];
};

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	/* Lock control registers. */
	int (*lock_crs)(void);

	/* Signal end of kernel boot */
	int (*finish_boot)(void);

	/* Protect guest memory */
	int (*protect_memory)(phys_addr_t pa, unsigned long nranges);
};

#ifdef CONFIG_HEKI

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 */
struct heki {
	struct heki_hypervisor *hypervisor;
	struct mutex lock;
};

extern struct heki heki;
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
	struct xarray permissions;

	/* attributes passed to heki_add_pa_range(). */
	unsigned long attributes;

	/* Page list is built by the callback. */
	struct heki_page *head;
	struct heki_page *tail;
	struct heki_range *cur;
	unsigned long nranges;
	phys_addr_t head_pa;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(struct heki_args *args);

void heki_late_init(void);
void heki_register_hypervisor(struct heki_hypervisor *hypervisor);
void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func,
	       struct heki_args *args);
void heki_map(unsigned long va, unsigned long end);
void heki_init_perm(unsigned long va, unsigned long end,
		    struct heki_args *args);
void heki_protect(unsigned long va, unsigned long end, struct heki_args *args);
void heki_add_range(struct heki_args *args, unsigned long va,
		    phys_addr_t pa, phys_addr_t epa);
void heki_cleanup_args(struct heki_args *args);

/* Arch-specific functions. */
void heki_arch_init(void);
unsigned long heki_flags_to_permissions(unsigned long flags);

#else /* !CONFIG_HEKI */

static inline void heki_late_init(void)
{
}

static void heki_register_hypervisor(struct heki_hypervisor *hypervisor) { }

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
