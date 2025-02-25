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

static void heki_apply_permissions(struct heki_args *args);

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

bool __weak heki_protect_pfn(unsigned long pfn)
{
	return true;
}

static void heki_protect_cb(struct heki_args *args)
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
		if (!heki_protect_pfn(pfn))
			continue;

		cur_perm = (unsigned long) xa_load(&args->permissions, pfn);

		args->attributes = cur_perm | perm;
		heki_add_range(args, va, pa, pa + PAGE_SIZE);
	}
}

/* Protect guest memory in the host page table. */
void heki_protect(unsigned long va, unsigned long end, struct heki_args *args)
{
	va = ALIGN_DOWN(va, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	heki_walk(va, end, heki_protect_cb, args);
	heki_apply_permissions(args);
}

/*
 * Build a list of guest pages with their permissions. This list will be
 * passed to the VMM/Hypervisor to set these permissions in the host page
 * table.
 */
void heki_add_range(struct heki_args *args, unsigned long va,
		    phys_addr_t pa, phys_addr_t epa)
{
	struct heki_page *list = args->head;
	struct heki_range *cur = args->cur;
	struct heki_range *range;
	u64 max_ranges;
	struct page *page;

	max_ranges = (PAGE_SIZE - sizeof(*list)) / sizeof(*range);

	if (cur && cur->epa == pa && cur->attributes == args->attributes) {
		cur->epa = epa;
		return;
	}

	if (!list || list->nranges == max_ranges) {
		page = alloc_page(GFP_KERNEL);
		if (WARN_ON_ONCE(!page))
			return;

		list = page_address(page);
		list->nranges = 0;
		list->next = NULL;
		list->next_pa = 0;

		if (args->head) {
			args->tail->next = list;
			args->tail->next_pa = page_to_pfn(page) << PAGE_SHIFT;
		} else {
			args->head = list;
			args->head_pa = page_to_pfn(page) << PAGE_SHIFT;
		}
		args->tail = list;
	}

	range = &list->ranges[list->nranges];
	range->va = va;
	range->pa = pa;
	range->epa = epa;
	range->attributes = args->attributes;
	args->cur = range;
	list->nranges++;
	args->nranges++;
}

void heki_cleanup_args(struct heki_args *args)
{
	struct heki_page *list = args->head;
	phys_addr_t list_pa = args->head_pa;
	struct page *page;

	/* Free all the pages in the page list. */
	while (list) {
		page = pfn_to_page(list_pa >> PAGE_SHIFT);
		list_pa = list->next_pa;
		list = list->next;
		__free_pages(page, 0);
	}
}

static void heki_apply_permissions(struct heki_args *args)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_page *list = args->head;
	phys_addr_t list_pa = args->head_pa;
	int ret;

	if (!list)
		return;

	/* Protect guest memory in the host page table. */
	ret = hypervisor->protect_memory(list_pa, args->nranges);
	if (ret) {
		pr_warn_ratelimited("Failed to set memory permission\n");
		return;
	}

	heki_cleanup_args(args);
}
