// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Kernel page table walker.
 *
 * Copyright © 2023 Microsoft Corporation
 *
 * Cf. arch/x86/mm/init_64.c
 */

#include <linux/heki.h>
#include <linux/pgtable.h>

static void heki_walk_pte(pmd_t *pmd, unsigned long va, unsigned long va_end,
			  heki_func_t func, struct heki_args *args)
{
	pte_t *pte;
	unsigned long next_va;

	for (pte = pte_offset_kernel(pmd, va); va < va_end;
	     va = next_va, pte++) {
		next_va = (va + PAGE_SIZE) & PAGE_MASK;
		if (next_va > va_end)
			next_va = va_end;

		if (!pte_present(*pte))
			continue;

		args->va = va;
		args->pa = pte_pfn(*pte) << PAGE_SHIFT;
		args->pa += va & (PAGE_SIZE - 1);
		args->size = next_va - va;
		args->flags = pte_flags(*pte);

		func(args);
	}
}

static void heki_walk_pmd(pud_t *pud, unsigned long va, unsigned long va_end,
			  heki_func_t func, struct heki_args *args)
{
	pmd_t *pmd;
	unsigned long next_va;

	for (pmd = pmd_offset(pud, va); va < va_end; va = next_va, pmd++) {
		next_va = pmd_addr_end(va, va_end);
		if (next_va > va_end)
			next_va = va_end;

		if (!pmd_present(*pmd))
			continue;

		if (pmd_large(*pmd)) {
			args->va = va;
			args->pa = pmd_pfn(*pmd) << PAGE_SHIFT;
			args->pa += va & (PMD_SIZE - 1);
			args->size = next_va - va;
			args->flags = pmd_flags(*pmd);

			func(args);
		} else {
			heki_walk_pte(pmd, va, next_va, func, args);
		}
	}
}

static void heki_walk_pud(p4d_t *p4d, unsigned long va, unsigned long va_end,
			  heki_func_t func, struct heki_args *args)
{
	pud_t *pud;
	unsigned long next_va;

	for (pud = pud_offset(p4d, va); va < va_end; va = next_va, pud++) {
		next_va = pud_addr_end(va, va_end);
		if (next_va > va_end)
			next_va = va_end;

		if (!pud_present(*pud))
			continue;

		if (pud_large(*pud)) {
			args->va = va;
			args->pa = pud_pfn(*pud) << PAGE_SHIFT;
			args->pa += va & (PUD_SIZE - 1);
			args->size = next_va - va;
			args->flags = pud_flags(*pud);

			func(args);
		} else {
			heki_walk_pmd(pud, va, next_va, func, args);
		}
	}
}

static void heki_walk_p4d(pgd_t *pgd, unsigned long va, unsigned long va_end,
			  heki_func_t func, struct heki_args *args)
{
	p4d_t *p4d;
	unsigned long next_va;

	for (p4d = p4d_offset(pgd, va); va < va_end; va = next_va, p4d++) {
		next_va = p4d_addr_end(va, va_end);
		if (next_va > va_end)
			next_va = va_end;

		if (!p4d_present(*p4d))
			continue;

		if (p4d_large(*p4d)) {
			args->va = va;
			args->pa = p4d_pfn(*p4d) << PAGE_SHIFT;
			args->pa += va & (P4D_SIZE - 1);
			args->size = next_va - va;
			args->flags = p4d_flags(*p4d);

			func(args);
		} else {
			heki_walk_pud(p4d, va, next_va, func, args);
		}
	}
}

void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func,
	       struct heki_args *args)
{
	pgd_t *pgd;
	unsigned long next_va;

	for (pgd = pgd_offset_k(va); va < va_end; va = next_va, pgd++) {
		next_va = pgd_addr_end(va, va_end);
		if (next_va > va_end)
			next_va = va_end;

		if (!pgd_present(*pgd))
			continue;

		if (pgd_large(*pgd)) {
			args->va = va;
			args->pa = pgd_pfn(*pgd) << PAGE_SHIFT;
			args->pa += va & (PGDIR_SIZE - 1);
			args->size = next_va - va;
			args->flags = pgd_flags(*pgd);

			func(args);
		} else {
			heki_walk_p4d(pgd, va, next_va, func, args);
		}
	}
}
