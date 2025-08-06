// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Patch code
 *
 * Copyright © 2025 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include "common.h"

static LIST_HEAD(heki_patch_list);
static DEFINE_MUTEX(heki_patch_mtx);
static DEFINE_PER_CPU(struct heki_patch, heki_patch_req);
bool heki_patch_text_enabled;

static struct page *heki_va_to_page(const void *va)
{
	if (!core_kernel_text((unsigned long)va))
		return vmalloc_to_page(va);
	else
		return virt_to_page(va);
}

static unsigned long heki_va_to_pa(const void *va)
{
	struct page *pg = heki_va_to_page(va);

	if (!pg)
		return 0;
	return page_to_phys(pg) + offset_in_page(va);
}

/* If the size of memory pointed to by va straddles
 * two physical pages, return the physical start of
 * the next page
 */
static unsigned long heki_straddle_va_to_pa(const void *va, unsigned long size)
{
	unsigned long addr_in_next_pg;

	if (offset_in_page(va) + size <= PAGE_SIZE)
		return 0;

	addr_in_next_pg = (unsigned long)va;
	addr_in_next_pg += PAGE_SIZE - offset_in_page(va);
	return heki_va_to_pa((void *)addr_in_next_pg);
}

void heki_enable_patch_text(void)
{
	heki_patch_text_enabled = true;
}

int heki_text_poke(void *addr, const void *opcode, unsigned long len)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_patch patch_req;
	int ret;

	if (!heki.hypervisor || !heki_patch_text_enabled)
		return -ENOENT;

	if (len > POKE_MAX_OPCODE_SIZE)
		return -EINVAL;

	mutex_lock(&heki.lock);
	patch_req = get_cpu_var(heki_patch_req);
	patch_req.pa[0] = heki_va_to_pa(addr);
	patch_req.pa[1] = heki_straddle_va_to_pa(addr, len);
	memcpy(&patch_req.code, opcode, len);
	patch_req.size = len;

	ret = hypervisor->patch_text(heki_va_to_pa(&patch_req),
		heki_straddle_va_to_pa(&patch_req, sizeof(patch_req)));

	put_cpu_var(heki_patch_req);
	mutex_unlock(&heki.lock);

	if (ret && ret != -ENOENT) {
		pr_emerg("%s: Failed for addr:%p %pS ret:%d\n",
			 __func__, addr, addr, ret);
		BUG();
	}
	return ret;
}

void heki_load_patch_info(struct heki_args *args, struct module *mod)
{
	struct heki_patch_info *info;
	unsigned long size;

	mutex_lock(&heki_patch_mtx);
	list_for_each_entry(info, &heki_patch_list, list) {
		if (info->mod != mod)
			continue;
		/* We load only valid entries. patch_idx could be less
		 * than max_patch_count
		 */
		size = sizeof(struct heki_patch_info) +
		       sizeof(struct heki_patch) * info->patch_idx;
		heki_walk((unsigned long)info,
			  (unsigned long)info + size,
			  heki_get_ranges, args);
	}
	mutex_unlock(&heki_patch_mtx);
}

int heki_add_patch(struct heki_patch_info *info,
		   void *addr, const void *code, unsigned long size)
{
	struct heki_patch *patch;

	if (info->patch_idx == info->max_patch_count) {
		pr_warn("%s: Too many patches for %s\n", __func__, HEKI_MOD_NAME(info->mod));
		return -ENOMEM;
	}

	patch = &info->patch[info->patch_idx];
	if (size > sizeof(patch->code))
		return -EINVAL;
	memcpy(patch->code, code, size);
	patch->size = size;
	patch->pa[0] = heki_va_to_pa(addr);
	patch->pa[1] = heki_straddle_va_to_pa(addr, size);
	/* Patches are added in heki_late_init() or module_init()
	 * so no need for mutex protection
	 */
	info->patch_idx++;
	return 0;
}

struct heki_patch_info *
heki_init_patch_info(enum heki_patch_type type,
		     struct module *mod, unsigned long count)
{
	struct heki_patch_info *info;
	unsigned long size;

	if (!count)
		return NULL;
	size = sizeof(struct heki_patch_info) +
	       sizeof(struct heki_patch) * count;
	info = __vmalloc(size, GFP_KERNEL | __GFP_ZERO);
	if (!info)
		return NULL;
	info->type = type;
	info->mod = mod;
	info->max_patch_count = count;

	mutex_lock(&heki_patch_mtx);
	list_add(&info->list, &heki_patch_list);
	mutex_unlock(&heki_patch_mtx);
	return info;
}

void heki_free_patch_info(enum heki_patch_type type, struct module *mod)
{
	struct heki_patch_info *info, *tmp;

	mutex_lock(&heki_patch_mtx);
	list_for_each_entry_safe(info, tmp, &heki_patch_list, list)  {
		if (info->mod != mod || info->type != type)
			continue;
		list_del(&info->list);
		vfree(info);
	}
	mutex_unlock(&heki_patch_mtx);
}

int heki_init_all_patch_types(struct module *mod)
{
	return heki_init_jump_label(mod);
}

void heki_free_all_patch_types(struct module *mod)
{
	heki_free_jump_label(mod);
}
