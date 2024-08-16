// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Authentication
 *
 * Copyright © 2024 Microsoft Corporation
 */

#include <linux/heki.h>
#include "../../kernel/module/internal.h"

#include <asm-generic/sections.h>

#include "common.h"

extern __initconst const u8 system_certificate_list[];
extern __initconst const unsigned long module_cert_size;

extern __initconst const u8 revocation_certificate_list[];
extern __initconst const unsigned long revocation_certificate_list_size;

static struct heki_kinfo heki_kinfo;

static u8 *heki_module_certs;
static unsigned long heki_module_cert_size;

static u8 *heki_revocation_certs;
static unsigned long heki_revocation_cert_size;

static char *heki_blacklist_hashes;
static size_t heki_blacklist_hash_count;

static int __init heki_copy_boot_certs(void)
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

	if (revocation_certificate_list_size <= 0) {
		pr_info("No revocation certificates found.\n");
		return 0;
	}

	heki_revocation_certs = vmalloc(revocation_certificate_list_size);
	if (!heki_revocation_certs) {
		pr_warn("Failed to alloc revocation certificates.\n");
		return -ENOMEM;
	}
	heki_revocation_cert_size = revocation_certificate_list_size;

	/*
	 * Copy the revocation certificates because they will be freed at
	 * the end of init.
	 */
	memcpy(heki_revocation_certs, revocation_certificate_list,
	       revocation_certificate_list_size);
	return 0;
}
core_initcall(heki_copy_boot_certs);

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

	if (heki_revocation_cert_size > 0) {
		args.attributes = HEKI_REVOCATION_CERTS;
		heki_walk((unsigned long)heki_revocation_certs,
			  (unsigned long)heki_revocation_certs + heki_revocation_cert_size,
			  heki_get_ranges, &args);
	}

	if (heki_blacklist_hash_count > 0) {
		args.attributes = HEKI_BLACKLIST_HASHES;
		heki_walk((unsigned long)heki_blacklist_hashes,
			  (unsigned long)heki_blacklist_hashes +
			  HEKI_MAX_TOTAL_HASH_LEN * heki_blacklist_hash_count,
			  heki_get_ranges, &args);
	}

	heki_kinfo.ksymtab_start =
			(struct kernel_symbol *)__start___ksymtab;
	heki_kinfo.ksymtab_end =
			(struct kernel_symbol *)__stop___ksymtab;
	heki_kinfo.ksymtab_gpl_start =
			(struct kernel_symbol *)__start___ksymtab_gpl;
	heki_kinfo.ksymtab_gpl_end =
			(struct kernel_symbol *)__stop___ksymtab_gpl;

	heki_load_arch_kinfo(&heki_kinfo);

	args.attributes = HEKI_KERNEL_INFO;
	heki_walk((unsigned long)&heki_kinfo,
		  (unsigned long)&heki_kinfo + sizeof(heki_kinfo),
		  heki_get_ranges, &args);

	args.attributes = HEKI_KERNEL_DATA;
	heki_walk((unsigned long)__start_rodata,
		  (unsigned long)__end_rodata,
		  heki_get_ranges, &args);

	if (hypervisor->load_kdata(args.head_pa, args.nranges))
		pr_warn("Failed to load kernel data.\n");
	else
		pr_warn("Loaded kernel data\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);
	vfree(heki_module_certs);
	vfree(heki_revocation_certs);
	vfree(heki_blacklist_hashes);
	heki_blacklist_hashes = NULL;
	heki_blacklist_hash_count = 0;
}

long heki_validate_module(struct module *mod, struct load_info *info, int flags)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_args args = {};
	long token;

	if (!hypervisor)
		return 0;

	mutex_lock(&heki.lock);

	/* Load original unmodified module ELF buffer. */
	args.attributes = MOD_ELF;
	heki_walk((unsigned long)info->orig_hdr,
		  (unsigned long)info->orig_hdr + info->orig_len,
		  heki_get_ranges, &args);

	/* Load module sections. */
	for_each_mod_mem_type(type) {
		struct module_memory *mem = &mod->mem[type];

		if (!mem->size)
			continue;

		args.attributes = type;
		heki_walk((unsigned long)mem->base,
			  (unsigned long)mem->base + mem->size,
			  heki_get_ranges, &args);
	}

	token = hypervisor->validate_module(args.head_pa, args.nranges, flags);
	if (token < 0) {
		pr_warn("Failed to validate module %s (%ld).\n",
			info->name, token);
	}

	heki_cleanup_args(&args);

	mutex_unlock(&heki.lock);

	return token;
}

void heki_free_module_init(struct module *mod)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int err;

	if (!hypervisor)
		return;

	mutex_lock(&heki.lock);

	err = hypervisor->free_module_init(mod->heki_token);
	if (err) {
		pr_warn("Failed to free module %s init (%d).\n",
			mod->name, err);
	}

	mutex_unlock(&heki.lock);
}

void heki_unload_module(struct module *mod)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int err;

	if (!hypervisor)
		return;

	mutex_lock(&heki.lock);

	err = hypervisor->unload_module(mod->heki_token);
	if (err) {
		pr_warn("Failed to unload module %s (%d).\n",
			mod->name, err);
	}

	mutex_unlock(&heki.lock);
}

void heki_copy_secondary_key(const void *data, size_t size)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	struct heki_args args = {};

	if (!data || !hypervisor)
		return;

	mutex_lock(&heki.lock);

	heki_walk((unsigned long)data,
		  (unsigned long)data + size,
		  heki_get_ranges, &args);

	if (hypervisor->copy_secondary_key(args.head_pa, args.nranges))
		pr_warn("Failed to load secondary key data.\n");
	else
		pr_warn("Loaded secondary key data\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);
}

void __init heki_store_blacklist_raw_hashes(const char *hash)
{
	/* Initialize the blacklist hashes array if it does not already exist */
	if (!heki_blacklist_hashes) {
		heki_blacklist_hashes = vmalloc(HEKI_MAX_TOTAL_HASHES * HEKI_MAX_TOTAL_HASH_LEN);
		if (!heki_blacklist_hashes) {
			pr_warn("Failed to allocate memory for blacklist hashes\n");
			return;
		}
	}

	/* Check if the hash is longer than 132 characters not including null terminator.
	 * Hashes are formally vetted automatically in both vtl0 and vtl1.
	 */
	if (strlen(hash) > HEKI_MAX_TOTAL_HASH_LEN - 1) {
		pr_warn("Invalid hash: %s\n", hash);
		return;
	}

	if (heki_blacklist_hash_count >= HEKI_MAX_TOTAL_HASHES) {
		pr_warn("Maximum number of hashes reached. Cannot add new hash: %s\n", hash);
		return;
	}

	strscpy(&heki_blacklist_hashes[heki_blacklist_hash_count * HEKI_MAX_TOTAL_HASH_LEN],
		hash, HEKI_MAX_TOTAL_HASH_LEN);
	heki_blacklist_hash_count++;
}
