/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common header
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef _HEKI_COMMON_H

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

#include <linux/heki.h>

int heki_init_all_patch_types(struct module *mod);
void heki_free_all_patch_types(struct module *mod);
struct heki_patch_info *
heki_init_patch_info(enum heki_patch_type type,
		     struct module *mod, unsigned long count);
void heki_free_patch_info(enum heki_patch_type type, struct module *mod);
int heki_add_patch(struct heki_patch_info *info,
		   void *addr, const void *code, unsigned long size);
void heki_load_patch_info(struct heki_args *args, struct module *mod);
void heki_enable_patch_text(void);

#ifdef CONFIG_JUMP_LABEL
int heki_init_jump_label(struct module *mod);
void heki_free_jump_label(struct module *mod);
#else
static inline int heki_init_jump_label(struct module *mod)
{
	return 0;
}

static inline void heki_free_jump_label(struct module *mod)
{
}
#endif

#endif /* _HEKI_COMMON_H */
