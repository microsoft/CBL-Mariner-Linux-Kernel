// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Jump label patch code
 *
 * Copyright © 2025 Microsoft Corporation
 */

#include <linux/jump_label.h>
#include "common.h"

static int heki_add_jump_label_patch(struct heki_patch_info *info,
				     struct jump_entry *entry)
{
	const void *code, *nop;

	jump_label_get_patch(entry, &code, &nop);
	return heki_add_patch(info, (void *)jump_entry_code(entry),
			      code, jump_entry_size(entry));
}

int heki_init_jump_label(struct module *mod)
{
	struct heki_patch_info *info;
	struct jump_entry *iter_start, *iter_stop, *iter;
	unsigned long count;
	int ret;

	if (mod) {
		iter_start = mod->jump_entries;
		iter_stop = iter_start + mod->num_jump_entries;
	} else {
		iter_start = __start___jump_table;
		iter_stop = __stop___jump_table;
	}
	count = iter_stop - iter_start;
	if (!count)
		return 0;

	info = heki_init_patch_info(HEKI_PATCH_TYPE_JUMP_LABEL, mod, count);
	if (!info)
		return -ENOMEM;

	for (iter = iter_start; iter < iter_stop; iter++) {
		/* init section of kernel is reallocated by the time
		 * HEKI protection is in force
		 */
		if (!mod && jump_entry_is_init(iter))
			continue;
		ret = heki_add_jump_label_patch(info, iter);
		if (ret)
			goto free_patch_info;
	}
	return 0;

free_patch_info:
	heki_free_patch_info(HEKI_PATCH_TYPE_JUMP_LABEL, mod);
	return ret;
}

void heki_free_jump_label(struct module *mod)
{
	heki_free_patch_info(HEKI_PATCH_TYPE_JUMP_LABEL, mod);
}
