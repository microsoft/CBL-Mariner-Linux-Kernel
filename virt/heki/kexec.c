// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Kexec support
 *
 * Copyright © 2024 Microsoft Corporation
 */
#include <linux/heki.h>

int heki_kexec_validate(struct kimage *image)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	bool crash = image->type == KEXEC_TYPE_CRASH;
	struct heki_args args = {};
	int ret;

	if (!hypervisor)
		return 0;

	mutex_lock(&heki.lock);

	args.attributes = HEKI_KEXEC_IMAGE;
	heki_walk((unsigned long) image,
		  (unsigned long) image + sizeof(*image),
		  heki_get_ranges, &args);

	ret = hypervisor->kexec_validate(args.head_pa, args.nranges, crash);
	if (ret)
		pr_warn("Failed to validate kexec data.\n");
	else
		pr_warn("Validated kexec data.\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);

	return ret;
}
