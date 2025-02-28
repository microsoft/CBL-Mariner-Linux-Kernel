// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Kexec support
 *
 * Copyright © 2024 Microsoft Corporation
 */
#include <linux/heki.h>

static void		*heki_kernel;
static unsigned long	heki_kernel_len;

void heki_copy_kernel(void *kernel, unsigned long kernel_len)
{
	if (heki_kernel)
		vfree(heki_kernel);

	heki_kernel = vmalloc(kernel_len);
	if (!heki_kernel) {
		pr_warn("Failed to alloc memory for copying kexec kernel.\n");
		return;
	}

	heki_kernel_len = kernel_len;
	memcpy(heki_kernel, kernel, kernel_len);
}

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

	args.attributes = HEKI_KEXEC_KERNEL_BLOB;
	heki_walk((unsigned long) heki_kernel,
		  (unsigned long) heki_kernel + heki_kernel_len,
		  heki_get_ranges, &args);

	ret = hypervisor->kexec_validate(args.head_pa, args.nranges, crash);
	if (ret)
		pr_warn("Failed to validate kexec data.\n");
	else
		pr_warn("Validated kexec data.\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);

	vfree(heki_kernel);
	heki_kernel = NULL;
	heki_kernel_len = 0;

	return ret;
}
