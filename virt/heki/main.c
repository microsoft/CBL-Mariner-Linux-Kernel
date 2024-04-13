// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;
struct heki heki;

/*
 * Must be called after mark_readonly().
 */
void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int ret;

	if (!heki_enabled || !heki.hypervisor)
		return;

	/* Locks control registers so a compromised guest cannot change them. */
	if (hypervisor->lock_crs)
		ret = hypervisor->lock_crs();

	if (ret)
		pr_warn("Unable to lock down control registers\n");
	else
		pr_warn("Control registers locked\n");
}

void heki_register_hypervisor(struct heki_hypervisor *hypervisor)
{
	heki.hypervisor = hypervisor;
}

static int __init heki_parse_config(char *str)
{
	if (kstrtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);
