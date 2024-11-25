// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/ima.h>

#include "eval.h"
#include "policy.h"
#include "measure.h"

/**
 * ipe_measure_state - Measure IPE state and hash of policy
 */
void ipe_measure_state(void)
{
	struct ipe_policy *p = NULL;
	char *buf;

	buf = kasprintf(GFP_KERNEL, "enforce=%d;success_audit=%d;",
			READ_ONCE(enforce), READ_ONCE(success_audit));
	if (!buf)
		pr_err("state measurement data not allocated.");

	ima_measure_critical_data("ipe", "ipe-state", buf, strlen(buf),
				  false, NULL, 0);
	kfree(buf);

	rcu_read_lock();
	p = rcu_dereference(ipe_active_policy);
	ima_measure_critical_data("ipe", "ipe-policy-hash", p->text, p->textlen,
				  true, NULL, 0);
	rcu_read_unlock();
}
