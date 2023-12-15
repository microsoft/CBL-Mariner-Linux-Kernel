/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VSM - Headers
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __VSM_H__
#define __VSM_H__

#ifdef CONFIG_HYPERV_VSM

int __init hv_vsm_boot_init(void);

#else /* !CONFIG_HYPERV_VSM */

static inline int hv_vsm_boot_init(void)
{
	return 0;
}

#endif /* CONFIG_HYPERV_VSM */

#endif /* __VSM_H__ */
