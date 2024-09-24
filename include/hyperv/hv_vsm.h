/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VSM - Headers
 *
 * Copyright © 2024 Microsoft Corporation
 */

#ifndef __HV_VSM_H__
#define __HV_VSM_H__

#ifdef CONFIG_HYPERV_VSM
void vsm_init(void);
#else /* CONFIG_HYPERV_VSM */
static inline void vsm_init(void) {}
#endif /* CONFIG_HYPERV_VSM */

#endif /* __HV_VSM_H__ */
