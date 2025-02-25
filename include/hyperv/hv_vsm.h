/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VSM - Headers
 *
 * Copyright © 2024 Microsoft Corporation
 */

#ifndef __HV_VSM_H__
#define __HV_VSM_H__

#if IS_ENABLED(CONFIG_HYPERV_VSM)
int vsm_init(void);
#else /* CONFIG_HYPERV_VSM */
static inline int vsm_init(void) { return 0; }
#endif /* CONFIG_HYPERV_VSM */

#endif /* __HV_VSM_H__ */
