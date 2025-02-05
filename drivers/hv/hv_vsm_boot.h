/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 * Author:
 *
 */

#ifndef _HV_VSM_BOOT_H
#define _HV_VSM_BOOT_H

#include <linux/sizes.h>

/* Secure kernel map (16MB minimum)
 * Region		Offset		Size
 * VSM PAGES		0		< 2MB
 * SKERNEL		2MB		16MB+ (based on config)
 */
#define VSM_SK_MIN_BASE_SIZE		SZ_16M
#define VSM_SKERNEL_OFFSET		SZ_2M

extern struct boot_params boot_params;

#endif /* _HV_VSM_BOOT_H */
