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
 * SKLOADER		0		2MB-4KB
 * VSM_BOOT_PARAMS	2MB-4KB		4KB
 * SKERNEL		2MB		16MB+ (based on config)
 */
#define VSM_SK_MIN_BASE_SIZE		SZ_16M
#define VSM_SKERNEL_OFFSET		SZ_2M
#define VSM_SKLOADER_BOOT_PARAMS_SIZE	SZ_4K
#define VSM_SKLOADER_BOOT_PARAMS_OFFSET \
		(VSM_SKERNEL_OFFSET - VSM_SKLOADER_BOOT_PARAMS_SIZE)
#define VSM_SKLOADER_SIZE		VSM_SKLOADER_BOOT_PARAMS_OFFSET
#define VSM_SKLOADER_OFFSET		0

extern struct boot_params boot_params;

#endif /* _HV_VSM_BOOT_H */
