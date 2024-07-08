/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common header
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef _HEKI_COMMON_H

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

#endif /* _HEKI_COMMON_H */
