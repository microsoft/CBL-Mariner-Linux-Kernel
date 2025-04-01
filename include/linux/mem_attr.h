/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Guest page permissions - Definitions.
 *
 * Copyright © 2023 Microsoft Corporation.
 */
#ifndef __MEM_ATTR_H__
#define __MEM_ATTR_H__

/* clang-format off */

#define MEM_ATTR_READ			BIT(0)
#define MEM_ATTR_WRITE			BIT(1)
#define MEM_ATTR_EXEC			BIT(2)
#define MEM_ATTR_IMMUTABLE		BIT(3)

#define MEM_ATTR_PROT ( \
	MEM_ATTR_READ | \
	MEM_ATTR_WRITE | \
	MEM_ATTR_EXEC | \
	MEM_ATTR_IMMUTABLE)

/* clang-format on */

#endif /* __MEM_ATTR_H__ */
