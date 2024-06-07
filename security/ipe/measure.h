/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_MEASURE_H
#define IPE_MEASURE_H
#ifdef CONFIG_IMA
void ipe_measure_state(void);
#else
static inline void ipe_measure_state(void) {}
#endif
#endif /* IPE_MEASURE_H */
