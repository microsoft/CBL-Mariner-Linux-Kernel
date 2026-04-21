/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2023, Microsoft Corporation.
 * Headers and definitions for Diagnostic Logs and other telemetry data
 */

#ifndef _MSHV_DIAG_H
#define _MSHV_DIAG_H

extern int mshv_diaglog_init(void);
extern int mshv_diaglog_exit(void);
extern int mshv_diaglog_get_fd(void);

extern int mshv_trace_get_fd(void);
extern void mshv_trace_disable(void);

#endif /*  _MSHV_DIAG_H */
