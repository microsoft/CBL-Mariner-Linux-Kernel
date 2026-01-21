// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contains code that handles pending work before transferring
 * to guest context. It needs to be in a separate file because the symbols
 * it uses are not exported.
 *
 * Inspired by native and KVM switching code.
 *
 * Author: Wei Liu <wei.liu@kernel.org>
 */

#include <linux/resume_user_mode.h>

/* Invoke with preemption and interrupt enabled */
int mshv_xfer_to_guest_mode_handle_work(unsigned long ti_work)
{
	if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
		return -EINTR;

	if (ti_work & _TIF_NEED_RESCHED)
		schedule();

	if (ti_work & _TIF_NOTIFY_RESUME)
		resume_user_mode_work(NULL);

	return 0;
}
EXPORT_SYMBOL_GPL(mshv_xfer_to_guest_mode_handle_work);
