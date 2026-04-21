// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * This module exposes Diagnostic Logs, Performance Tracing and other
 * telemetry data from hyp to userspace via special device /dev/mshv_diag
 *
 * Authors:
 *	Praveen K Paladugu <prapal@linux.microsoft.com>
 *	Mukesh Rathor <mrathor@linux.microsoft.com>
 */

#include <asm/mshyperv.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/reboot.h>
#include <linux/crash_dump.h>
#include <hyperv/hvhdk.h>
#include <uapi/linux/mshv.h>

#include "mshv_diag.h"

static long mshv_diag_ioctl(struct file *filp, unsigned int ioctl,
			    unsigned long arg)
{
	int rc;

	switch (ioctl) {
	case MSHV_GET_TRACE_FD:
		rc = mshv_trace_get_fd();
		break;
	case MSHV_GET_DIAGLOG_FD:
		rc = mshv_diaglog_get_fd();
		break;
	default:
		return -ENOTTY;
	}

	return rc;
}

static const struct file_operations mshv_diag_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mshv_diag_ioctl,
};

static struct miscdevice mshv_diag_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mshv_diag",
	.fops = &mshv_diag_fops,
	.mode = 0400,
};

static int mshv_diag_reboot(struct notifier_block *nb,
			    unsigned long action, void *data)
{
	if (action == SYS_RESTART) {
		mshv_trace_disable();
		mshv_diaglog_exit();
	}

	return NOTIFY_DONE;
}

struct notifier_block mshv_diag_reboot_notifier = {
	.notifier_call = mshv_diag_reboot,
};

static int __init mshv_diag_init(void)
{
	int ret;

	if (!hv_parent_partition() || is_kdump_kernel())
		return -EPERM;

	ret = misc_register(&mshv_diag_dev);
	if (ret) {
		pr_err("%s: misc device register failed\n", __func__);
		return ret;
	}

	ret = register_reboot_notifier(&mshv_diag_reboot_notifier);
	if (ret) {
		pr_err("%s: failed to register reboot notifier: %d\n",
		       __func__, ret);
		goto unregister_misc;
	}

	ret = mshv_diaglog_init();
	if (ret < 0)
		goto unregister_reboot_notifier;

	return 0;

unregister_reboot_notifier:
	unregister_reboot_notifier(&mshv_diag_reboot_notifier);
unregister_misc:
	misc_deregister(&mshv_diag_dev);
	return ret;
}

static void __exit mshv_diag_exit(void)
{
	mshv_diaglog_exit();
	unregister_reboot_notifier(&mshv_diag_reboot_notifier);
	misc_deregister(&mshv_diag_dev);
}

module_init(mshv_diag_init);
module_exit(mshv_diag_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsoft");
