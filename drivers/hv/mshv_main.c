// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * The /dev/mshv device.
 * This is the core module mshv_root and mshv_vtl depend on.
 *
 * Authors:
 *   Nuno Das Neves <nudasnev@microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/cpuhotplug.h>
#include <linux/random.h>
#include <linux/nospec.h>
#include <asm/mshyperv.h>

#include "mshv_eventfd.h"
#include "mshv.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

static struct mutex mshv_mutex;
static mshv_ioctl_func_t mshv_ioctl_func;

static int mshv_register_dev(void);
static void mshv_deregister_dev(void);

static int mshv_dev_open(struct inode *inode, struct file *filp);
static int mshv_dev_release(struct inode *inode, struct file *filp);
static long mshv_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);

static const struct file_operations mshv_dev_fops = {
	.owner = THIS_MODULE,
	.open = mshv_dev_open,
	.release = mshv_dev_release,
	.unlocked_ioctl = mshv_dev_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice mshv_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mshv",
	.fops = &mshv_dev_fops,
	.mode = 0600,
};

int mshv_set_ioctl_func(const mshv_ioctl_func_t func, struct device **dev)
{
	int ret = 0;

	mutex_lock(&mshv_mutex);
	if (func && dev) {
		ret = mshv_register_dev();
		if (!ret)
			*dev = mshv_dev.this_device;
	} else {
		mshv_deregister_dev();
	}

	if (!ret)
		mshv_ioctl_func = func;
	mutex_unlock(&mshv_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(mshv_set_ioctl_func);

static int mshv_register_dev(void)
{
	int ret;

	if (mshv_dev.this_device &&
	    device_is_registered(mshv_dev.this_device)) {
		dev_err(mshv_dev.this_device, "mshv device already registered\n");
		return -ENODEV;
	}

	ret = misc_register(&mshv_dev);
	if (ret)
		pr_err("%s: mshv device register failed\n", __func__);

	return ret;
}

static void mshv_deregister_dev(void)
{
	misc_deregister(&mshv_dev);
}

static long
mshv_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	if (!mshv_ioctl_func)
		return -ENODEV;

	return mshv_ioctl_func(filp, ioctl, arg);
}

static int
mshv_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int
mshv_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int
__init mshv_init(void)
{
	if (!hv_is_hyperv_initialized())
		return -ENODEV;

	mutex_init(&mshv_mutex);
	mshv_ioctl_func = NULL;

	return 0;
}

static void
__exit mshv_exit(void)
{
}

module_init(mshv_init);
module_exit(mshv_exit);
