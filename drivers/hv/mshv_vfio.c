// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO-MSHV bridge pseudo device
 *
 * Heavily inspired by the VFIO-KVM bridge pseudo device.
 * Copyright (C) 2013 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/anon_inodes.h>
#include <linux/nospec.h>
#include "mshv.h"
#include "mshv_root.h"

struct mshv_device {
	const struct mshv_device_ops *ops;
	struct mshv_partition *partition;
	void *private;
	struct hlist_node partition_node;
};

/*
 * @create is called holding partition->mutex and any operations not suitable
 *	to do while holding the lock should be deferred to init (see below.
 * @init is called after create if create is successful and is called
 *	outside of holding partition->mutex.
 * @destroy is responsible for freeing dev.
 * It may be called before or after destructors are called
 *	on emulated I/O regions, depending on whether a reference is
 *	held by a vcpu or other mshv component that gets destroyed
 *	after the emulated I/O.
 * @release is an alternative method to free the device. It is
 *	called when the device file descriptor is closed. Once
 *	release is called, the destroy method will not be called
 *	anymore as the device is removed from the device list of
 *	the VM. partition->mutex is held.
 */
struct mshv_device_ops {
	const char *name;				   /* required */
	int (*create)(struct mshv_device *dev, u32 type);  /* required */
	void (*init)(struct mshv_device *dev);
	void (*destroy)(struct mshv_device *dev);	   /* required */
	void (*release)(struct mshv_device *dev);
	int (*set_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	int (*get_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	int (*has_attr)(struct mshv_device *dev, struct mshv_device_attr *attr);
	long (*ioctl)(struct mshv_device *dev, unsigned int ioctl,
		      unsigned long arg);
	int (*mmap)(struct mshv_device *dev, struct vm_area_struct *vma);
};

struct mshv_vfio_file {
	struct list_head node;
	struct file *file; /* list of struct mshv_vfio_file */
};

struct mshv_vfio {
	struct list_head file_list;
	struct mutex lock;
};

static bool mshv_vfio_file_is_valid(struct file *file)
{
	bool (*fn)(struct file *file);
	bool ret;

	fn = symbol_get(vfio_file_is_valid);
	if (!fn)
		return false;

	ret = fn(file);

	symbol_put(vfio_file_is_valid);

	return ret;
}

static int mshv_vfio_file_add(struct mshv_device *dev, unsigned int fd)
{
	struct mshv_vfio *mv = dev->private;
	struct mshv_vfio_file *mvf;
	struct file *filp;
	int ret = 0;

	filp = fget(fd);
	if (!filp)
		return -EBADF;

	/* Ensure the FD is a vfio FD. */
	if (!mshv_vfio_file_is_valid(filp)) {
		ret = -EINVAL;
		goto out_fput;
	}

	mutex_lock(&mv->lock);

	list_for_each_entry(mvf, &mv->file_list, node) {
		if (mvf->file == filp) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	mvf = kzalloc(sizeof(*mvf), GFP_KERNEL_ACCOUNT);
	if (!mvf) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	mvf->file = get_file(filp);
	list_add_tail(&mvf->node, &mv->file_list);

out_unlock:
	mutex_unlock(&mv->lock);
out_fput:
	fput(filp);
	return ret;
}

static int mshv_vfio_file_del(struct mshv_device *dev, unsigned int fd)
{
	struct mshv_vfio *mv = dev->private;
	struct mshv_vfio_file *mvf;
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -ENOENT;

	mutex_lock(&mv->lock);

	list_for_each_entry(mvf, &mv->file_list, node) {
		if (mvf->file != f.file)
			continue;

		list_del(&mvf->node);
		fput(mvf->file);
		kfree(mvf);
		ret = 0;
		break;
	}

	mutex_unlock(&mv->lock);

	fdput(f);

	return ret;
}

static int mshv_vfio_set_file(struct mshv_device *hvdev, long attr, void __user *arg)
{
	int32_t __user *argp = arg;
	int32_t fd;

	switch (attr) {
	case MSHV_DEV_VFIO_FILE_ADD:
		if (get_user(fd, argp))
			return -EFAULT;
		return mshv_vfio_file_add(hvdev, fd);

	case MSHV_DEV_VFIO_FILE_DEL:
		if (get_user(fd, argp))
			return -EFAULT;
		return mshv_vfio_file_del(hvdev, fd);
	}

	return -ENXIO;
}

static int mshv_vfio_set_attr(struct mshv_device *hvdev,
			      struct mshv_device_attr *attr)
{
	switch (attr->group) {
	case MSHV_DEV_VFIO_FILE:
		return mshv_vfio_set_file(hvdev, attr->attr,
					  u64_to_user_ptr(attr->addr));
	}

	return -ENXIO;
}

static int mshv_vfio_has_attr(struct mshv_device *hvdev,
			      struct mshv_device_attr *attr)
{
	switch (attr->group) {
	case MSHV_DEV_VFIO_FILE:
		switch (attr->attr) {
		case MSHV_DEV_VFIO_FILE_ADD:
		case MSHV_DEV_VFIO_FILE_DEL:
			return 0;
		}

		break;
	}

	return -ENXIO;
}

static void mshv_vfio_destroy(struct mshv_device *hvdev)
{
	struct mshv_vfio *mv = hvdev->private;
	struct mshv_vfio_file *mvf, *tmp;

	list_for_each_entry_safe(mvf, tmp, &mv->file_list, node) {
		list_del(&mvf->node);
		kfree(mvf);
	}

	kfree(mv);
	kfree(hvdev);
}

static int mshv_vfio_create(struct mshv_device *dev, u32 type);

static struct mshv_device_ops mshv_vfio_ops = {
	.name = "mshv-vfio",
	.create = mshv_vfio_create,
	.destroy = mshv_vfio_destroy,
	.set_attr = mshv_vfio_set_attr,
	.has_attr = mshv_vfio_has_attr,
};

static int mshv_vfio_create(struct mshv_device *hvdev, u32 type)
{
	struct mshv_device *tmp;
	struct mshv_vfio *mv;

	/* Only one VFIO "device" per VM */
	hlist_for_each_entry(tmp, &hvdev->partition->pt_devices, partition_node)
		if (tmp->ops == &mshv_vfio_ops)
			return -EBUSY;

	mv = kzalloc(sizeof(*mv), GFP_KERNEL_ACCOUNT);
	if (!mv)
		return -ENOMEM;

	INIT_LIST_HEAD(&mv->file_list);
	mutex_init(&mv->lock);

	hvdev->private = mv;

	return 0;
}

static int mshv_device_release(struct inode *inode, struct file *filp);
static long mshv_device_ioctl(struct file *filp, unsigned int ioctl,
			      unsigned long arg);

static const struct file_operations mshv_device_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mshv_device_ioctl,
	.release = mshv_device_release,
};

static const struct mshv_device_ops *mshv_device_ops_table[MSHV_DEV_TYPE_MAX];

static int mshv_device_ioctl_attr(struct mshv_device *dev,
				 int (*accessor)(struct mshv_device *dev,
						 struct mshv_device_attr *attr),
				 unsigned long arg)
{
	struct mshv_device_attr attr;

	if (!accessor)
		return -EPERM;

	if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
		return -EFAULT;

	return accessor(dev, &attr);
}

static long mshv_device_ioctl(struct file *filp, unsigned int ioctl,
			      unsigned long arg)
{
	struct mshv_device *dev = filp->private_data;

	switch (ioctl) {
	case MSHV_SET_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->set_attr, arg);
	case MSHV_GET_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->get_attr, arg);
	case MSHV_HAS_DEVICE_ATTR:
		return mshv_device_ioctl_attr(dev, dev->ops->has_attr, arg);
	default:
		if (dev->ops->ioctl)
			return dev->ops->ioctl(dev, ioctl, arg);
	}
	return -ENOTTY;
}

static int mshv_device_release(struct inode *inode, struct file *filp)
{
	struct mshv_device *dev = filp->private_data;
	struct mshv_partition *partition = dev->partition;

	if (dev->ops->release) {
		mutex_lock(&partition->pt_mutex);
		hlist_del(&dev->partition_node);
		dev->ops->release(dev);
		mutex_unlock(&partition->pt_mutex);
	}

	mshv_partition_put(partition);
	return 0;
}

long mshv_partition_ioctl_create_device(struct mshv_partition *partition,
					void __user *user_args)
{
	long r;
	struct mshv_create_device tmp, *cd;
	struct mshv_device *dev;
	const struct mshv_device_ops *ops;
	int type;

	if (copy_from_user(&tmp, user_args, sizeof(tmp))) {
		r = -EFAULT;
		goto out;
	}

	cd = &tmp;

	if (cd->type >= ARRAY_SIZE(mshv_device_ops_table)) {
		r = -ENODEV;
		goto out;
	}

	type = array_index_nospec(cd->type, ARRAY_SIZE(mshv_device_ops_table));
	ops = mshv_device_ops_table[type];
	if (ops == NULL) {
		r = -ENODEV;
		goto out;
	}

	if (cd->flags & MSHV_CREATE_DEVICE_TEST) {
		r = 0;
		goto out;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL_ACCOUNT);
	if (!dev) {
		r = -ENOMEM;
		goto out;
	}

	dev->ops = ops;
	dev->partition = partition;

	r = ops->create(dev, type);
	if (r < 0) {
		kfree(dev);
		goto out;
	}

	hlist_add_head(&dev->partition_node, &partition->pt_devices);

	if (ops->init)
		ops->init(dev);

	mshv_partition_get(partition);
	r = anon_inode_getfd(ops->name, &mshv_device_fops, dev,
			     O_RDWR | O_CLOEXEC);
	if (r < 0) {
		mshv_partition_put(partition);
		hlist_del(&dev->partition_node);
		ops->destroy(dev);
		goto out;
	}

	cd->fd = r;
	r = 0;

	if (copy_to_user(user_args, &tmp, sizeof(tmp))) {
		r = -EFAULT;
		goto out;
	}
out:
	return r;
}

void mshv_destroy_devices(struct mshv_partition *partition)
{
	struct mshv_device *dev;
	struct hlist_node *n;

	/*
	 * No need to take any lock since at this point nobody else can
	 * reference this partition.
	 */
	hlist_for_each_entry_safe(dev, n, &partition->pt_devices,
				  partition_node) {
		hlist_del(&dev->partition_node);
		dev->ops->destroy(dev);
	}
}

static int mshv_register_device_ops(const struct mshv_device_ops *ops, u32 type)
{
	if (type >= ARRAY_SIZE(mshv_device_ops_table))
		return -ENOSPC;

	if (mshv_device_ops_table[type] != NULL)
		return -EEXIST;

	mshv_device_ops_table[type] = ops;
	return 0;
}

static void mshv_unregister_device_ops(u32 type)
{
	if (type >= ARRAY_SIZE(mshv_device_ops_table))
		return;
	mshv_device_ops_table[type] = NULL;
}

int mshv_vfio_ops_init(void)
{
	return mshv_register_device_ops(&mshv_vfio_ops, MSHV_DEV_TYPE_VFIO);
}

void mshv_vfio_ops_exit(void)
{
	mshv_unregister_device_ops(MSHV_DEV_TYPE_VFIO);
}
