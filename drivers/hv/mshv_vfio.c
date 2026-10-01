// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO-MSHV bridge pseudo device
 *
 * Heavily inspired by the VFIO-KVM bridge pseudo device.
 */
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vfio.h>
#include <asm/mshyperv.h>

#include "mshv.h"
#include "mshv_root.h"

struct mshv_vfio_file {
	struct list_head node;
	struct file *file;	/* list of struct mshv_vfio_file */
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

static long mshv_vfio_file_add(struct mshv_device *mshvdev, unsigned int fd)
{
	struct mshv_vfio *mshv_vfio = mshvdev->device_private;
	struct mshv_vfio_file *mvf;
	struct file *filp;
	long ret = 0;

	filp = fget(fd);
	if (!filp)
		return -EBADF;

	/* Ensure the FD is a vfio FD. */
	if (!mshv_vfio_file_is_valid(filp)) {
		ret = -EINVAL;
		goto out_fput;
	}

	mutex_lock(&mshv_vfio->lock);

	list_for_each_entry(mvf, &mshv_vfio->file_list, node) {
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
	list_add_tail(&mvf->node, &mshv_vfio->file_list);

out_unlock:
	mutex_unlock(&mshv_vfio->lock);
out_fput:
	fput(filp);
	return ret;
}

static long mshv_vfio_file_del(struct mshv_device *mshvdev, unsigned int fd)
{
	struct mshv_vfio *mshv_vfio = mshvdev->device_private;
	struct mshv_vfio_file *mvf;
	long ret;

	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return -EBADF;

	ret = -ENOENT;
	mutex_lock(&mshv_vfio->lock);

	list_for_each_entry(mvf, &mshv_vfio->file_list, node) {
		if (mvf->file != fd_file(f))
			continue;

		list_del(&mvf->node);
		fput(mvf->file);
		kfree(mvf);
		ret = 0;
		break;
	}

	mutex_unlock(&mshv_vfio->lock);
	return ret;
}

static long mshv_vfio_set_file(struct mshv_device *mshvdev, long attr,
			      void __user *arg)
{
	int32_t __user *argp = arg;
	int32_t fd;

	switch (attr) {
	case MSHV_DEV_VFIO_FILE_ADD:
		if (get_user(fd, argp))
			return -EFAULT;
		return mshv_vfio_file_add(mshvdev, fd);

	case MSHV_DEV_VFIO_FILE_DEL:
		if (get_user(fd, argp))
			return -EFAULT;
		return mshv_vfio_file_del(mshvdev, fd);
	}

	return -ENXIO;
}

static long mshv_vfio_set_attr(struct mshv_device *mshvdev,
			      struct mshv_device_attr *attr)
{
	switch (attr->group) {
	case MSHV_DEV_VFIO_FILE:
		return mshv_vfio_set_file(mshvdev, attr->attr,
					  u64_to_user_ptr(attr->addr));
	}

	return -ENXIO;
}

static long mshv_vfio_has_attr(struct mshv_device *mshvdev,
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

static long mshv_vfio_create_device(struct mshv_device *mshvdev)
{
	struct mshv_device *tmp;
	struct mshv_vfio *mshv_vfio;

	/* Only one VFIO "device" per VM */
	hlist_for_each_entry(tmp, &mshvdev->device_pt->pt_devices,
			     device_ptnode)
		if (tmp->device_ops == &mshv_vfio_device_ops)
			return -EBUSY;

	mshv_vfio = kzalloc(sizeof(*mshv_vfio), GFP_KERNEL_ACCOUNT);
	if (mshv_vfio == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&mshv_vfio->file_list);
	mutex_init(&mshv_vfio->lock);

	mshvdev->device_private = mshv_vfio;

	return 0;
}

/* This is called from mshv_device_fop_release() */
static void mshv_vfio_release_device(struct mshv_device *mshvdev)
{
	struct mshv_vfio *mv = mshvdev->device_private;
	struct mshv_vfio_file *mvf, *tmp;

	list_for_each_entry_safe(mvf, tmp, &mv->file_list, node) {
		fput(mvf->file);
		list_del(&mvf->node);
		kfree(mvf);
	}

	kfree(mv);
	kfree(mshvdev);
}

struct mshv_device_ops mshv_vfio_device_ops = {
	.device_name = "mshv-vfio",
	.device_create = mshv_vfio_create_device,
	.device_release = mshv_vfio_release_device,
	.device_set_attr = mshv_vfio_set_attr,
	.device_has_attr = mshv_vfio_has_attr,
};
