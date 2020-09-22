// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Watchdog driver for virtio. Derived from virto-rng.c and i6300esb.c
 * Copyright 2007, 2008 Rusty Russell IBM Corporation
 * Copyright 2004 Google Inc.
 * Copyright 2005 David Härdeman <david@2gen.com>
 * Copyright 2020 Intel Corporation
 */

#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/watchdog.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

static DEFINE_IDA(watchdog_index_ida);

#define to_info(wptr) container_of(wptr, struct virtio_watchdog_info, wdd)

/* Only support an interval of 15s */
#define VW_HEARTBEAT_DEFAULT 15

struct virtio_watchdog_info {
	struct watchdog_device wdd;
	struct virtio_device *vdev;
	struct virtqueue *vq;
	struct completion have_data;
	char name[25];
	unsigned int data_avail;
	int index;
	bool busy;
	bool wdd_register_done;
};

static void virtio_watchdog_recv_done(struct virtqueue *vq)
{
	struct virtio_watchdog_info *vi = vq->vdev->priv;

	/* We can get spurious callbacks, e.g. shared IRQs + virtio_pci. */
	if (!virtqueue_get_buf(vi->vq, &vi->data_avail))
		return;

	complete(&vi->have_data);
}

/* Host will change the buffer from 0->1 */
static void register_buffer(struct virtio_watchdog_info *vi, u8 *buf,
							size_t size)
{
	struct scatterlist sg;

	sg_init_one(&sg, buf, size);
	virtqueue_add_inbuf(vi->vq, &sg, 1, buf, GFP_KERNEL);

	virtqueue_kick(vi->vq);
}


static int virtio_watchdog_ping(struct watchdog_device *wdd)
{
	struct virtio_watchdog_info *vi = to_info(wdd);
	struct virtio_device *vdev = vi->vdev;
	int ret;
	u8 *buf;

	if (!vi->wdd_register_done)
		return -ENODEV;

	buf = kzalloc(sizeof(u8), GFP_KERNEL);
	if (!vi->busy) {
		vi->busy = true;
		reinit_completion(&vi->have_data);
		register_buffer(vi, (void *)buf, sizeof(u64));
	}

	ret = wait_for_completion_killable(&vi->have_data);
	if (ret < 0)
		goto err;

	if (*buf != 1) {
		dev_err(&vdev->dev,
				"Host did not acknowledge buffer correctly");
		ret = -EINVAL;
	}

err:
	vi->busy = false;
	kfree(buf);

	return ret;
}

static int virtio_watchdog_start(struct watchdog_device *wdd)
{
	struct virtio_watchdog_info *vi = to_info(wdd);
	struct virtio_device *vdev = vi->vdev;

	dev_info(&vdev->dev, "Watchdog started");

	return 0;
}

static int virtio_watchdog_stop(struct watchdog_device *wdd)
{
	struct virtio_watchdog_info *vi = to_info(wdd);
	struct virtio_device *vdev = vi->vdev;

	dev_info(&vdev->dev, "Watchdog stop request ignored");

	return 0;
}

static struct watchdog_info vw_info = {
	.identity = "virtio-watchdog",
	.options = WDIOF_KEEPALIVEPING,
};

static const struct watchdog_ops vw_ops = {
	.owner = THIS_MODULE,
	.start = virtio_watchdog_start,
	.stop = virtio_watchdog_stop,
	.ping = virtio_watchdog_ping,
};

static int probe_common(struct virtio_device *vdev)
{
	int err, index;
	struct virtio_watchdog_info *vi = NULL;

	vi = kzalloc(sizeof(struct virtio_watchdog_info), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	vi->index = index =
		ida_simple_get(&watchdog_index_ida, 0, 0, GFP_KERNEL);
	if (index < 0) {
		err = index;
		goto err_ida;
	}
	sprintf(vi->name, "virtio_watchdog.%d", index);
	init_completion(&vi->have_data);

	vdev->priv = vi;
	vi->vdev = vdev;

	vi->vq =
		virtio_find_single_vq(vdev, virtio_watchdog_recv_done, "input");
	if (IS_ERR(vi->vq)) {
		err = PTR_ERR(vi->vq);
		goto err_find;
	}

	vi->wdd.info = &vw_info;
	vi->wdd.ops = &vw_ops;
	vi->wdd.min_timeout = VW_HEARTBEAT_DEFAULT;
	vi->wdd.max_timeout = VW_HEARTBEAT_DEFAULT;
	vi->wdd.timeout = VW_HEARTBEAT_DEFAULT;

	err = watchdog_register_device(&vi->wdd);
	if (err != 0)
		goto err_find;
	vi->wdd_register_done = true;

	return 0;

err_find:
	ida_simple_remove(&watchdog_index_ida, index);
err_ida:
	kfree(vi);
	return err;
}

static void remove_common(struct virtio_device *vdev)
{
	struct virtio_watchdog_info *vi = vdev->priv;

	if (vi->busy) {
		wait_for_completion(&vi->have_data);
		vi->data_avail = 0;
		complete(&vi->have_data);
		vi->busy = false;
	}
	vdev->config->reset(vdev);
	if (vi->wdd_register_done) {
		watchdog_unregister_device(&vi->wdd);
		vi->wdd_register_done = false;
	}
	vdev->config->del_vqs(vdev);
	ida_simple_remove(&watchdog_index_ida, vi->index);
	kfree(vi);
}

static int virtio_watchdog_probe(struct virtio_device *vdev)
{
	return probe_common(vdev);
}

static void virtio_watchdog_remove(struct virtio_device *vdev)
{
	remove_common(vdev);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_watchdog_freeze(struct virtio_device *vdev)
{
	remove_common(vdev);
	return 0;
}

static int virtio_watchdog_restore(struct virtio_device *vdev)
{
	return probe_common(vdev);
}
#endif

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_WATCHDOG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_watchdog_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_watchdog_probe,
	.remove = virtio_watchdog_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze = virtio_watchdog_freeze,
	.restore = virtio_watchdog_restore,
#endif
};

module_virtio_driver(virtio_watchdog_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio watchdog driver");
MODULE_LICENSE("GPL");
