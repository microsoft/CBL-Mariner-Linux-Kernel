/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MSHV_VFIO_H
#define __MSHV_VFIO_H

#ifdef CONFIG_MSHV_VFIO
int mshv_vfio_ops_init(void);
void mshv_vfio_ops_exit(void);

long mshv_partition_ioctl_create_device(struct mshv_partition *partition,
					void __user *user_args);
void mshv_destroy_devices(struct mshv_partition *partition);
#else
static inline int mshv_vfio_ops_init(void)
{
	return 0;
}
static inline void mshv_vfio_ops_exit(void) {}
void mshv_destroy_devices(struct mshv_partition *partition) {}
#endif

#endif
