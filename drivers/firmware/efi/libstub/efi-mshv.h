/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _DRIVERS_FIRMWARE_EFI_MSHV_H
#define _DRIVERS_FIRMWARE_EFI_MSHV_H

#if !IS_ENABLED(CONFIG_MSHV_ROOT)
#ifdef CONFIG_X86_64
static inline efi_status_t mshv_efi_setup(struct boot_params *boot_params)
{
	return EFI_SUCCESS;
}

static inline efi_status_t mshv_set_efi_rt_range(struct efi_boot_memmap *map)
{
	return EFI_SUCCESS;
}

static inline efi_status_t mshv_launch(void) {}
#endif /* CONFIG_X86_64 */
#else /* !CONFIG_MSHV_ROOT */

#ifdef CONFIG_X86_64
efi_status_t mshv_efi_setup(struct boot_params *boot_params);
efi_status_t mshv_set_efi_rt_range(struct efi_boot_memmap *map);
efi_status_t mshv_launch(void);
#endif /* CONFIG_X86_64 */

struct hvl_dbg_data {
	u8 unused[552];
} __packed;

struct hvl_launch_data {
	u64 launch_status;
	u64 launch_substatus1;
} __packed;

struct hvl_load_data {
	u32 is_unsafe_config:1;
	u32 reserved:31;
} __packed;

struct hvl_return_data {
	u32 crash_dump_area_page_count;
	u32 unused;
	u64 crashdump_area_spa;
	union {
		struct hvl_launch_data launch_data;
		struct hvl_load_data load_data;
	};
	struct hvl_dbg_data debug_data;
	void *spa_page_range_array;
	u32 range_count;

	struct
	{
		u32 base_checksum;
		u32 base_timestamp;
		u32 patch_checksum;
		u32 patch_timestamp;
		u32 base_hpat_entries_used;
		u32 patch_hpat_entries_used;
		u32 patch_sequence_number;
	} patch_details;
} __packed;

struct efi_hvloader_protocol {
	void (__efiapi * launch_hv)(void *, struct hvl_return_data *);
	efi_status_t (__efiapi * register_range)(u64, u64);
	efi_status_t (__efiapi * get_memory_map)(unsigned long *, void *,
						unsigned long *,
						unsigned long *, u32 *);
	efi_status_t (__efiapi * get_hv_ranges)(void **,
						unsigned long *,
						unsigned long *);
	efi_status_t (__efiapi * get_loader_init_status)(void);
	efi_char16_t *(__efiapi * get_next_log_msg)(size_t *);
};

#endif /* CONFIG_MSHV_ROOT */

#endif /* _DRIVERS_FIRMWARE_EFI_MSHV_H */
