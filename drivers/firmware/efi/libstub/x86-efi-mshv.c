// SPDX-License-Identifier: GPL-2.0-only

#include <asm/setup.h>

#include "efistub.h"
#include "efi-mshv.h"

/* Initial number of MSHV reserved ranges, extended as needed */
#define MSHV_RESERVED_RANGES_COUNT 16

struct mshv_setup_data {
	struct setup_data sd;
	struct setup_indirect si;
} __packed;

static int mshv_realloc_ranges(struct resource **data,
				unsigned long *data_sz, int nr_ranges)
{
	struct resource *new_data;
	unsigned long new_sz;
	int status;

	new_sz = sizeof(struct resource) * nr_ranges;
	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, new_sz,
				(void **)&new_data);
	if (status != EFI_SUCCESS) {
		efi_err("mshv failed to allocate setup_data\n");
		return status;
	}

	memset(new_data, 0, new_sz);
	if (*data) {
		memcpy(new_data, *data, *data_sz);
		efi_bs_call(free_pool, *data);
	}

	*data = new_data;
	*data_sz = new_sz;

	return EFI_SUCCESS;
}

static efi_status_t mshv_populate_ranges(struct boot_params *boot_params,
			efi_memory_desc_t *mem_map, unsigned long map_sz,
			unsigned long desc_sz)
{
	unsigned long cmdline_ptr;
	u32 cmdline_size;
	static u8 mshv_cmdline[COMMAND_LINE_SIZE];

	memset(mshv_cmdline, 0, sizeof(mshv_cmdline));

	cmdline_ptr = boot_params->hdr.cmd_line_ptr;
	cmdline_ptr |= (u64)boot_params->ext_cmd_line_ptr << 32;
	cmdline_size = boot_params->hdr.cmdline_size;

	mshv_efi_update_cmdline(mem_map, map_sz, desc_sz,
				(char *)cmdline_ptr,
				(char *)mshv_cmdline, COMMAND_LINE_SIZE);

	boot_params->hdr.cmd_line_ptr = (u32)((unsigned long)mshv_cmdline);
	boot_params->ext_cmd_line_ptr = (u32)((unsigned long)mshv_cmdline >> 32);
	boot_params->hdr.cmdline_size = sizeof(mshv_cmdline);

	return EFI_SUCCESS;
}

/*
 * Prepare for running as root partition with mshv.
 * - Open the hypervisor loader EFI protocol, used for launching mshv after
 *   'exit boot services'.
 * - Get mshv reserved memory ranges from the loader, and populates those
 *   via a command line parameter 'hyperv_resvd_new'.
 * If mshv_efi_setup() fails, boot continues as a bare-metal boot.
 */
efi_status_t mshv_efi_setup(struct boot_params *boot_params)
{
	struct setup_data **setup_data_itr;
	struct mshv_setup_data *sd_block;
	efi_memory_desc_t *mem_map;
	unsigned long map_sz, desc_sz;
	u64 start, end;
	struct resource *mshv_range, *prev;
	struct resource *mshv_reserved;
	unsigned long mshv_reserved_sz;
	u32 nr_desc;
	int i, nr_ranges, max_ranges;
	efi_status_t status;

	mem_map = NULL;
	mshv_reserved = NULL;

	status = mshv_efi_init();
	if (status == EFI_NOT_FOUND) {
		/*
		 * If the protocol is not installed
		 * we are in a standard Linux boot
		 */
		return EFI_SUCCESS;
	}

	/*
	 * Get mshv memory map to figure out mshv reserved ranges.
	 */

	map_sz = 0;
	mshv_get_hv_ranges((void *)&mem_map, &map_sz, &desc_sz);

	/*
	 * Build an array of kernel 'struct resource' objects that contain mshv
	 * reserved ranges. This array is populated via a command line parameter
	 * called 'hyperv_resvd_new'.
	 */

	status = mshv_realloc_ranges(&mshv_reserved,
				&mshv_reserved_sz,
				MSHV_RESERVED_RANGES_COUNT);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to allocate space for hv ranges with code %d",
			status);

	max_ranges = MSHV_RESERVED_RANGES_COUNT;
	mshv_range = mshv_reserved;
	prev = NULL;
	nr_desc = map_sz / desc_sz;
	for (i = 0, nr_ranges = 0; i < nr_desc; i++) {
		efi_memory_desc_t *d;

		d = efi_early_memdesc_ptr(mem_map, desc_sz, i);

		/* Merge adjacent ranges */
		if (prev && ((prev->end + 1) == d->phys_addr)) {
			prev->end += (d->num_pages << PAGE_SHIFT);
			continue;
		}

		mshv_range->name = "Hypervisor Code and Data";
		mshv_range->flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
		mshv_range->start = d->phys_addr;
		mshv_range->end = d->phys_addr + (d->num_pages << PAGE_SHIFT) - 1;

		prev = mshv_range++;
		nr_ranges++;
		if (nr_ranges >= max_ranges) {
			/* Extend the array to accommodate more ranges */
			max_ranges += MSHV_RESERVED_RANGES_COUNT;
			status = mshv_realloc_ranges(&mshv_reserved, &mshv_reserved_sz,
						max_ranges);
			if (status != EFI_SUCCESS)
				mshv_efi_reboot("failed to allocate space for "
					"hv ranges with code %d", status);

			prev = &mshv_reserved[nr_ranges-1];
			mshv_range = prev + 1;
		}
	}

	status = mshv_populate_ranges(boot_params, mem_map, map_sz, desc_sz);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to allocate space for hv ranges with code %d",
			status);

	/* Build an indirect setup_data for each mshv reserved range. */
	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA,
				nr_ranges * sizeof(struct mshv_setup_data),
				(void **)&sd_block);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to allocate space for "
			"hv ranges: error code %d", status);

	memset((void *)sd_block, 0, nr_ranges * sizeof(struct mshv_setup_data));
	setup_data_itr = (struct setup_data **)&boot_params->hdr.setup_data;

	while (*setup_data_itr && (*setup_data_itr)->next)
		setup_data_itr = (struct setup_data **)&(*setup_data_itr)->next;

	*setup_data_itr = (struct setup_data *)sd_block;

	for (i = 0; i < nr_ranges; i++) {
		start = mshv_reserved[i].start;
		end = mshv_reserved[i].end;

		sd_block[i].sd.type = SETUP_INDIRECT;
		sd_block[i].sd.len  = sizeof(struct setup_indirect);
		sd_block[i].sd.next = (__u64)&sd_block[i + 1];

		sd_block[i].si.type = SETUP_MSHV;
		sd_block[i].si.reserved = 0;
		sd_block[i].si.len = end - start + 1;
		sd_block[i].si.addr = start;
	}

	/*
	 * Remove the trailing 'next' pointer which is currently
	 * outside of the struct mshv_setup_data buffer.
	 */

	sd_block[nr_ranges - 1].sd.next = 0;

	efi_bs_call(free_pool, mem_map);

	return EFI_SUCCESS;
}
