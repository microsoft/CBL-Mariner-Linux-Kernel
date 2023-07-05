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

static struct efi_hvloader_protocol *efi_mshv;

static inline void __noreturn efistub_reboot(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	efi_printk(fmt, args);
	va_end(args);

	efi_bs_call(stall, 5 * EFI_USEC_PER_SEC);
	efi_rt_call(reset_system, EFI_RESET_COLD, EFI_ABORTED, 0, NULL);
}

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
			void *mshv_reserved, unsigned long mshv_reserved_sz)
{
	unsigned long cmdline_ptr;
	struct resource *res;
	int res_len, i;
	u32 cmdline_size;
	u32 cmdline_len;
	static u8 mshv_cmdline[COMMAND_LINE_SIZE];

	if (!efi_mshv)
		return EFI_SUCCESS;

	res = mshv_reserved;
	res_len = mshv_reserved_sz / sizeof(struct resource);

	memset(mshv_cmdline, 0, sizeof(mshv_cmdline));

	cmdline_ptr = boot_params->hdr.cmd_line_ptr;
	cmdline_ptr |= (u64)boot_params->ext_cmd_line_ptr << 32;
	cmdline_size = boot_params->hdr.cmdline_size;

	cmdline_len = strnlen((const char *)cmdline_ptr, cmdline_size);
	if (cmdline_len >= sizeof(mshv_cmdline))
		return EFI_BUFFER_TOO_SMALL;
	memcpy(mshv_cmdline, (void *)cmdline_ptr, cmdline_len);

	/*
	 * Create the 'hyperv_resvd_new' command line option:
	 * 'hyperv_resvd_new=<size>!<address>,<size>!<address>,...'
	 */
	cmdline_len += snprintf(&mshv_cmdline[cmdline_len],
				sizeof(mshv_cmdline) - cmdline_len,
				" hyperv_resvd_new=");

	for (i = 0; i < res_len; ++i) {
		resource_size_t sz = res[i].end - res[i].start + 1;

		cmdline_len += snprintf(&mshv_cmdline[cmdline_len],
					sizeof(mshv_cmdline) - cmdline_len,
					"%s0x%llx!0x%llx", i == 0 ? "" : ",", sz,
					res[i].start);

		if (cmdline_len >= sizeof(mshv_cmdline) - 1)
			return EFI_BUFFER_TOO_SMALL;
	}

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
	static efi_guid_t hv_proto_guid = EFI_MSHV_MEDIA_PROTOCOL_GUID;
	efi_memory_desc_t *mem_map;
	unsigned long map_sz, key, desc_sz, setup_data_sz;
	u32 desc_ver;
	u64 start, end;
	struct resource *mshv_range, *prev;
	struct resource *mshv_reserved;
	unsigned long mshv_reserved_sz;
	u32 nr_desc;
	int i, nr_ranges, max_ranges;
	efi_status_t status;

	mem_map = NULL;
	mshv_reserved = NULL;

	status = efi_bs_call(locate_protocol,
				&hv_proto_guid, NULL, (void **)&efi_mshv);
	if (status == EFI_NOT_FOUND) {
		/*
		 * If the protocol is not installed
		 * we are in a standard Linux boot
		 */
		return EFI_SUCCESS;
	} else if (status != EFI_SUCCESS)
		efistub_reboot("LocateProtocol failed "
			"unexpectedly with code %d", status);

	status = efi_mshv->get_loader_init_status();
	if (status != EFI_SUCCESS)
		efistub_reboot("mshv protocol installed but seems to "
			"have failed with code %d", status);

	/*
	 * Get mshv memory map to figure out mshv reserved ranges.
	 */

	map_sz = 0;
	status = efi_mshv->get_hv_ranges((void *)&mem_map, &map_sz, &desc_sz);
	if (status != EFI_SUCCESS)
		efistub_reboot("failed to retrieve mshv ranges: error code %d",
			status);

	/*
	 * Build an array of kernel 'struct resource' objects that contain mshv
	 * reserved ranges. This array is populated via a command line parameter
	 * called 'hyperv_resvd_new'.
	 */

	status = mshv_realloc_ranges(&mshv_reserved,
				&mshv_reserved_sz,
				MSHV_RESERVED_RANGES_COUNT);
	if (status != EFI_SUCCESS)
		efistub_reboot("failed to allocate space for hv ranges with code %d",
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
				efistub_reboot("failed to allocate space for "
					"hv ranges with code %d", status);

			prev = &mshv_reserved[nr_ranges-1];
			mshv_range = prev + 1;
		}
	}
	
	status = mshv_populate_ranges(boot_params, mshv_reserved,
				nr_ranges * sizeof(struct resource));
	if (status != EFI_SUCCESS)
		efistub_reboot("failed to allocate space for hv ranges with code %d",
			status);

	/* Build an indirect setup_data for each mshv reserved range. */
	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA,
				nr_ranges * sizeof(struct mshv_setup_data),
				(void **)&sd_block);
	if (status != EFI_SUCCESS)
		efistub_reboot("failed to allocate space for "
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
		sd_block[i].sd.next = &sd_block[i + 1];

		sd_block[i].si.type = SETUP_MSHV;
		sd_block[i].si.reserved = 0;
		sd_block[i].si.len = end - start + 1;
		sd_block[i].si.addr = start;
	}

	/*
	 * Remove the trailing 'next' pointer which is currently
	 * outside of the struct mshv_setup_data buffer.
	 */

	sd_block[nr_ranges - 1].sd.next = NULL;

	efi_bs_call(free_pool, mem_map);

	return EFI_SUCCESS;
}

efi_status_t mshv_set_efi_rt_range(struct efi_boot_memmap *map)
{
	u32 nr_desc;
	int i;
	efi_status_t status;

	if (!efi_mshv)
		return EFI_SUCCESS;

	nr_desc = map->map_size / map->desc_size;

	for (i = 0; i < nr_desc; i++) {
		efi_memory_desc_t *d;

		d = efi_early_memdesc_ptr(map->map, map->desc_size, i);
		switch (d->type) {
		case EFI_RUNTIME_SERVICES_CODE:
		case EFI_RUNTIME_SERVICES_DATA:
			status = efi_mshv->register_range(d->phys_addr >> PAGE_SHIFT,
								d->num_pages);
			if (status != EFI_SUCCESS)
				return status;
			break;
		default:
			/* default case: range is not relevant to mshv */
			break;
		}
	}

	return EFI_SUCCESS;
}

/*
 * Launch mshv, if enabled.
 *
 * If mshv reports a bad status at this point, abort the boot.
 * To get more information about the failure, the HV loader's internal
 * logging can be used, which is exposed via efi_hv->get_next_log_msg(...).
 *
 */
efi_status_t mshv_launch(void)
{
	struct hvl_return_data ret;

	if (!efi_mshv)
		return;

	efi_mshv->launch_hv(NULL, &ret);
	/* TODO: Where/how do we dump the hv loader logs? */
	if (ret.launch_data.launch_status != 0)
		efi_rt_call(reset_system, EFI_RESET_COLD, EFI_ABORTED, 0, NULL);
	return EFI_SUCCESS;
}

