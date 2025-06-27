// SPDX-License-Identifier: GPL-2.0-only

#include "efistub.h"
#include "efi-mshv.h"

struct efi_hvloader_protocol *efi_mshv;

efi_status_t mshv_efi_init(void)
{
	efi_status_t status;
	static efi_guid_t hv_proto_guid = EFI_MSHV_MEDIA_PROTOCOL_GUID;

	status = efi_bs_call(locate_protocol,
			     &hv_proto_guid, NULL, (void **)&efi_mshv);
	if (status == EFI_NOT_FOUND) {
		/* If the protocol is not installed we are in a standard Linux boot */
		return status;
	} else if (status != EFI_SUCCESS) {
		mshv_efi_reboot("LocateProtocol failed unexpectedly with code %d",
			       status);
	}

	status = efi_mshv->get_loader_init_status();
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("mshv protocol installed but seems to have failed with code %d",
			       status);

	return EFI_SUCCESS;
}

void mshv_get_hv_ranges(efi_memory_desc_t **mem_map, unsigned long *map_sz,
			unsigned long *desc_sz)
{
	efi_status_t status;

	status = efi_mshv->get_hv_ranges((void **)mem_map, map_sz, desc_sz);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to retrieve mshv ranges: error code %d",
			       status);
}

/*
 * Concatenate the hypervisor reserved ranges to the command line.
 *
 * The reserved ranges are formatted as follows:
 * 'hyperv_resvd_new=<size>!<address>,<size>!<address>,...'
 *
 * @mem_map:		EFI memory map with the hypervisor reserved ranges
 * @map_sz:		size of the memory map
 * @desc_sz:		size of each descriptor in the memory map
 * @old_cmdline:	old command line
 * @buf:		buffer to hold the new command line
 */
void mshv_efi_update_cmdline(efi_memory_desc_t *mem_map,
		unsigned long map_sz, unsigned long desc_sz, char *old_cmdline,
		char *buf, unsigned long buf_sz)
{
	int i, cmdline_len, nr_desc;

	cmdline_len = strlen(old_cmdline);
	memcpy(buf, old_cmdline, cmdline_len + 1);

	cmdline_len += snprintf(buf + cmdline_len,
				buf_sz - cmdline_len,
				" hyperv_resvd_new=");

	nr_desc = map_sz / desc_sz;
	for (i = 0; i < nr_desc; ++i) {
		efi_memory_desc_t *d;
		u64 start, end, sz;

		d = efi_early_memdesc_ptr(mem_map, desc_sz, i);
		start = d->phys_addr;
		sz = d->num_pages << PAGE_SHIFT;
		end = start + sz - 1;

		cmdline_len += snprintf(buf + cmdline_len,
					buf_sz - cmdline_len,
					"%s0x%llx!0x%llx", i > 0 ? "," : "",
					sz, start);
	}
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
void mshv_launch(void)
{
	struct hvl_return_data ret;

	if (!efi_mshv)
		return;

	efi_mshv->launch_hv(NULL, &ret);
	/* TODO: Where/how do we dump the hv loader logs? */
	if (ret.launch_data.launch_status != 0)
		efi_rt_call(reset_system, EFI_RESET_COLD, EFI_ABORTED, 0, NULL);
}
