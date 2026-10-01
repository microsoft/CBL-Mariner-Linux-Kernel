// SPDX-License-Identifier: GPL-2.0-only

#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/setup.h>

#include "efistub.h"
#include "efi-mshv.h"

efi_status_t mshv_efi_setup(char **cmdline_ptr)
{
	efi_status_t status;
	efi_memory_desc_t *mem_map;
	unsigned long map_sz, desc_sz, new_cmdline_addr;

	status = mshv_efi_init();
	if (status == EFI_NOT_FOUND) // we are in a standard Linux boot
		return EFI_SUCCESS;

	map_sz = 0;
	mshv_get_hv_ranges((void *)&mem_map, &map_sz, &desc_sz);

	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, COMMAND_LINE_SIZE,
			     (void **)&new_cmdline_addr);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to allocate space for cmdline with code %d",
				status);

	mshv_efi_update_cmdline(mem_map, map_sz, desc_sz,
				*cmdline_ptr,
				(char *)new_cmdline_addr, COMMAND_LINE_SIZE);

	status = efi_bs_call(free_pool, *cmdline_ptr);
	if (status != EFI_SUCCESS)
		mshv_efi_reboot("failed to free old cmdline with code %d",
				status);

	*cmdline_ptr = (char *)new_cmdline_addr;

	return EFI_SUCCESS;
}
