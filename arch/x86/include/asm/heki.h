/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_HEKI_H
#define _ASM_X86_HEKI_H

#include <asm/paravirt_types.h>
#include <asm/text-patching.h>

struct heki_arch_kinfo {
	struct paravirt_patch_template	pv_ops;
	void				(*pv_bug)(void);
	void				(*pv_nop)(void);
	unsigned long			indirect_thunk_array_addr;
	unsigned long			return_thunk_init_addr;
	unsigned long			return_thunk_addr;
};

#endif /* _ASM_X86_HEKI_H */
