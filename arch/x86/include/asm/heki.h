/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_HEKI_H
#define _ASM_X86_HEKI_H

#include <asm/paravirt_types.h>

struct heki_arch_kinfo {
	struct paravirt_patch_template	pv_ops;
	void				(*pv_bug)(void);
	void				(*pv_nop)(void);
};

#endif /* _ASM_X86_HEKI_H */
