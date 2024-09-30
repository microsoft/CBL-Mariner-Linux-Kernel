// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 * Author:
 *
 */

#include <linux/memblock.h>

/* Define Memory Reservation for Secure Kernel */
#define SECKERNEL_ALIGN			SZ_2M
#define SECKERNEL_ADDR_MAX		(max_low_pfn_mapped << PAGE_SHIFT)
#define SECKERNEL_BASE_SIZE		(16 * 1024 * 1024)
#define SECKERNEL_PERCPU_SIZE		(4 * 1024 * 1024)

/* Estimate amount of memory needed for Secure Kernel */
#define SECKERNEL_MIN_SIZE (SECKERNEL_BASE_SIZE + num_possible_cpus() * SECKERNEL_PERCPU_SIZE)

struct resource sk_res = {
	.name  = "vsm",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc  = IORES_DESC_RESERVED
};

/*
 * That function parses "simple" securekernel command lines like
 *
 *	securekernel=size[@offset]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
static int __init parse_securekernel_simple(char *cmdline,
					    unsigned long long *securekernel_size,
					    unsigned long long *securekernel_base)
{
	char *cur = cmdline;

	*securekernel_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("securekernel: memory value expected\n");
		return -EINVAL;
	}

	if (*cur == '@') {
		*securekernel_base = memparse(cur + 1, &cur);
	} else if (*cur != ' ' && *cur != '\0') {
		pr_warn("securekernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

static __init char *get_last_securekernel(char *cmdline, const char *name)
{
	char *p = cmdline, *sk_cmdline = NULL;

	/* find securekernel and use the last one if there are more */
	p = strstr(p, name);
	while (p) {
		sk_cmdline = p;
		p = strstr(p + 1, name);
	}

	if (!sk_cmdline)
		return NULL;

	return sk_cmdline;
}

static int __init __parse_securekernel(char *cmdline,
				       unsigned long long system_ram,
				       unsigned long long *securekernel_size,
				       unsigned long long *securekernel_base,
				       const char *name)
{
	char *sk_cmdline;

	if (!securekernel_size || !securekernel_base)
		return -EINVAL;

	*securekernel_size = 0;
	*securekernel_base = 0;

	sk_cmdline = get_last_securekernel(cmdline, name);

	if (!sk_cmdline)
		return -EINVAL;

	sk_cmdline += strlen(name);

	return parse_securekernel_simple(sk_cmdline, securekernel_size, securekernel_base);
}

/*
 * That function is the entry point for command line parsing and should be
 * called from the arch-specific code.
 */
static int __init parse_securekernel(char *cmdline,
			      unsigned long long system_ram,
			      unsigned long long *securekernel_size,
			      unsigned long long *securekernel_base)
{
	return __parse_securekernel(cmdline, system_ram, securekernel_size, securekernel_base,
					"securekernel=");
}

static int __init hv_vsm_seckernel_mem_init(char *__unused)
{
	unsigned long long securekernel_size = 0, securekernel_base = 0;
	int ret;

	/*
	 * Reserve Secure Kernel memory.
	 * Check command line first, if secure kernel memory was defined
	 */
	ret = parse_securekernel(boot_command_line, SECKERNEL_ADDR_MAX, &securekernel_size,
				 &securekernel_base);

	if (ret != 0 || securekernel_size < SECKERNEL_MIN_SIZE) {
		if (ret != 0)
			pr_info("%s: securekernel cmd line not defined. Falling back to default.\n",
				__func__);
		else if (securekernel_size < SECKERNEL_MIN_SIZE)
			pr_info("%s: securekernel cmd line too small. Falling back to default.\n",
				__func__);

		securekernel_size = SECKERNEL_MIN_SIZE;
		securekernel_base = 0;
	}

	/* If securekernel_base was specified from command line,
	 * try to reserve memory starting from that address
	 */
	if (securekernel_base) {
		unsigned long long start, end;

		end = securekernel_base + securekernel_size;
		if (end >  SECKERNEL_ADDR_MAX || end < securekernel_base) {
			pr_warn("%s: Invalid Securekernel base address %llx. Falling back to default.\n",
				__func__, securekernel_base);
			securekernel_base = 0;
		} else {
			start = memblock_phys_alloc_range(securekernel_size, SECKERNEL_ALIGN,
							  securekernel_base,
							  securekernel_base + securekernel_size);
			if (start != securekernel_base) {
				pr_warn("%s: memory reservation @ %llx failed-memory is in use\n",
					__func__, securekernel_base);
				pr_warn("%s:Falling back to default mem allocation\n", __func__);
				securekernel_base = 0;
			}
		}
	}
	/* Default: Find the base address automatically */
	if (!securekernel_base) {
		securekernel_base = memblock_phys_alloc_range(securekernel_size, SECKERNEL_ALIGN,
							      0, SECKERNEL_ADDR_MAX);
		if (!securekernel_base) {
			pr_err("%s: Securekernel reservation failed-VSM will not be enabled.\n",
			       __func__);
			return -EINVAL;
		}
	}

	pr_info("Reserving %ldMB of memory at 0x%llx(%ld MB) for securekernel(System RAM:%ldMB)\n",
		(unsigned long)(securekernel_size >> 20),
		securekernel_base,
		(unsigned long)(securekernel_base >> 20),
		(unsigned long)(memblock_phys_mem_size() >> 20));

	sk_res.start = securekernel_base;
	sk_res.end   = securekernel_base + securekernel_size - 1;
	insert_resource(&iomem_resource, &sk_res);

	return 0;
}
__setup("securekernel", hv_vsm_seckernel_mem_init);
