// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Kexec support
 *
 * Copyright © 2024 Microsoft Corporation
 */
#include <linux/heki.h>

static void		*heki_kernel;
static unsigned long	heki_kernel_len;

void heki_copy_kernel(void *kernel, unsigned long kernel_len)
{
	if (heki_kernel)
		vfree(heki_kernel);

	heki_kernel = vmalloc(kernel_len);
	if (!heki_kernel) {
		pr_warn("Failed to alloc memory for copying kexec kernel.\n");
		return;
	}

	heki_kernel_len = kernel_len;
	memcpy(heki_kernel, kernel, kernel_len);
}

void heki_load_pages(unsigned long pfn, struct heki_args *args)
{
	struct page *page = boot_pfn_to_page(pfn);
	unsigned int order = page_private(page);
	size_t size = 1UL << (order + PAGE_SHIFT);
	unsigned long pa = pfn << PAGE_SHIFT;
	void *va = __va(pa);

	args->attributes = HEKI_KEXEC_PAGES;
	heki_walk((unsigned long) va, (unsigned long) va + size,
		  heki_get_ranges, args);
}

/*
 * For a normal kexec, memory is only ear-marked for kexec segments and not
 * actually allocated. The current kernel could be using that ear-marked
 * memory. So, segment contents are first copied to separate pages called
 * source pages. Just before jumping to the new kernel, the source pages are
 * copied to their corresponding destination pages in the ear-marked memory.
 *
 * The source and the destination page addresses are recorded in the image as
 * an array of entries in an entry page. If there are more entries than will
 * fit into an entry page, the entries are recorded in multiple entry pages and
 * the entry pages are chained together using indirection entries. Basically,
 * it is a linked list.
 *
 * Walk the list and load the source pages. Load the indirection pages as well.
 * These will be write-protected until the source pages are copied into the
 * destination pages just before jumping to the new kernel.
 */
void heki_load_entries(struct kimage *image, struct heki_args *args)
{
	kimage_entry_t *ptr, entry;
	kimage_entry_t ind = 0;

	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_INDIRECTION) {
			/* Load the previous indirection page */
			if (ind & IND_INDIRECTION)
				heki_load_pages(ind >> PAGE_SHIFT, args);
			/* Save this indirection page. */
			ind = entry;
		} else if (entry & IND_SOURCE)
			heki_load_pages(entry >> PAGE_SHIFT, args);
	}
	/* Load the final indirection page */
	if (ind & IND_INDIRECTION)
		heki_load_pages(ind >> PAGE_SHIFT, args);
}

/*
 * Load control pages setup for kexec (code page, page table pages, etc)
 * so they can be write-protected until we jump to the new kernel.
 */
void heki_load_control_pages(struct kimage *image, struct heki_args *args)
{
	struct list_head *list = &image->control_pages;
	struct page *page;

	list_for_each_entry(page, list, lru) {
		if (page == image->vmcoreinfo_page) {
			/*
			 * This page is modified before jumping to the new
			 * kernel. It cannot be made read-only in the EPT at
			 * file load time. It doesn't need to be. So, don't
			 * load it.
			 */
			continue;
		}
		heki_load_pages(page_to_pfn(page), args);
	}
}

/*
 * For crash kexec, segment memory is reserved up front. So, segment contents
 * are copied to reserved memory at kexec file load time. Load the segment
 * pages so they can be write-protected until we jump to the new kernel.
 */
static void heki_load_segment(struct kimage *image, int seg,
			      struct heki_args *args)
{
	struct kexec_segment *segment = &image->segment[seg];
	size_t size = segment->memsz;
	unsigned long pa = segment->mem;
	void *va = __va(pa);

	args->attributes = HEKI_KEXEC_PAGES;
	heki_walk((unsigned long) va, (unsigned long) va + size,
		  heki_get_ranges, args);
}

void heki_load_segments(struct kimage *image, struct heki_args *args)
{
	int i;

	for (i = 0; i < image->nr_segments; i++)
		heki_load_segment(image, i, args);
}

int heki_kexec_validate(struct kimage *image)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	bool crash = image->type == KEXEC_TYPE_CRASH;
	struct heki_args args = {};
	int ret;

	if (!hypervisor)
		return 0;

	mutex_lock(&heki.lock);

	args.attributes = HEKI_KEXEC_IMAGE;
	heki_walk((unsigned long) image,
		  (unsigned long) image + sizeof(*image),
		  heki_get_ranges, &args);

	args.attributes = HEKI_KEXEC_KERNEL_BLOB;
	heki_walk((unsigned long) heki_kernel,
		  (unsigned long) heki_kernel + heki_kernel_len,
		  heki_get_ranges, &args);

	if (crash)
		heki_load_segments(image, &args);
	else
		heki_load_entries(image, &args);
	heki_load_control_pages(image, &args);
	heki_load_arch_pages(image, &args);

	ret = hypervisor->kexec_validate(args.head_pa, args.nranges, crash);
	if (ret)
		pr_warn("Failed to validate kexec data.\n");
	else
		pr_warn("Validated kexec data.\n");

	mutex_unlock(&heki.lock);

	heki_cleanup_args(&args);

	vfree(heki_kernel);
	heki_kernel = NULL;
	heki_kernel_len = 0;

	return ret;
}
