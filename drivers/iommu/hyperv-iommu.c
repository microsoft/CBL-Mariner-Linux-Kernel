// SPDX-License-Identifier: GPL-2.0

/*
 * Hyper-V stub IOMMU driver.
 *
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Lan Tianyu <Tianyu.Lan@microsoft.com>
 */

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interval_tree.h>
#include <linux/dma-map-ops.h>
#include <linux/dmar.h>

#include <asm/apic.h>
#include <asm/cpu.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/irq_remapping.h>
#include <asm/hypervisor.h>
#include <asm/mshyperv.h>

#include "irq_remapping.h"
#include "dma-iommu.h"
#include "intel/iommu.h"

#ifdef CONFIG_IRQ_REMAP

/*
 * According 82093AA IO-APIC spec , IO APIC has a 24-entry Interrupt
 * Redirection Table. Hyper-V exposes one single IO-APIC and so define
 * 24 IO APIC remmapping entries.
 */
#define IOAPIC_REMAPPING_ENTRY 24

static cpumask_t ioapic_max_cpumask = { CPU_BITS_NONE };
static struct irq_domain *ioapic_ir_domain;
static size_t hv_iommu_unmap(struct iommu_domain *d, unsigned long iova,
			     size_t size, struct iommu_iotlb_gather *gather);

static int hyperv_ir_set_affinity(struct irq_data *data,
		const struct cpumask *mask, bool force)
{
	struct irq_data *parent = data->parent_data;
	struct irq_cfg *cfg = irqd_cfg(data);
	int ret;

	/* Return error If new irq affinity is out of ioapic_max_cpumask. */
	if (!cpumask_subset(mask, &ioapic_max_cpumask))
		return -EINVAL;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret < 0 || ret == IRQ_SET_MASK_OK_DONE)
		return ret;

	vector_schedule_cleanup(cfg);

	return 0;
}

static struct irq_chip hyperv_ir_chip = {
	.name			= "HYPERV-IR",
	.irq_ack		= apic_ack_irq,
	.irq_set_affinity	= hyperv_ir_set_affinity,
};

static int hyperv_irq_remapping_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	struct irq_alloc_info *info = arg;
	struct irq_data *irq_data;
	int ret = 0;

	if (!info || info->type != X86_IRQ_ALLOC_TYPE_IOAPIC || nr_irqs > 1)
		return -EINVAL;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	irq_data = irq_domain_get_irq_data(domain, virq);
	if (!irq_data) {
		irq_domain_free_irqs_common(domain, virq, nr_irqs);
		return -EINVAL;
	}

	irq_data->chip = &hyperv_ir_chip;

	/*
	 * Hypver-V IO APIC irq affinity should be in the scope of
	 * ioapic_max_cpumask because no irq remapping support.
	 */
	irq_data_update_affinity(irq_data, &ioapic_max_cpumask);

	return 0;
}

static void hyperv_irq_remapping_free(struct irq_domain *domain,
				 unsigned int virq, unsigned int nr_irqs)
{
	irq_domain_free_irqs_common(domain, virq, nr_irqs);
}

static int hyperv_irq_remapping_select(struct irq_domain *d,
				       struct irq_fwspec *fwspec,
				       enum irq_domain_bus_token bus_token)
{
	/* Claim the only I/O APIC emulated by Hyper-V */
	return x86_fwspec_is_ioapic(fwspec);
}

static const struct irq_domain_ops hyperv_ir_domain_ops = {
	.select = hyperv_irq_remapping_select,
	.alloc = hyperv_irq_remapping_alloc,
	.free = hyperv_irq_remapping_free,
};

static const struct irq_domain_ops hyperv_root_ir_domain_ops;
static int __init hyperv_prepare_irq_remapping(void)
{
	struct fwnode_handle *fn;
	int i;
	const char *name;
	const struct irq_domain_ops *ops;

	/*
	 * For a Hyper-V root partition, ms_hyperv_msi_ext_dest_id()
	 * will always return false.
	 */
	if (!hypervisor_is_type(X86_HYPER_MS_HYPERV) ||
	    x86_init.hyper.msi_ext_dest_id())
		return -ENODEV;

	if (hv_root_partition()) {
		name = "HYPERV-ROOT-IR";
		ops = &hyperv_root_ir_domain_ops;
	} else {
		name = "HYPERV-IR";
		ops = &hyperv_ir_domain_ops;
	}

	fn = irq_domain_alloc_named_id_fwnode(name, 0);
	if (!fn)
		return -ENOMEM;

	ioapic_ir_domain =
		irq_domain_create_hierarchy(arch_get_ir_parent_domain(),
				0, IOAPIC_REMAPPING_ENTRY, fn, ops, NULL);

	if (!ioapic_ir_domain) {
		irq_domain_free_fwnode(fn);
		return -ENOMEM;
	}

	if (hv_root_partition())
		return 0; /* The rest is only relevant to guests */

	/*
	 * Hyper-V doesn't provide irq remapping function for
	 * IO-APIC and so IO-APIC only accepts 8-bit APIC ID.
	 * Cpu's APIC ID is read from ACPI MADT table and APIC IDs
	 * in the MADT table on Hyper-v are sorted monotonic increasingly.
	 * APIC ID reflects cpu topology. There maybe some APIC ID
	 * gaps when cpu number in a socket is not power of two. Prepare
	 * max cpu affinity for IOAPIC irqs. Scan cpu 0-255 and set cpu
	 * into ioapic_max_cpumask if its APIC ID is less than 256.
	 */
	for (i = min_t(unsigned int, num_possible_cpus() - 1, 255); i >= 0; i--)
		if (cpu_physical_id(i) < 256)
			cpumask_set_cpu(i, &ioapic_max_cpumask);

	return 0;
}

static int __init hyperv_enable_irq_remapping(void)
{
	if (x2apic_supported())
		return IRQ_REMAP_X2APIC_MODE;
	return IRQ_REMAP_XAPIC_MODE;
}

struct irq_remap_ops hyperv_irq_remap_ops = {
	.prepare		= hyperv_prepare_irq_remapping,
	.enable			= hyperv_enable_irq_remapping,
};

/* IRQ remapping domain when Linux runs as the root partition */
struct hyperv_root_ir_data {
	u8 ioapic_id;
	bool is_level;
	struct hv_interrupt_entry entry;
};

static void
hyperv_root_ir_compose_msi_msg(struct irq_data *irq_data, struct msi_msg *msg)
{
	u64 status;
	u32 vector;
	struct irq_cfg *cfg;
	int ioapic_id;
	const struct cpumask *affinity;
	int cpu;
	struct hv_interrupt_entry entry;
	struct hyperv_root_ir_data *data = irq_data->chip_data;
	struct IO_APIC_route_entry e;

	cfg = irqd_cfg(irq_data);
	affinity = irq_data_get_effective_affinity_mask(irq_data);
	cpu = cpumask_first_and(affinity, cpu_online_mask);

	vector = cfg->vector;
	ioapic_id = data->ioapic_id;

	if (data->entry.source == HV_DEVICE_TYPE_IOAPIC
	    && data->entry.ioapic_rte.as_uint64) {
		entry = data->entry;

		status = hv_unmap_ioapic_interrupt(ioapic_id, &entry);

		if (status != HV_STATUS_SUCCESS)
			pr_debug("%s: unexpected unmap status %lld\n", __func__, status);

		data->entry.ioapic_rte.as_uint64 = 0;
		data->entry.source = 0; /* Invalid source */
	}


	status = hv_map_ioapic_interrupt(ioapic_id, data->is_level, cpu,
					vector, &entry);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: map hypercall failed, status %lld\n", __func__, status);
		return;
	}

	data->entry = entry;

	/* Turn it into an IO_APIC_route_entry, and generate MSI MSG. */
	e.w1 = entry.ioapic_rte.low_uint32;
	e.w2 = entry.ioapic_rte.high_uint32;

	memset(msg, 0, sizeof(*msg));
	msg->arch_data.vector = e.vector;
	msg->arch_data.delivery_mode = e.delivery_mode;
	msg->arch_addr_lo.dest_mode_logical = e.dest_mode_logical;
	msg->arch_addr_lo.dmar_format = e.ir_format;
	msg->arch_addr_lo.dmar_index_0_14 = e.ir_index_0_14;
}

static int hyperv_root_ir_set_affinity(struct irq_data *data,
		const struct cpumask *mask, bool force)
{
	struct irq_data *parent = data->parent_data;
	struct irq_cfg *cfg = irqd_cfg(data);
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret < 0 || ret == IRQ_SET_MASK_OK_DONE)
		return ret;

	vector_schedule_cleanup(cfg);

	return 0;
}

static struct irq_chip hyperv_root_ir_chip = {
	.name			= "HYPERV-ROOT-IR",
	.irq_ack		= apic_ack_irq,
	.irq_set_affinity	= hyperv_root_ir_set_affinity,
	.irq_compose_msi_msg	= hyperv_root_ir_compose_msi_msg,
};

static int hyperv_root_irq_remapping_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	struct irq_alloc_info *info = arg;
	struct irq_data *irq_data;
	struct hyperv_root_ir_data *data;
	int ret = 0;

	if (!info || info->type != X86_IRQ_ALLOC_TYPE_IOAPIC || nr_irqs > 1)
		return -EINVAL;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		irq_domain_free_irqs_common(domain, virq, nr_irqs);
		return -ENOMEM;
	}

	irq_data = irq_domain_get_irq_data(domain, virq);
	if (!irq_data) {
		kfree(data);
		irq_domain_free_irqs_common(domain, virq, nr_irqs);
		return -EINVAL;
	}

	data->ioapic_id = info->devid;
	data->is_level = info->ioapic.is_level;

	irq_data->chip = &hyperv_root_ir_chip;
	irq_data->chip_data = data;

	return 0;
}

static void hyperv_root_irq_remapping_free(struct irq_domain *domain,
				 unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *irq_data;
	struct hyperv_root_ir_data *data;
	struct hv_interrupt_entry *e;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(domain, virq + i);

		if (irq_data && irq_data->chip_data) {
			data = irq_data->chip_data;
			e = &data->entry;

			if (e->source == HV_DEVICE_TYPE_IOAPIC
			      && e->ioapic_rte.as_uint64)
				hv_unmap_ioapic_interrupt(data->ioapic_id,
							&data->entry);

			kfree(data);
		}
	}

	irq_domain_free_irqs_common(domain, virq, nr_irqs);
}

static const struct irq_domain_ops hyperv_root_ir_domain_ops = {
	.select = hyperv_irq_remapping_select,
	.alloc = hyperv_root_irq_remapping_alloc,
	.free = hyperv_root_irq_remapping_free,
};

#endif

#ifdef CONFIG_HYPERV_ROOT_PVIOMMU

/* The IOMMU will not claim these PCI devices. */
static char *pci_devs_to_skip;
static int __init mshv_iommu_setup_skip(char *str)
{
	pci_devs_to_skip = str;

	return 0;
}
/* mshv_iommu_skip=(SSSS:BB:DD.F)(SSSS:BB:DD.F) */
__setup("mshv_iommu_skip=", mshv_iommu_setup_skip);

/* DMA remapping support */
struct hv_iommu_domain {
	struct iommu_domain domain;
	struct hv_iommu_dev *hv_iommu;

	struct hv_input_device_domain device_domain;

	spinlock_t mappings_lock;
	struct rb_root_cached mappings;

	u32 map_flags;
	u64 pgsize_bitmap;
};

/* What hardware IOMMU? */
enum {
	INVALID = 0,
	INTEL, /* Only Intel for now */
} hw_iommu_type = { INVALID };

static struct hv_iommu_domain hv_identity_domain, hv_null_domain;

#define to_hv_iommu_domain(d) \
	container_of(d, struct hv_iommu_domain, domain)

struct hv_iommu_mapping {
	phys_addr_t paddr;
	struct interval_tree_node iova;
	u32 flags;
};

struct hv_iommu_dev {
	struct iommu_device iommu;

	struct ida domain_ids;

	/* Device configuration */
	struct iommu_domain_geometry geometry;
	u64 first_domain;
	u64 last_domain;

	u32 map_flags;
	u64 pgsize_bitmap;
};

static struct hv_iommu_dev *hv_iommu_device;

struct hv_iommu_endpoint {
	struct device *dev;
	struct hv_iommu_dev *hv_iommu;
	struct hv_iommu_domain *domain;
};

static void __init hv_initialize_special_domains(void)
{
	struct hv_iommu_domain *domain;

	/* Default passthrough domain */
	domain = &hv_identity_domain;

	memset(domain, 0, sizeof(*domain));

	domain->device_domain.partition_id = HV_PARTITION_ID_SELF;
	domain->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	domain->device_domain.domain_id.id = HV_DEVICE_DOMAIN_ID_S2_DEFAULT;

	domain->domain.geometry = hv_iommu_device->geometry;

	/* NULL domain that blocks all DMA transactions */
	domain = &hv_null_domain;

	memset(domain, 0, sizeof(*domain));

	domain->device_domain.partition_id = HV_PARTITION_ID_SELF;
	domain->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	domain->device_domain.domain_id.id = HV_DEVICE_DOMAIN_ID_S2_NULL;

	domain->domain.geometry = hv_iommu_device->geometry;
}

static bool is_identity_domain(struct hv_iommu_domain *d)
{
	return d->device_domain.domain_id.id == HV_DEVICE_DOMAIN_ID_S2_DEFAULT;
}

static bool is_null_domain(struct hv_iommu_domain *d)
{
	return d->device_domain.domain_id.id == HV_DEVICE_DOMAIN_ID_S2_NULL;
}

static struct iommu_domain *hv_iommu_domain_alloc(unsigned int type)
{
	struct hv_iommu_domain *domain;
	int ret;
	u64 status;
	unsigned long flags;
	struct hv_input_create_device_domain *input;

	if (type == IOMMU_DOMAIN_IDENTITY)
		return &hv_identity_domain.domain;

	if (type == IOMMU_DOMAIN_BLOCKED)
		return &hv_null_domain.domain;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		goto out;

	spin_lock_init(&domain->mappings_lock);
	domain->mappings = RB_ROOT_CACHED;

	if (type == IOMMU_DOMAIN_DMA &&
		iommu_get_dma_cookie(&domain->domain)) {
		goto out_free;
	}

	ret = ida_alloc_range(&hv_iommu_device->domain_ids,
			hv_iommu_device->first_domain, hv_iommu_device->last_domain,
			GFP_KERNEL);
	if (ret < 0)
		goto out_put_cookie;

	domain->device_domain.partition_id = HV_PARTITION_ID_SELF;
	domain->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	domain->device_domain.domain_id.id = ret;

	domain->hv_iommu = hv_iommu_device;
	domain->map_flags = hv_iommu_device->map_flags;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain = domain->device_domain;

	input->create_device_domain_flags.forward_progress_required = 1;
	input->create_device_domain_flags.inherit_owning_vtl = 0;

	status = hv_do_hypercall(HVCALL_CREATE_DEVICE_DOMAIN, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: hypercall failed, status %lld\n", __func__, status);
		goto out_free_id;
	}

	domain->domain.pgsize_bitmap = hv_iommu_device->pgsize_bitmap;
	domain->domain.geometry = hv_iommu_device->geometry;

	return &domain->domain;

out_free_id:
	ida_free(&hv_iommu_device->domain_ids, domain->device_domain.domain_id.id);
out_put_cookie:
	iommu_put_dma_cookie(&domain->domain);
out_free:
	kfree(domain);
out:
	return NULL;
}

static void hv_iommu_domain_free(struct iommu_domain *d)
{
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);
	unsigned long flags;
	u64 status;
	struct hv_input_delete_device_domain *input;

	if (is_identity_domain(domain) || is_null_domain(domain))
		return;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain = domain->device_domain;

	status = hv_do_hypercall(HVCALL_DELETE_DEVICE_DOMAIN, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status %lld\n", __func__, status);

	ida_free(&domain->hv_iommu->domain_ids, domain->device_domain.domain_id.id);

	iommu_put_dma_cookie(d);

	kfree(domain);
}

static int hv_iommu_attach_dev(struct iommu_domain *d, struct device *dev)
{
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);
	u64 status;
	unsigned long flags;
	struct hv_input_attach_device_domain *input;
	struct pci_dev *pdev;
	struct hv_iommu_endpoint *vdev = dev_iommu_priv_get(dev);

	/* Only allow PCI devices for now */
	if (!dev_is_pci(dev))
		return -EINVAL;

	pdev = to_pci_dev(dev);

	dev_dbg(dev, "Attaching (%strusted) to %d\n", pdev->untrusted ? "un" : "",
		domain->device_domain.domain_id.id);

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain = domain->device_domain;
	input->device_id = hv_build_pci_dev_id(pdev);

	status = hv_do_hypercall(HVCALL_ATTACH_DEVICE_DOMAIN, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status %lld\n", __func__, status);
	else
		vdev->domain = domain;

	return hv_status_to_errno(status);
}

static void hv_iommu_detach_dev(struct iommu_domain *d, struct device *dev)
{
	u64 status;
	unsigned long flags;
	struct hv_input_detach_device_domain *input;
	struct pci_dev *pdev;
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);
	struct hv_iommu_endpoint *vdev = dev_iommu_priv_get(dev);

	/* See the attach function, only PCI devices for now */
	if (!dev_is_pci(dev))
		return;

	pdev = to_pci_dev(dev);

	dev_dbg(dev, "Detaching from %d\n", domain->device_domain.domain_id.id);

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = HV_PARTITION_ID_SELF;
	input->device_id = hv_build_pci_dev_id(pdev);

	status = hv_do_hypercall(HVCALL_DETACH_DEVICE_DOMAIN, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status %lld\n", __func__, status);

	vdev->domain = NULL;
}

static int hv_iommu_add_mapping(struct hv_iommu_domain *domain, unsigned long iova,
		phys_addr_t paddr, size_t size, u32 flags)
{
	unsigned long irqflags;
	struct hv_iommu_mapping *mapping;

	mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
	if (!mapping)
		return -ENOMEM;

	mapping->paddr = paddr;
	mapping->iova.start = iova;
	mapping->iova.last = iova + size - 1;
	mapping->flags = flags;

	spin_lock_irqsave(&domain->mappings_lock, irqflags);
	interval_tree_insert(&mapping->iova, &domain->mappings);
	spin_unlock_irqrestore(&domain->mappings_lock, irqflags);

	return 0;
}

static size_t hv_iommu_del_mappings(struct hv_iommu_domain *domain,
		unsigned long iova, size_t size)
{
	unsigned long flags;
	size_t unmapped = 0;
	unsigned long last = iova + size - 1;
	struct hv_iommu_mapping *mapping = NULL;
	struct interval_tree_node *node, *next;

	spin_lock_irqsave(&domain->mappings_lock, flags);
	next = interval_tree_iter_first(&domain->mappings, iova, last);
	while (next) {
		node = next;
		mapping = container_of(node, struct hv_iommu_mapping, iova);
		next = interval_tree_iter_next(node, iova, last);

		/* Trying to split a mapping? Not supported for now. */
		if (mapping->iova.start < iova)
			break;

		unmapped += mapping->iova.last - mapping->iova.start + 1;

		interval_tree_remove(node, &domain->mappings);
		kfree(mapping);
	}
	spin_unlock_irqrestore(&domain->mappings_lock, flags);

	return unmapped;
}

/* Return: must return exact status from the hypercall without changes */
static u64 hv_iommu_map_pgs(struct hv_iommu_domain *domain,
			      unsigned long iova, phys_addr_t paddr,
			      unsigned long npages, u32 map_flags)
{
	u64 status;
	int i;
	struct hv_input_map_device_gpa_pages *input;
	unsigned long flags, pfn = paddr >> HV_HYP_PAGE_SHIFT;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain = domain->device_domain;
	input->map_flags = map_flags;
	input->target_device_va_base = iova;

	pfn = paddr >> HV_HYP_PAGE_SHIFT;
	for (i = 0; i < npages; i++, pfn++)
		input->gpa_page_list[i] = pfn;

	status = hv_do_rep_hypercall(HVCALL_MAP_DEVICE_GPA_PAGES, npages, 0,
				     input, NULL);

	local_irq_restore(flags);
	return status;
}

/*
 * At present Cloud Hyp maps the entire guest ram, say 32G, into the
 * iommu. The core vfio loops over huge ranges calling this function with
 * the largest size from HV_IOMMU_PGSIZES. cond_resched() in vfio_iommu_map.
 */
static int hv_iommu_map(struct iommu_domain *d, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	u32 map_flags;
	unsigned long npages, done = 0;
	int ret;
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);
	u64 status;

	/* Reject size that's not a whole page */
	if (size & ~HV_HYP_PAGE_MASK)
		return -EINVAL;

	map_flags = HV_MAP_GPA_READABLE; /* Always required */
	map_flags |= prot & IOMMU_WRITE ? HV_MAP_GPA_WRITABLE : 0;

	ret = hv_iommu_add_mapping(domain, iova, paddr, size, map_flags);
	if (ret)
		return ret;

	npages = size >> HV_HYP_PAGE_SHIFT;
	while (done < npages) {
		ulong completed, remain = npages - done;

		status = hv_iommu_map_pgs(domain, iova, paddr, remain,
					  map_flags);

		completed = hv_repcomp(status);
		done = done + completed;
		iova = iova + (completed << HV_HYP_PAGE_SHIFT);
		paddr = paddr + (completed << HV_HYP_PAGE_SHIFT);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			status = hv_call_deposit_pages(NUMA_NO_NODE,
						       hv_current_partition_id,
						       256);
			if (!hv_result_success(status)) {
				pr_err("iommu map deposit failed: %llx\n",
				       status);
				break;
			}
		}
		if (!hv_result_success(status))
			break;
	}

	if (!hv_result_success(status)) {
		pr_err("%s: iommu map failed. pgs:%lx/%lx iova:%lx st:%llx\n",
		       __func__, done, npages, iova, status);

		size = done << HV_HYP_PAGE_SHIFT;

		/* following will call hv_iommu_del_mappings() */
		hv_iommu_unmap(d, iova - size, size, NULL);
	}

	return hv_status_to_errno(status);
}

static size_t hv_iommu_unmap(struct iommu_domain *d, unsigned long iova,
			   size_t size, struct iommu_iotlb_gather *gather)
{
	size_t unmapped;
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);
	unsigned long flags, npages;
	struct hv_input_unmap_device_gpa_pages *input;
	u64 status;

	unmapped = hv_iommu_del_mappings(domain, iova, size);
	if (unmapped < size)
		return 0;

	npages = size >> HV_HYP_PAGE_SHIFT;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain = domain->device_domain;
	input->target_device_va_base = iova;

	/* Unmap `npages` pages starting from VA base */
	status = hv_do_rep_hypercall(HVCALL_UNMAP_DEVICE_GPA_PAGES, npages,
			0, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status %lld\n", __func__, status);

	return hv_result_success(status) ? unmapped : 0;
}

static phys_addr_t hv_iommu_iova_to_phys(struct iommu_domain *d,
				       dma_addr_t iova)
{
	u64 paddr = 0;
	unsigned long flags;
	struct hv_iommu_mapping *mapping;
	struct interval_tree_node *node;
	struct hv_iommu_domain *domain = to_hv_iommu_domain(d);

	spin_lock_irqsave(&domain->mappings_lock, flags);
	node = interval_tree_iter_first(&domain->mappings, iova, iova);
	if (node) {
		mapping = container_of(node, struct hv_iommu_mapping, iova);
		paddr = mapping->paddr + (iova - mapping->iova.start);
	}
	spin_unlock_irqrestore(&domain->mappings_lock, flags);

	return paddr;
}

static struct iommu_device *hv_iommu_probe_device(struct device *dev)
{
	struct hv_iommu_endpoint *vdev;

	if (!dev_is_pci(dev))
		return ERR_PTR(-ENODEV);

	/*
	 * Skip the PCI device specified in `pci_devs_to_skip`. This is a
	 * temporary solution until we figure out a way to extract information
	 * from the hypervisor what devices it is already using.
	 */
	if (pci_devs_to_skip && *pci_devs_to_skip) {
		int pos = 0;
		int parsed;
		int segment, bus, slot, func;
		struct pci_dev *pdev = to_pci_dev(dev);

		do {
			parsed = 0;

			sscanf(pci_devs_to_skip + pos,
				" (%x:%x:%x.%x) %n",
				&segment, &bus, &slot, &func, &parsed);

			if (parsed <= 0)
				break;

			if (pci_domain_nr(pdev->bus) == segment &&
				pdev->bus->number == bus &&
				PCI_SLOT(pdev->devfn) == slot &&
				PCI_FUNC(pdev->devfn) == func)
			{
				dev_info(dev, "skipped by MSHV IOMMU\n");
				return ERR_PTR(-ENODEV);
			}

			pos += parsed;

		} while (pci_devs_to_skip[pos]);
	}

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return ERR_PTR(-ENOMEM);

	vdev->dev = dev;
	vdev->hv_iommu = hv_iommu_device;
	dev_iommu_priv_set(dev, vdev);

	return &vdev->hv_iommu->iommu;
}

static void hv_iommu_probe_finalize(struct device *dev)
{
	struct iommu_domain *d = iommu_get_domain_for_dev(dev);

	if (d && d->type == IOMMU_DOMAIN_DMA)
		iommu_setup_dma_ops(dev, 1 << PAGE_SHIFT, 0);
	else
		set_dma_ops(dev, NULL);
}

static void hv_iommu_release_device(struct device *dev)
{
	struct hv_iommu_endpoint *vdev = dev_iommu_priv_get(dev);

	/* Need to detach device from device domain if necessary. */
	if (vdev->domain)
		hv_iommu_detach_dev(&vdev->domain->domain, dev);

	dev_iommu_priv_set(dev, NULL);
	set_dma_ops(dev, NULL);

	kfree(vdev);
}

static struct iommu_group *hv_iommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	else
		return generic_device_group(dev);
}

/*
 * This bitmap is used to advertise the page sizes our hardware support to the
 * IOMMU core, which will then use this information to split physically
 * contiguous memory regions it is mapping into page sizes that we support.
 *
 * Given the size of the PFN array we can accommodate less than 512 4KiB pages.
 */
#define HV_IOMMU_PGSIZES (SZ_4K | SZ_1M)

static void hv_iommu_get_resv_regions(struct device *dev,
		struct list_head *head)
{
	switch (hw_iommu_type) {
	case INTEL:
		intel_iommu_get_resv_regions(dev, head);
		break;
	default:
		/* Do nothing */;
	}
}

static int hv_iommu_def_domain_type(struct device *dev)
{
	/* The hypervisor has created a default passthrough domain */
	return IOMMU_DOMAIN_IDENTITY;
}

static struct iommu_ops hv_iommu_ops = {
	.domain_alloc       = hv_iommu_domain_alloc,
	.probe_device       = hv_iommu_probe_device,
	.probe_finalize     = hv_iommu_probe_finalize,
	.release_device     = hv_iommu_release_device,
	.def_domain_type    = hv_iommu_def_domain_type,
	.device_group       = hv_iommu_device_group,
	.get_resv_regions   = hv_iommu_get_resv_regions,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.attach_dev = hv_iommu_attach_dev,
		.map          = hv_iommu_map,
		.unmap        = hv_iommu_unmap,
		.iova_to_phys = hv_iommu_iova_to_phys,
		.free         = hv_iommu_domain_free,
	},
	.pgsize_bitmap      = HV_IOMMU_PGSIZES,
	.owner              = THIS_MODULE,
};

static void __init hv_initalize_resv_regions_intel(void)
{
	int ret;

	down_write(&dmar_global_lock);
	if (dmar_table_init(false, true)) {
		pr_err("Failed to initialize DMAR table\n");
		up_write(&dmar_global_lock);
		return;
	}

	ret = dmar_dev_scope_init();
	if (ret)
		pr_err("Failed to initialize device scope\n");

	up_write(&dmar_global_lock);

	hw_iommu_type = INTEL;
}

static void __init hv_initialize_resv_regions(void)
{
	hv_initalize_resv_regions_intel();
}

int __init hv_iommu_init(void)
{
	int ret = 0;
	struct hv_iommu_dev *hv_iommu = NULL;

	if (!hv_is_hyperv_initialized())
		return -ENODEV;

	hv_initialize_resv_regions();

	hv_iommu = kzalloc(sizeof(*hv_iommu), GFP_KERNEL);
	if (!hv_iommu)
		return -ENOMEM;

	ida_init(&hv_iommu->domain_ids);
	hv_iommu->first_domain = HV_DEVICE_DOMAIN_ID_S2_DEFAULT + 1;
	hv_iommu->last_domain = HV_DEVICE_DOMAIN_ID_S2_NULL - 1;

	hv_iommu->geometry = (struct iommu_domain_geometry) {
		.aperture_start = 0,
		.aperture_end = -1UL,
		.force_aperture = true,
	};

	hv_iommu->map_flags = IOMMU_READ | IOMMU_WRITE;
	hv_iommu->pgsize_bitmap = HV_IOMMU_PGSIZES;

	ret = iommu_device_sysfs_add(&hv_iommu->iommu, NULL, NULL, "%s", "hv-iommu");
	if (ret) {
		pr_err("iommu_device_sysfs_add failed: %d\n", ret);
		goto err_free;
	}

	/* This must come before bus_set_iommu because it calls into the hooks. */
	hv_iommu_device = hv_iommu;
	hv_initialize_special_domains();

	ret = iommu_device_register(&hv_iommu->iommu, &hv_iommu_ops, NULL);
	if (ret) {
		pr_err("iommu_device_register failed: %d\n", ret);
		goto err_sysfs_remove;
	}
	pr_info("Microsoft Hypervisor IOMMU initialized\n");

	return 0;

err_sysfs_remove:
	iommu_device_sysfs_remove(&hv_iommu->iommu);
err_free:
	kfree(hv_iommu);
	return ret;
}

void __init hv_iommu_detect(void)
{
	if (!(ms_hyperv.misc_features & HV_DEVICE_DOMAIN_AVAILABLE))
		return;

	iommu_detected = 1;
	x86_init.iommu.iommu_init = hv_iommu_init;

	pci_request_acs();

	return;
}

#endif /* CONFIG_HYPERV_ROOT_PVIOMMU */
