// SPDX-License-Identifier: GPL-2.0

/*
 * Hyper-V stub IOMMU driver.
 *
 * Copyright (C) 2024, Microsoft, Inc.
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
					    0, IOAPIC_REMAPPING_ENTRY, fn,
					    ops, NULL);

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
			pr_debug("%s: unexpected unmap status 0x%llx\n",
				 __func__, status);

		data->entry.ioapic_rte.as_uint64 = 0;
		data->entry.source = 0; /* Invalid source */
	}


	status = hv_map_ioapic_interrupt(ioapic_id, data->is_level, cpu,
					vector, &entry);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: map hypercall failed, status 0x%llx\n", __func__,
		       status);
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

static int hyperv_root_irq_remapping_alloc(struct irq_domain *irqdom,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	struct irq_alloc_info *info = arg;
	struct irq_data *irq_data;
	struct hyperv_root_ir_data *data;
	int ret = 0;

	if (!info || info->type != X86_IRQ_ALLOC_TYPE_IOAPIC || nr_irqs > 1)
		return -EINVAL;

	ret = irq_domain_alloc_irqs_parent(irqdom, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		irq_domain_free_irqs_common(irqdom, virq, nr_irqs);
		return -ENOMEM;
	}

	irq_data = irq_domain_get_irq_data(irqdom, virq);
	if (!irq_data) {
		kfree(data);
		irq_domain_free_irqs_common(irqdom, virq, nr_irqs);
		return -EINVAL;
	}

	data->ioapic_id = info->devid;
	data->is_level = info->ioapic.is_level;

	irq_data->chip = &hyperv_root_ir_chip;
	irq_data->chip_data = data;

	return 0;
}

static void hyperv_root_irq_remapping_free(struct irq_domain *irqdom,
				 unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *irq_data;
	struct hyperv_root_ir_data *data;
	struct hv_interrupt_entry *e;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(irqdom, virq + i);

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

	irq_domain_free_irqs_common(irqdom, virq, nr_irqs);
}

static const struct irq_domain_ops hyperv_root_ir_domain_ops = {
	.select = hyperv_irq_remapping_select,
	.alloc = hyperv_root_irq_remapping_alloc,
	.free = hyperv_root_irq_remapping_free,
};

#endif

#ifdef CONFIG_HYPERV_ROOT_PVIOMMU

static void hv_iommu_detach_dev(struct iommu_domain *immdom,
				struct device *dev);
static size_t hv_iommu_unmap(struct iommu_domain *d, unsigned long iova,
			    size_t size, struct iommu_iotlb_gather *gather);

/* The IOMMU will not claim these PCI devices. */
static char *pci_devs_to_skip;
static int __init hv_iommu_setup_skip(char *str)
{
	pci_devs_to_skip = str;

	return 0;
}
/* hv_iommu_skip=(SSSS:BB:DD.F)(SSSS:BB:DD.F) */
__setup("hv_iommu_skip=", hv_iommu_setup_skip);

/* iommu device that we export to the world. HyperV supports one device only */
static struct iommu_device hv_virt_iommu;

struct hv_domain {
	struct iommu_domain iommu_dom;
	u32 domid_num;			      /* as opposed to domain_id.type */
	spinlock_t mappings_lock;	      /* protects mappings_tree */
	struct rb_root_cached mappings_tree;  /* iova to pa interval tree */
};

#define to_hv_domain(d) container_of(d, struct hv_domain, iommu_dom)

/*
 * At present, hyperv supports stage 2 domain types. Stage 2 means that the
 * page table is controlled by the hypervisor. By default, two special S2
 * type domains are precreated during boot in the hypervisor:
 *    S2 default: access to entire root partition memory. This for us easily
 *		  maps to IOMMU_DOMAIN_IDENTITY in the iommu subsystem, and
 *		  is called HV_DEVICE_DOMAIN_ID_S2_DEFAULT in the hypervisor.
 *    S2 NULL: Block all DMAs except for RMRR
 *
 * L1VH: hypervisor does not support S2 or other domains. Only direct attach.
 */

/*
 * Create 2 dummy domains to correspond to hypervisor prebuilt domains (dummy
 * because we do not hcall create them): default identiy domain and null domain
 */
static struct hv_domain hv_def_identity_dom, hv_null_dom;

static bool hv_special_domain(struct hv_domain *hvdom)
{
	return hvdom == &hv_def_identity_dom || hvdom == &hv_null_dom;
}

struct iommu_domain_geometry default_geometry = (struct iommu_domain_geometry) {
	.aperture_start = 0,
	.aperture_end = -1UL,
	.force_aperture = true,
};

static u32 unique_id;	      /* unique numeric id of a new domain */

/*
 * We are required to report the contiguous ram chunks or page sizes (.map vs
 * .map_pages in iommu_ops) that our virtual iommu device can handle. Since the
 * relevant hypercalls can only fit less than 512 PFNs in the pfn array, we
 * report 1M max.
 */
#define HV_IOMMU_PGSIZES (SZ_4K | SZ_1M)

struct hv_iommu_mapping {
	phys_addr_t paddr;
	struct interval_tree_node iova;
	u32 flags;
};


/*
 * If the current thread is a VMM thread, return the partition id of the vm it
 * is managing, other wise return HV_PARTITION_ID_INVALID.
 */
u64 hv_iommu_get_curr_partid(void)
{
	u64 (*fn)(pid_t pid);
	u64 partid;

	fn = symbol_get(mshv_pid_to_partid);
	if (!fn)
		return HV_PARTITION_ID_INVALID;

	partid = fn(current->tgid);
	symbol_put(mshv_pid_to_partid);

	return partid;

}

/* If this is a VMM thread, then this domain is for a guest vm */
static bool hv_curr_thread_is_vmm(void)
{
	return hv_iommu_get_curr_partid() != HV_PARTITION_ID_INVALID;
}

static bool hv_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;

	default:
		return false;
	}
}

/*
 * Check if given pci device is a direct attached device. caller must have
 * verified pdev is a valid pci device
 */
bool hv_pcidev_is_attached_dev(struct pci_dev *pdev)
{
	return false;
}
EXPORT_SYMBOL_GPL(hv_pcidev_is_attached_dev);

/* Create a new device domain in the hypervisor */
static int hv_iommu_create_hyp_devdom(struct hv_domain *hvdom)
{
	u64 status;
	unsigned long flags;
	struct hv_input_device_domain *ddp;
	struct hv_input_create_device_domain *input;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	ddp = &input->device_domain;
	ddp->partition_id = HV_PARTITION_ID_SELF;
	ddp->domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	ddp->domain_id.id = hvdom->domid_num;

	input->create_device_domain_flags.forward_progress_required = 1;
	input->create_device_domain_flags.inherit_owning_vtl = 0;

	status = hv_do_hypercall(HVCALL_CREATE_DEVICE_DOMAIN, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status 0x%llx\n", __func__,
		       status);

	return hv_status_to_errno(status);
}

static struct iommu_domain *hv_iommu_domain_alloc(unsigned int type)
{
	struct hv_domain *hvdom;
	int rc;

	/* during boot, all devices are attached to this */
	if (type == IOMMU_DOMAIN_IDENTITY)
		return &hv_def_identity_dom.iommu_dom;

	if (type == IOMMU_DOMAIN_BLOCKED)
		return &hv_null_dom.iommu_dom;

	hvdom = kzalloc(sizeof(struct hv_domain), GFP_KERNEL);
	if (hvdom == NULL)
		goto out;

	spin_lock_init(&hvdom->mappings_lock);
	hvdom->mappings_tree = RB_ROOT_CACHED;

	if (type == IOMMU_DOMAIN_DMA && iommu_get_dma_cookie(&hvdom->iommu_dom))
		goto out_free;

	if (++unique_id == HV_DEVICE_DOMAIN_ID_S2_DEFAULT)   /* ie, 0 */
		goto out_put_cookie;

	hvdom->domid_num = unique_id;
	hvdom->iommu_dom.geometry = default_geometry;
	hvdom->iommu_dom.pgsize_bitmap = HV_IOMMU_PGSIZES;

	rc = hv_iommu_create_hyp_devdom(hvdom);
	if (rc)
		goto out_free_id;

	return &hvdom->iommu_dom;

out_free_id:
	unique_id--;
out_put_cookie:
	if (type == IOMMU_DOMAIN_DMA)
		iommu_put_dma_cookie(&hvdom->iommu_dom);
out_free:
	kfree(hvdom);
out:
	return NULL;
}

static void hv_iommu_domain_free(struct iommu_domain *immdom)
{
	struct hv_domain *hvdom = to_hv_domain(immdom);
	unsigned long flags;
	u64 status;
	struct hv_input_delete_device_domain *input;

	if (hv_special_domain(hvdom))
		return;

	if (!hv_curr_thread_is_vmm()) {
		struct hv_input_device_domain *ddp;

		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		ddp = &input->device_domain;
		memset(input, 0, sizeof(*input));

		ddp->partition_id = HV_PARTITION_ID_SELF;
		ddp->domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
		ddp->domain_id.id = hvdom->domid_num;

		status = hv_do_hypercall(HVCALL_DELETE_DEVICE_DOMAIN, input,
					 NULL);
		local_irq_restore(flags);

		if (!hv_result_success(status))
			pr_err("%s: hypercall failed, status 0x%llx\n",
			       __func__, status);
	}

	if (immdom->type == IOMMU_DOMAIN_DMA)
		iommu_put_dma_cookie(immdom);

	kfree(hvdom);
}

/* Attach a device to a domain previously created in the hypervisor */
static int hv_iommu_att_dev2dom(struct hv_domain *hvdom, struct pci_dev *pdev)
{
	unsigned long flags;
	u64 status;
	enum hv_device_type dev_type;
	struct hv_input_attach_device_domain *input;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain.partition_id = HV_PARTITION_ID_SELF;
	input->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	input->device_domain.domain_id.id = hvdom->domid_num;

	dev_type = HV_DEVICE_TYPE_PCI;
	input->device_id.as_uint64 = hv_build_devid_oftype(pdev, dev_type);

	status = hv_do_hypercall(HVCALL_ATTACH_DEVICE_DOMAIN, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status 0x%llx\n", __func__,
		       status);

	return hv_status_to_errno(status);
}


/* This to attach a device to a host app like dpdk or a hyperv guest */
static int hv_iommu_attach_dev(struct iommu_domain *immdom, struct device *dev)
{
	struct pci_dev *pdev;
	int rc, rc1;
	struct hv_domain *hvdom_new = to_hv_domain(immdom);
	struct hv_domain *hvdom_prev = dev_iommu_priv_get(dev);

	/* Only allow PCI devices for now */
	if (!dev_is_pci(dev))
		return -EINVAL;

	pdev = to_pci_dev(dev);

	/*
	 * vfio does not do explicit detach calls, hence check first if we need
	 * to detach first. Also, in case of guest shutdown, it's the vmm
	 * thread that attaches it back to the hv_def_identity_dom, and
	 * hvdom_prev will not be null then. It is null during boot.
	 */
	if (hvdom_prev)
		if (!hv_special_domain(hvdom_prev))
			hv_iommu_detach_dev(&hvdom_prev->iommu_dom, dev);

	if (hv_special_domain(hvdom_new)) {
		dev_iommu_priv_set(dev, hvdom_new);  /* sets "private" field */
		return 0;
	}

	rc = hv_iommu_att_dev2dom(hvdom_new, pdev);
	if (rc && hvdom_prev) {
		rc1 = hv_iommu_att_dev2dom(hvdom_prev, pdev);

		if (rc1)
			pr_err("Hyper-V: iommu could not restore orig device "
			       "state.. dev:%s\n", dev_name(dev));
	}

	if (rc == 0) {
		dev_iommu_priv_set(dev, hvdom_new);  /* sets "private" field */
	}

	return rc;
}

static void hv_iommu_det_dev_from_dom(struct hv_domain *hvdom,
				      struct pci_dev *pdev)
{
	u64 status, devid;
	unsigned long flags;
	struct hv_input_detach_device_domain *input;

	devid = hv_build_devid_oftype(pdev, HV_DEVICE_TYPE_PCI);

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = HV_PARTITION_ID_SELF;
	input->device_id.as_uint64 = devid;
	status = hv_do_hypercall(HVCALL_DETACH_DEVICE_DOMAIN, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status 0x%llx\n", __func__,
		       status);
}

static void hv_iommu_detach_dev(struct iommu_domain *immdom, struct device *dev)
{
	struct pci_dev *pdev;
	struct hv_domain *hvdom = to_hv_domain(immdom);

	/* See the attach function, only PCI devices for now */
	if (!dev_is_pci(dev))
		return;

	pdev = to_pci_dev(dev);

	hv_iommu_det_dev_from_dom(hvdom, pdev);
}

static int hv_iommu_add_tree_mapping(struct hv_domain *hvdom,
				     unsigned long iova, phys_addr_t paddr,
				     size_t size, u32 flags)
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

	spin_lock_irqsave(&hvdom->mappings_lock, irqflags);
	interval_tree_insert(&mapping->iova, &hvdom->mappings_tree);
	spin_unlock_irqrestore(&hvdom->mappings_lock, irqflags);

	return 0;
}

static size_t hv_iommu_del_tree_mappings(struct hv_domain *hvdom,
					unsigned long iova, size_t size)
{
	unsigned long flags;
	size_t unmapped = 0;
	unsigned long last = iova + size - 1;
	struct hv_iommu_mapping *mapping = NULL;
	struct interval_tree_node *node, *next;

	spin_lock_irqsave(&hvdom->mappings_lock, flags);
	next = interval_tree_iter_first(&hvdom->mappings_tree, iova, last);
	while (next) {
		node = next;
		mapping = container_of(node, struct hv_iommu_mapping, iova);
		next = interval_tree_iter_next(node, iova, last);

		/* Trying to split a mapping? Not supported for now. */
		if (mapping->iova.start < iova)
			break;

		unmapped += mapping->iova.last - mapping->iova.start + 1;

		interval_tree_remove(node, &hvdom->mappings_tree);
		kfree(mapping);
	}
	spin_unlock_irqrestore(&hvdom->mappings_lock, flags);

	return unmapped;
}

/* Return: must return exact status from the hypercall without changes */
static u64 hv_iommu_map_pgs(struct hv_domain *hvdom,
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

	input->device_domain.partition_id = HV_PARTITION_ID_SELF;
	input->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	input->device_domain.domain_id.id = hvdom->domid_num;
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
static int hv_iommu_map(struct iommu_domain *immdom, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	u32 map_flags;
	unsigned long npages, done = 0;
	int ret;
	struct hv_domain *hvdom = to_hv_domain(immdom);
	u64 status;

	/* Reject size that's not a whole page */
	if (size & ~HV_HYP_PAGE_MASK)
		return -EINVAL;

	map_flags = HV_MAP_GPA_READABLE; /* Always required */
	map_flags |= prot & IOMMU_WRITE ? HV_MAP_GPA_WRITABLE : 0;

	ret = hv_iommu_add_tree_mapping(hvdom, iova, paddr, size, map_flags);
	if (ret)
		return ret;

	npages = size >> HV_HYP_PAGE_SHIFT;
	while (done < npages) {
		ulong completed, remain = npages - done;

		status = hv_iommu_map_pgs(hvdom, iova, paddr, remain,
					  map_flags);

		completed = hv_repcomp(status);
		done = done + completed;
		iova = iova + (completed << HV_HYP_PAGE_SHIFT);
		paddr = paddr + (completed << HV_HYP_PAGE_SHIFT);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_call_deposit_pages(NUMA_NO_NODE,
						    hv_current_partition_id,
						    256);
			if (ret)
				break;
		}
		if (!hv_result_success(status))
			break;
	}

	if (!hv_result_success(status)) {
		size_t done_size = done << HV_HYP_PAGE_SHIFT;

		pr_err("%s: iommu map failed. pgs:%lx/%lx iova:%lx st:%llx\n",
		       __func__, done, npages, iova, status);

		/*
		 * lookup tree has all mappings [0 - size-1]. Below unmap will
		 * only remove from [0 - done], we need to remove second chunk
		 * [done+1 - size-1].
		 */
		hv_iommu_del_tree_mappings(hvdom, iova, size - done_size);
		hv_iommu_unmap(immdom, iova - done_size, done_size, NULL);
	}

	return hv_status_to_errno(status);
}

static size_t hv_iommu_unmap(struct iommu_domain *immdom, unsigned long iova,
			   size_t size, struct iommu_iotlb_gather *gather)
{
	size_t unmapped;
	struct hv_domain *hvdom = to_hv_domain(immdom);
	unsigned long flags, npages;
	struct hv_input_unmap_device_gpa_pages *input;
	u64 status;

	unmapped = hv_iommu_del_tree_mappings(hvdom, iova, size);
	if (unmapped < size)
		pr_err("%s: could not delete all mappings (%lx:%lx/%lx)\n",
		       __func__, iova, unmapped, size);

	npages = size >> HV_HYP_PAGE_SHIFT;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->device_domain.partition_id = HV_PARTITION_ID_SELF;
	input->device_domain.domain_id.type = HV_DEVICE_DOMAIN_TYPE_S2;
	input->device_domain.domain_id.id = hvdom->domid_num;
	input->target_device_va_base = iova;

	/* Unmap `npages` pages starting from VA base */
	status = hv_do_rep_hypercall(HVCALL_UNMAP_DEVICE_GPA_PAGES, npages,
				     0, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, status 0x%llx\n", __func__,
		       status);

	return hv_result_success(status) ? unmapped : 0;
}

static phys_addr_t hv_iommu_iova_to_phys(struct iommu_domain *immdom,
					 dma_addr_t iova)
{
	u64 paddr = 0;
	unsigned long flags;
	struct hv_iommu_mapping *mapping;
	struct interval_tree_node *node;
	struct hv_domain *hvdom = to_hv_domain(immdom);

	spin_lock_irqsave(&hvdom->mappings_lock, flags);
	node = interval_tree_iter_first(&hvdom->mappings_tree, iova, iova);
	if (node) {
		mapping = container_of(node, struct hv_iommu_mapping, iova);
		paddr = mapping->paddr + (iova - mapping->iova.start);
	}
	spin_unlock_irqrestore(&hvdom->mappings_lock, flags);

	return paddr;
}

static struct iommu_device *hv_iommu_probe_device(struct device *dev)
{
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

			sscanf(pci_devs_to_skip + pos, " (%x:%x:%x.%x) %n",
				&segment, &bus, &slot, &func, &parsed);

			if (parsed <= 0)
				break;

			if (pci_domain_nr(pdev->bus) == segment &&
			    pdev->bus->number == bus &&
			    PCI_SLOT(pdev->devfn) == slot &&
			    PCI_FUNC(pdev->devfn) == func) {

				dev_info(dev, "skipped by Hyper-V IOMMU\n");
				return ERR_PTR(-ENODEV);
			}

			pos += parsed;

		} while (pci_devs_to_skip[pos]);
	}

	/* device will be explicitly attached to the default domain, so no need
	 * to dev_iommu_priv_set() here */

	return &hv_virt_iommu;
}

static void hv_iommu_probe_finalize(struct device *dev)
{
	struct iommu_domain *immdom = iommu_get_domain_for_dev(dev);

	if (immdom && immdom->type == IOMMU_DOMAIN_DMA)
		iommu_setup_dma_ops(dev, 1 << PAGE_SHIFT, 0);
	else
		set_dma_ops(dev, NULL);
}

static void hv_iommu_release_device(struct device *dev)
{
	struct hv_domain *hvdom = dev_iommu_priv_get(dev);

	/* Need to detach device from device domain if necessary. */
	if (hvdom)
		hv_iommu_detach_dev(&hvdom->iommu_dom, dev);

	dev_iommu_priv_set(dev, NULL);
	set_dma_ops(dev, NULL);
}

static struct iommu_group *hv_iommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	else
		return generic_device_group(dev);
}

static void hv_iommu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	if (hv_l1vh_partition())
		return;

	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_INTEL:
		intel_iommu_get_resv_regions(dev, head);
		break;
	default:
		break;	/* Do nothing */;
	}
}

static int hv_iommu_def_domain_type(struct device *dev)
{
	/* hypervisor always creates this by default during boot */
	return IOMMU_DOMAIN_IDENTITY;
}

static struct iommu_ops hv_iommu_ops = {
	.capable	    = hv_iommu_capable,
	.domain_alloc	    = hv_iommu_domain_alloc,
	.probe_device	    = hv_iommu_probe_device,
	.probe_finalize     = hv_iommu_probe_finalize,
	.release_device     = hv_iommu_release_device,
	.def_domain_type    = hv_iommu_def_domain_type,
	.device_group	    = hv_iommu_device_group,
	.get_resv_regions   = hv_iommu_get_resv_regions,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.attach_dev   = hv_iommu_attach_dev,
		.map	      = hv_iommu_map,
		.unmap	      = hv_iommu_unmap,
		.iova_to_phys = hv_iommu_iova_to_phys,
		.free	      = hv_iommu_domain_free,
	},
	.pgsize_bitmap	    = HV_IOMMU_PGSIZES,
	.owner		    = THIS_MODULE,
};

static void __init hv_initalize_resv_regions_intel(void)
{
	int ret;

	down_write(&dmar_global_lock);
	if (dmar_table_init(false, true)) {
		pr_err("Hyper-V: Failed to initialize DMAR table\n");
		up_write(&dmar_global_lock);
		return;
	}

	ret = dmar_dev_scope_init();
	if (ret)
		pr_err("Hyper-V: Failed to initialize device scope\n");

	up_write(&dmar_global_lock);
}

static void __init hv_initialize_resv_regions(void)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		hv_initalize_resv_regions_intel();
	else
		pr_err("Hyper-V: No PV-iommu support for this platform\n");
}

static void __init hv_initialize_special_domains(void)
{
	hv_def_identity_dom.iommu_dom.geometry = default_geometry;
	hv_def_identity_dom.domid_num = HV_DEVICE_DOMAIN_ID_S2_DEFAULT;/* 0 */

	hv_null_dom.iommu_dom.geometry = default_geometry;
	hv_null_dom.domid_num = HV_DEVICE_DOMAIN_ID_S2_NULL;  /* INTMAX */
}

int __init hv_iommu_init(void)
{
	int ret;
	struct iommu_device *iommup = &hv_virt_iommu;

	if (!hv_is_hyperv_initialized())
		return -ENODEV;

	/* l1vh host does not get any bios or firmware regions */
	if (!hv_l1vh_partition())
		hv_initialize_resv_regions();

	ret = iommu_device_sysfs_add(iommup, NULL, NULL, "%s", "hyperv-iommu");
	if (ret) {
		pr_err("Hyper-V: iommu_device_sysfs_add failed: %d\n", ret);
		return ret;
	}

	/* This must come before iommu_device_register because the latter calls
	 * into the hooks */
	hv_initialize_special_domains();

	ret = iommu_device_register(iommup, &hv_iommu_ops, NULL);
	if (ret) {
		pr_err("Hyper-V: iommu_device_register failed: %d\n", ret);
		goto err_sysfs_remove;
	}

	pr_info("Hyper-V IOMMU initialized\n");

	return 0;

err_sysfs_remove:
	iommu_device_sysfs_remove(iommup);
	return ret;
}

void __init hv_iommu_detect(void)
{
	if (no_iommu || iommu_detected)
		return;

	if (!(ms_hyperv.misc_features & HV_DEVICE_DOMAIN_AVAILABLE))
		return;

	iommu_detected = 1;
	x86_init.iommu.iommu_init = hv_iommu_init;

	pci_request_acs();
}

#endif /* CONFIG_HYPERV_ROOT_PVIOMMU */
