// SPDX-License-Identifier: GPL-2.0

/*
 * Irqdomain for Linux to run as the root partition on Microsoft Hypervisor.
 *
 * Authors:
 * 	Anirudh Rayabharam (Microsoft) <anirudh@anirudhrb.com>
 *  Souradeep Chakrabarti <schakrabarti@microsoft.com>
 */

#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/acpi.h>
#include <asm/mshyperv.h>

#include "irq-gic-common.h"

static int hv_map_interrupt_hcall(u64 ptid, union hv_device_id device_id,
				  bool level, int cpu, int vector,
				  struct hv_interrupt_entry *ret_entry)
{
	struct hv_input_map_device_interrupt *input;
	struct hv_output_map_device_interrupt *output;
	struct hv_device_interrupt_descriptor *intr_desc;
	unsigned long flags;
	u64 status;
	int nr_bank, var_size;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	input->partition_id = ptid;
	input->device_id = device_id.as_uint64;

	intr_desc = &input->interrupt_descriptor;
	intr_desc->interrupt_type = HV_X64_INTERRUPT_TYPE_FIXED;
	intr_desc->vector_count = 1;
	intr_desc->target.vector = vector;

	if (level)
		intr_desc->trigger_mode = HV_INTERRUPT_TRIGGER_MODE_LEVEL;
	else
		intr_desc->trigger_mode = HV_INTERRUPT_TRIGGER_MODE_EDGE;

	intr_desc->target.vp_set.valid_bank_mask = 0;
	intr_desc->target.vp_set.format = HV_GENERIC_SET_SPARSE_4K;
	nr_bank = cpumask_to_vpset(&intr_desc->target.vp_set, cpumask_of(cpu));
	if (nr_bank < 0) {
		local_irq_restore(flags);
		pr_err("%s: unable to generate VP set\n", __func__);
		return HV_STATUS_INVALID_PARAMETER;
	}
	intr_desc->target.flags = HV_DEVICE_INTERRUPT_TARGET_PROCESSOR_SET;

	/*
	 * var-sized hypercall, var-size starts after vp_mask (thus
	 * vp_set.format does not count, but vp_set.valid_bank_mask
	 * does).
	 */
	var_size = nr_bank + 1;

	status = hv_do_rep_hypercall(HVCALL_MAP_DEVICE_INTERRUPT, 0, var_size,
				     input, output);
	*ret_entry = output->interrupt_entry;

	local_irq_restore(flags);

	return status;
}

static int hv_map_interrupt(u64 ptid, union hv_device_id device_id, bool level,
			    int cpu, int vector,
			    struct hv_interrupt_entry *ret_entry)
{
	u64 status;
	int deposit_pgs = 16;		/* don't loop forever */

	while (deposit_pgs--) {
		status = hv_map_interrupt_hcall(ptid, device_id, level, cpu,
						vector, ret_entry);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			status = hv_deposit_memory_node(NUMA_NO_NODE, ptid, status);
			if (!hv_result_success(status)) {
				pr_err("%s deposit pages failed:%llx\n",
				       __func__, status);
				break;
			}
			continue;
		}

		break;
	};

	if (!hv_result_success(status))
		pr_err("%s: hypercall failed, cpu %d, vec %d, status 0x%llx\n", __func__,
		       cpu, vector, status);

	return hv_result(status);
}

struct rid_data {
	struct pci_dev *bridge;
	u32 rid;
};

static int get_rid_cb(struct pci_dev *pdev, u16 alias, void *data)
{
	struct rid_data *rd = data;
	u8 bus = PCI_BUS_NUM(rd->rid);

	if (pdev->bus->number != bus || PCI_BUS_NUM(alias) != bus) {
		rd->bridge = pdev;
		rd->rid = alias;
	}

	return 0;
}

static u64 hv_build_devid_type_pci(struct pci_dev *pdev)
{
	int pos;
	union hv_device_id dev_id;
	struct rid_data data = {
		.bridge = NULL,
		.rid = PCI_DEVID(pdev->bus->number, pdev->devfn)
	};

	pci_for_each_dma_alias(pdev, get_rid_cb, &data);

	dev_id.as_uint64 = 0;
	dev_id.device_type = HV_DEVICE_TYPE_PCI;
	dev_id.pci.segment = pci_domain_nr(pdev->bus);

	dev_id.pci.bdf.bus = PCI_BUS_NUM(data.rid);
	dev_id.pci.bdf.device = PCI_SLOT(data.rid);
	dev_id.pci.bdf.function = PCI_FUNC(data.rid);
	dev_id.pci.source_shadow = HV_SOURCE_SHADOW_NONE;

	if (!data.bridge)
		goto out;

	/*
	 * Microsoft Hypervisor requires a bus range when the bridge is
	 * running in PCI-X mode.
	 *
	 * To distinguish conventional vs PCI-X bridge, we can check
	 * the bridge's PCI-X Secondary Status Register, Secondary Bus
	 * Mode and Frequency bits. See PCI Express to PCI/PCI-X Bridge
	 * Specification Revision 1.0 5.2.2.1.3.
	 *
	 * Value zero means it is in conventional mode, otherwise it is
	 * in PCI-X mode.
	 */

	pos = pci_find_capability(data.bridge, PCI_CAP_ID_PCIX);
	if (pos) {
		u16 status;

		pci_read_config_word(data.bridge, pos + PCI_X_BRIDGE_SSTATUS,
				     &status);

		if (status & PCI_X_SSTATUS_FREQ) {
			/* Non-zero, PCI-X mode */
			u8 sec_bus, sub_bus;

			dev_id.pci.source_shadow =
					      HV_SOURCE_SHADOW_BRIDGE_BUS_RANGE;
			pci_read_config_byte(data.bridge, PCI_SECONDARY_BUS,
					     &sec_bus);
			dev_id.pci.shadow_bus_range.secondary_bus = sec_bus;
			pci_read_config_byte(data.bridge, PCI_SUBORDINATE_BUS,
					     &sub_bus);
			dev_id.pci.shadow_bus_range.subordinate_bus = sub_bus;
		}
	}

out:
	return dev_id.as_uint64;
}

/* Build device id for direct attached devices */
static u64 hv_build_devid_type_logical(struct pci_dev *pdev)
{
	hv_pci_segment segment;
	union hv_device_id hv_devid;
	union hv_pci_bdf bdf = {.as_uint16 = 0};
	struct rid_data data = {
		.bridge = NULL,
		.rid = PCI_DEVID(pdev->bus->number, pdev->devfn)
	};

	segment = pci_domain_nr(pdev->bus);
	bdf.bus = PCI_BUS_NUM(data.rid);
	bdf.device = PCI_SLOT(data.rid);
	bdf.function = PCI_FUNC(data.rid);

	hv_devid.as_uint64 = 0;
	hv_devid.device_type = HV_DEVICE_TYPE_LOGICAL;
	hv_devid.logical.id = (u64)segment << 16 | bdf.as_uint16;

	return hv_devid.as_uint64;
}

/*
 * Build device id after the device has been attached.
 *
 * NB: 6.18 already provides a generic hv_build_devid_oftype() (built on x86 via
 * CONFIG_HYPERV_IOMMU, and on arm64 via CONFIG_HYPERV_IOMMU_ARM). That generic
 * builder returns 0 for the HV_DEVICE_TYPE_PCI path on non-x86, so keep a
 * file-local implementation here for the arm64 root partition that also builds
 * the PCI device id.
 */
static u64 hv_pci_build_devid_oftype(struct pci_dev *pdev,
				     enum hv_device_type type)
{
	if (type == HV_DEVICE_TYPE_LOGICAL) {
		if (hv_l1vh_partition())
			return hv_pci_vmbus_device_id(pdev);
		else
			return hv_build_devid_type_logical(pdev);
	} else if (type == HV_DEVICE_TYPE_PCI)
		return hv_build_devid_type_pci(pdev);

	return 0;
}

/* Build device id for the interrupt path */
static u64 hv_build_irq_devid(struct pci_dev *pdev)
{
	enum hv_device_type dev_type;

	if (hv_pcidev_is_attached_dev(pdev) || hv_l1vh_partition())
		dev_type = HV_DEVICE_TYPE_LOGICAL;
	else
		dev_type = HV_DEVICE_TYPE_PCI;

	return hv_pci_build_devid_oftype(pdev, dev_type);
}

/**
 * hv_map_msi_interrupt() - "Map" the MSI IRQ in the hypervisor.
 * @data:      Describes the IRQ
 * @out_entry: Hypervisor (MSI) interrupt entry (can be NULL)
 *
 * Map the IRQ in the hypervisor by issuing a MAP_DEVICE_INTERRUPT hypercall.
 */
int hv_map_msi_interrupt(struct irq_data *data,
			 struct hv_interrupt_entry *out_entry)
{
	struct msi_desc *msidesc;
	struct pci_dev *pdev;
	union hv_device_id hv_devid;
	struct hv_interrupt_entry dummy;
	int vector = data->parent_data->hwirq;
	const cpumask_t *affinity;
	int cpu;
	u64 res, ptid;

	msidesc = irq_data_get_msi_desc(data);
	pdev = msi_desc_to_pci_dev(msidesc);
	affinity = irq_data_get_effective_affinity_mask(data);
	cpu = cpumask_first_and(affinity, cpu_online_mask);
	hv_devid.as_uint64 = hv_build_irq_devid(pdev);

	/*
	 * For a passthrough (attached) device the interrupt must be mapped in
	 * the guest partition that owns it; fetch that partition id from the
	 * iommu driver. Devices owned by the root/L1VH dom0 itself use the
	 * current (root) partition id.
	 */
	if (hv_devid.device_type == HV_DEVICE_TYPE_LOGICAL &&
	    hv_pcidev_is_attached_dev(pdev))
		ptid = hv_get_current_partid();
	else
		ptid = hv_current_partition_id;

	/* prints error in case of failure */
	res = hv_map_interrupt(ptid, hv_devid, false, cpu, vector,
			       out_entry ? out_entry : &dummy);

	return hv_result_to_errno(res);
}
EXPORT_SYMBOL_GPL(hv_map_msi_interrupt);

static void entry_to_msi_msg(struct hv_interrupt_entry *hvirqe,
			     struct msi_msg *msi)
{
	/* High address is always 0 */
	msi->address_hi = upper_32_bits(hvirqe->msi_entry.address);
	msi->address_lo = lower_32_bits(hvirqe->msi_entry.address);
	msi->data = hvirqe->msi_entry.data;
}

static int hv_unmap_interrupt(union hv_device_id hv_devid,
			      struct hv_interrupt_entry *hvirqe)
{
	unsigned long flags;
	struct hv_input_unmap_device_interrupt *input;
	struct hv_interrupt_entry *intr_entry;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	memset(input, 0, sizeof(*input));

	if (hv_devid.device_type == HV_DEVICE_TYPE_LOGICAL) {
		u64 ptid = hv_get_current_partid();

		/*
		 * During cleanup the VMM process is dead and mshv has already
		 * removed its pid->partid mapping. Fall back to the root
		 * partition id; the hypervisor still tracks the mapping by
		 * device_id + interrupt_entry, so this lets the unmap succeed
		 * and prevents per-vector leaks that later return
		 * HV_STATUS_OBJECT_IN_USE on remap.
		 */
		input->partition_id = (ptid == HV_PARTITION_ID_INVALID) ?
				      hv_current_partition_id : ptid;
	} else {
		input->partition_id = hv_current_partition_id;
	}

	input->device_id = hv_devid.as_uint64;
	intr_entry = &input->interrupt_entry;
	*intr_entry = *hvirqe;

	status = hv_do_hypercall(HVCALL_UNMAP_DEVICE_INTERRUPT, input, NULL);
	local_irq_restore(flags);

	return hv_result(status);
}

int hv_unmap_msi_interrupt(struct pci_dev *pdev,
	struct hv_interrupt_entry *hvirqe)
{
	union hv_device_id hv_devid;

	hv_devid.as_uint64 = hv_build_irq_devid(pdev);

	return hv_unmap_interrupt(hv_devid, hvirqe);
}

void hv_irq_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct msi_desc *msidesc;
	struct pci_dev *pdev;
	struct hv_interrupt_entry *stored_entry;
	u64 status;

	msidesc = irq_data_get_msi_desc(data);
	pdev = msi_desc_to_pci_dev(msidesc);

	if (data->chip_data) {
		/*
		 * This interrupt is already mapped. Let's unmap first.
		 *
		 * We don't use retarget interrupt hypercalls here because
		 * Microsoft Hypervisor doesn't allow root to change the vector
		 * or specify VPs outside of the set that is initially used
		 * during mapping.
		 */
		stored_entry = data->chip_data;
		data->chip_data = NULL;

		status = hv_unmap_msi_interrupt(pdev, stored_entry);

		kfree(stored_entry);

		if (status != HV_STATUS_SUCCESS) {
			pr_err("%s: failed to unmap, status 0x%llx\n", __func__,
			       status);
			return;
		}
	}

	stored_entry = kzalloc(sizeof(*stored_entry), GFP_ATOMIC);
	if (!stored_entry) {
		pr_err("%s: failed to allocate chip data\n", __func__);
		return;
	}

	status = hv_map_msi_interrupt(data, stored_entry);
	if (status != HV_STATUS_SUCCESS) {
		pr_info("%s: failed to map msi interrupt, status 0x%llx\n", __func__,
			status);
		kfree(stored_entry);
		return;
	}

	data->chip_data = stored_entry;
	entry_to_msi_msg(data->chip_data, msg);
}
EXPORT_SYMBOL_GPL(hv_irq_compose_msi_msg);

/* NB: during map, hv_interrupt_entry is saved via data->chip_data */
static void hv_teardown_msi_irq(struct pci_dev *pdev, struct irq_data *irqd)
{
	struct hv_interrupt_entry old_entry;
	u64 status;

	if (!irqd->chip_data)
		return;

	old_entry = *(struct hv_interrupt_entry *)irqd->chip_data;

	kfree(irqd->chip_data);
	irqd->chip_data = NULL;

	status = hv_unmap_msi_interrupt(pdev, &old_entry);

	if (status != HV_STATUS_SUCCESS)
		pr_err("%s: hypercall failed, status:0x%llx irq:%d\n",
		       __func__, status, irqd->irq);
}

static void hv_msi_free_irq(struct irq_domain *domain,
			    struct msi_domain_info *info, unsigned int virq)
{
	struct irq_data *irqd = irq_get_irq_data(virq);
	struct msi_desc *desc;

	if (!irqd)
		return;

	desc = irq_data_get_msi_desc(irqd);
	if (!desc || !desc->irq || WARN_ON_ONCE(!dev_is_pci(desc->dev)))
		return;

	hv_teardown_msi_irq(to_pci_dev(desc->dev), irqd);
}

static int hv_irq_set_affinity(struct irq_data *irqd, const struct cpumask *mask,
			       bool force)
{
	int cpu = cpumask_first(mask);

	irq_data_update_effective_affinity(irqd, cpumask_of(cpu));
	return IRQ_SET_MASK_OK_DONE;
}

static void hv_irq_unmask(struct irq_data *irqd)
{
	struct rdists *rdists;
	void *va;
	u8 *cfg;
	const struct cpumask *aff;
	int cpu;

	aff = irq_data_get_effective_affinity_mask(irqd);
	cpu = cpumask_first(aff);

	rdists = gic_get_rdists();
	va = rdists->prop_table_va;

	cfg = va + irqd->parent_data->hwirq - 8192;
	*cfg |= LPI_PROP_ENABLED | LPI_PROP_GROUP1;

	if (rdists->flags & RDIST_FLAGS_PROPBASE_NEEDS_FLUSHING)
		gic_flush_dcache_to_poc(cfg, sizeof(*cfg));
	else
		dsb(ishst);

	gic_write_lpir(0, per_cpu_ptr(rdists->rdist, cpu)->rd_base + GICR_INVALLR);

	pci_msi_unmask_irq(irqd);
}

/*
 * Stub used as the irqchip .irq_compose_msi_msg callback so that the MSI/MSI-X
 * allocation path (e.g. vfio-pci enable) does NOT issue a
 * HVCALL_MAP_DEVICE_INTERRUPT for passthrough devices. On root the correct
 * guest partition_id / vector / vCPU set are only known later, at mshv
 * irqfd-assign time, where mshv_map_interrupt() calls the real
 * hv_irq_compose_msi_msg().
 */
static void hv_irq_compose_msi_msg_stub(struct irq_data *data,
					struct msi_msg *msg)
{
	struct msi_desc *msidesc = irq_data_get_msi_desc(data);
	struct pci_dev *pdev = msi_desc_to_pci_dev(msidesc);

	/*
	 * For VFIO-passthrough devices (in an attached_dom domain), defer the
	 * MAP to mshv_map_interrupt(), which fires at irqfd-assign time with
	 * the guest's vector / target partid. Return a zero msi_msg here --
	 * mshv will overwrite it via pci_write_msi_msg().
	 *
	 * For host-owned devices (dom0's own NVMe etc.), do the normal MAP so
	 * the kernel programs valid MSI-X entries.
	 */
	if (pdev && hv_pcidev_is_attached_dev(pdev)) {
		memset(msg, 0, sizeof(*msg));
		return;
	}

	hv_irq_compose_msi_msg(data, msg);
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip hv_pci_msi_controller = {
	.name			= "HV-PCI-MSI",
	.irq_unmask		= hv_irq_unmask,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_compose_msi_msg	= hv_irq_compose_msi_msg_stub,
	.irq_set_affinity	= hv_irq_set_affinity,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static struct msi_domain_ops pci_msi_domain_ops = {
	.msi_free		= hv_msi_free_irq,
};

static struct msi_domain_info hv_pci_msi_domain_info = {
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_PCI_MSIX,
	.ops		= &pci_msi_domain_ops,
	.chip		= &hv_pci_msi_controller,
};

#define HV_PCI_MSI_LPI_START	0x2000
#define HV_PCI_MSI_LPI_NR	(1U << 16)

struct hv_pci_chip_data {
	DECLARE_BITMAP(spi_map, HV_PCI_MSI_LPI_NR);
	struct mutex	map_lock;
};

/*
 * @nr_bm_irqs:		Indicates the number of IRQs that were allocated from
 *			the bitmap.
 * @nr_dom_irqs:	Indicates the number of IRQs that were allocated from
 *			the parent domain.
 */
static void hv_pci_vec_irq_free(struct irq_domain *domain,
				unsigned int virq,
				unsigned int nr_bm_irqs,
				unsigned int nr_dom_irqs)
{
	struct hv_pci_chip_data *chip_data = domain->host_data;
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	int first = d->hwirq - HV_PCI_MSI_LPI_START;
	int i;

	mutex_lock(&chip_data->map_lock);
	bitmap_release_region(chip_data->spi_map,
			      first,
			      get_count_order(nr_bm_irqs));
	mutex_unlock(&chip_data->map_lock);
	for (i = 0; i < nr_dom_irqs; i++) {
		if (i)
			d = irq_domain_get_irq_data(domain, virq + i);
		irq_domain_reset_irq_data(d);
	}

	irq_domain_free_irqs_parent(domain, virq, nr_dom_irqs);
}

static void hv_pci_vec_irq_domain_free(struct irq_domain *domain,
				       unsigned int virq,
				       unsigned int nr_irqs)
{
	hv_pci_vec_irq_free(domain, virq, nr_irqs, nr_irqs);
}

static int hv_pci_vec_alloc_device_irq(struct irq_domain *domain,
				       unsigned int nr_irqs,
				       irq_hw_number_t *hwirq)
{
	struct hv_pci_chip_data *chip_data = domain->host_data;
	int index;

	/* Find and allocate region from the SPI bitmap */
	mutex_lock(&chip_data->map_lock);
	index = bitmap_find_free_region(chip_data->spi_map,
					HV_PCI_MSI_LPI_NR,
					get_count_order(nr_irqs));
	mutex_unlock(&chip_data->map_lock);
	if (index < 0)
		return -ENOSPC;

	*hwirq = index + HV_PCI_MSI_LPI_START;

	return 0;
}

static int hv_pci_vec_irq_gic_domain_alloc(struct irq_domain *domain,
					   unsigned int virq,
					   irq_hw_number_t hwirq)
{
	struct irq_fwspec fwspec;

	fwspec.fwnode = domain->parent->fwnode;
	fwspec.param_count = 2;
	fwspec.param[0] = hwirq;
	fwspec.param[1] = IRQ_TYPE_EDGE_RISING;

	return irq_domain_alloc_irqs_parent(domain, virq, 1, &fwspec);
}

static int hv_pci_vec_irq_domain_alloc(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs,
				       void *args)
{
	irq_hw_number_t hwirq;
	unsigned int i;
	int ret;

	ret = hv_pci_vec_alloc_device_irq(domain, nr_irqs, &hwirq);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = hv_pci_vec_irq_gic_domain_alloc(domain, virq + i,
						      hwirq + i);
		if (ret) {
			hv_pci_vec_irq_free(domain, virq, nr_irqs, i);
			return ret;
		}

		irq_domain_set_hwirq_and_chip(domain, virq + i,
					      hwirq + i,
					      &hv_pci_msi_controller,
					      domain->host_data);
	}

	return 0;
}

/*
 * Pick the first cpu as the irq affinity that can be temporarily used for
 * composing MSI from the hypervisor. GIC will eventually set the right
 * affinity for the irq and the 'unmask' will retarget the interrupt to that
 * cpu.
 */
static int hv_pci_vec_irq_domain_activate(struct irq_domain *domain,
					  struct irq_data *irqd, bool reserve)
{
	int cpu = cpumask_first(cpu_present_mask);

	irq_data_update_effective_affinity(irqd, cpumask_of(cpu));

	return 0;
}

static const struct irq_domain_ops hv_pci_domain_ops = {
	.alloc	= hv_pci_vec_irq_domain_alloc,
	.free	= hv_pci_vec_irq_domain_free,
	.activate = hv_pci_vec_irq_domain_activate,
};

struct irq_domain *hv_pci_msi_domain;

static struct irq_domain * __init hv_create_pci_msi_domain(struct irq_domain *parent)
{
	struct irq_domain *hv_msi_gic_irq_domain = NULL;
	struct irq_domain *d = NULL;
	struct fwnode_handle *fn;
	struct hv_pci_chip_data *chip_data;

	chip_data = kzalloc(sizeof(*chip_data), GFP_KERNEL);
	BUG_ON(!chip_data);

	fn = irq_domain_alloc_named_fwnode("HV-PCI-MSI");
	BUG_ON(!fn);

	hv_msi_gic_irq_domain = acpi_irq_create_hierarchy(0, HV_PCI_MSI_LPI_NR,
			fn, &hv_pci_domain_ops, chip_data);

	BUG_ON(!hv_msi_gic_irq_domain);

	d = pci_msi_create_irq_domain(fn, &hv_pci_msi_domain_info,
		hv_msi_gic_irq_domain);

	/* No point in going further if we can't get an irq domain */
	BUG_ON(!d);

	return d;
}

static int __init hv_pci_msi_init(void)
{
	/*
	 * Only the Microsoft Hypervisor root partition owns the PCI MSI
	 * irqdomain. On bare metal (no MSHV) hyperv_pcpu_input_arg is never
	 * set up, so installing the Hyper-V MSI chip will cause panic.
	 */
	if (!hv_root_partition())
		return 0;

	hv_pci_msi_domain = hv_create_pci_msi_domain(NULL);
	BUG_ON(!hv_pci_msi_domain);

	return 0;
}

early_initcall(hv_pci_msi_init);

/*
 * Microsoft Hypervisor does not present an ITS to the root partition, but PCI
 * MSIs are still delivered as LPIs once mapped via hypercall. Tell the GICv3
 * driver to set up the redistributor LPI tables even though no ITS will be
 * enumerated.
 *
 * This has to run before irqchip_init(), so it cannot be an initcall.
 */
void __init hv_pci_msi_early_init(void)
{
	if (!hv_root_partition())
		return;

	gic_request_lpis_without_its();
}
