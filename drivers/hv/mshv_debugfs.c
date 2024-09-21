// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * The /sys/kernel/debug/mshv directory contents.
 * Contains various statistics data, provided by the hypervisor.
 *
 * Authors:
 *   Stanislav Kinsburskii <skinsburskii@linux.microsoft.com>
 */

#include <linux/debugfs.h>
#include <linux/stringify.h>
#include <asm/mshyperv.h>

#include "mshv.h"
#include "mshv_root.h"

static struct dentry *mshv_debugfs;
static struct dentry *mshv_debugfs_partition;
static struct dentry *mshv_debugfs_lp;

static u64 mshv_lps_count;

static int lp_stats_show(struct seq_file *m, void *v)
{
	const struct hv_stats_page *stats = m->private;

#define LP_SEQ_PRINTF(cnt)		\
	seq_printf(m, "%-29s: %llu\n", __stringify(cnt), stats->lp_cntrs[Lp##cnt])

	LP_SEQ_PRINTF(GlobalTime);
	LP_SEQ_PRINTF(TotalRunTime);
	LP_SEQ_PRINTF(HypervisorRunTime);
	LP_SEQ_PRINTF(HardwareInterrupts);
	LP_SEQ_PRINTF(ContextSwitches);
	LP_SEQ_PRINTF(InterProcessorInterrupts);
	LP_SEQ_PRINTF(SchedulerInterrupts);
	LP_SEQ_PRINTF(TimerInterrupts);
	LP_SEQ_PRINTF(InterProcessorInterruptsSent);
	LP_SEQ_PRINTF(ProcessorHalts);
	LP_SEQ_PRINTF(MonitorTransitionCost);
	LP_SEQ_PRINTF(ContextSwitchTime);
	LP_SEQ_PRINTF(C1TransitionsCount);
	LP_SEQ_PRINTF(C1RunTime);
	LP_SEQ_PRINTF(C2TransitionsCount);
	LP_SEQ_PRINTF(C2RunTime);
	LP_SEQ_PRINTF(C3TransitionsCount);
	LP_SEQ_PRINTF(C3RunTime);
	LP_SEQ_PRINTF(RootVpIndex);
	LP_SEQ_PRINTF(IdleSequenceNumber);
	LP_SEQ_PRINTF(GlobalTscCount);
	LP_SEQ_PRINTF(ActiveTscCount);
	LP_SEQ_PRINTF(IdleAccumulation);
	LP_SEQ_PRINTF(ReferenceCycleCount0);
	LP_SEQ_PRINTF(ActualCycleCount0);
	LP_SEQ_PRINTF(ReferenceCycleCount1);
	LP_SEQ_PRINTF(ActualCycleCount1);
	LP_SEQ_PRINTF(ProximityDomainId);
	LP_SEQ_PRINTF(PostedInterruptNotifications);
	LP_SEQ_PRINTF(BranchPredictorFlushes);
#if defined(__x86_64__)
	LP_SEQ_PRINTF(L1DataCacheFlushes);
	LP_SEQ_PRINTF(ImmediateL1DataCacheFlushes);
	LP_SEQ_PRINTF(MbFlushes);
	LP_SEQ_PRINTF(CounterRefreshSequenceNumber);
	LP_SEQ_PRINTF(CounterRefreshReferenceTime);
	LP_SEQ_PRINTF(IdleAccumulationSnapshot);
	LP_SEQ_PRINTF(ActiveTscCountSnapshot);
	LP_SEQ_PRINTF(HwpRequestContextSwitches);
	LP_SEQ_PRINTF(Placeholder1);
	LP_SEQ_PRINTF(Placeholder2);
	LP_SEQ_PRINTF(Placeholder3);
	LP_SEQ_PRINTF(Placeholder4);
	LP_SEQ_PRINTF(Placeholder5);
	LP_SEQ_PRINTF(Placeholder6);
	LP_SEQ_PRINTF(Placeholder7);
	LP_SEQ_PRINTF(Placeholder8);
	LP_SEQ_PRINTF(Placeholder9);
	LP_SEQ_PRINTF(Placeholder10);
	LP_SEQ_PRINTF(ReserveGroupId);
	LP_SEQ_PRINTF(RunningPriority);
	LP_SEQ_PRINTF(PerfmonInterruptCount);
#elif defined(__aarch64__)
	LP_SEQ_PRINTF(CounterRefreshSequenceNumber);
	LP_SEQ_PRINTF(CounterRefreshReferenceTime);
	LP_SEQ_PRINTF(IdleAccumulationSnapshot);
	LP_SEQ_PRINTF(ActiveTscCountSnapshot);
	LP_SEQ_PRINTF(HwpRequestContextSwitches);
	LP_SEQ_PRINTF(Placeholder2);
	LP_SEQ_PRINTF(Placeholder3);
	LP_SEQ_PRINTF(Placeholder4);
	LP_SEQ_PRINTF(Placeholder5);
	LP_SEQ_PRINTF(Placeholder6);
	LP_SEQ_PRINTF(Placeholder7);
	LP_SEQ_PRINTF(Placeholder8);
	LP_SEQ_PRINTF(Placeholder9);
	LP_SEQ_PRINTF(SchLocalRunListSize);
	LP_SEQ_PRINTF(ReserveGroupId);
	LP_SEQ_PRINTF(RunningPriority);
#endif

#undef LP_SEQ_PRINTF

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(lp_stats);

static void mshv_lp_stats_unmap(u32 lp_index)
{
	union hv_stats_object_identity identity = {
		.lp.lp_index = lp_index,
	};
	int err;

	err = hv_call_unmap_stat_page(HV_STATS_OBJECT_LOGICAL_PROCESSOR,
				      &identity);
	if (err)
		pr_err("%s: failed to unmap logical processor %u stats, "
		       "err: %d\n", __func__, lp_index, err);
}

static void __init *mshv_lp_stats_map(u32 lp_index)
{
	union hv_stats_object_identity identity = {
		.lp.lp_index = lp_index,
	};
	void *stats;
	int err;

	err = hv_call_map_stat_page(HV_STATS_OBJECT_LOGICAL_PROCESSOR,
				    &identity, &stats);
	if (err) {
		pr_err("%s: failed to map logical processor %u stats, "
		       "err: %d\n", __func__, lp_index, err);
		return ERR_PTR(err);
	}
	return stats;
}

static void __init *lp_debugfs_stats_create(u32 lp_index, struct dentry *parent)
{
	struct dentry *dentry;
	void *stats;

	stats = mshv_lp_stats_map(lp_index);
	if (IS_ERR(stats))
		return stats;

	dentry = debugfs_create_file("stats", 0400, parent,
				     stats, &lp_stats_fops);
	if (IS_ERR(dentry)) {
		mshv_lp_stats_unmap(lp_index);
		return dentry;
	}
	return stats;
}

static int __init lp_debugfs_create(u32 lp_index, struct dentry *parent)
{
	struct dentry *idx;
	char lp_idx_str[11]; /* sizeof(u32) + 1 */
	void *stats;
	int err;

	sprintf(lp_idx_str, "%u", lp_index);

	idx = debugfs_create_dir(lp_idx_str, parent);
	if (IS_ERR(idx))
		return PTR_ERR(idx);

	stats = lp_debugfs_stats_create(lp_index, idx);
	if (IS_ERR(stats)) {
		err = PTR_ERR(stats);
		goto remove_debugfs_lp_idx;
	}

	return 0;

remove_debugfs_lp_idx:
	debugfs_remove_recursive(idx);
	return err;
}

static void mshv_debugfs_lp_remove(void)
{
	int lp_index;

	debugfs_remove_recursive(mshv_debugfs_lp);

	for (lp_index = 0; lp_index < mshv_lps_count; lp_index++)
		mshv_lp_stats_unmap(lp_index);
}

static int __init mshv_debugfs_lp_create(struct dentry *parent)
{
	struct dentry *lp_dir;
	int err, lp_index;

	lp_dir = debugfs_create_dir("lp", parent);
	if (IS_ERR(lp_dir))
		return PTR_ERR(lp_dir);

	for (lp_index = 0; lp_index < mshv_lps_count; lp_index++) {
		err = lp_debugfs_create(lp_index, lp_dir);
		if (err)
			goto remove_debugfs_lps;
	}

	mshv_debugfs_lp = lp_dir;

	return 0;

remove_debugfs_lps:
	for (lp_index -= 1; lp_index >= 0; lp_index--)
		mshv_lp_stats_unmap(lp_index);
	debugfs_remove_recursive(lp_dir);
	return err;
}

static int vp_stats_show(struct seq_file *m, void *v)
{
	const struct hv_stats_page *stats = m->private;

#define VP_SEQ_PRINTF(cnt)		\
	seq_printf(m, "%-41s: %llu\n", __stringify(cnt), stats->vp_cntrs[Vp##cnt])

	VP_SEQ_PRINTF(TotalRunTime);
	VP_SEQ_PRINTF(HypervisorRunTime);
	VP_SEQ_PRINTF(RemoteNodeRunTime);
	VP_SEQ_PRINTF(NormalizedRunTime);
	VP_SEQ_PRINTF(IdealCpu);
	VP_SEQ_PRINTF(HypercallsCount);
	VP_SEQ_PRINTF(HypercallsTime);
#if defined(__x86_64__)
	VP_SEQ_PRINTF(PageInvalidationsCount);
	VP_SEQ_PRINTF(PageInvalidationsTime);
	VP_SEQ_PRINTF(ControlRegisterAccessesCount);
	VP_SEQ_PRINTF(ControlRegisterAccessesTime);
	VP_SEQ_PRINTF(IoInstructionsCount);
	VP_SEQ_PRINTF(IoInstructionsTime);
	VP_SEQ_PRINTF(HltInstructionsCount);
	VP_SEQ_PRINTF(HltInstructionsTime);
	VP_SEQ_PRINTF(MwaitInstructionsCount);
	VP_SEQ_PRINTF(MwaitInstructionsTime);
	VP_SEQ_PRINTF(CpuidInstructionsCount);
	VP_SEQ_PRINTF(CpuidInstructionsTime);
	VP_SEQ_PRINTF(MsrAccessesCount);
	VP_SEQ_PRINTF(MsrAccessesTime);
	VP_SEQ_PRINTF(OtherInterceptsCount);
	VP_SEQ_PRINTF(OtherInterceptsTime);
	VP_SEQ_PRINTF(ExternalInterruptsCount);
	VP_SEQ_PRINTF(ExternalInterruptsTime);
	VP_SEQ_PRINTF(PendingInterruptsCount);
	VP_SEQ_PRINTF(PendingInterruptsTime);
	VP_SEQ_PRINTF(EmulatedInstructionsCount);
	VP_SEQ_PRINTF(EmulatedInstructionsTime);
	VP_SEQ_PRINTF(DebugRegisterAccessesCount);
	VP_SEQ_PRINTF(DebugRegisterAccessesTime);
	VP_SEQ_PRINTF(PageFaultInterceptsCount);
	VP_SEQ_PRINTF(PageFaultInterceptsTime);
	VP_SEQ_PRINTF(GuestPageTableMaps);
	VP_SEQ_PRINTF(LargePageTlbFills);
	VP_SEQ_PRINTF(SmallPageTlbFills);
	VP_SEQ_PRINTF(ReflectedGuestPageFaults);
	VP_SEQ_PRINTF(ApicMmioAccesses);
	VP_SEQ_PRINTF(IoInterceptMessages);
	VP_SEQ_PRINTF(MemoryInterceptMessages);
	VP_SEQ_PRINTF(ApicEoiAccesses);
	VP_SEQ_PRINTF(OtherMessages);
	VP_SEQ_PRINTF(PageTableAllocations);
	VP_SEQ_PRINTF(LogicalProcessorMigrations);
	VP_SEQ_PRINTF(AddressSpaceEvictions);
	VP_SEQ_PRINTF(AddressSpaceSwitches);
	VP_SEQ_PRINTF(AddressDomainFlushes);
	VP_SEQ_PRINTF(AddressSpaceFlushes);
	VP_SEQ_PRINTF(GlobalGvaRangeFlushes);
	VP_SEQ_PRINTF(LocalGvaRangeFlushes);
	VP_SEQ_PRINTF(PageTableEvictions);
	VP_SEQ_PRINTF(PageTableReclamations);
	VP_SEQ_PRINTF(PageTableResets);
	VP_SEQ_PRINTF(PageTableValidations);
	VP_SEQ_PRINTF(ApicTprAccesses);
	VP_SEQ_PRINTF(PageTableWriteIntercepts);
	VP_SEQ_PRINTF(SyntheticInterrupts);
	VP_SEQ_PRINTF(VirtualInterrupts);
	VP_SEQ_PRINTF(ApicIpisSent);
	VP_SEQ_PRINTF(ApicSelfIpisSent);
	VP_SEQ_PRINTF(GpaSpaceHypercalls);
	VP_SEQ_PRINTF(LogicalProcessorHypercalls);
	VP_SEQ_PRINTF(LongSpinWaitHypercalls);
	VP_SEQ_PRINTF(OtherHypercalls);
	VP_SEQ_PRINTF(SyntheticInterruptHypercalls);
	VP_SEQ_PRINTF(VirtualInterruptHypercalls);
	VP_SEQ_PRINTF(VirtualMmuHypercalls);
	VP_SEQ_PRINTF(VirtualProcessorHypercalls);
	VP_SEQ_PRINTF(HardwareInterrupts);
	VP_SEQ_PRINTF(NestedPageFaultInterceptsCount);
	VP_SEQ_PRINTF(NestedPageFaultInterceptsTime);
	VP_SEQ_PRINTF(PageScans);
	VP_SEQ_PRINTF(LogicalProcessorDispatches);
	VP_SEQ_PRINTF(WaitingForCpuTime);
	VP_SEQ_PRINTF(ExtendedHypercalls);
	VP_SEQ_PRINTF(ExtendedHypercallInterceptMessages);
	VP_SEQ_PRINTF(MbecNestedPageTableSwitches);
	VP_SEQ_PRINTF(OtherReflectedGuestExceptions);
	VP_SEQ_PRINTF(GlobalIoTlbFlushes);
	VP_SEQ_PRINTF(GlobalIoTlbFlushCost);
	VP_SEQ_PRINTF(LocalIoTlbFlushes);
	VP_SEQ_PRINTF(LocalIoTlbFlushCost);
	VP_SEQ_PRINTF(HypercallsForwardedCount);
	VP_SEQ_PRINTF(HypercallsForwardingTime);
	VP_SEQ_PRINTF(PageInvalidationsForwardedCount);
	VP_SEQ_PRINTF(PageInvalidationsForwardingTime);
	VP_SEQ_PRINTF(ControlRegisterAccessesForwardedCount);
	VP_SEQ_PRINTF(ControlRegisterAccessesForwardingTime);
	VP_SEQ_PRINTF(IoInstructionsForwardedCount);
	VP_SEQ_PRINTF(IoInstructionsForwardingTime);
	VP_SEQ_PRINTF(HltInstructionsForwardedCount);
	VP_SEQ_PRINTF(HltInstructionsForwardingTime);
	VP_SEQ_PRINTF(MwaitInstructionsForwardedCount);
	VP_SEQ_PRINTF(MwaitInstructionsForwardingTime);
	VP_SEQ_PRINTF(CpuidInstructionsForwardedCount);
	VP_SEQ_PRINTF(CpuidInstructionsForwardingTime);
	VP_SEQ_PRINTF(MsrAccessesForwardedCount);
	VP_SEQ_PRINTF(MsrAccessesForwardingTime);
	VP_SEQ_PRINTF(OtherInterceptsForwardedCount);
	VP_SEQ_PRINTF(OtherInterceptsForwardingTime);
	VP_SEQ_PRINTF(ExternalInterruptsForwardedCount);
	VP_SEQ_PRINTF(ExternalInterruptsForwardingTime);
	VP_SEQ_PRINTF(PendingInterruptsForwardedCount);
	VP_SEQ_PRINTF(PendingInterruptsForwardingTime);
	VP_SEQ_PRINTF(EmulatedInstructionsForwardedCount);
	VP_SEQ_PRINTF(EmulatedInstructionsForwardingTime);
	VP_SEQ_PRINTF(DebugRegisterAccessesForwardedCount);
	VP_SEQ_PRINTF(DebugRegisterAccessesForwardingTime);
	VP_SEQ_PRINTF(PageFaultInterceptsForwardedCount);
	VP_SEQ_PRINTF(PageFaultInterceptsForwardingTime);
	VP_SEQ_PRINTF(VmclearEmulationCount);
	VP_SEQ_PRINTF(VmclearEmulationTime);
	VP_SEQ_PRINTF(VmptrldEmulationCount);
	VP_SEQ_PRINTF(VmptrldEmulationTime);
	VP_SEQ_PRINTF(VmptrstEmulationCount);
	VP_SEQ_PRINTF(VmptrstEmulationTime);
	VP_SEQ_PRINTF(VmreadEmulationCount);
	VP_SEQ_PRINTF(VmreadEmulationTime);
	VP_SEQ_PRINTF(VmwriteEmulationCount);
	VP_SEQ_PRINTF(VmwriteEmulationTime);
	VP_SEQ_PRINTF(VmxoffEmulationCount);
	VP_SEQ_PRINTF(VmxoffEmulationTime);
	VP_SEQ_PRINTF(VmxonEmulationCount);
	VP_SEQ_PRINTF(VmxonEmulationTime);
	VP_SEQ_PRINTF(NestedVMEntriesCount);
	VP_SEQ_PRINTF(NestedVMEntriesTime);
	VP_SEQ_PRINTF(NestedSLATSoftPageFaultsCount);
	VP_SEQ_PRINTF(NestedSLATSoftPageFaultsTime);
	VP_SEQ_PRINTF(NestedSLATHardPageFaultsCount);
	VP_SEQ_PRINTF(NestedSLATHardPageFaultsTime);
	VP_SEQ_PRINTF(InvEptAllContextEmulationCount);
	VP_SEQ_PRINTF(InvEptAllContextEmulationTime);
	VP_SEQ_PRINTF(InvEptSingleContextEmulationCount);
	VP_SEQ_PRINTF(InvEptSingleContextEmulationTime);
	VP_SEQ_PRINTF(InvVpidAllContextEmulationCount);
	VP_SEQ_PRINTF(InvVpidAllContextEmulationTime);
	VP_SEQ_PRINTF(InvVpidSingleContextEmulationCount);
	VP_SEQ_PRINTF(InvVpidSingleContextEmulationTime);
	VP_SEQ_PRINTF(InvVpidSingleAddressEmulationCount);
	VP_SEQ_PRINTF(InvVpidSingleAddressEmulationTime);
	VP_SEQ_PRINTF(NestedTlbPageTableReclamations);
	VP_SEQ_PRINTF(NestedTlbPageTableEvictions);
	VP_SEQ_PRINTF(FlushGuestPhysicalAddressSpaceHypercalls);
	VP_SEQ_PRINTF(FlushGuestPhysicalAddressListHypercalls);
	VP_SEQ_PRINTF(PostedInterruptNotifications);
	VP_SEQ_PRINTF(PostedInterruptScans);
	VP_SEQ_PRINTF(TotalCoreRunTime);
	VP_SEQ_PRINTF(MaximumRunTime);
	VP_SEQ_PRINTF(HwpRequestContextSwitches);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket0);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket1);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket2);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket3);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket4);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket5);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket6);
	VP_SEQ_PRINTF(VmloadEmulationCount);
	VP_SEQ_PRINTF(VmloadEmulationTime);
	VP_SEQ_PRINTF(VmsaveEmulationCount);
	VP_SEQ_PRINTF(VmsaveEmulationTime);
	VP_SEQ_PRINTF(GifInstructionEmulationCount);
	VP_SEQ_PRINTF(GifInstructionEmulationTime);
	VP_SEQ_PRINTF(EmulatedErrataSvmInstructions);
	VP_SEQ_PRINTF(Placeholder1);
	VP_SEQ_PRINTF(Placeholder2);
	VP_SEQ_PRINTF(Placeholder3);
	VP_SEQ_PRINTF(Placeholder4);
	VP_SEQ_PRINTF(Placeholder5);
	VP_SEQ_PRINTF(Placeholder6);
	VP_SEQ_PRINTF(Placeholder7);
	VP_SEQ_PRINTF(Placeholder8);
	VP_SEQ_PRINTF(Placeholder9);
	VP_SEQ_PRINTF(Placeholder10);
	VP_SEQ_PRINTF(SchedulingPriority);
	VP_SEQ_PRINTF(RdpmcInstructionsCount);
	VP_SEQ_PRINTF(RdpmcInstructionsTime);
	VP_SEQ_PRINTF(PerfmonPmuMsrAccessesCount);
	VP_SEQ_PRINTF(PerfmonLbrMsrAccessesCount);
	VP_SEQ_PRINTF(PerfmonIptMsrAccessesCount);
	VP_SEQ_PRINTF(PerfmonInterruptCount);
	VP_SEQ_PRINTF(Vtl1DispatchCount);
	VP_SEQ_PRINTF(Vtl2DispatchCount);
	VP_SEQ_PRINTF(Vtl2DispatchBucket0);
	VP_SEQ_PRINTF(Vtl2DispatchBucket1);
	VP_SEQ_PRINTF(Vtl2DispatchBucket2);
	VP_SEQ_PRINTF(Vtl2DispatchBucket3);
	VP_SEQ_PRINTF(Vtl2DispatchBucket4);
	VP_SEQ_PRINTF(Vtl2DispatchBucket5);
	VP_SEQ_PRINTF(Vtl2DispatchBucket6);
	VP_SEQ_PRINTF(Vtl1RunTime);
	VP_SEQ_PRINTF(Vtl2RunTime);
	VP_SEQ_PRINTF(IommuHypercalls);
	VP_SEQ_PRINTF(CpuGroupHypercalls);
	VP_SEQ_PRINTF(VsmHypercalls);
	VP_SEQ_PRINTF(EventLogHypercalls);
	VP_SEQ_PRINTF(DeviceDomainHypercalls);
	VP_SEQ_PRINTF(DepositHypercalls);
	VP_SEQ_PRINTF(SvmHypercalls);
	VP_SEQ_PRINTF(BusLockAcquisitionCount);
#elif defined(__aarch64__)
	VP_SEQ_PRINTF(SysRegAccessesCount);
	VP_SEQ_PRINTF(SysRegAccessesTime);
	VP_SEQ_PRINTF(SmcInstructionsCount);
	VP_SEQ_PRINTF(SmcInstructionsTime);
	VP_SEQ_PRINTF(OtherInterceptsCount);
	VP_SEQ_PRINTF(OtherInterceptsTime);
	VP_SEQ_PRINTF(ExternalInterruptsCount);
	VP_SEQ_PRINTF(ExternalInterruptsTime);
	VP_SEQ_PRINTF(PendingInterruptsCount);
	VP_SEQ_PRINTF(PendingInterruptsTime);
	VP_SEQ_PRINTF(GuestPageTableMaps);
	VP_SEQ_PRINTF(LargePageTlbFills);
	VP_SEQ_PRINTF(SmallPageTlbFills);
	VP_SEQ_PRINTF(ReflectedGuestPageFaults);
	VP_SEQ_PRINTF(MemoryInterceptMessages);
	VP_SEQ_PRINTF(OtherMessages);
	VP_SEQ_PRINTF(LogicalProcessorMigrations);
	VP_SEQ_PRINTF(AddressDomainFlushes);
	VP_SEQ_PRINTF(AddressSpaceFlushes);
	VP_SEQ_PRINTF(SyntheticInterrupts);
	VP_SEQ_PRINTF(VirtualInterrupts);
	VP_SEQ_PRINTF(ApicSelfIpisSent);
	VP_SEQ_PRINTF(GpaSpaceHypercalls);
	VP_SEQ_PRINTF(LogicalProcessorHypercalls);
	VP_SEQ_PRINTF(LongSpinWaitHypercalls);
	VP_SEQ_PRINTF(OtherHypercalls);
	VP_SEQ_PRINTF(SyntheticInterruptHypercalls);
	VP_SEQ_PRINTF(VirtualInterruptHypercalls);
	VP_SEQ_PRINTF(VirtualMmuHypercalls);
	VP_SEQ_PRINTF(VirtualProcessorHypercalls);
	VP_SEQ_PRINTF(HardwareInterrupts);
	VP_SEQ_PRINTF(NestedPageFaultInterceptsCount);
	VP_SEQ_PRINTF(NestedPageFaultInterceptsTime);
	VP_SEQ_PRINTF(LogicalProcessorDispatches);
	VP_SEQ_PRINTF(WaitingForCpuTime);
	VP_SEQ_PRINTF(ExtendedHypercalls);
	VP_SEQ_PRINTF(ExtendedHypercallInterceptMessages);
	VP_SEQ_PRINTF(MbecNestedPageTableSwitches);
	VP_SEQ_PRINTF(OtherReflectedGuestExceptions);
	VP_SEQ_PRINTF(GlobalIoTlbFlushes);
	VP_SEQ_PRINTF(GlobalIoTlbFlushCost);
	VP_SEQ_PRINTF(LocalIoTlbFlushes);
	VP_SEQ_PRINTF(LocalIoTlbFlushCost);
	VP_SEQ_PRINTF(FlushGuestPhysicalAddressSpaceHypercalls);
	VP_SEQ_PRINTF(FlushGuestPhysicalAddressListHypercalls);
	VP_SEQ_PRINTF(PostedInterruptNotifications);
	VP_SEQ_PRINTF(PostedInterruptScans);
	VP_SEQ_PRINTF(TotalCoreRunTime);
	VP_SEQ_PRINTF(MaximumRunTime);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket0);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket1);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket2);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket3);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket4);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket5);
	VP_SEQ_PRINTF(WaitingForCpuTimeBucket6);
	VP_SEQ_PRINTF(HwpRequestContextSwitches);
	VP_SEQ_PRINTF(Placeholder2);
	VP_SEQ_PRINTF(Placeholder3);
	VP_SEQ_PRINTF(Placeholder4);
	VP_SEQ_PRINTF(Placeholder5);
	VP_SEQ_PRINTF(Placeholder6);
	VP_SEQ_PRINTF(Placeholder7);
	VP_SEQ_PRINTF(Placeholder8);
	VP_SEQ_PRINTF(ContentionTime);
	VP_SEQ_PRINTF(WakeUpTime);
	VP_SEQ_PRINTF(SchedulingPriority);
	VP_SEQ_PRINTF(Vtl1DispatchCount);
	VP_SEQ_PRINTF(Vtl2DispatchCount);
	VP_SEQ_PRINTF(Vtl2DispatchBucket0);
	VP_SEQ_PRINTF(Vtl2DispatchBucket1);
	VP_SEQ_PRINTF(Vtl2DispatchBucket2);
	VP_SEQ_PRINTF(Vtl2DispatchBucket3);
	VP_SEQ_PRINTF(Vtl2DispatchBucket4);
	VP_SEQ_PRINTF(Vtl2DispatchBucket5);
	VP_SEQ_PRINTF(Vtl2DispatchBucket6);
	VP_SEQ_PRINTF(Vtl1RunTime);
	VP_SEQ_PRINTF(Vtl2RunTime);
	VP_SEQ_PRINTF(IommuHypercalls);
	VP_SEQ_PRINTF(CpuGroupHypercalls);
	VP_SEQ_PRINTF(VsmHypercalls);
	VP_SEQ_PRINTF(EventLogHypercalls);
	VP_SEQ_PRINTF(DeviceDomainHypercalls);
	VP_SEQ_PRINTF(DepositHypercalls);
	VP_SEQ_PRINTF(SvmHypercalls);
#endif

#undef VP_SEQ_PRINTF

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(vp_stats);

static void mshv_vp_stats_unmap(u64 partition_id, u32 vp_index)
{
	union hv_stats_object_identity identity = {
		.vp.partition_id = partition_id,
		.vp.vp_index = vp_index,
	};
	int err;

	err = hv_call_unmap_stat_page(HV_STATS_OBJECT_VP, &identity);
	if (err)
		pr_err("%s: failed to unmap partition %llu vp %u stats, err: %d\n",
		       __func__, partition_id, vp_index, err);
}

static void *mshv_vp_stats_map(u64 partition_id, u32 vp_index)
{
	union hv_stats_object_identity identity = {
		.vp.partition_id = partition_id,
		.vp.vp_index = vp_index,
	};
	void *stats;
	int err;

	err = hv_call_map_stat_page(HV_STATS_OBJECT_VP, &identity, &stats);
	if (err) {
		pr_err("%s: failed to map partition %llu vp %u stats, err: %d\n",
		       __func__, partition_id, vp_index, err);
		return ERR_PTR(err);
	}
	return stats;
}

static void *vp_debugfs_stats_create(u64 partition_id, u32 vp_index,
				     struct dentry *parent)
{
	struct dentry *dentry;
	void *stats;

	stats = mshv_vp_stats_map(partition_id, vp_index);
	if (IS_ERR(stats))
		return stats;

	dentry = debugfs_create_file("stats", 0400, parent,
				     stats, &vp_stats_fops);
	if (IS_ERR(dentry)) {
		mshv_vp_stats_unmap(partition_id, vp_index);
		return dentry;
	}
	return stats;
}

static void vp_debugfs_remove(u64 partition_id, u32 vp_index,
			      struct dentry *vp_idx_dir)
{
	debugfs_remove_recursive(vp_idx_dir);
	mshv_vp_stats_unmap(partition_id, vp_index);
}

static void *vp_debugfs_create(u64 partition_id, u32 vp_index,
			       struct dentry *parent)
{
	struct dentry *vp_idx_dir;
	char vp_idx_str[11]; /* sizeof(u32) + 1 */
	u64 *stats;
	int err;

	sprintf(vp_idx_str, "%u", vp_index);

	vp_idx_dir = debugfs_create_dir(vp_idx_str, parent);
	if (IS_ERR(vp_idx_dir))
		return vp_idx_dir;

	stats = vp_debugfs_stats_create(partition_id, vp_index, vp_idx_dir);
	if (IS_ERR(stats)) {
		err = PTR_ERR(stats);
		goto remove_debugfs_vp_idx;
	}

	return vp_idx_dir;

remove_debugfs_vp_idx:
	debugfs_remove_recursive(vp_idx_dir);
	return ERR_PTR(err);
}

static int partition_stats_show(struct seq_file *m, void *v)
{
	const struct hv_stats_page *stats = m->private;

#define PARTITION_SEQ_PRINTF(cnt)		\
	seq_printf(m, "%-30s: %llu\n", __stringify(cnt), stats->pt_cntrs[Partition##cnt])

	PARTITION_SEQ_PRINTF(VirtualProcessors);
	PARTITION_SEQ_PRINTF(TlbSize);
	PARTITION_SEQ_PRINTF(AddressSpaces);
	PARTITION_SEQ_PRINTF(DepositedPages);
	PARTITION_SEQ_PRINTF(GpaPages);
	PARTITION_SEQ_PRINTF(GpaSpaceModifications);
	PARTITION_SEQ_PRINTF(VirtualTlbFlushEntires);
	PARTITION_SEQ_PRINTF(RecommendedTlbSize);
	PARTITION_SEQ_PRINTF(GpaPages4K);
	PARTITION_SEQ_PRINTF(GpaPages2M);
	PARTITION_SEQ_PRINTF(GpaPages1G);
	PARTITION_SEQ_PRINTF(GpaPages512G);
	PARTITION_SEQ_PRINTF(DevicePages4K);
	PARTITION_SEQ_PRINTF(DevicePages2M);
	PARTITION_SEQ_PRINTF(DevicePages1G);
	PARTITION_SEQ_PRINTF(DevicePages512G);
	PARTITION_SEQ_PRINTF(AttachedDevices);
	PARTITION_SEQ_PRINTF(DeviceInterruptMappings);
	PARTITION_SEQ_PRINTF(IoTlbFlushes);
	PARTITION_SEQ_PRINTF(IoTlbFlushCost);
	PARTITION_SEQ_PRINTF(DeviceInterruptErrors);
	PARTITION_SEQ_PRINTF(DeviceDmaErrors);
	PARTITION_SEQ_PRINTF(DeviceInterruptThrottleEvents);
	PARTITION_SEQ_PRINTF(SkippedTimerTicks);
	PARTITION_SEQ_PRINTF(PartitionId);
#if defined(__x86_64__)
	PARTITION_SEQ_PRINTF(NestedTlbSize);
	PARTITION_SEQ_PRINTF(RecommendedNestedTlbSize);
	PARTITION_SEQ_PRINTF(NestedTlbFreeListSize);
	PARTITION_SEQ_PRINTF(NestedTlbTrimmedPages);
	PARTITION_SEQ_PRINTF(PagesShattered);
	PARTITION_SEQ_PRINTF(PagesRecombined);
	PARTITION_SEQ_PRINTF(HwpRequestValue);
#elif defined(__aarch64__)
	PARTITION_SEQ_PRINTF(HwpRequestValue);
#endif

#undef PARTITION_SEQ_PRINTF

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(partition_stats);

static void mshv_partition_stats_unmap(u64 partition_id)
{
	union hv_stats_object_identity identity = {
		.partition.partition_id = partition_id,
	};
	int err;

	err = hv_call_unmap_stat_page(HV_STATS_OBJECT_PARTITION,
				      &identity);
	if (err)
		pr_err("%s: failed to unmap partition %lld stats, err: %d\n",
			__func__, partition_id, err);
}

static void *mshv_partition_stats_map(u64 partition_id)
{
	union hv_stats_object_identity identity = {
		.partition.partition_id = partition_id,
	};
	void *stats;
	int err;

	err = hv_call_map_stat_page(HV_STATS_OBJECT_PARTITION,
				    &identity, &stats);
	if (err) {
		pr_err("%s: failed to map partition %lld stats, err: %d\n",
				__func__, partition_id, err);
		return ERR_PTR(err);
	}
	return stats;
}

static int mshv_debugfs_partition_stats_create(u64 partition_id, struct dentry *parent)
{
	struct dentry *dentry;
	void *stats;
	int err;

	stats = mshv_partition_stats_map(partition_id);
	if (IS_ERR(stats))
		return PTR_ERR(stats);

	dentry = debugfs_create_file("stats", 0400, parent,
				     stats, &partition_stats_fops);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto unmap_partition_stats;
	}

	return 0;

unmap_partition_stats:
	mshv_partition_stats_unmap(partition_id);
	return err;
}

static void partition_debugfs_remove(u64 partition_id, struct dentry *dentry)
{
	debugfs_remove_recursive(dentry);

	mshv_partition_stats_unmap(partition_id);
}

static struct dentry *partition_debugfs_create(u64 partition_id,
					       struct dentry **vp_dir_ptr,
					       struct dentry *parent)
{
	char part_id_str[21]; /* sizeof(u64) + 1 */
	struct dentry *part_id_dir, *vp_dir;
	int err;

	sprintf(part_id_str, "%llu", partition_id);

	part_id_dir = debugfs_create_dir(part_id_str, parent);
	if (IS_ERR(part_id_dir))
		return part_id_dir;

	vp_dir = debugfs_create_dir("vp", part_id_dir);
	if (IS_ERR(vp_dir)) {
		err = PTR_ERR(vp_dir);
		goto remove_debugfs_partition_id;
	}

	err = mshv_debugfs_partition_stats_create(partition_id, part_id_dir);
	if (err)
		goto remove_debugfs_partition_id;

	*vp_dir_ptr = vp_dir;

	return part_id_dir;

remove_debugfs_partition_id:
	debugfs_remove_recursive(part_id_dir);
	return ERR_PTR(err);
}

static void mshv_debugfs_root_partition_remove(void)
{
	int idx;

	for_each_online_cpu(idx)
		vp_debugfs_remove(hv_current_partition_id, idx, NULL);

	partition_debugfs_remove(hv_current_partition_id, NULL);
}

static int __init mshv_debugfs_root_partition_create(void)
{
	struct dentry *part_id_dir, *vp_dir;
	int err, idx, i;

	mshv_debugfs_partition = debugfs_create_dir("partition",
						     mshv_debugfs);
	if (IS_ERR(mshv_debugfs_partition))
		return PTR_ERR(mshv_debugfs_partition);

	part_id_dir = partition_debugfs_create(hv_current_partition_id,
					       &vp_dir,
					       mshv_debugfs_partition);
	if (IS_ERR(part_id_dir)) {
		err = PTR_ERR(part_id_dir);
		goto remove_debugfs_partition;
	}

	for_each_online_cpu(idx) {
		struct dentry *d;

		d = vp_debugfs_create(hv_current_partition_id, hv_vp_index[idx],
			vp_dir);
		if (IS_ERR(d)) {
			err = PTR_ERR(d);
			goto remove_debugfs_partition_vp;
		}
	}

	return 0;

remove_debugfs_partition_vp:
	for_each_online_cpu(i) {
		if (i >= idx)
			break;
		vp_debugfs_remove(hv_current_partition_id, i, NULL);
	}
	partition_debugfs_remove(hv_current_partition_id, NULL);
remove_debugfs_partition:
	debugfs_remove_recursive(mshv_debugfs_partition);
	return err;
}

static int hv_stats_show(struct seq_file *m, void *v)
{
	const struct hv_stats_page *stats = m->private;

#define HV_SEQ_PRINTF(cnt)		\
	seq_printf(m, "%-25s: %llu\n", __stringify(cnt), stats->hv_cntrs[Hv##cnt])

	HV_SEQ_PRINTF(LogicalProcessors);
	HV_SEQ_PRINTF(Partitions);
	HV_SEQ_PRINTF(TotalPages);
	HV_SEQ_PRINTF(VirtualProcessors);
	HV_SEQ_PRINTF(MonitoredNotifications);
	HV_SEQ_PRINTF(ModernStandbyEntries);
	HV_SEQ_PRINTF(PlatformIdleTransitions);
	HV_SEQ_PRINTF(HypervisorStartupCost);

	HV_SEQ_PRINTF(IOSpacePages);
	HV_SEQ_PRINTF(NonEssentialPagesForDump);
	HV_SEQ_PRINTF(SubsumedPages);

#undef HV_SEQ_PRINTF

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hv_stats);

static void mshv_hv_stats_unmap(void)
{
	union hv_stats_object_identity identity = { };
	int err;

	err = hv_call_unmap_stat_page(HV_STATS_OBJECT_HYPERVISOR,
				      &identity);
	if (err)
		pr_err("%s: failed to unmap hypervisor stats: %d\n",
				__func__, err);
}

static void * __init mshv_hv_stats_map(void)
{
	union hv_stats_object_identity identity = { };
	void *stats;
	int err;

	err = hv_call_map_stat_page(HV_STATS_OBJECT_HYPERVISOR,
				    &identity, &stats);
	if (err) {
		pr_err("%s: failed to map hypervisor stats: %d\n",
				__func__, err);
		return ERR_PTR(err);
	}
	return stats;
}

static int __init mshv_debugfs_hv_stats_create(struct dentry *parent)
{
	struct dentry *dentry;
	u64 *stats;
	int err;

	stats = mshv_hv_stats_map();
	if (IS_ERR(stats))
		return PTR_ERR(stats);

	dentry = debugfs_create_file("stats", 0400, parent,
				     stats, &hv_stats_fops);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		pr_err("%s: failed to create hypervisor stats dentry: %d\n",
				__func__, err);
		goto unmap_hv_stats;
	}

	mshv_lps_count = stats[HvLogicalProcessors];

	return 0;

unmap_hv_stats:
	mshv_hv_stats_unmap();
	return err;
}

int mshv_debugfs_vp_create(struct mshv_vp *vp)
{
	struct mshv_partition *p = vp->vp_partition;
	struct dentry *d;

	if (!mshv_debugfs)
		return 0;

	d = vp_debugfs_create(p->pt_id, vp->vp_index, p->pt_debugfs_vp_dentry);
	if (IS_ERR(d))
		return PTR_ERR(d);

	vp->vp_debugfs_dentry = d;

	return 0;
}

void mshv_debugfs_vp_remove(struct mshv_vp *vp)
{
	if (!mshv_debugfs)
		return;

	vp_debugfs_remove(vp->vp_partition->pt_id, vp->vp_index,
			  vp->vp_debugfs_dentry);
}

int mshv_debugfs_partition_create(struct mshv_partition *partition)
{
	struct dentry *part_id_dir;

	if (!mshv_debugfs)
		return 0;

	part_id_dir = partition_debugfs_create(partition->pt_id,
					       &partition->pt_debugfs_vp_dentry,
					       mshv_debugfs_partition);
	if (IS_ERR(part_id_dir))
		return PTR_ERR(part_id_dir);

	partition->pt_debugfs_dentry = part_id_dir;

	return 0;
}

void mshv_debugfs_partition_remove(struct mshv_partition *partition)
{
	if (!mshv_debugfs)
		return;

	partition_debugfs_remove(partition->pt_id,
				 partition->pt_debugfs_dentry);
}

int __init mshv_debugfs_init(void)
{
	int err;

	mshv_debugfs = debugfs_create_dir("mshv", NULL);
	if (IS_ERR(mshv_debugfs)) {
		pr_err("mshv: failed to create debugfs directory\n");
		return PTR_ERR(mshv_debugfs);
	}

	err = mshv_debugfs_hv_stats_create(mshv_debugfs);
	if (err)
		goto remove_mshv_dir;

	err = mshv_debugfs_root_partition_create();
	if (err)
		goto unmap_hv_stats;

	err = mshv_debugfs_lp_create(mshv_debugfs);
	if (err)
		goto remove_partition_dir;

	return 0;

remove_partition_dir:
	partition_debugfs_remove(hv_current_partition_id, NULL);
unmap_hv_stats:
	mshv_hv_stats_unmap();
remove_mshv_dir:
	debugfs_remove_recursive(mshv_debugfs);
	return err;
}

void mshv_debugfs_exit(void)
{
	mshv_debugfs_lp_remove();

	mshv_debugfs_root_partition_remove();

	debugfs_remove_recursive(mshv_debugfs);

	mshv_hv_stats_unmap();
}
