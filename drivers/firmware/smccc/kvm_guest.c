// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "smccc: KVM: " fmt

#include <linux/arm-smccc.h>
#include <linux/bitmap.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <asm/hypervisor.h>

static DECLARE_BITMAP(__kvm_arm_hyp_services, ARM_SMCCC_KVM_NUM_FUNCS) __ro_after_init = { };

void __init kvm_init_hyp_services(void)
{
	uuid_t kvm_uuid = ARM_SMCCC_VENDOR_HYP_UID_KVM;
	struct arm_smccc_res res;
	u32 val[4];

	if (!arm_smccc_hypervisor_has_uuid(&kvm_uuid))
		return;

	memset(&res, 0, sizeof(res));
	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID, &res);

	val[0] = lower_32_bits(res.a0);
	val[1] = lower_32_bits(res.a1);
	val[2] = lower_32_bits(res.a2);
	val[3] = lower_32_bits(res.a3);

	bitmap_from_arr32(__kvm_arm_hyp_services, val, ARM_SMCCC_KVM_NUM_FUNCS);

	pr_info("hypervisor services detected (0x%08lx 0x%08lx 0x%08lx 0x%08lx)\n",
		 res.a3, res.a2, res.a1, res.a0);
}

bool kvm_arm_hyp_service_available(u32 func_id)
{
	if (func_id >= ARM_SMCCC_KVM_NUM_FUNCS)
		return false;

	return test_bit(func_id, __kvm_arm_hyp_services);
}
EXPORT_SYMBOL_GPL(kvm_arm_hyp_service_available);
