/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 * hyp test framework apis
 */

#ifndef _HV_TF_API_H_
#define _HV_TF_API_H_

/* see onecore/hv/hvx/inc/HvTfApi.h */
#define _TF_COMPONENT_KD_ 2
#define HV_TEST_KD_TRIGGER_EXCEPTION (_TF_COMPONENT_KD_ << 16 | 0x00000001)

/* HV_TF_INPUT_COMMAND */
struct hv_tf_input_command {
	__u32 type;	/* 2 TfTypeTestcase */
	__u32 command;	/* 2 TfCmdMethod */
} __packed;

/* HV_INPUT_TF_TESTCASE */
struct hv_input_tf_testcase {
	__u32 id;
	__u32 padding;
} __packed;

/* HV_TF_INPUT_KD_TRIGGER_EXCEPTION */
struct hv_tf_input_kd_trigger_exception {
	__u32 exception_type;	/* 0 bugcheck, 1 exception, 2 assert */
	__u32 padding;
	__u64 parameter1;
	__u64 parameter2;
	__u64 parameter3;
} __packed;

/* HV_INPUT_INVOKE_TF */
struct hv_input_invoke_tf {
	__u64 input_buffer_gva;
	__u64 output_buffer_gva;
	__u32 input_buffer_size;
	__u32 output_buffer_size;
} __packed;

#endif /* _HV_TF_API_H_ */
