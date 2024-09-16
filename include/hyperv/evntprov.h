/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _HV_EVNTPROV_H
#define _HV_EVNTPROV_H

struct hv_event_descriptor {  /* EVENT_DESCRIPTOR */
	__u16 id;
	__u8  version;
	__u8  channel;
	__u8  level;
	__u8  opcode;
	__u16 task;
	__u64 keyword;
} __packed;

#endif
