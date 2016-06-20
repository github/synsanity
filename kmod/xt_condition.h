/*
 * xt_condition
 * iptables kernel module for userspace condition match.
 *
 * Copyright (c) Theo Julienne <theo@github.com>
 *
 * Based on original ipt_condition:
 * Copyright (c) Stephane Ouellette <ouellettes@videotron.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __XT_CONDITION_MATCH__
#define __XT_CONDITION_MATCH__

#define CONDITION_NAME_LEN  32

struct condition_info {
	char name[CONDITION_NAME_LEN];
	uint8_t invert;

	/* kernel use: copy of the condition variable
	 * note that ".userspacesize" in the iptables extension doesn't include this field.
	 * when a rule is first checked, we also throw away this value and replace it with
	 * a trusted copy.
	 * Reference: http://inai.de/documents/Netfilter_Modules.pdf
	 *  (4.5 Attaching kernel-specific data)
	 */
	struct condition_variable *var __attribute__((aligned(8)));
};

#endif