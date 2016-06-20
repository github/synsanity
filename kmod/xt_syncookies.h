/* Kernel module to match syncookie metadata
 *
 * Copyright (c) 2015 Theo Julienne <theo@github.com>
 *
 * Based on xt_state.c:
 * Copyright (c) 1999-2001 Paul `Rusty' Russell
 * Copyright (c) 2002-2005 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _XT_SYNCOOKIES_H
#define _XT_SYNCOOKIES_H

enum {
	O_XT_SYNCOOKIES_ACCEPTED = 0,
	O_XT_SYNCOOKIES_SENT = 1,
	O_XT_SYNCOOKIES_LEVEL = 2,
};

struct xt_syncookies_info {
	uint8_t invert;
	uint8_t mode;
	uint8_t queue_level_percent;
};

#endif /*_XT_SYNCOOKIES_H*/
