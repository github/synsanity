/*
 * libxt_syncookies
 * Shared library add-on to iptables for syncookies matching support.
 *
 * Copyright (c) Theo Julienne <theo@github.com>
 *
 * Based on snippets from libxt_conntrack.c:
 * GPL (C) 2001  Marc Boucher (marc@mbsi.ca).
 * Copyright © CC Computer Consultants GmbH, 2007 - 2008
 * Jan Engelhardt <jengelh@computergmbh.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <stdbool.h>
#include <stdio.h>

// hacks for precise, because the system linux/asm includes don't match the trusty kernel
#define _ASM_X86_POSIX_TYPES_64_H
#include "asm-generic/posix_types.h"

#include <xtables.h>
#include "../kmod/xt_syncookies.h"

static void
syncookies_help(void)
{
	printf(
"syncookies match options:\n"
" [!] --syncookies-accepted\n"
"				Match if syncookies would be accepted\n"
" [!] --syncookies-would-send\n"
"				Match if syncookies would be sent\n"
" [!] --syn-queue-level percentage\n"
"				Match if SYN queue for this socket is over percentage (0-100)\n"
	);
}

static const struct xt_option_entry syncookies_opts[] = {
	{.name = "syncookies-accepted", .id = O_XT_SYNCOOKIES_ACCEPTED, .type = XTTYPE_NONE,
	 .flags = XTOPT_INVERT},
	{.name = "syncookies-would-send", .id = O_XT_SYNCOOKIES_SENT, .type = XTTYPE_NONE,
 	 .flags = XTOPT_INVERT},
	{.name = "syn-queue-level", .id = O_XT_SYNCOOKIES_LEVEL, .type = XTTYPE_UINT8, .min = 0, .max = 100,
 	 .flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_syncookies_info, queue_level_percent)},
	XTOPT_TABLEEND,
};

static void syncookies_parse(struct xt_option_call *cb)
{
	struct xt_syncookies_info *sinfo = cb->data;

	xtables_option_parse(cb);
	sinfo->mode = cb->entry->id;
	sinfo->invert = cb->invert;
}

static void
syncookies_print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	const struct xt_syncookies_info *sinfo = (const void *)match->data;

	if (sinfo->invert)
		printf(" !");
	if (sinfo->mode == O_XT_SYNCOOKIES_SENT)
		printf(" syncookies-would-send");
	else if (sinfo->mode == O_XT_SYNCOOKIES_ACCEPTED)
		printf(" syncookies-accepted");
	else if (sinfo->mode == O_XT_SYNCOOKIES_LEVEL)
		printf(" syn-queue-level %d", sinfo->queue_level_percent);
}

static void syncookies_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_syncookies_info *sinfo = (const void *)match->data;

	if (sinfo->invert)
		printf(" !");

	if (sinfo->mode == O_XT_SYNCOOKIES_SENT)
		printf(" --syncookies-would-send");
	else if (sinfo->mode == O_XT_SYNCOOKIES_ACCEPTED)
		printf(" --syncookies-accepted");
	else if (sinfo->mode == O_XT_SYNCOOKIES_LEVEL)
		printf(" --syn-queue-level %d", sinfo->queue_level_percent);
}

static struct xtables_match syncookies_mt_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "syncookies",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_syncookies_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_syncookies_info)),
		.help          = syncookies_help,
		.print         = syncookies_print,
		.save          = syncookies_save,
		.x6_parse      = syncookies_parse,
		.x6_options    = syncookies_opts,
	},
};

void _init(void)
{
	xtables_register_matches(syncookies_mt_reg, 1);
}
