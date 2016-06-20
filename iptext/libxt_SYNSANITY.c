/*
 * Original SYNPROXY code copyright (c) 2013 Patrick McHardy <kaber@trash.net>
 * SYNSANITY modifications copyright (c) 2015 Theo Julienne <theo@github.com>
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
#include <linux/netfilter/xt_SYNPROXY.h>

enum {
	O_SACK_PERM = 0,
	O_TIMESTAMP,
	O_WSCALE,
	O_MSS,
	O_ECN,
};

static void SYNSANITY_help(void)
{
	printf(
"SYNSANITY target options:\n"
"  --sack-perm                        Set SACK_PERM\n"
"  --timestamp                        Set TIMESTAMP\n"
"  --wscale value                     Set window scaling factor\n"
"  --mss value                        Set MSS value\n"
"  --ecn                              Set ECN\n");
}

static const struct xt_option_entry SYNSANITY_opts[] = {
	{.name = "sack-perm", .id = O_SACK_PERM, .type = XTTYPE_NONE, },
	{.name = "timestamp", .id = O_TIMESTAMP, .type = XTTYPE_NONE, },
	{.name = "wscale",    .id = O_WSCALE,    .type = XTTYPE_UINT32, },
	{.name = "mss",       .id = O_MSS,       .type = XTTYPE_UINT32, },
	{.name = "ecn",       .id = O_ECN,	 .type = XTTYPE_NONE, },
	XTOPT_TABLEEND,
};

static void SYNSANITY_parse(struct xt_option_call *cb)
{
	struct xt_synproxy_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SACK_PERM:
		info->options |= XT_SYNPROXY_OPT_SACK_PERM;
		break;
	case O_TIMESTAMP:
		info->options |= XT_SYNPROXY_OPT_TIMESTAMP;
		break;
	case O_WSCALE:
		info->options |= XT_SYNPROXY_OPT_WSCALE;
		info->wscale = cb->val.u32;
		break;
	case O_MSS:
		info->options |= XT_SYNPROXY_OPT_MSS;
		info->mss = cb->val.u32;
		break;
	case O_ECN:
		info->options |= XT_SYNPROXY_OPT_ECN;
		break;
	}
}

static void SYNSANITY_check(struct xt_fcheck_call *cb)
{
}

static void SYNSANITY_print(const void *ip, const struct xt_entry_target *target,
                           int numeric)
{
	const struct xt_synproxy_info *info =
		(const struct xt_synproxy_info *)target->data;

	printf(" SYNSANITY ");
	if (info->options & XT_SYNPROXY_OPT_SACK_PERM)
		printf("sack-perm ");
	if (info->options & XT_SYNPROXY_OPT_TIMESTAMP)
		printf("timestamp ");
	if (info->options & XT_SYNPROXY_OPT_WSCALE)
		printf("wscale %u ", info->wscale);
	if (info->options & XT_SYNPROXY_OPT_MSS)
		printf("mss %u ", info->mss);
	if (info->options & XT_SYNPROXY_OPT_ECN)
		printf("ecn ");
}

static void SYNSANITY_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_synproxy_info *info =
		(const struct xt_synproxy_info *)target->data;

	if (info->options & XT_SYNPROXY_OPT_SACK_PERM)
		printf(" --sack-perm");
	if (info->options & XT_SYNPROXY_OPT_TIMESTAMP)
		printf(" --timestamp");
	if (info->options & XT_SYNPROXY_OPT_WSCALE)
		printf(" --wscale %u", info->wscale);
	if (info->options & XT_SYNPROXY_OPT_MSS)
		printf(" --mss %u", info->mss);
	if (info->options & XT_SYNPROXY_OPT_ECN)
		printf(" --ecn");
}

static struct xtables_target synsanity_tg_reg = {
	.family        = NFPROTO_UNSPEC,
	.name          = "SYNSANITY",
	.version       = XTABLES_VERSION,
	.revision      = 0,
	.size          = XT_ALIGN(sizeof(struct xt_synproxy_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_synproxy_info)),
	.help          = SYNSANITY_help,
	.print         = SYNSANITY_print,
	.save          = SYNSANITY_save,
	.x6_parse      = SYNSANITY_parse,
	.x6_fcheck     = SYNSANITY_check,
	.x6_options    = SYNSANITY_opts,
};

void _init(void)
{
	xtables_register_target(&synsanity_tg_reg);
}
