/*
 * libxt_condition
 * Shared library add-on to iptables for userspace condition match.
 *
 * Copyright (c) Theo Julienne <theo@github.com>
 *
 * Based on original libipt_condition:
 * Copyright (c) Stephane Ouellette <ouellettes@videotron.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 // hacks for precise, because the system linux/asm includes don't match the trusty kernel
#define _ASM_X86_POSIX_TYPES_64_H
#include "asm-generic/posix_types.h"

#include <xtables.h>

#include "../kmod/xt_condition.h"

/** condition match **/

static void condition_help(void)
{
	printf(
"condition match options:\n"
" [!] --condition filename\n"
"				Match on boolean value stored in /proc file\n");
}

enum {
	O_CONDITION = 0,
};

static const struct xt_option_entry condition_opts[] = {
	{
		.name = "condition",
		.id = O_CONDITION,
		.type = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_PUT,
		XTOPT_POINTER(struct condition_info, name)
	},
	XTOPT_TABLEEND,
};

static void condition_parse(struct xt_option_call *cb)
{
	struct condition_info *sinfo = cb->data;

	xtables_option_parse(cb);
	sinfo->invert = cb->invert;
}

static void condition_print(const void *ip, const struct xt_entry_match *match,
                            int numeric)
{
	const struct condition_info *info =
	    (const struct condition_info *) match->data;

	printf("%s condition %s", (info->invert) ? " !" : "", info->name);
}


static void condition_save(const void *ip, const struct xt_entry_match *match)
{
	const struct condition_info *info =
	    (const struct condition_info *) match->data;

	printf("%s --condition \"%s\"", (info->invert) ? " !" : "", info->name);
}

static struct xtables_match condition_mt_reg = {
	.name          = "condition",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct condition_info)),
	.userspacesize = offsetof(struct condition_info, var),
	.help          = condition_help,
	.print         = condition_print,
	.save          = condition_save,
	.x6_parse      = condition_parse,
	.x6_options    = condition_opts,
};

/** CONDITION target **/

static void CONDITION_help(void)
{
	printf(
"CONDITION target options:\n"
"  [!] --condition filename          Set (or unset if inverted) condition variable\n");
}

static void CONDITION_check(struct xt_fcheck_call *cb)
{
}

static void CONDITION_print(const void *ip, const struct xt_entry_target *target,
                           int numeric)
{
	const struct condition_info *info =
		(const struct condition_info *)target->data;

	printf(" CONDITION ");
	if (info->invert)
		printf("! ");
	printf("%s", info->name);
}

static void CONDITION_save(const void *ip, const struct xt_entry_target *target)
{
	const struct condition_info *info =
		(const struct condition_info *)target->data;

	if (info->invert)
		printf(" !");
	printf(" --condition \"%s\"", info->name);
}

static struct xtables_target condition_tg_reg = {
	.family        = NFPROTO_UNSPEC,
	.name          = "CONDITION",
	.version       = XTABLES_VERSION,
	.revision      = 0,
	.size          = XT_ALIGN(sizeof(struct condition_info)),
	.userspacesize = offsetof(struct condition_info, var),
	.help          = CONDITION_help,
	.print         = CONDITION_print,
	.save          = CONDITION_save,
	.x6_parse      = condition_parse,
	.x6_fcheck     = CONDITION_check,
	.x6_options    = condition_opts,
};

void
_init(void)
{
	xtables_register_matches(&condition_mt_reg, 1);
	xtables_register_targets(&condition_tg_reg, 1);
}