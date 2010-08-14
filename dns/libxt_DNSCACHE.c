/* Shared library add-on to iptables to add DNSCACHE target support.
 *
 * Copyright (c) 2010 Changli Gao <xiaosuo@gmail.com>
*/
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_DNSCACHE.h>

static void DNSCACHE_help(void)
{
	printf(
"DNSCACHE target mutually-exclusion options:\n"
"  --dnscache-cache		cache the query result\n"
"  --dnscache-query		query and reply the DNS query if cache exists\n"
	);
}

static const struct option DNSCACHE_opts[] = {
	{.name = "dnscache-cache", .has_arg = false, .val = '1'},
	{.name = "dnscache-query", .has_arg = false, .val = '2'},
	{.name = NULL},
};

static int DNSCACHE_parse(int c, char **argv, int invert, unsigned int *flags,
                          const void *entry, struct xt_entry_target **target)
{
	struct xt_dnscache_info *info
		= (struct xt_dnscache_info *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
			           "DNSCACHE target: Only one option may be specified");
		info->action = XT_DNSCACHE_ACTION_CACHE;
		*flags = 1;
		break;

	case '2':
		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
			           "DNSCACHE target: Only one option may be specified");
		info->action = XT_DNSCACHE_ACTION_QUERY;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void DNSCACHE_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
		           "DNSCACHE target: At least one parameter is required");
}

static const char *dnscache_action_str[] = {
	[XT_DNSCACHE_ACTION_CACHE]	= "dnscache-cache",
	[XT_DNSCACHE_ACTION_QUERY]	= "dnscache-query",
};

static void DNSCACHE_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct xt_dnscache_info *info =
		(const struct xt_dnscache_info *)target->data;
	printf("DNSCACHE %s ", dnscache_action_str[info->action]);
}

static void DNSCACHE_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_dnscache_info *info =
		(const struct xt_dnscache_info *)target->data;

	printf("--%s ", dnscache_action_str[info->action]);
}

static struct xtables_target dnscache_target = {
	.family		= NFPROTO_IPV4,
	.name		= "DNSCACHE",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_dnscache_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_dnscache_info)),
	.help		= DNSCACHE_help,
	.parse		= DNSCACHE_parse,
	.final_check	= DNSCACHE_check,
	.print		= DNSCACHE_print,
	.save		= DNSCACHE_save,
	.extra_opts	= DNSCACHE_opts,
};

void _init(void)
{
	xtables_register_target(&dnscache_target);
}
