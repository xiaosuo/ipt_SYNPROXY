#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/xt_dns.h>

static void dns_help(void)
{
	printf(
"dns match options:\n"
"[!] --dns-fqdn FQDN   Match FQDN\n");
}

static const struct option dns_opts[] = {
	{.name = "dns-fqdn", .has_arg = true, .val = '1'},
	{.name = NULL},
};

static int
dns_parse(int c, char **argv, int invert, unsigned int *flags,
          const void *entry, struct xt_entry_match **match)
{
	struct xt_dns_info *dnsinfo = (struct xt_dns_info *)(*match)->data;

	switch (c) {
	case '1':
		xtables_check_inverse(optarg, &invert, &optind, 0, argv);
		if (strlen(optarg) >= sizeof(dnsinfo->fqdn))
			xtables_error(PARAMETER_PROBLEM, "--dns-fqdn must be "
				   "shorter than %lu", sizeof(dnsinfo->fqdn));
		strcpy(dnsinfo->fqdn, optarg);
		if (invert)
			dnsinfo->invert = 1;
		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void dns_check(unsigned int flags)
{
}

static void
dns_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_dns_info *info = (void *)match->data;

	printf("dns %s", info->invert ? "! " : "");
	if (info->fqdn[0] != '\0')
		printf("%s ", info->fqdn);
}

static void dns_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_dns_info *info = (void *)match->data;

	printf("%s", info->invert ? "! " : "");
	if (info->fqdn[0] != '\0')
		printf("--dns-fqdn %s ", info->fqdn);
}

static struct xtables_match dns_match = {
	.family		= NFPROTO_IPV4,
 	.name		= "dns",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_dns_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_dns_info)),
	.help		= dns_help,
	.parse		= dns_parse,
	.final_check	= dns_check,
	.print		= dns_print,
	.save		= dns_save,
	.extra_opts	= dns_opts,
};

void _init(void)
{
	xtables_register_match(&dns_match);
}
