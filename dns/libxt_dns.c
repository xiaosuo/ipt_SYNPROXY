#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/dns.h>
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

static int str2qn(char *str, __u8 *qn, unsigned int len)
{
	int label_len;

	do {
		label_len = strcspn(str, ".");
		if (label_len == 0 || label_len > 63 || label_len + 2 > len)
			return -1;
		len -= label_len + 1;
		*qn++ = label_len;
		if (!qn_label_valid((unsigned char *)str, label_len))
			return -1;
		memcpy(qn, str, label_len);
		qn += label_len;
		str += label_len;
	} while (*str++ == '.');

	*qn = 0;

	return 0;
}

static void qn_print(const __u8 *qn)
{
	int label_len;
	int point = 0;

	for (;;) {
		label_len = *qn++;
		if (label_len == 0)
			break;
		if (point)
			fprintf(stdout, ".");
		else
			point = 1;
		fwrite(qn, label_len, 1, stdout);
		qn += label_len;
	}
}

static int
dns_parse(int c, char **argv, int invert, unsigned int *flags,
          const void *entry, struct xt_entry_match **match)
{
	struct xt_dns_info *dnsinfo = (struct xt_dns_info *)(*match)->data;

	switch (c) {
	case '1':
		xtables_check_inverse(optarg, &invert, &optind, 0, argv);
		if (str2qn(optarg, dnsinfo->fqdn, sizeof(dnsinfo->fqdn)))
			xtables_error(PARAMETER_PROBLEM, "--dns-fqdn invalid "
				      "fqdn");
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
	if (info->fqdn[0] != '\0') {
		qn_print(info->fqdn);
		printf(" ");
	}
}

static void dns_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_dns_info *info = (void *)match->data;

	printf("%s", info->invert ? "! " : "");
	if (info->fqdn[0] != '\0') {
		printf("--dns-fqdn ");
		qn_print(info->fqdn);
		printf(" ");
	}
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
