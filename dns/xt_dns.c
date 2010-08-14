/* (C) 2010- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/xt_dns.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/ip.h>
#include <linux/dns.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: DNS match");

static int dns_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_dns_info *info = par->matchinfo;

	if (info->invert & ~1)
		return -EINVAL;
	if (qn_valid(info->fqdn, sizeof(info->fqdn), info->fqdn) < 0)
		return -EINVAL;

	return 0;
}

static bool dns_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_dns_info *info = par->matchinfo;
	struct iphdr *iph;
	struct udphdr *udph;
	struct dnshdr *dnsh;
	u8 *data;
	int len, off;
	bool retval = !!(info->invert & 1);
	struct dns_q_fixed *qf;

	/* FIXME: Handle nonlinear skb */
	if (skb_is_nonlinear(skb))
		goto out;

	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET))
		goto out;

	if (skb->len < iph->ihl * 4 + sizeof(*udph) + sizeof(*dnsh))
		goto out;
	udph = (struct udphdr *)(skb->data + iph->ihl * 4);
	dnsh = (struct dnshdr *)&udph[1];

	/* only handle the request with only one question */
	if (dnsh->qr != 0 || dnsh->opcode != 0 || dnsh->qdcount != htons(1) ||
	    dnsh->ancount != htons(0) || dnsh->nscount != htons(0) ||
	    dnsh->arcount != htons(0))
		goto out;

	data = (u8 *)&dnsh[1];
	len = skb->len - (data - skb->data);
	off = qn_valid((u8 *)dnsh, len + sizeof(*dnsh), data);
	if (off < 0 || off + sizeof(*qf) != len)
		goto out;
	qf = (struct dns_q_fixed *)(data + off);
	if (qf->type != htons(DNS_TYPE_A) || qf->class != htons(DNS_CLASS_IN))
		goto out;
	if (info->fqdn[0] != '\0' &&
	    qn_cmp((u8 *)info->fqdn, data, (u8 *)info->fqdn, (u8 *)dnsh) != 0)
		goto out;
	retval ^= true;

out:
	return retval;
}

static struct xt_match dns_mt_reg __read_mostly = {
	.name		= "dns",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.proto		= IPPROTO_UDP,
	.checkentry	= dns_mt_check,
	.match		= dns_mt,
	.matchsize	= sizeof(struct xt_dns_info),
	.me		= THIS_MODULE,
};

static int __init dns_mt_init(void)
{
	return xt_register_match(&dns_mt_reg);
}

static void __exit dns_mt_exit(void)
{
	xt_unregister_match(&dns_mt_reg);
}

module_init(dns_mt_init);
module_exit(dns_mt_exit);
