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
#include <linux/unaligned/access_ok.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: DNS match");

struct dnshdr {
	__be16	id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__be16	rd	: 1,
		tc	: 1,
		aa	: 1,
		opcode	: 4,
		qr	: 1,
		rcode	: 4,
		cd	: 1,
		ad	: 1,
		unused	: 1,
		ra	: 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__be16	qr	: 1,
		opcode	: 4,
		aa	: 1,
		tc	: 1,
		rd	: 1,
		ra	: 1,
		unused	: 1,
		ad	: 1,
		cd	: 1,
		rcode	: 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	__be16	nr_q;
	__be16	nr_r;
	__be16	nr_a;
	__be16	nr_er;
};

static int dns_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_dns_info *info = par->matchinfo;
	const struct ipt_entry *e = par->entryinfo;
	int i;

	if (e->ip.proto != IPPROTO_UDP || (e->ip.invflags & XT_INV_PROTO))
		return -EINVAL;
	if (info->invert & ~1)
		return -EINVAL;
	for (i = 0; i < sizeof(info->fqdn); i++) {
		if (info->fqdn[i] == '\0')
			break;
	}
	if (i == sizeof(info->fqdn))
		return -EINVAL;
	info->fqdn[sizeof(info->fqdn) - 1] = '\0';

	return 0;
}

static bool dns_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_dns_info *info = par->matchinfo;
	struct iphdr *iph;
	struct udphdr *udph;
	struct dnshdr *dnsh;
	unsigned char *data;
	int len;
	char *fqdn = (char *)info->fqdn;
	bool retval = !!(info->invert & 1);

	/* FIXME: Handle nonlinear skb */
	if (skb_is_nonlinear(skb))
		return retval;

	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET))
		return retval;

	if (skb->len < iph->ihl * 4 + sizeof(*udph) + sizeof(*dnsh))
		return retval;
	udph = (struct udphdr *)(skb->data + iph->ihl * 4);
	dnsh = (struct dnshdr *)&udph[1];

	/* only handle the request with only one question */
	if (dnsh->qr != 0 || dnsh->opcode != 0 || dnsh->nr_q != htons(1) ||
	    dnsh->nr_r != 0 || dnsh->nr_a != 0 || dnsh->nr_er != 0)
		return retval;

	data = (unsigned char *)&dnsh[1];
	len = skb->len - (data - skb->data);
	while (len > 0) {
		unsigned char label_len = *data++;

		len--;
		if (label_len == 0) {
			if (*fqdn == '\0' && len == 4 &&
			    get_unaligned_be16(data) == 1 &&
			    get_unaligned_be16(data + 2) == 1)
				retval ^= true;
			break;
		}
		/* FIXME: handle compression format */
		if (label_len > 63)
			break;
		if (label_len >= len)
			break;
		if (info->fqdn[0] != '\0' &&
		    strncmp(fqdn, data, label_len) != 0)
			break;
		data += label_len;
		len -= label_len;
		if (info->fqdn[0] != '\0')
			fqdn += label_len;
		if (fqdn - info->fqdn >= sizeof(info->fqdn))
			break;
		if (*fqdn == '\0')
			continue;
		if (*fqdn++ != '.')
			break;
		if (fqdn - info->fqdn >= sizeof(info->fqdn))
			break;
	}

	return retval;
}

static struct xt_match dns_mt_reg __read_mostly = {
	.name       = "dns",
	.revision   = 0,
	.family     = NFPROTO_IPV4,
	.checkentry = dns_mt_check,
	.match      = dns_mt,
	.matchsize  = sizeof(struct xt_dns_info),
	.me         = THIS_MODULE,
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
