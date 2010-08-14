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
#include <linux/netfilter/xt_DNSCACHE.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/ip.h>
#include <linux/dns.h>
#include <linux/dns.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: DNSCACHE target");

struct dnscache {
	struct hlist_node	node;
	u8			*header;
	unsigned int		len;
	spinlock_t		lock;
	struct list_head	lru;
	unsigned long		last_access;
	struct timer_list	timeout;
	unsigned int		hash_index;
};

struct dnscache_head {
	spinlock_t		lock;
	struct hlist_head	head;
};

static struct dnscache_head	*dnscache_ht;
static struct DEFINE_LIST(dnscache_lru);

static int dns_rr_valid(struct dnshdr *dnsh, unsigned int dnslen, u8 *data,
			unsigned int len)
{
	int off, rlen;
	struct dns_rr_fixed *rf;
	unsigned int olen = len;

	off = qn_valid((u8 *)dnsh, dnslen, data);
	if (off < 0 || off + sizeof(*rf) > len)
		goto err;
	data += off;
	len -= off;

	rf = (struct dns_rr_fixed *)(data);
	if (rf->class != htons(DNS_CLASS_IN))
		goto err;
	/* the server don't want us to cache the result */
	if (rf->ttl == htons(0))
		goto err;
	data += sizeof(*rf);
	len -= sizeof(*rf);
	rlen = ntohs(rf->len);
	if (rlen > len)
		goto err;
	switch (ntohs(rf->type)) {
	case DNS_TYPE(A):
		if (rlen != 4)
			goto err;
		break;
	case DNS_TYPE(NS):
	case DNS_TYPE(CNAME):
	case DNS_TYPE(PTR):
		off = qn_valid((u8 *)dnsh, dnslen, data);
		if (off < 0 || off != rlen)
			goto err;
		break;
	case DNS_TYPE(MX):
		/* skip preference __be16 */
		off = qn_valid((u8 *)dnsh, dnslen, data + 2);
		if (off < 0 || off + 2 != rlen)
			goto err;
		break;
	default:
		break;
	}
	data += rlen;
	len -= rlen;

	return olen - len;
err:
	return -EINVAL;
}

static int dns_rr_valid_n(struct dnshdr *dnsh, unsigned int dnslen, u8 *data,
			  unsigned int len, int ancountr)
{
	int off, i;
	unsigned int olen = len;

	for (i = 0; i < ancountr; i++) {
		off = dns_rr_valid(dnsh, dnslen, data, len);
		if (off < 0)
			goto err;
		data += off;
		len -= off;
	}

	return olen - len;
err:
	return -EINVAL;
}

static unsigned int dnscache_tg(struct sk_buff *skb,
				const struct xt_action_param *par)
{
	const struct xt_dnscache_info *info = par->targinfo;
	struct iphdr *iph;
	struct udphdr *udph;
	struct dnshdr *dnsh;
	u8 *data;
	int len, dnslen, off;
	unsigned int retval = NF_ACCEPT;

	if (skb_linearize(skb))
		goto out;
	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET))
		goto out;
	if (skb->len < iph->ihl * 4 + sizeof(*udph) + sizeof(*dnsh))
		goto out;
	udph = (struct udphdr *)(skb->data + iph->ihl * 4);
	dnsh = (struct dnshdr *)&udph[1];
	dnslen = skb->len - ((u8*)dnsh - skb->data);
	data = (u8 *)&dnsh[1];
	len = skb->len - (data - skb->data);

	if (dnsh->rcode != 0 || dnsh->tc || dnsh->aa)
		goto out;

	if (dnsh->qdcount == htons(1)) {
		struct dns_q_fixed *qf;

		off = qn_valid((u8 *)dnsh, dnslen, data);
		if (off < 0 || off + sizeof(*qf) > len)
			goto out;
		qf = (struct dns_q_fixed *)(data + off);
		if (qf->type != htons(DNS_TYPE_A) ||
		    qf->class != htons(DNS_CLASS_IN))
			goto out;
		data += off + sizeof(*qf);
		len -= off + sizeof(*qf);
	} else {
		goto out;
	}

	/* query message */
	if (dnsh->qdcount == ntohs(0))
		goto out;

	off = dns_rr_valid_n(dnsh, dnslen, data, len, ntohs(dnsh->ancount) +
			     ntohs(dnsh->nscount) + ntohs(dnsh->arcount));
	if (off != len)
		goto out;

	/* FIXME: mangle */
out:
	return retval;
}

static int dnscache_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_dnscache_info *info = par->targinfo;

	if (info->action > XT_DNSCACHE_ACTION_MAX)
		return -EINVAL;
	return 0;
}

static struct xt_target dnscache_tg_reg __read_mostly = {
	.name		= "DNSCACHE",
	.family		= NFPROTO_IPV4,
	.target		= dnscache_tg,
	.targetsize	= sizeof(struct xt_dnscache_info),
	.proto		= IPPROTO_UDP,
	.checkentry	= dnscache_tg_check,
	.me		= THIS_MODULE,
};

static int __init dnscache_tg_init(void)
{
	return xt_register_target(&dnscache_tg_reg);
}

static void __exit dnscache_tg_exit(void)
{
	xt_unregister_target(&dnscache_tg_reg);
}

module_init(dnscache_tg_init);
module_exit(dnscache_tg_exit);
