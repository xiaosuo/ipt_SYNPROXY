
#define DEBUG
#define pr_fmt(fmt) "nf_rtcache: " fmt
#include <linux/module.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/netfilter/nf_conntrack_extend.h>

MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_LICENSE("GPL");

struct nf_rtcache {
	struct dst_entry	*dst[IP_CT_DIR_MAX];
};

static void nf_rtcache_destroy(struct nf_conn *ct)
{
	struct nf_rtcache *cache = nf_ct_ext_find(ct, NF_CT_EXT_RTCACHE);
	struct dst_entry *dst;

	/* rcu_read_lock is held by __nf_ct_ext_destroy() */
	dst = rcu_dereference(cache->dst[IP_CT_DIR_ORIGINAL]);
	if (dst)
		dst_release(dst);
	dst = rcu_dereference(cache->dst[IP_CT_DIR_REPLY]);
	if (dst)
		dst_release(dst);
}

static struct nf_ct_ext_type nf_rtcache_ext __read_mostly = {
	.len		= sizeof(struct nf_rtcache),
	.align		= __alignof__(struct nf_rtcache),
	.id		= NF_CT_EXT_RTCACHE,
	.destroy	= nf_rtcache_destroy,
};

static unsigned int nf_rtcache_hook(unsigned int hooknum, struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_rtcache *cache;
	enum ip_conntrack_dir dir;
	struct dst_entry *dst;
	struct iphdr *iph;
	int err;

	dst = skb_dst(skb);
	if (dst)
		return NF_ACCEPT;
	/* rcu_read_lock is held by nf_hook_slow() */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;
	cache = nf_ct_ext_find(ct, NF_CT_EXT_RTCACHE);
	if (!cache) {
		cache = nf_ct_ext_add(ct, NF_CT_EXT_RTCACHE, GFP_ATOMIC);
		if (!cache)
			return NF_ACCEPT;
	}
	dir = CTINFO2DIR(ctinfo);
	dst = rcu_dereference(cache->dst[dir]);
	iph = ip_hdr(skb);
	if (dst && dst->obsolete <= 0) {
		struct rtable *rth;

		rth = (struct rtable *)dst;
		if ((((__force u32)rth->fl.fl4_dst ^ (__force u32)iph->daddr) |
		     ((__force u32)rth->fl.fl4_src ^ (__force u32)iph->saddr) |
		     (rth->fl.iif ^ skb->dev->ifindex) |
		     rth->fl.oif |
		     (rth->fl.fl4_tos ^ (iph->tos & IPTOS_RT_MASK))) == 0 &&
		    rth->fl.mark == skb->mark &&
		    net_eq(dev_net(rth->dst.dev), dev_net(skb->dev)) &&
		    rth->dst.ops->check(&rth->dst, 0)) {
			dst_use_noref(dst, jiffies);
			skb_dst_set_noref(skb, dst);
			pr_debug("hit: %p\n", cache);

			return NF_ACCEPT;
		}
	}

	err = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos,
				   skb->dev);
	if (unlikely(err)) {
		if (err == -EHOSTUNREACH)
			IP_INC_STATS(dev_net(skb->dev),
				     IPSTATS_MIB_INADDRERRORS);
		else if (err == -ENETUNREACH)
			IP_INC_STATS(dev_net(skb->dev),
				     IPSTATS_MIB_INNOROUTES);
		else if (err == -EXDEV)
			NET_INC_STATS(dev_net(skb->dev),
				      LINUX_MIB_IPRPFILTER);
		return NF_DROP;
	}

	dst = skb_dst(skb);
	if (dst->flags & DST_NOCACHE)
		dst = NULL;
	else
		dst_hold(dst);
	dst = xchg(&cache->dst[dir], dst);
	if (dst)
		dst_release(dst);
	pr_debug("miss: %p\n", cache);

	return NF_ACCEPT;
}

static struct nf_hook_ops nf_rtcache_ops __read_mostly = {
	.hook		= nf_rtcache_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_INET_PRE_ROUTING,
	.priority	= NF_IP_PRI_LAST,
};

static __init int init(void)
{
	int err;

	err = nf_ct_extend_register(&nf_rtcache_ext);
	if (err)
		return err;

	err = nf_register_hook(&nf_rtcache_ops);
	if (err) {
		nf_ct_extend_unregister(&nf_rtcache_ext);
		return err;
	}

	return 0;
}

static __exit void fini(void)
{
	nf_unregister_hook(&nf_rtcache_ops);
	nf_ct_extend_unregister(&nf_rtcache_ext);
}

module_init(init);
module_exit(fini);
