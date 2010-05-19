/* (C) 2010- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * It bases on ipt_REJECT.c
 */
#define DEBUG
#define pr_fmt(fmt) "SYNPROXY: " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/unaligned/access_ok.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: \"SYNPROXY\" target for IPv4");

/* depends on nf_conntrack_proto_tcp and syncookies */

/* FIXME: window size is the same with mss, is better for data handling */
#define SYN_PROXY_WINDOW	4096

enum {
	TCP_SEND_FLAG_NOTRACE	= 0x1,
	TCP_SEND_FLAG_SYNCOOKIE	= 0x2,
};

struct syn_proxy_state {
	u32	seq_diff;
	u16	seq_inited	: 1;
	__be16	window;
};

static int syn_proxy_route(struct sk_buff *skb, struct net *net)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	struct flowi fl = {};
	unsigned int type;
	int flags = 0;

	type = inet_addr_type(net, iph->saddr);
	if (type != RTN_LOCAL) {
		type = inet_addr_type(net, iph->daddr);
		if (type == RTN_LOCAL)
			flags |= FLOWI_FLAG_ANYSRC;
	}

	if (type == RTN_LOCAL) {
		fl.nl_u.ip4_u.daddr = iph->daddr;
		fl.nl_u.ip4_u.saddr = iph->saddr;
		fl.nl_u.ip4_u.tos = RT_TOS(iph->tos);
		fl.flags = flags;
		if (ip_route_output_key(net, &rt, &fl) != 0)
			return -1;

		skb_dst_set(skb, &rt->u.dst);
	} else {
		/* non-local src, find valid iif to satisfy
		 * rp-filter when calling ip_route_input. */
		fl.nl_u.ip4_u.daddr = iph->saddr;
		if (ip_route_output_key(net, &rt, &fl) != 0)
			return -1;

		if (ip_route_input(skb, iph->daddr, iph->saddr,
				   RT_TOS(iph->tos), rt->u.dst.dev) != 0) {
			dst_release(&rt->u.dst);
			return -1;
		}
		dst_release(&rt->u.dst);
	}

	if (skb_dst(skb)->error)
		return -1;

	return 0;
}

static int get_mtu(const struct dst_entry *dst)
{
	int mtu;

	mtu = dst_mtu(dst);
	if (mtu)
		return mtu;

	return dst->dev ? dst->dev->mtu : 0;
}

static int get_advmss(const struct dst_entry *dst)
{
	int advmss;

	advmss = dst_metric(dst, RTAX_ADVMSS);
	if (advmss)
		return advmss;
	advmss = get_mtu(dst);
	if (advmss)
		return advmss - (sizeof(struct iphdr) + sizeof(struct tcphdr));

	return TCP_MSS_DEFAULT;
}

static int tcp_send(__be32 src, __be32 dst, __be16 sport, __be16 dport,
		    u32 seq, u32 ack_seq, __be16 window, u16 mss,
		    __be32 tcp_flags, u8 tos, struct net_device *dev, int flags,
		    const struct iphdr *oiph, const struct tcphdr *otcph)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int err, len;
	u16 advmss;

	len = sizeof(*iph) + sizeof(*tcph);
	if (mss)
		len += TCPOLEN_MSS;

	skb = alloc_skb(LL_MAX_HEADER + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_MAX_HEADER);

	skb_reset_network_header(skb);
	iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
	iph->version	= 4;
	iph->ihl	= sizeof(*iph) / 4;
	iph->tos	= tos;
	/* tot_len is set in ip_local_out() */
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->protocol	= IPPROTO_TCP;
	iph->check	= 0;
	iph->saddr	= src;
	iph->daddr	= dst;

	len -= sizeof(*iph);
	tcph = (struct tcphdr *)skb_put(skb, len);
	tcph->source	= sport;
	tcph->dest	= dport;
	tcph->seq	= htonl(seq);
	tcph->ack_seq	= htonl(ack_seq);
	tcp_flag_word(tcph) = tcp_flags;
	tcph->doff	= len / 4;
	tcph->window	= window;
	tcph->check	= 0;
	tcph->urg_ptr	= 0;

	err = syn_proxy_route(skb, dev_net(dev));
	if (err)
		goto err_out;

	if (mss) {
		advmss = get_advmss(skb_dst(skb));
		if (mss < advmss)
			advmss = mss;
	}
	
	if ((flags & TCP_SEND_FLAG_SYNCOOKIE)) {
		if (!mss)
			advmss = TCP_MSS_DEFAULT;
		tcph->seq = htonl(cookie_v4_init_sequence(oiph, otcph,
				  &advmss));
	}

	if (mss)
		* (__force __be32 *)(tcph + 1) = htonl((TCPOPT_MSS << 24) |
						       (TCPOLEN_MSS << 16) |
						       advmss);
	tcph->check	= tcp_v4_check(len, src, dst,
				       csum_partial(tcph, len, 0));

	iph->ttl	= dst_metric(skb_dst(skb), RTAX_HOPLIMIT);
	skb->ip_summed	= CHECKSUM_NONE;

	if (skb->len > get_mtu(skb_dst(skb))) {
		if (printk_ratelimit())
			pr_warning("%s has smaller mtu: %d\n",
				   skb_dst(skb)->dev->name,
				   get_mtu(skb_dst(skb)));
		err = -EINVAL;
		goto err_out;
	}

	if ((flags & TCP_SEND_FLAG_NOTRACE)) {
		skb->nfct = &nf_conntrack_untracked.ct_general;
		skb->nfctinfo = IP_CT_NEW;
		nf_conntrack_get(skb->nfct);
	}

	pr_debug("tcp_send: %pI4n:%hu -> %pI4n:%hu (seq=%u, "
		 "ack_seq=%u mss=%hu flags=%x)\n", &src, ntohs(sport), &dst,
		 ntohs(dport), ntohl(tcph->seq), ack_seq, mss ? advmss : 0,
		 ntohl(tcp_flags));

	err = ip_local_out(skb);
	if (err > 0)
		err = net_xmit_errno(err);

	pr_debug("tcp_send: finish");

	return err;

err_out:
	if (err)
		kfree_skb(skb);

	return err;
}

static int get_mss(u8 *data, int len)
{
	u8 olen;

	while (len >= TCPOLEN_MSS) {
		switch (data[0]) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:
			data++;
			len--;
			break;
		case TCPOPT_MSS:
			if (data[1] != TCPOLEN_MSS)
				return -EINVAL;
			return get_unaligned_be16(data + 2);
		default:
			olen = data[1];
			if (olen < 2 || olen > len)
				return -EINVAL;
			data += olen;
			len -= olen;
			break;
		}
	}

	return 0;
}

static DEFINE_PER_CPU(struct sk_buff *, syn_proxy_skb);

/* syn_proxy_pre isn't under the protection of nf_conntrack_proto_tcp.c */
static int syn_proxy_pre(struct sk_buff *skb, struct nf_conn *ct,
			 struct tcphdr *th)
{
	struct syn_proxy_state *state;

	/* only support IPv4 now */
	if (ip_hdr(skb)->version != 4)
		return NF_ACCEPT;

	if (!nf_ct_is_confirmed(ct)) {
		struct sk_buff *oskb;
		int ret;

		if (!th->syn || th->ack)
			return NF_ACCEPT;

		local_bh_disable();
		ret = NF_ACCEPT;
		oskb = __get_cpu_var(syn_proxy_skb);
		if (oskb != NULL) {
			struct tcphdr *oth;
			struct iphdr *iph, *oiph;

			iph = ip_hdr(skb);
			oiph = ip_hdr(oskb);
			oth = (struct tcphdr *)(oskb->data + oiph->ihl * 4);
			if (iph->saddr == oiph->saddr &&
			    iph->daddr == oiph->daddr &&
			    *(__force u32 *)th == *(__force u32 *)oth) {
				state = nf_ct_ext_add(ct, NF_CT_EXT_SYNPROXY,
						      GFP_ATOMIC);
				if (state != NULL) {
					state->seq_inited = 0;
					state->window = oth->window;
					state->seq_diff = ntohl(oth->ack_seq)
							  - 1;
					pr_debug("seq_diff: %u\n",
						 state->seq_diff);
				} else {
					ret = NF_DROP;
				}
			}
		}
		local_bh_enable();

		return ret;
	}

	state = nf_ct_ext_find(ct, NF_CT_EXT_SYNPROXY);
	if (!state)
		return NF_ACCEPT;

	if (CTINFO2DIR(skb->nfctinfo) == IP_CT_DIR_ORIGINAL) {
		__be32 newack;

		/* don't need to mangle duplicate SYN packets */
		if (th->syn && !th->ack)
			return NF_ACCEPT;
		if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*th)))
			return NF_DROP;
		th = (struct tcphdr *)(skb->data + ip_hdrlen(skb));
		newack = htonl(ntohl(th->ack_seq) - state->seq_diff);
		inet_proto_csum_replace4(&th->check, skb, th->ack_seq, newack,
					 0);
		pr_debug("alter ack seq: %u -> %u\n",
			 ntohl(th->ack_seq), ntohl(newack));
		th->ack_seq = newack;
	} else {
		/* Simultaneous open ? Oh, no. The connection between
		 * client and us is established. */
		if (th->syn && !th->ack)
			return NF_DROP;
	}

	return NF_ACCEPT;
}

static int syn_proxy_post(struct sk_buff *skb, struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo)
{
	struct syn_proxy_state *state;
	struct iphdr *iph;
	struct tcphdr *th;

	/* untraced packets don't have NF_CT_EXT_SYNPROXY ext, as they don't
	 * enter syn_proxy_pre() */
	state = nf_ct_ext_find(ct, NF_CT_EXT_SYNPROXY);
	if (state == NULL)
		return NF_ACCEPT;
	
	iph = ip_hdr(skb);
	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(*th)))
		return NF_DROP;
	th = (struct tcphdr *)(skb->data + iph->ihl * 4);
	if (!state->seq_inited) {
		if (th->syn) {
			/* It must be from original direction, as the ones
			 * from the other side are dropped in function
			 * syn_proxy_pre() */
			if (!th->ack)
				return NF_ACCEPT;

			pr_debug("SYN-ACK %pI4n:%hu -> %pI4n:%hu "
				 "(seq=%u ack_seq=%u)\n",
				 &iph->saddr, ntohs(th->source), &iph->daddr,
				 ntohs(th->dest), ntohl(th->seq),
				 ntohl(th->ack_seq));

			/* SYN-ACK from reply direction with the protection
			 * of conntrack */
			spin_lock_bh(&ct->lock);
			if (!state->seq_inited) {
				state->seq_inited = 1;
				pr_debug("update seq_diff %u -> %u\n",
					 state->seq_diff,
					 state->seq_diff - ntohl(th->seq));
				state->seq_diff -= ntohl(th->seq);
			}
			spin_unlock_bh(&ct->lock);
			tcp_send(iph->daddr, iph->saddr, th->dest, th->source,
				 ntohl(th->ack_seq),
				 ntohl(th->seq) + 1 + state->seq_diff,
				 state->window, 0, TCP_FLAG_ACK, iph->tos,
				 skb->dev, 0, NULL, NULL);
			tcp_send(iph->saddr, iph->daddr, th->source, th->dest,
				 ntohl(th->seq) + 1, ntohl(th->ack_seq),
				 th->window, 0, TCP_FLAG_ACK, iph->tos,
				 skb->dev, 0, NULL, NULL);

			return NF_DROP;
		} else {
			__be32 newseq;

			if (!th->rst)
				return NF_ACCEPT;
			newseq = htonl(state->seq_diff + 1);
			inet_proto_csum_replace4(&th->check, skb, th->seq,
						 newseq, 0);
			pr_debug("alter RST seq: %u -> %u\n",
				 ntohl(th->seq), ntohl(newseq));
			th->seq = newseq;

			return NF_ACCEPT;
		}
	}

	/* ct should be in ESTABLISHED state, but if the ack packets from
	 * us are lost. */
	if (th->syn) {
		if (!th->ack)
			return NF_ACCEPT;

		tcp_send(iph->daddr, iph->saddr, th->dest, th->source,
			 ntohl(th->ack_seq),
			 ntohl(th->seq) + 1 + state->seq_diff,
			 state->window, 0, TCP_FLAG_ACK, iph->tos,
			 skb->dev, 0, NULL, NULL);
		tcp_send(iph->saddr, iph->daddr, th->source, th->dest,
			 ntohl(th->seq) + 1, ntohl(th->ack_seq),
			 th->window, 0, TCP_FLAG_ACK, iph->tos,
			 skb->dev, 0, NULL, NULL);

		return NF_DROP;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY) {
		__be32 newseq;

		newseq = htonl(ntohl(th->seq) + state->seq_diff);
		inet_proto_csum_replace4(&th->check, skb, th->seq, newseq, 0);
		pr_debug("alter seq: %u -> %u\n", ntohl(th->seq),
			 ntohl(newseq));
		th->seq = newseq;
	}

	return NF_ACCEPT;
}

static int process_tcp(struct sk_buff *skb, unsigned int hook)
{
	const struct iphdr *iph;
	const struct tcphdr *tcph;
	int err;
	u16 mss;

	iph = ip_hdr(skb);

	if (iph->frag_off & htons(IP_OFFSET))
		return -EINVAL;
	err = skb_linearize(skb);
	if (err)
		return err;
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*tcph)))
		return -EINVAL;
	if (nf_ip_checksum(skb, hook, iph->ihl * 4, IPPROTO_TCP))
		return -EINVAL;

	tcph = (const struct tcphdr *)(skb->data + iph->ihl * 4);
	mss = 0;
	if (tcph->doff > sizeof(*tcph) / 4) {
		if (!pskb_may_pull(skb, (iph->ihl + tcph->doff) * 4))
			return -EINVAL;
		err = get_mss((u8 *)(tcph + 1), tcph->doff * 4 - sizeof(*tcph));
		if (err < 0)
			return -EINVAL;
		if (err != 0)
			mss = err;
	} else if (tcph->doff != sizeof(*tcph) / 4)
		return -EINVAL;

	if (tcph->fin || tcph->rst)
		return -EINVAL;
	if (tcph->syn && !tcph->ack) {
		return tcp_send(iph->daddr, iph->saddr, tcph->dest,
				tcph->source, 0, ntohl(tcph->seq) + 1,
				htons(SYN_PROXY_WINDOW), mss,
				TCP_FLAG_SYN | TCP_FLAG_ACK, iph->tos,
				skb->dev, TCP_SEND_FLAG_NOTRACE |
				TCP_SEND_FLAG_SYNCOOKIE, iph, tcph);
	} else if (!tcph->syn && tcph->ack) {
		mss = cookie_v4_check_sequence(iph, tcph,
					       ntohl(tcph->ack_seq) - 1);
		if (!mss)
			return -EINVAL;

		pr_debug("%pI4n:%hu -> %pI4n:%hu(mss=%hu)\n",
			 &iph->saddr, ntohs(tcph->source),
			 &iph->daddr, ntohs(tcph->dest), mss);

		/* FIXME: do we need to check if there is tcp payload? */

		__get_cpu_var(syn_proxy_skb) = skb;
		err = tcp_send(iph->saddr, iph->daddr, tcph->source, tcph->dest,
			       ntohl(tcph->seq) - 1, 0, tcph->window,
			       mss, TCP_FLAG_SYN, iph->tos, skb->dev, 0, NULL,
			       NULL);
		__get_cpu_var(syn_proxy_skb) = NULL;
		if (err) {
			/* We can't send SYN packet successfully, and we'd
			 * better send RST to the original client to close
			 * the connection. */
			tcp_send(iph->daddr, iph->saddr, tcph->dest,
				 tcph->source, ntohl(tcph->ack_seq),
				 ntohl(tcph->seq), 0, 0, TCP_FLAG_RST, iph->tos,
				 skb->dev, TCP_SEND_FLAG_NOTRACE, NULL, NULL);
		}

		return 0;
	}

	return -EINVAL;
}

static unsigned int synproxy_tg(struct sk_buff *skb,
				const struct xt_action_param *par)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct && nf_ct_is_confirmed(ct))
		return IPT_CONTINUE;

	if (process_tcp(skb, par->hooknum) == 0)
		return NF_DROP;

	return IPT_CONTINUE;
}

static struct xt_target synproxy_tg_reg __read_mostly = {
	.name		= "SYNPROXY",
	.family		= NFPROTO_IPV4,
	.target		= synproxy_tg,
	.table		= "mangle",
	.hooks		= (1 << NF_INET_PRE_ROUTING),
	.proto		= IPPROTO_TCP,
	.me		= THIS_MODULE,
};

static struct nf_ct_ext_type syn_proxy_state_ext __read_mostly = {
	.len	= sizeof(struct syn_proxy_state),
	.align	= __alignof__(struct syn_proxy_state),
	.id	= NF_CT_EXT_SYNPROXY,
};

static int __init synproxy_tg_init(void)
{
	int err, cpu;

	for_each_possible_cpu(cpu)
		per_cpu(syn_proxy_skb, cpu) = NULL;
	rcu_assign_pointer(syn_proxy_pre_hook, syn_proxy_pre);
	rcu_assign_pointer(syn_proxy_post_hook, syn_proxy_post);
	err = nf_ct_extend_register(&syn_proxy_state_ext);
	if (err)
		goto err_out;
	err = xt_register_target(&synproxy_tg_reg);
	if (err)
		goto err_out2;

	return err;

err_out2:
	nf_ct_extend_unregister(&syn_proxy_state_ext);
err_out:
	rcu_assign_pointer(syn_proxy_post_hook, NULL);
	rcu_assign_pointer(syn_proxy_pre_hook, NULL);
	rcu_barrier();

	return err;
}

static void __exit synproxy_tg_exit(void)
{
	xt_unregister_target(&synproxy_tg_reg);
	nf_ct_extend_unregister(&syn_proxy_state_ext);
	rcu_assign_pointer(syn_proxy_post_hook, NULL);
	rcu_assign_pointer(syn_proxy_pre_hook, NULL);
	rcu_barrier();
}

module_init(synproxy_tg_init);
module_exit(synproxy_tg_exit);
