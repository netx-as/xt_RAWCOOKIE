/*
 * Based on module created by Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SYNPROXY.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#include <linux/netfilter/nf_synproxy.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <net/netfilter/nf_synproxy.h>
#endif

#include "xt_RAWCOOKIE.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#error "The module is not supported on this kernel. Use >= 3.10.0"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
static unsigned int
synproxy_options_size(const struct synproxy_options *opts)
{
	unsigned int size = 0;

	if (opts->options & NF_SYNPROXY_OPT_MSS)
		size += TCPOLEN_MSS_ALIGNED;
	if (opts->options & NF_SYNPROXY_OPT_TIMESTAMP)
		size += TCPOLEN_TSTAMP_ALIGNED;
	else if (opts->options & NF_SYNPROXY_OPT_SACK_PERM)
		size += TCPOLEN_SACKPERM_ALIGNED;
	if (opts->options & NF_SYNPROXY_OPT_WSCALE)
		size += TCPOLEN_WSCALE_ALIGNED;

	return size;
}


static void
synproxy_build_options(struct tcphdr *th, const struct synproxy_options *opts)
{
	__be32 *ptr = (__be32 *)(th + 1);
	u8 options = opts->options;

	if (options & NF_SYNPROXY_OPT_MSS)
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss_option);

	if (options & NF_SYNPROXY_OPT_TIMESTAMP) {
		if (options & NF_SYNPROXY_OPT_SACK_PERM)
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		else
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);

		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	} else if (options & NF_SYNPROXY_OPT_SACK_PERM)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);

	if (options & NF_SYNPROXY_OPT_WSCALE)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->wscale);
}
#endif

static int
rawcookie_ip_route_me_harder(struct net *net, struct sk_buff *skb, unsigned int addr_type)
{
//    struct net *net = dev_net(skb_dst(skb)->dev);
    const struct iphdr *iph = ip_hdr(skb);
    struct rtable *rt;
    struct flowi4 fl4 = {};
    __be32 saddr = iph->saddr;
    __u8 flags = skb->sk ? inet_sk_flowi_flags(skb->sk) : 0;
    unsigned int hh_len;

    if (addr_type == RTN_UNSPEC)
        addr_type = inet_addr_type(net, saddr);
    if (addr_type == RTN_LOCAL || addr_type == RTN_UNICAST)
        flags |= FLOWI_FLAG_ANYSRC;
    else
        saddr = 0;

    /* 	some non-standard hacks like ipt_REJECT.c:send_reset() can cause
		packets with foreign saddr to appear on the NF_INET_LOCAL_OUT hook. */
    fl4.daddr = iph->daddr;
    fl4.saddr = saddr;
    fl4.flowi4_tos = RT_TOS(iph->tos);
    fl4.flowi4_oif = skb->sk ? skb->sk->sk_bound_dev_if : 0;
    fl4.flowi4_mark = skb->mark;
    fl4.flowi4_flags = flags;
    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
        return PTR_ERR(rt);

    /* Drop old route. */
    skb_dst_drop(skb);
    skb_dst_set(skb, &rt->dst);

    if (skb_dst(skb)->error)
        return skb_dst(skb)->error;

    /* Change in oif may mean change in hh_len. */
    hh_len = skb_dst(skb)->dev->hard_header_len;
    if (skb_headroom(skb) < hh_len &&
        pskb_expand_head(skb, HH_DATA_ALIGN(hh_len - skb_headroom(skb)),
                0, GFP_ATOMIC))
        return -ENOMEM;

    return 0;
}


static struct iphdr *
rawcookie_build_ip(struct net *net, struct sk_buff *skb, u32 saddr, u32 daddr)
{
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
	iph->version	= 4;
	iph->ihl	= sizeof(*iph) / 4;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	iph->ttl = net->ipv4.sysctl_ip_default_ttl;
#else
	iph->ttl = net->ipv4_sysctl_ip_default_ttl;
#endif
	iph->protocol	= IPPROTO_TCP;
	iph->check	= 0;
	iph->saddr	= saddr;
	iph->daddr	= daddr;

	return iph;
}

static void
rawcookie_send_tcp(struct net *net,
  const struct sk_buff *skb, struct sk_buff *nskb,
		  struct nf_conntrack *nfct, enum ip_conntrack_info ctinfo,
		  struct iphdr *niph, struct tcphdr *nth,
		  unsigned int tcp_hdr_size)
{

	nth->check = ~tcp_v4_check(tcp_hdr_size, niph->saddr, niph->daddr, 0);
	nskb->ip_summed   = CHECKSUM_PARTIAL;
	nskb->csum_start  = (unsigned char *)nth - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	skb_dst_set_noref(nskb, skb_dst(skb));
	nskb->protocol = htons(ETH_P_IP);

	if (rawcookie_ip_route_me_harder(net, nskb, RTN_UNSPEC)) {
		goto free_nskb;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip_local_out(net, nskb->sk, nskb);
#else
	ip_local_out(nskb);
#endif

	return;

free_nskb:
	kfree_skb(nskb);
}


static void
rawcookie_send_tcp_raw(struct net *net,
  const struct sk_buff *skb, struct sk_buff *nskb,
		  struct nf_conntrack *nfct, enum ip_conntrack_info ctinfo,
		  struct iphdr *niph, struct tcphdr *nth,
		  unsigned int tcp_hdr_size,
		  const struct xt_rawcookie_info *info)
{

	struct ethhdr *eth_h;  /* Ethernet header */

	nth->check = ~tcp_v4_check(tcp_hdr_size, niph->saddr, niph->daddr, 0);
	nskb->ip_summed   = CHECKSUM_PARTIAL;
	nskb->csum_start  = (unsigned char *)nth - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);

	skb_dst_set_noref(nskb, skb_dst(skb));
	nskb->protocol = htons(ETH_P_IP);

	nskb->dev = skb->dev;

	/* Add a custom ethernet header so we can send the packet */
	eth_h = (struct ethhdr *) skb_push(nskb, ETH_HLEN);

	memcpy(eth_h->h_source, nskb->dev->dev_addr, ETH_ALEN);

	if (info->options & XT_RAWCOOKIE_OPT_TXMAC) {
		memcpy(eth_h->h_dest, info->txmac, ETH_ALEN);
	} else {
		struct ethhdr *rec_eth_h = eth_hdr(skb);
		if (rec_eth_h != NULL) {
			memcpy(eth_h->h_dest, rec_eth_h->h_source, ETH_ALEN);
		} else {
			pr_debug("xt_rawcookie2: received pck src mac address copy failed.\n");
			kfree_skb(nskb);
			return;
		}
	}

	eth_h->h_proto = nskb->protocol;

	/* dev_queue_xmit always consumes the buffer, regardless of the return value. */
	dev_queue_xmit(nskb);
}


static void
rawcookie_send_client_synack(struct net *net,
			    const struct sk_buff *skb, const struct tcphdr *th,
			    u16 client_mss,
			    struct synproxy_options *opts,
				const struct xt_rawcookie_info *info)
{
	struct sk_buff *nskb;
	struct iphdr *iph, *niph;
	struct tcphdr *nth;
	unsigned int tcp_hdr_size;

	iph = ip_hdr(skb);

	tcp_hdr_size = sizeof(*nth) + synproxy_options_size(opts);
	nskb = alloc_skb(sizeof(*niph) + tcp_hdr_size + MAX_TCP_HEADER,
			 GFP_ATOMIC);
	if (nskb == NULL)
		return;
	skb_reserve(nskb, MAX_TCP_HEADER);

	niph = rawcookie_build_ip(net, nskb, iph->daddr, iph->saddr);

	skb_reset_transport_header(nskb);
	nth = (struct tcphdr *)skb_put(nskb, tcp_hdr_size);
	nth->source	= th->dest;
	nth->dest	= th->source;
	nth->seq	= htonl(__cookie_v4_init_sequence(iph, th, &client_mss));
	nth->ack_seq	= htonl(ntohl(th->seq) + 1);
	tcp_flag_word(nth) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (opts->options & XT_RAWCOOKIE_OPT_ECN)
		tcp_flag_word(nth) |= TCP_FLAG_ECE;
	nth->doff	= tcp_hdr_size / 4;
	nth->window	= 0;
	nth->check	= 0;
	nth->urg_ptr	= 0;

	synproxy_build_options(nth, opts);
	nskb->priority = 1;

	nskb->queue_mapping = skb->queue_mapping;


	if (info->options & XT_RAWCOOKIE_OPT_SENDDIRECT) {
		rawcookie_send_tcp_raw(net, skb, nskb, NULL,
			IP_CT_ESTABLISHED_REPLY, niph, nth, tcp_hdr_size, info);
	} else {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		nskb->nfct = &nf_ct_untracked_get()->ct_general;
		nskb->nfctinfo = IP_CT_NEW;
		nf_conntrack_get(nskb->nfct);
#else
		/* backported from kernel 4.11 - centos7 */
		nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#endif
		rawcookie_send_tcp(net, skb, nskb, NULL,
			IP_CT_ESTABLISHED_REPLY, niph, nth, tcp_hdr_size);
	}
}


void
rawcookie_init_timestamp_cookie(const struct xt_rawcookie_info *info,
				    struct synproxy_options *opts)
{
	opts->tsecr = opts->tsval;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	opts->tsval = tcp_clock_ms() & ~0x3f;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	opts->tsval = tcp_time_stamp_raw() & ~0x3f;
#else
	opts->tsval = tcp_time_stamp & ~0x3f;
#endif
	if (opts->options & XT_RAWCOOKIE_OPT_WSCALE) {
		opts->tsval |= opts->wscale;
		opts->wscale = info->wscale;
	} else
		opts->tsval |= 0xf;
	if (opts->options & XT_RAWCOOKIE_OPT_SACK_PERM)
		opts->tsval |= 1 << 4;
	if (opts->options & XT_RAWCOOKIE_OPT_ECN)
		opts->tsval |= 1 << 5;
}


static unsigned int
rawcookie_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_rawcookie_info *info = par->targinfo;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = dev_net(xt_in(par));
#else
	struct net *net = dev_net(par->in);
#endif


	struct synproxy_net *snet = synproxy_pernet(net);
	struct synproxy_options opts = {};
	struct tcphdr *th, _th;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	if (nf_ip_checksum(skb, xt_hooknum(par), par->thoff, IPPROTO_TCP)) {
#else
	if (nf_ip_checksum(skb, par->hooknum, par->thoff, IPPROTO_TCP)) {
#endif
		return NF_DROP;
	}

	th = skb_header_pointer(skb, par->thoff, sizeof(_th), &_th);
	if (th == NULL)
		return NF_DROP;

	if (!synproxy_parse_options(skb, par->thoff, th, &opts)) {
		return NF_DROP;
	}

	if (th->syn && !(th->ack || th->fin || th->rst)) {
		/*
		 * Work around lack of mss_encode in synproxy_options on older kernels
		 * by passing it to rawcookie_send_client_synack using separate argument.
		 */
		u16 client_mss;

		/* Initial SYN from client */
		this_cpu_inc(snet->stats->syn_received);

		if (th->ece && th->cwr)
			opts.options |= XT_RAWCOOKIE_OPT_ECN;

		/*
		 * Reset client provided TCP option to only those present in filter
		 * configuration. This will, for example, cause MSS option to be
		 * left out of SYN/ACK when MSS was not configured when inserting
		 * the filter.
		 */
		opts.options &= info->options;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
		client_mss = opts.mss_option;
		opts.mss_encode = opts.mss_option;
		opts.mss_option = info->mss;
#else
		client_mss = opts.mss;
		opts.mss = info->mss;
#endif
		if (opts.options & XT_RAWCOOKIE_OPT_TIMESTAMP)
			rawcookie_init_timestamp_cookie(info, &opts);
		else
			opts.options &= ~(XT_RAWCOOKIE_OPT_WSCALE |
					  XT_RAWCOOKIE_OPT_SACK_PERM |
					  XT_RAWCOOKIE_OPT_ECN);

		rawcookie_send_client_synack(net, skb, th, client_mss, &opts, info);
		return NF_DROP;

	} else if (th->ack && !(th->fin || th->rst || th->syn)) {
		return NF_DROP;
	}

	return XT_CONTINUE;
}


static int
rawcookie_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_entry *e = par->entryinfo;

	if (e->ip.proto != IPPROTO_TCP ||
	    e->ip.invflags & XT_INV_PROTO)
		return -EINVAL;

	return nf_ct_netns_get(par->net, par->family);
}


static void rawcookie_tg4_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}


static struct xt_target synproxy_tg4_reg __read_mostly = {
	.name		= "RAWCOOKIE",
	.family		= NFPROTO_IPV4,
	.target		= rawcookie_tg4,
	.targetsize	= sizeof(struct xt_rawcookie_info),
	.checkentry	= rawcookie_tg4_check,
	.destroy	= rawcookie_tg4_destroy,
	.me		= THIS_MODULE,
};

static int __init synproxy_tg4_init(void)
{
	int err;

	err = xt_register_target(&synproxy_tg4_reg);
	return err;
}

static void __exit synproxy_tg4_exit(void)
{
	xt_unregister_target(&synproxy_tg4_reg);
}

module_init(synproxy_tg4_init);
module_exit(synproxy_tg4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomas Podermanski <tpoder@netx.as>");
MODULE_DESCRIPTION("SYNCOOKIE performance helper module for SYNPROXY");
