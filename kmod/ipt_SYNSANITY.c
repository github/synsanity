/*
 * Original SYNPROXY code copyright (c) 2013 Patrick McHardy <kaber@trash.net>
 * SYNSANITY modifications copyright (c) 2015 Theo Julienne <theo@github.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SYNPROXY.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_synproxy.h>

static struct iphdr *
synsanity_build_ip(struct sk_buff *skb, u32 saddr, u32 daddr)
{
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
	iph->version	= 4;
	iph->ihl	= sizeof(*iph) / 4;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->ttl	= sysctl_ip_default_ttl;
	iph->protocol	= IPPROTO_TCP;
	iph->check	= 0;
	iph->saddr	= saddr;
	iph->daddr	= daddr;

	return iph;
}

static void
synsanity_send_tcp(const struct sk_buff *skb, struct sk_buff *nskb,
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
	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	if (nfct) {
		nskb->nfct = nfct;
		nskb->nfctinfo = ctinfo;
		nf_conntrack_get(nfct);
	}

	ip_local_out(nskb);
	return;

free_nskb:
	kfree_skb(nskb);
}

static void
synsanity_send_client_synack(const struct sk_buff *skb, const struct tcphdr *th,
			    const struct synproxy_options *opts, struct sock *listen_sk)
{
	struct sk_buff *nskb;
	struct iphdr *iph, *niph;
	struct tcphdr *nth;
	unsigned int tcp_hdr_size;
	u16 mss = opts->mss;

	iph = ip_hdr(skb);

	tcp_hdr_size = sizeof(*nth) + synproxy_options_size(opts);
	nskb = alloc_skb(sizeof(*niph) + tcp_hdr_size + MAX_TCP_HEADER,
			 GFP_ATOMIC);
	if (nskb == NULL)
		return;
	skb_reserve(nskb, MAX_TCP_HEADER);

	niph = synsanity_build_ip(nskb, iph->daddr, iph->saddr);

	skb_reset_transport_header(nskb);
	nth = (struct tcphdr *)skb_put(nskb, tcp_hdr_size);
	nth->source	= th->dest;
	nth->dest	= th->source;
	nth->seq	= htonl(__cookie_v4_init_sequence(iph, th, &mss));
	nth->ack_seq	= htonl(ntohl(th->seq) + 1);
	tcp_flag_word(nth) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (opts->options & XT_SYNPROXY_OPT_ECN)
		tcp_flag_word(nth) |= TCP_FLAG_ECE;
	nth->doff	= tcp_hdr_size / 4;
	nth->window = htons(min((u32)th->window, 65535U));
	nth->check	= 0;
	nth->urg_ptr	= 0;

	/* Match the stats and overflow marking performed by the core tcp stack.
	 * This must be done without a lock. We write to the timestamp field even
	 * though we don't hold a lock, which shouldn't be an issue since it's not
	 * used on the LISTEN socket by anything else, and it's just an integer.
	 * The stats call is per-cpu and so is safe to call outside a lock.
	 */
	{
		struct net *net = dev_net(skb_dst(skb)->dev);
		NET_INC_STATS_BH(net, LINUX_MIB_SYNCOOKIESSENT);

		if (listen_sk)
			tcp_synq_overflow(listen_sk);
	}

	synproxy_build_options(nth, opts);

	synsanity_send_tcp(skb, nskb, skb->nfct, IP_CT_ESTABLISHED_REPLY,
			  niph, nth, tcp_hdr_size);
}

/* Cleans up a connection matching the provided skb from conntrack.
 * This is used for TIME_WAIT assassination to keep conntrack in sync.
 * Based on: http://lxr.free-electrons.com/source/net/netfilter/nf_conntrack_netlink.c#L1081
 */
static void
synsanity_nf_ct_delete_from_skb(struct sk_buff *skb)
{
	const struct nf_conntrack_tuple_hash *thash;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb), NFPROTO_IPV4, &tuple))
		return;

	thash = nf_conntrack_find_get(dev_net(skb->dev), NF_CT_DEFAULT_ZONE, &tuple);
	if (!thash)
		return;

	ct = nf_ct_tuplehash_to_ctrack(thash);

	if (del_timer(&ct->timeout))
		nf_ct_delete(ct, 0, 0);

	nf_ct_put(ct);
}

#define TSBITS	6
#define TSMASK	(((__u32)1 << TSBITS) - 1)

static unsigned int
synsanity_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_synproxy_info *info = par->targinfo;
	struct synproxy_net *snet = synproxy_pernet(dev_net(par->in));
	struct synproxy_options opts = {};
	struct tcphdr *th, _th;
	struct sock *listen_sk;
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct iphdr *iph;
	unsigned int action = XT_CONTINUE;

	/* If syncookies are globally disabled, let packets through immediately.
	 * SYNSANITY won't work without syncookies enabled anyway.
	 */
	if (sysctl_tcp_syncookies == 0)
		return XT_CONTINUE;

	if (nf_ip_checksum(skb, par->hooknum, par->thoff, IPPROTO_TCP))
		return NF_DROP;

	th = skb_header_pointer(skb, par->thoff, sizeof(_th), &_th);
	if (th == NULL)
		return NF_DROP;

	if (!synproxy_parse_options(skb, par->thoff, th, &opts))
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph == NULL)
		return NF_DROP;

	/* We only want SYN and ACK by themselves */
	if (th->fin || th->rst || (th->syn && th->ack))
		return XT_CONTINUE;

	/* Find a LISTEN socket for this packet, if available. */
	listen_sk = inet_lookup_listener(net, &tcp_hashinfo,
			iph->saddr, th->source,
			iph->daddr, th->dest, inet_iif(skb));

	if (th->syn) {
		/* Initial SYN from client */
		this_cpu_inc(snet->stats->syn_received);

		/* Check for SYNs received while an existing socket with the same tuple
		 * is in TIME_WAIT state. This is commonly called "TIME_WAIT assassination",
		 * and is implemented in the kernel by default. However, the core TCP stack
		 * cannot tell the difference between a new syncookie ACK and any other ACK,
		 * so we need to perform this cleanup ourselves on the SYN itself.
		 * Thankfully, this doesn't seem to require any locking.
		 */
		{
			struct sock *nsk;

			nsk = inet_lookup_established(dev_net(skb->dev), &tcp_hashinfo,
						iph->saddr, th->source,
						iph->daddr, th->dest,
						inet_iif(skb));

			if (nsk) {
				if (nsk->sk_state == TCP_TIME_WAIT) {
					// from tcp_ipv4.c: check if the SYN is a valid reuse
					if (tcp_timewait_state_process(inet_twsk(nsk), skb, th) == TCP_TW_SYN) {
						// if it is, complete the old socket to prep for the new one
						inet_twsk_deschedule(inet_twsk(nsk), &tcp_death_row);

						// also update conntrack entry, if available
						synsanity_nf_ct_delete_from_skb(skb);
					}
					inet_twsk_put(inet_twsk(nsk));
				} else {
					sock_put(nsk);
				}
			}
		}

		if (th->ece && th->cwr)
			opts.options |= XT_SYNPROXY_OPT_ECN;

		opts.options &= info->options;
		if (opts.options & XT_SYNPROXY_OPT_TIMESTAMP) {
			synproxy_init_timestamp_cookie(info, &opts);

			/* since this was reimplemented in SYNPROXY and not quite the same,
			 * lets now re-adjust the timestamp to be compatible with the ones
			 * generated by core linux. primarily, the always-increasing check.
			 * see: cookie_init_timestamp@syncookies.c
			 */
			{
				u32 ts_now = tcp_time_stamp;
				u32 options = opts.tsval & TSMASK;
				opts.tsval = ts_now & ~TSMASK;
				opts.tsval |= options;
				if (opts.tsval > ts_now) {
					opts.tsval >>= TSBITS;
					opts.tsval--;
					opts.tsval <<= TSBITS;
					opts.tsval |= options;
				}
			}
		} else
			opts.options &= ~(XT_SYNPROXY_OPT_WSCALE |
					  XT_SYNPROXY_OPT_SACK_PERM |
					  XT_SYNPROXY_OPT_ECN);

		synsanity_send_client_synack(skb, tcp_hdr(skb), &opts, listen_sk);

		action = NF_DROP;
		goto cleanup;
	} else if (th->ack) {
		/* ACK from client */
		int mss;

		/* If we have a LISTEN socket, check if SYN cookies are valid right now.
		 * When they are valid, pre-validate, and when they aren't, let them through.
		 * Note that ACKs generated by non-syncookie code will never get here since
		 * conntrack will recognise them as part of an ESTABLISHED connection.
		 */
		if (listen_sk) {
			bool want_cookie = (sysctl_tcp_syncookies == 2 ||
			                    !tcp_synq_no_recent_overflow(listen_sk));

			if (!want_cookie) {
				action = XT_CONTINUE;
				goto cleanup;
			}
		}

		/* We pre-validate the cookie in netfilter to avoid making ACK floods lock
		 * in the kernel. Note that only the initial ACK that is not part of a
		 * connection will be sent here by the iptables rules.
		 */
		mss = __cookie_v4_check(ip_hdr(skb), th, ntohl(th->ack_seq) - 1);
		if (mss == 0) {
			NET_INC_STATS_BH(dev_net(skb_dst(skb)->dev), LINUX_MIB_SYNCOOKIESFAILED);
			action = NF_DROP;
		} else {
			action = XT_CONTINUE; // handled by the kernel syncookie code
		}
		goto cleanup;
	}

	action = XT_CONTINUE;

cleanup:
	if (listen_sk)
		sock_put(listen_sk);

	return action;
}

static int synsanity_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_entry *e = par->entryinfo;

	if (e->ip.proto != IPPROTO_TCP ||
	    e->ip.invflags & XT_INV_PROTO)
		return -EINVAL;

	return nf_ct_l3proto_try_module_get(par->family);
}

static void synsanity_tg4_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_l3proto_module_put(par->family);
}

static struct xt_target synsanity_tg4_reg __read_mostly = {
	.name		= "SYNSANITY",
	.family		= NFPROTO_IPV4,
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
	.target		= synsanity_tg4,
	.targetsize	= sizeof(struct xt_synproxy_info),
	.checkentry	= synsanity_tg4_check,
	.destroy	= synsanity_tg4_destroy,
	.me		= THIS_MODULE,
};

static int __init synsanity_tg4_init(void)
{
	int err;

	err = xt_register_target(&synsanity_tg4_reg);
	if (err < 0)
		goto err1;

	return 0;

err1:
	return err;
}

static void __exit synsanity_tg4_exit(void)
{
	xt_unregister_target(&synsanity_tg4_reg);
}

module_init(synsanity_tg4_init);
module_exit(synsanity_tg4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Theo Julienne <theo@github.com>");
