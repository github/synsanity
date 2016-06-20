/* Kernel module to match syncookie metadata
 *
 * Copyright (c) 2015 Theo Julienne <theo@github.com>
 *
 * Based on xt_state.c:
 * Copyright (c) 1999-2001 Paul `Rusty' Russell
 * Copyright (c) 2002-2005 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <net/tcp.h>
#include "xt_syncookies.h"

static inline int
inet_csk_reqsk_queue_is_above_percent(const struct sock *sk, uint8_t percent)
{
	const struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	unsigned int watermark = (queue->listen_opt->nr_table_entries * percent) / 100;
	return reqsk_queue_len(queue) > watermark;
}

static bool
syncookies_accepted(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_syncookies_info *sinfo = par->matchinfo;
	struct iphdr *iph;
	struct tcphdr *th, _th;
	const struct net_device *net_dev = (par->in ? par->in : par->out);
	struct net *net;
	struct sock *listen_sk;
	bool want_cookie = false;

	/* Early exit, wont be allowed regardless of count */
	if (sysctl_tcp_syncookies == 0)
		return false;

	if (net_dev == NULL)
		return false;

	net = dev_net(net_dev);
	if (net == NULL)
		return false;

	th = skb_header_pointer(skb, par->thoff, sizeof(_th), &_th);
	if (th == NULL)
		return false;

	iph = ip_hdr(skb);
	if (iph == NULL)
		return false;

	/* Find a LISTEN socket for this packet, if available. */
	listen_sk = inet_lookup_listener(net, &tcp_hashinfo,
			iph->saddr, th->source,
			iph->daddr, th->dest, net_dev->ifindex);

	/* Perform the usual check for whether a syncookie ACK would be accepted
	 * right now. */
	if (listen_sk) {
		if (sinfo->mode == O_XT_SYNCOOKIES_SENT) {
			want_cookie = (sysctl_tcp_syncookies == 2 ||
				inet_csk_reqsk_queue_is_full(listen_sk));
		} else if (sinfo->mode == O_XT_SYNCOOKIES_ACCEPTED) {
			want_cookie = !tcp_synq_no_recent_overflow(listen_sk);
		} else if (sinfo->mode == O_XT_SYNCOOKIES_LEVEL) {
			want_cookie = inet_csk_reqsk_queue_is_above_percent(
				listen_sk, sinfo->queue_level_percent);
		}
		sock_put(listen_sk);
	}

	return want_cookie;
}

static bool
syncookies_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_syncookies_info *sinfo = par->matchinfo;

	bool result = syncookies_accepted(skb, par);

	if (sinfo->invert)
		result = !result;

	return result;
}

static int syncookies_mt_check(const struct xt_mtchk_param *par)
{
	return 0;
}

static void syncookies_mt_destroy(const struct xt_mtdtor_param *par)
{

}

static struct xt_match syncookies_mt_reg __read_mostly = {
	.name       = "syncookies",
	.family     = NFPROTO_UNSPEC,
	.checkentry = syncookies_mt_check,
	.match      = syncookies_mt,
	.destroy    = syncookies_mt_destroy,
	.matchsize  = sizeof(struct xt_syncookies_info),
	.me         = THIS_MODULE,
};

static int __init syncookies_mt_init(void)
{
	return xt_register_match(&syncookies_mt_reg);
}

static void __exit syncookies_mt_exit(void)
{
	xt_unregister_match(&syncookies_mt_reg);
}

module_init(syncookies_mt_init);
module_exit(syncookies_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Theo Julienne <theo@github.com>");
MODULE_DESCRIPTION("ip[6]_tables syncookie metadata match module");
MODULE_ALIAS("ipt_syncookies");
MODULE_ALIAS("ip6t_syncookies");
