// SPDX-License-Identifier: GPL-2.0-only
/* Carrying a 464XLAT client's connections in the firmware.
 *
 * A CLAT is a nat46 device: what the host routes to it as IPv4 it translates
 * to IPv6 and receives again, now arriving on the device, and the other way
 * round. So the kernel sees two ordinary connections where there is one -
 * an IPv4 one from the LAN to the device, and an IPv6 one from the device
 * to the uplink - and its flow table offers each like any other. Nothing in
 * the offer translates; the device is only an end of each.
 *
 * The firmware has the translator: a MAP-T node pair, given the device's
 * own rules. The inner node takes IPv4 and hands it on as IPv6, the outer
 * the reverse, each to the other connection engine. With the device named by
 * the inner node in its IPv4 rules and by the outer in its IPv6 ones, a
 * packet from the LAN meets the IPv4 rule, is translated, meets the IPv6
 * rule and leaves; the two rules are made independently, as the two offers
 * arrive. That is how the vendor's connection manager named the device too.
 *
 * Until both rules exist a packet falls off the firmware's path half way,
 * translated: the inner node hands up an IPv4 packet with no IPv4 rule, the
 * outer an IPv6 one with no IPv6 rule. Either is what the device itself
 * would have produced, so it goes up the stack as if it had arrived on the
 * device - which is where the host's own path would have put it, and where
 * the missing connection is then seen and offered.
 *
 * Like a modem, the device exists before the core is up and a restart loses
 * the nodes, so the pair is made wherever a running core meets a device that
 * is up. The rules are read when the pair is made; a CLAT whose rules change
 * is taken down and up again by its protocol.
 */

#include <linux/cleanup.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>

#include "nss_drv.h"

/* MAP-T node messages (public nss_map_t.h). */
#define NSS_MAP_T_MSG_INSTANCE_RULE_CONFIGURE	0
#define NSS_MAP_T_MSG_INSTANCE_RULE_DECONFIGURE	1
#define NSS_MAP_T_MSG_SYNC_STATS		2

/* The vendor's limits: four instances, and a rule count it would configure. */
#define NSS_XLAT_MAX		4
#define NSS_XLAT_RULES_MAX	64

/* One rule pair, sent once to each node. Prefixes are host-order words. */
struct nss_map_t_rule_msg {
	u32 rule_num;		/* from 1 */
	u32 total_rules;
	u32 local_ipv6_prefix_len;
	u32 local_ipv4_prefix;
	u32 local_ipv4_prefix_len;
	u32 local_ea_len;
	u32 local_psid_offset;
	u32 reserve_a;
	u32 remote_ipv6_prefix_len;
	u32 remote_ipv4_prefix;
	u32 remote_ipv4_prefix_len;
	u32 remote_ea_len;
	u32 remote_psid_offset;
	u32 local_map_style;
	u32 remote_map_style;
	u32 sibling_if;
	u8 local_ipv6_prefix[16];
	u8 reserve_b[16];
	u8 remote_ipv6_prefix[16];
	u8 valid_rule;
	u8 flags;
	u8 reserved[2];
};

static_assert(sizeof(struct nss_map_t_rule_msg) == 116);

struct nss_map_t_sync_msg {
	struct nss_cmn_node_stats node;
	u32 tx_dropped;
	u32 exception;		/* handed to the host */
	u32 no_rule;		/* no translation rule matched */
	u32 not_tcp_udp;
};

struct nss_map_t_msg {
	struct nss_cmn_msg cm;
	union {
		struct nss_map_t_rule_msg rule;
		s32 if_number;
		struct nss_map_t_sync_msg stats;
	} msg;
};

/* nat46's own rule layout, which it checks the size of. */
enum {
	NSS_XLAT_STYLE_NONE,
	NSS_XLAT_STYLE_MAP,
	NSS_XLAT_STYLE_MAP0,
	NSS_XLAT_STYLE_RFC6052,
};

struct nss_xlat_nat46_rule {
	int style;
	struct in6_addr v6_pref;
	int v6_pref_len;
	__be32 v4_pref;
	int v4_pref_len;
	int ea_len;
	int psid_offset;
	int fmr_flag;
};

struct nss_xlat_nat46_pair {
	struct nss_xlat_nat46_rule local;
	struct nss_xlat_nat46_rule remote;
};

/* Exported by a nat46 that carries the offload patch; looked up rather than
 * linked, so the driver loads without nat46.
 */
int nat46_get_rules(struct net_device *dev, void *pairs, size_t pair_size,
		    int max);

/* The address the firmware frames a packet for the inner node with. The node
 * takes the packet off the frame, so any address will do that an ethernet
 * path does not drop.
 */
const u8 nss_xlat_mac[ETH_ALEN] = { 0x02, 0x46, 0x46, 0x00, 0x00, 0x00 };

/* Per node: what the last statistics push said. */
struct nss_xlat_node {
	u64 rx;
	u64 tx;
	u64 exception;
	u64 no_rule;
};

struct nss_xlat {
	struct net_device *dev;	/* NULL: slot free */
	int ifindex;
	int inner;		/* -1 until a running core gives the pair */
	int outer;
	/* The device while paired, for the receive path. */
	struct net_device __rcu *rdev;
	int rules;
	int tries;		/* refused pairings since the last success */
	u64 back4;		/* came back translated to IPv4, delivered up */
	u64 back6;
	u64 drop;
	struct nss_xlat_node fw[2];	/* inner, outer */
};

/* Written under the RTNL, read from the receive paths. */
static struct nss_xlat nss_xlat_tbl[NSS_XLAT_MAX];
static struct nss_core *nss_xlat_core;

/* The firmware has few translators and frees one given back only some while
 * later - half a minute to a minute on 12.5 - refusing a new one until then.
 * A CLAT that its protocol takes down and brings straight back up is refused
 * that way, so it is asked again later, waiting longer each time up to the
 * longest the firmware was seen to take.
 */
#define NSS_XLAT_TRIES		8
#define NSS_XLAT_WAIT_MAX	(30 * HZ)

static void nss_xlat_retry_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(nss_xlat_retry, nss_xlat_retry_fn);

static bool nss_xlat_enable = true;
module_param_named(xlat, nss_xlat_enable, bool, 0644);
MODULE_PARM_DESC(xlat, "carry 464XLAT (nat46) devices in the firmware; read when a device comes up");

/* @dev's rules, or <0: no nat46, or not one of its devices. May sleep. */
static int nss_xlat_rules(struct net_device *dev,
			  struct nss_xlat_nat46_pair *pairs, int max)
{
	typeof(&nat46_get_rules) get;
	int n;

	get = symbol_get(nat46_get_rules);
	if (!get)
		return -ENOENT;
	n = get(dev, pairs, sizeof(*pairs), max);
	symbol_put(nat46_get_rules);

	return n;
}

static bool nss_xlat_wanted(struct net_device *dev)
{
	return dev->type == ARPHRD_NONE && nss_xlat_rules(dev, NULL, 0) >= 0;
}

static struct nss_xlat *nss_xlat_find(const struct net_device *dev)
{
	int i;

	for (i = 0; i < NSS_XLAT_MAX; i++)
		if (nss_xlat_tbl[i].dev == dev)
			return &nss_xlat_tbl[i];

	return NULL;
}

/* Whether @ifindex is a device the firmware can translate for. */
bool nss_xlat_bound(int ifindex)
{
	int i;

	for (i = 0; i < NSS_XLAT_MAX; i++)
		if (READ_ONCE(nss_xlat_tbl[i].ifindex) == ifindex &&
		    READ_ONCE(nss_xlat_tbl[i].inner) >= 0)
			return true;

	return false;
}

/* Whether @dev is a CLAT whose flow block this driver takes: one in the
 * table, or one the flow table meets before the device's own notification
 * reached it. May sleep.
 */
bool nss_xlat_known(struct net_device *dev)
{
	int i;

	for (i = 0; i < NSS_XLAT_MAX; i++)
		if (READ_ONCE(nss_xlat_tbl[i].dev) == dev)
			return true;

	return nss_xlat_enable && nss_xlat_wanted(dev);
}

/* The node that stands for @ifindex in a rule of one family, and the
 * device's frame size; -ENODEV for a device that is not a bound CLAT.
 */
int nss_xlat_ifnum(int ifindex, bool v6, u32 *mtu)
{
	int i;

	guard(rcu)();

	for (i = 0; i < NSS_XLAT_MAX; i++) {
		struct nss_xlat *x = &nss_xlat_tbl[i];
		struct net_device *dev;
		int node;

		if (READ_ONCE(x->ifindex) != ifindex)
			continue;
		node = v6 ? READ_ONCE(x->outer) : READ_ONCE(x->inner);
		dev = rcu_dereference(x->rdev);
		if (node < 0 || !dev)
			return -ENODEV;
		*mtu = dev->mtu;
		return node;
	}

	return -ENODEV;
}

/* What the firmware can be given of a nat46 rule: what nat46 itself accepts,
 * less what the vendor's client refused to send. A local side of style NONE
 * is a single address each way, which is what a CLAT has.
 */
static bool nss_xlat_rule_ok(const struct nss_xlat_nat46_rule *r, bool local)
{
	int psid_len;

	switch (r->style) {
	case NSS_XLAT_STYLE_NONE:
		return local;
	case NSS_XLAT_STYLE_MAP:
		if (r->ea_len < 0 || r->ea_len > 48)
			return false;
		psid_len = r->v4_pref_len + r->ea_len > 32 ?
			   r->ea_len - (32 - r->v4_pref_len) : 0;
		return psid_len + r->psid_offset <= 16;
	case NSS_XLAT_STYLE_RFC6052:
		switch (r->v6_pref_len) {
		case 32: case 40: case 48: case 56: case 64: case 96:
			return true;
		}
		return false;
	default:
		return false;
	}
}

static void nss_xlat_prefix6(u8 out[16], const struct in6_addr *in)
{
	u32 *w = (u32 *)out;
	int i;

	for (i = 0; i < 4; i++)
		w[i] = ntohl(in->s6_addr32[i]);
}

static int nss_xlat_configure(struct nss_core *core, int node, int sibling,
			      const struct nss_xlat_nat46_pair *p, int num,
			      int total)
{
	struct nss_map_t_msg *m __free(kfree) = kzalloc(sizeof(*m), GFP_KERNEL);
	struct nss_map_t_rule_msg *r;

	if (!m)
		return -ENOMEM;
	r = &m->msg.rule;

	r->rule_num = num;
	r->total_rules = total;

	r->local_map_style = p->local.style;
	nss_xlat_prefix6(r->local_ipv6_prefix, &p->local.v6_pref);
	r->local_ipv6_prefix_len = p->local.v6_pref_len;
	r->local_ipv4_prefix = ntohl(p->local.v4_pref);
	r->local_ipv4_prefix_len = p->local.v4_pref_len;
	r->local_ea_len = p->local.ea_len;
	r->local_psid_offset = p->local.psid_offset;

	r->remote_map_style = p->remote.style;
	nss_xlat_prefix6(r->remote_ipv6_prefix, &p->remote.v6_pref);
	r->remote_ipv6_prefix_len = p->remote.v6_pref_len;
	r->remote_ipv4_prefix = ntohl(p->remote.v4_pref);
	r->remote_ipv4_prefix_len = p->remote.v4_pref_len;
	r->remote_ea_len = p->remote.ea_len;
	r->remote_psid_offset = p->remote.psid_offset;

	r->sibling_if = sibling;
	r->valid_rule = 1;

	m->cm.interface = node;
	m->cm.type = NSS_MAP_T_MSG_INSTANCE_RULE_CONFIGURE;
	return nss_msg_send(core, m, offsetof(struct nss_map_t_msg, msg) +
				     sizeof(*r));
}

static void nss_xlat_deconfigure(struct nss_core *core, int node)
{
	struct nss_map_t_msg m = {};

	m.cm.interface = node;
	m.cm.type = NSS_MAP_T_MSG_INSTANCE_RULE_DECONFIGURE;
	m.msg.if_number = node;
	nss_msg_send(core, &m, offsetof(struct nss_map_t_msg, msg) +
			       sizeof(m.msg.if_number));
}

/* Give @x a node pair on @core with the device's rules, every one of them in
 * both nodes, each naming the other as its sibling. A rule the firmware could
 * not take would leave it translating differently from the device, so a
 * device with one is left to the host.
 */
static int nss_xlat_pair(struct nss_core *core, struct nss_xlat *x)
{
	struct nss_xlat_nat46_pair *pairs __free(kfree) =
		kcalloc(NSS_XLAT_RULES_MAX, sizeof(*pairs), GFP_KERNEL);
	int inner, outer, n, i, ret;

	if (!pairs)
		return -ENOMEM;

	n = nss_xlat_rules(x->dev, pairs, NSS_XLAT_RULES_MAX);
	if (n < 1 || n > NSS_XLAT_RULES_MAX) {
		netdev_warn(x->dev, "not translated by NSS: %d rules\n", n);
		return -EINVAL;
	}
	for (i = 0; i < n; i++) {
		if (!nss_xlat_rule_ok(&pairs[i].local, true) ||
		    !nss_xlat_rule_ok(&pairs[i].remote, false)) {
			netdev_warn(x->dev, "not translated by NSS: rule %d (styles %d/%d)\n",
				    i + 1, pairs[i].local.style,
				    pairs[i].remote.style);
			return -EINVAL;
		}
	}

	inner = nss_flow_dyn_alloc(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_INNER);
	if (inner < 0) {
		ret = inner;
		goto fail;
	}
	outer = nss_flow_dyn_alloc(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_OUTER);
	if (outer < 0) {
		ret = outer;
		goto inner;
	}

	for (i = 0; i < n; i++) {
		ret = nss_xlat_configure(core, inner, outer, &pairs[i], i + 1, n);
		if (ret)
			goto outer;
		ret = nss_xlat_configure(core, outer, inner, &pairs[i], i + 1, n);
		if (ret)
			goto outer;
	}

	dev_hold(x->dev);
	rcu_assign_pointer(x->rdev, x->dev);
	x->rules = n;
	memset(x->fw, 0, sizeof(x->fw));
	WRITE_ONCE(x->outer, outer);
	WRITE_ONCE(x->inner, inner);

	netdev_info(x->dev, "translated by NSS core %u, nodes %d/%d, %d rule%s\n",
		    core->id, inner, outer, n, n == 1 ? "" : "s");

	return 0;

outer:
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_OUTER, outer);
inner:
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_INNER, inner);
fail:
	netdev_warn(x->dev, "no NSS MAP-T node pair: %d\n", ret);

	return ret;
}

/* Take the device out of the receive path and drop the hold the pair had. */
static void nss_xlat_forget(struct nss_xlat *x)
{
	struct net_device *dev;

	WRITE_ONCE(x->inner, -1);
	WRITE_ONCE(x->outer, -1);
	dev = rcu_replace_pointer(x->rdev, NULL, true);
	if (!dev)
		return;
	synchronize_net();
	dev_put(dev);
}

/* Give the pair back while the core still runs. */
static void nss_xlat_unpair(struct nss_core *core, struct nss_xlat *x)
{
	int inner = x->inner, outer = x->outer;

	if (inner < 0)
		return;

	/* Out of every lookup before the rules naming the nodes go, so that
	 * none is made meanwhile; a later node may get the same number.
	 */
	nss_xlat_forget(x);
	nss_flow_withdraw_dev(x->dev);

	if (!core->running)
		return;

	/* In the vendor's order. */
	nss_xlat_deconfigure(core, inner);
	nss_xlat_deconfigure(core, outer);
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_INNER, inner);
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_MAP_T_OUTER, outer);
}

static struct nss_xlat *nss_xlat_of_node(u32 if_num, int *side)
{
	int i;

	for (i = 0; i < NSS_XLAT_MAX; i++) {
		if (READ_ONCE(nss_xlat_tbl[i].inner) == (int)if_num) {
			*side = 0;
			return &nss_xlat_tbl[i];
		}
		if (READ_ONCE(nss_xlat_tbl[i].outer) == (int)if_num) {
			*side = 1;
			return &nss_xlat_tbl[i];
		}
	}

	return NULL;
}

static __be16 nss_xlat_proto(const struct sk_buff *skb, unsigned int off)
{
	if (skb->len <= off)
		return 0;

	switch (skb->data[off] & 0xf0) {
	case 0x40:
		return htons(ETH_P_IP);
	case 0x60:
		return htons(ETH_P_IPV6);
	default:
		return 0;
	}
}

/* A packet one of the nodes handed up: translated, with no rule on the far
 * side to take it. It may be in a buffer the host lent or in one the host
 * sent - a modem's packet, translated on its way in - and the descriptor says
 * where it is in either.
 */
bool nss_xlat_recv(struct nss_core *core, const struct n2h_descriptor *desc,
		   struct sk_buff *skb)
{
	bool tx = NSS_SKB_CB(skb)->tx;
	u32 end = (u32)desc->payload_offs + desc->payload_len;
	struct net_device *dev;
	struct nss_xlat *x;
	unsigned int off;
	__be16 proto;
	u32 size;
	int side;

	if (desc->buffer_type != NSS_N2H_BUFFER_PACKET &&
	    desc->buffer_type != NSS_N2H_BUFFER_PACKET_VIRTUAL)
		return false;

	if (tx && !NSS_SKB_CB(skb)->bidir)
		return false;

	x = nss_xlat_of_node(desc->interface_num, &side);
	if (!x)
		return false;

	guard(rcu)();

	if (tx) {
		size = skb_end_pointer(skb) - skb->head;
		dma_unmap_single(core->dev, NSS_SKB_CB(skb)->dma, size,
				 DMA_BIDIRECTIONAL);
	} else {
		size = NSS_EMPTY_BUFFER_ALLOC;
		dma_unmap_single(core->dev, desc->buffer, size, DMA_FROM_DEVICE);
	}

	dev = rcu_dereference(x->rdev);
	if (!dev || end > size || skb_is_nonlinear(skb))
		goto drop;

	skb->data = skb->head + desc->payload_offs;
	skb->len = desc->payload_len;
	skb_set_tail_pointer(skb, skb->len);

	/* The inner node hands up IPv4 behind an ethernet header, the outer
	 * IPv6 behind a metadata block of the same size. A packet that comes
	 * bare is taken as it is.
	 */
	off = ETH_HLEN;
	proto = nss_xlat_proto(skb, off);
	if (side == 0 ? proto != htons(ETH_P_IP) ||
			((struct ethhdr *)skb->data)->h_proto != proto :
			proto != htons(ETH_P_IPV6)) {
		off = 0;
		proto = nss_xlat_proto(skb, off);
	}
	if (!proto)
		goto drop;
	skb_pull(skb, off);

	memset(skb->cb, 0, sizeof(skb->cb));
	skb->dev = dev;
	skb->protocol = proto;
	skb->ip_summed = CHECKSUM_NONE;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->mac_len = 0;

	if (proto == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);

		/* Translated without a header checksum, which the stack would
		 * take the packet for corrupt without.
		 */
		if (skb->len < sizeof(*iph) || iph->ihl < 5 ||
		    skb->len < iph->ihl * 4)
			goto drop;
		ip_send_check(iph);
		x->back4++;
	} else {
		if (skb->len < sizeof(struct ipv6hdr))
			goto drop;
		x->back6++;
	}

	/* As the device would have delivered it: whatever the packet carried
	 * when it went down belongs to the connection on the other side of
	 * the translation.
	 */
	nf_reset_ct(skb);
	skb_dst_drop(skb);
	skb->pkt_type = PACKET_HOST;
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);

	return true;

drop:
	x->drop++;
	dev_kfree_skb_any(skb);

	return true;
}

/* What the firmware translated, counted on the device as nat46 counts its
 * own: a packet into the device is a transmit, the translation it hands back
 * a receive. Without this the device shows only what the firmware left to
 * the host, which once a connection is carried is next to nothing.
 */
static void nss_xlat_dev_stats(struct nss_xlat *x,
			       const struct nss_map_t_sync_msg *st)
{
	const struct nss_cmn_node_stats *node = &st->node;
	struct net_device *dev;
	u32 dropped = st->tx_dropped;
	int i;

	for (i = 0; i < ARRAY_SIZE(node->rx_dropped); i++)
		dropped += node->rx_dropped[i];

	guard(rcu)();

	dev = rcu_dereference(x->rdev);
	if (!dev)
		return;

	DEV_STATS_ADD(dev, tx_packets, node->rx_packets);
	DEV_STATS_ADD(dev, tx_bytes, node->rx_bytes);
	DEV_STATS_ADD(dev, rx_packets, node->tx_packets);
	DEV_STATS_ADD(dev, rx_bytes, node->tx_bytes);
	if (dropped)
		DEV_STATS_ADD(dev, tx_dropped, dropped);
}

/* A statistics push from one of the nodes. Taken here so that nothing else
 * reads it for a message of its own.
 */
bool nss_xlat_notify(const struct nss_cmn_msg *ncm, u32 len)
{
	const struct nss_map_t_msg *m;
	struct nss_xlat_node *n;
	struct nss_xlat *x;
	int side;

	x = nss_xlat_of_node(NSS_INTERFACE_NUM_GET(ncm->interface), &side);
	if (!x)
		return false;

	m = container_of_const(ncm, struct nss_map_t_msg, cm);
	if (ncm->type != NSS_MAP_T_MSG_SYNC_STATS ||
	    len < offsetofend(struct nss_map_t_msg, msg.stats))
		return true;

	n = &x->fw[side];
	n->rx += m->msg.stats.node.rx_packets;
	n->tx += m->msg.stats.node.tx_packets;
	n->exception += m->msg.stats.exception;
	n->no_rule += m->msg.stats.no_rule;
	nss_xlat_dev_stats(x, &m->msg.stats);

	return true;
}

/* Take @dev into the table and, with a running core, give it a pair. Under
 * the RTNL, and under the core's lock when there is one.
 */
static void nss_xlat_add(struct nss_core *core, struct net_device *dev)
{
	struct nss_xlat *x;
	int i, ret;

	if (!nss_xlat_enable || !nss_xlat_wanted(dev))
		return;

	x = nss_xlat_find(dev);
	if (!x) {
		for (i = 0; i < NSS_XLAT_MAX && !x; i++)
			if (!nss_xlat_tbl[i].dev)
				x = &nss_xlat_tbl[i];
		if (!x) {
			netdev_warn(dev, "no room for another nat46 device\n");
			return;
		}

		*x = (struct nss_xlat){ .inner = -1, .outer = -1 };
		WRITE_ONCE(x->ifindex, dev->ifindex);
		WRITE_ONCE(x->dev, dev);
	}

	if (!core || !core->running || x->inner >= 0)
		return;

	ret = nss_xlat_pair(core, x);
	if (!ret) {
		x->tries = 0;
		return;
	}
	/* Rules the firmware cannot take are no different later. */
	if (ret == -EINVAL || x->tries >= NSS_XLAT_TRIES)
		return;
	mod_delayed_work(system_wq, &nss_xlat_retry,
			 min_t(unsigned long, 2 * HZ << x->tries,
			       NSS_XLAT_WAIT_MAX));
	x->tries++;
}

static void nss_xlat_retry_fn(struct work_struct *work)
{
	struct nss_core *core;
	int i;

	rtnl_lock();
	core = nss_xlat_core;
	if (core) {
		guard(mutex)(&core->lock);
		for (i = 0; i < NSS_XLAT_MAX; i++) {
			struct net_device *dev = nss_xlat_tbl[i].dev;

			if (dev && (dev->flags & IFF_UP) &&
			    nss_xlat_tbl[i].inner < 0)
				nss_xlat_add(core, dev);
		}
	}
	rtnl_unlock();
}

static void nss_xlat_del(struct nss_core *core, struct net_device *dev)
{
	struct nss_xlat *x = nss_xlat_find(dev);

	if (!x)
		return;

	if (core)
		nss_xlat_unpair(core, x);
	else
		nss_xlat_forget(x);
	WRITE_ONCE(x->ifindex, 0);
	WRITE_ONCE(x->dev, NULL);
}

/* Every device that is up, on a core that has just armed its ports. Under
 * the RTNL and the core's lock, as the arming is.
 */
void nss_xlat_arm(struct nss_core *core)
{
	struct net_device *dev;

	ASSERT_RTNL();

	if (core != nss_xlat_core || !core->running)
		return;

	for_each_netdev(&init_net, dev)
		if ((dev->flags & IFF_UP) && dev->type == ARPHRD_NONE)
			nss_xlat_add(core, dev);
}

/* The core is going into reset and its nodes with it. */
void nss_xlat_halt(struct nss_core *core)
{
	int i;

	if (READ_ONCE(nss_xlat_core) != core)
		return;

	for (i = 0; i < NSS_XLAT_MAX; i++) {
		nss_xlat_forget(&nss_xlat_tbl[i]);
		nss_xlat_tbl[i].tries = 0;
	}
}

/* The core the CLATs are paired on, the one the flow rules go to. Neither
 * the notifier, the retry nor the receive path reaches a core after it is
 * unbound.
 */
void nss_xlat_bind(struct nss_core *core)
{
	rtnl_lock();
	WRITE_ONCE(nss_xlat_core, core);
	rtnl_unlock();
	synchronize_net();
}

static int nss_xlat_event(struct notifier_block *nb, unsigned long event,
			  void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct nss_core *core = READ_ONCE(nss_xlat_core);

	switch (event) {
	case NETDEV_UP:
		if (dev->type != ARPHRD_NONE)
			break;
		if (core) {
			guard(mutex)(&core->lock);
			nss_xlat_add(core, dev);
		} else {
			nss_xlat_add(NULL, dev);
		}
		break;
	case NETDEV_GOING_DOWN:
	case NETDEV_UNREGISTER:
		if (!nss_xlat_find(dev))
			break;
		if (core) {
			guard(mutex)(&core->lock);
			nss_xlat_del(core, dev);
		} else {
			nss_xlat_del(NULL, dev);
		}
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nss_xlat_nb = {
	.notifier_call = nss_xlat_event,
};

void nss_xlat_print(struct seq_file *s)
{
	int i;

	seq_printf(s, "enabled %d\n", nss_xlat_enable);

	rtnl_lock();
	for (i = 0; i < NSS_XLAT_MAX; i++) {
		const struct nss_xlat *x = &nss_xlat_tbl[i];

		if (!x->dev)
			continue;
		seq_printf(s, "%s ifindex %d nodes %d/%d rules %d back4 %llu back6 %llu drop %llu\n",
			   netdev_name(x->dev), x->ifindex, x->inner, x->outer,
			   x->rules, x->back4, x->back6, x->drop);
		seq_printf(s, "  fw inner rx %llu tx %llu exception %llu no-rule %llu outer rx %llu tx %llu exception %llu no-rule %llu\n",
			   x->fw[0].rx, x->fw[0].tx, x->fw[0].exception,
			   x->fw[0].no_rule, x->fw[1].rx, x->fw[1].tx,
			   x->fw[1].exception, x->fw[1].no_rule);
	}
	rtnl_unlock();
}

int nss_xlat_init(void)
{
	int i;

	/* A free slot must not match node 0. */
	for (i = 0; i < NSS_XLAT_MAX; i++)
		nss_xlat_tbl[i] = (struct nss_xlat){ .inner = -1, .outer = -1 };

	return register_netdevice_notifier(&nss_xlat_nb);
}

/* After the cores are gone. Unregistering replays every device's going-down
 * and unregister events, which give back each slot.
 */
void nss_xlat_exit(void)
{
	unregister_netdevice_notifier(&nss_xlat_nb);
	cancel_delayed_work_sync(&nss_xlat_retry);
}
