// SPDX-License-Identifier: GPL-2.0-only
/* Carrying the connections of devices the firmware has no interface for.
 *
 * A modem's raw-IP device has no switch port behind it, and a radio whose
 * rings the firmware does not reap - a PCIe ath10k beside the SoC's own
 * radios - hands every frame to the host. The firmware reaches such a device
 * through a generic redirect node pair: what the host hands to one
 * node is routed as if it had arrived on the device, and what the firmware
 * routes to the other comes back to be sent there. Core 0 refuses the
 * rmnet_rx node type, which exists only in core 1's image; the redirect pair
 * has the same shape.
 *
 * Packets cross the pair framed as Ethernet. One the firmware does not route
 * comes back still framed and goes up the stack; nothing the modem sends or
 * receives carries the frame, and a radio's frames are Ethernet already.
 *
 * Only a packet as the device received it fits one firmware buffer, so a
 * radio's GRO is off while a core carries the device: coalesced, a station's
 * upload would never reach the firmware.
 *
 * A core that restarts loses its nodes, so the pair is made wherever a
 * running core meets a device that is up: when the device comes up and when
 * the core arms its ports.
 */

#include <linux/cleanup.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_netdev.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "nss_drv.h"

/* ponytail: a modem has one device per multiplexed channel and a router uses
 * one or two; a radio has one per network it serves.
 */
#define NSS_REDIR_MAX	8

/* The source address of the frame around a modem's packet; the modem driver
 * uses it for its own Ethernet mode.
 */
static const u8 nss_redir_peer[ETH_ALEN] = { 0x02, 0x50, 0xf3, 0x00, 0x00, 0x00 };

struct nss_redir {
	struct net_device *dev;	/* NULL: slot free */
	int ifindex;
	int n2h;		/* -1 until a running core gives the pair */
	int h2n;
	struct nf_hook_ops ops;	/* ahead of the flow table on the device */
	bool eth;		/* frames are Ethernet, not bare IP */
	bool gro;		/* GRO turned off here */
	u64 inject;
	u64 inject_fail;
	u64 back;		/* came back unrouted, delivered up */
	u64 xmit;		/* routed to the device by the firmware */
	u64 drop;
};

/* Written under the RTNL, read from the receive paths. */
static struct nss_redir nss_redir_tbl[NSS_REDIR_MAX];
static struct nss_core *nss_redir_core;

/* Set while a packet the firmware gave back goes up the stack, so it is not
 * handed down again. The delivery stays on this CPU.
 */
static DEFINE_PER_CPU(bool, nss_redir_reinject);

static bool nss_redir_enable = true;
module_param_named(redir, nss_redir_enable, bool, 0644);
MODULE_PARM_DESC(redir, "carry raw-IP (cellular) devices and radios the firmware does not drive; read when a device comes up");

static bool nss_redir_wanted(const struct net_device *dev)
{
	if (dev->addr_len != ETH_ALEN)
		return false;

	return dev->type == ARPHRD_RAWIP ||
	       (dev->type == ARPHRD_ETHER && dev->ieee80211_ptr &&
		!nss_wifili_owns(dev));
}

static struct nss_redir *nss_redir_find(const struct net_device *dev)
{
	int i;

	for (i = 0; i < NSS_REDIR_MAX; i++)
		if (nss_redir_tbl[i].dev == dev)
			return &nss_redir_tbl[i];

	return NULL;
}

/* Whether the firmware can route to @ifindex. */
bool nss_redir_bound(int ifindex)
{
	int i;

	for (i = 0; i < NSS_REDIR_MAX; i++)
		if (READ_ONCE(nss_redir_tbl[i].ifindex) == ifindex &&
		    READ_ONCE(nss_redir_tbl[i].n2h) >= 0)
			return true;

	return false;
}

static int nss_redir_config(struct nss_core *core, int if_num, int sibling,
			    int nexthop, const u8 *mac)
{
	struct nss_virt_if_config_msg c = {};

	c.sibling = sibling;
	c.nexthop = nexthop;
	ether_addr_copy(c.mac_addr, mac);

	return nss_phys_msg(core, if_num, NSS_VIRT_IF_TX_CONFIG_MSG, &c,
			    sizeof(c));
}

/* The host-to-firmware node feeds the Ethernet node, where the connection
 * engines are; the other hands what the firmware routes there to the host.
 */
static int nss_redir_pair(struct nss_core *core, struct nss_redir *r)
{
	int n2h, h2n, ret;

	n2h = nss_flow_dyn_alloc(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_N2H);
	if (n2h < 0)
		return n2h;

	h2n = nss_flow_dyn_alloc(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_H2N);
	if (h2n < 0) {
		ret = h2n;
		goto n2h;
	}

	ret = nss_redir_config(core, n2h, h2n, NSS_INTERFACE_N2H,
			       r->dev->dev_addr);
	if (ret)
		goto h2n;
	ret = nss_redir_config(core, h2n, n2h, NSS_INTERFACE_ETH_RX,
			       r->dev->dev_addr);
	if (ret)
		goto h2n;

	/* The flow back end names the device by the node sending to it. */
	dev_hold(r->dev);
	rcu_assign_pointer(core->iface[n2h], r->dev);
	WRITE_ONCE(r->h2n, h2n);
	WRITE_ONCE(r->n2h, n2h);

	netdev_info(r->dev, "routed by NSS core %u, nodes %d/%d\n", core->id,
		    n2h, h2n);

	return 0;

h2n:
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_H2N, h2n);
n2h:
	nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_N2H, n2h);
	netdev_warn(r->dev, "no NSS node pair: %d\n", ret);

	return ret;
}

static void nss_redir_unpair(struct nss_core *core, struct nss_redir *r)
{
	int n2h = r->n2h, h2n = r->h2n;
	struct net_device *dev;

	if (n2h < 0)
		return;

	/* Out of every lookup before the rules towards the node go, so that
	 * none is made meanwhile; a later node may get the same number.
	 */
	WRITE_ONCE(r->n2h, -1);
	WRITE_ONCE(r->h2n, -1);

	dev = rcu_replace_pointer(core->iface[n2h], NULL,
				  lockdep_is_held(&core->lock));
	synchronize_net();
	if (dev)
		dev_put(dev);

	nss_flow_withdraw_dev(r->dev);

	if (core->running) {
		nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_H2N,
				  h2n);
		nss_flow_dyn_free(core, NSS_DYNAMIC_INTERFACE_TYPE_GENERIC_REDIR_N2H,
				  n2h);
	}
}

/* Unicast, unfragmented TCP or UDP. A TCP segment that opens or closes a
 * connection stays with the host: no rule waits for the first, and conntrack
 * must see the second.
 */
static bool nss_redir_routable(struct sk_buff *skb, __be16 proto)
{
	unsigned int thoff;
	u8 l4;

	if (proto == htons(ETH_P_IP)) {
		const struct iphdr *iph;

		if (!pskb_may_pull(skb, sizeof(*iph)))
			return false;
		iph = ip_hdr(skb);
		if (iph->ihl != 5 || ip_is_fragment(iph) ||
		    ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr))
			return false;
		l4 = iph->protocol;
		thoff = sizeof(*iph);
	} else {
		const struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, sizeof(*ip6h)))
			return false;
		ip6h = ipv6_hdr(skb);
		if (ipv6_addr_is_multicast(&ip6h->daddr))
			return false;
		l4 = ip6h->nexthdr;
		thoff = sizeof(*ip6h);
	}

	if (l4 == IPPROTO_UDP)
		return true;
	if (l4 != IPPROTO_TCP || !pskb_may_pull(skb, thoff + sizeof(struct tcphdr)))
		return false;

	skb_set_transport_header(skb, thoff);

	return !(tcp_hdr(skb)->syn || tcp_hdr(skb)->fin || tcp_hdr(skb)->rst);
}

static __be16 nss_redir_proto(const struct sk_buff *skb, unsigned int off)
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

/* Hand a packet from the device to the firmware. False leaves it with the
 * host; @skb must not be shared.
 */
static bool nss_redir_inject(struct nss_redir *r, struct sk_buff *skb)
{
	struct nss_core *core = READ_ONCE(nss_redir_core);
	int h2n = READ_ONCE(r->h2n);
	struct ethhdr *eth;
	__be16 proto;

	if (!core || h2n < 0 || !READ_ONCE(core->running))
		return false;

	if (r->eth) {
		/* The device's own header and nothing between it and IP. */
		if (skb->pkt_type != PACKET_HOST &&
		    skb->pkt_type != PACKET_OTHERHOST)
			return false;
		if (skb_vlan_tag_present(skb) || skb->mac_len != ETH_HLEN)
			return false;
		proto = skb->protocol;
		if (proto != htons(ETH_P_IP) && proto != htons(ETH_P_IPV6))
			return false;
	} else {
		if (!pskb_may_pull(skb, 1))
			return false;
		proto = nss_redir_proto(skb, 0);
		if (!proto)
			return false;
	}
	if (skb->len > skb->dev->mtu)
		return false;

	skb_reset_network_header(skb);
	if (!nss_redir_routable(skb, proto))
		return false;

	/* Four more than the frame, for the word alignment the send may need. */
	if (skb_cow_head(skb, ETH_HLEN + 4)) {
		r->inject_fail++;
		return false;
	}

	eth = skb_push(skb, ETH_HLEN);
	if (!r->eth) {
		ether_addr_copy(eth->h_dest, skb->dev->dev_addr);
		ether_addr_copy(eth->h_source, nss_redir_peer);
		eth->h_proto = proto;
	}

	if (nss_data_send(core, skb, h2n, NSS_H2N_FLAG_VIRTUAL_BUFFER)) {
		/* The send may have moved the data to a word boundary. */
		skb_reset_mac_header(skb);
		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		if (!r->eth)
			skb_reset_mac_header(skb);
		r->inject_fail++;
		return false;
	}

	r->inject++;

	return true;
}

/* Ahead of the flow table's hook, which would otherwise forward an
 * offloaded connection's packets before the receive handler saw them.
 */
static unsigned int nss_redir_hook(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	if (__this_cpu_read(nss_redir_reinject) || skb_shared(skb))
		return NF_ACCEPT;

	return nss_redir_inject(priv, skb) ? NF_STOLEN : NF_ACCEPT;
}

/* A packet an ingress shaper redirected and gives back skips the hooks. */
static rx_handler_result_t nss_redir_rx(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;

	if (__this_cpu_read(nss_redir_reinject) ||
	    skb->pkt_type == PACKET_LOOPBACK)
		return RX_HANDLER_PASS;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;
	*pskb = skb;

	if (!nss_redir_inject(rcu_dereference(skb->dev->rx_handler_data), skb))
		return RX_HANDLER_PASS;

	return RX_HANDLER_CONSUMED;
}

static struct nss_redir *nss_redir_of_node(u32 if_num)
{
	int i;

	for (i = 0; i < NSS_REDIR_MAX; i++)
		if (READ_ONCE(nss_redir_tbl[i].n2h) == (int)if_num ||
		    READ_ONCE(nss_redir_tbl[i].h2n) == (int)if_num)
			return &nss_redir_tbl[i];

	return NULL;
}

/* A packet the firmware did not route, to go up the stack, or one it routed
 * to the device, to be sent there. Either may be in a lent buffer or in one
 * the host sent; the descriptor says where the packet is.
 */
bool nss_redir_recv(struct nss_core *core, const struct n2h_descriptor *desc,
		    struct sk_buff *skb)
{
	bool tx = NSS_SKB_CB(skb)->tx;
	u32 end = (u32)desc->payload_offs + desc->payload_len;
	struct net_device *dev;
	struct nss_redir *r;
	__be16 proto;
	u32 size;
	int n2h;

	if (desc->buffer_type != NSS_N2H_BUFFER_PACKET &&
	    desc->buffer_type != NSS_N2H_BUFFER_PACKET_VIRTUAL)
		return false;

	if (tx && !NSS_SKB_CB(skb)->bidir)
		return false;

	r = nss_redir_of_node(desc->interface_num);
	if (!r)
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

	n2h = READ_ONCE(r->n2h);
	if (n2h < 0)
		goto drop;
	dev = rcu_dereference(core->iface[n2h]);
	if (!dev || end > size || skb_is_nonlinear(skb))
		goto drop;

	skb->data = skb->head + desc->payload_offs;
	skb->len = desc->payload_len;
	skb_set_tail_pointer(skb, skb->len);

	/* A modem's packet that comes back bare is taken as it is; a radio's
	 * frame keeps its header.
	 */
	proto = nss_redir_proto(skb, ETH_HLEN);
	if (proto && ((struct ethhdr *)skb->data)->h_proto != proto)
		proto = 0;
	if (r->eth) {
		if (!proto)
			goto drop;
	} else if (proto) {
		skb_pull(skb, ETH_HLEN);
	} else {
		proto = nss_redir_proto(skb, 0);
		if (!proto)
			goto drop;
	}

	memset(skb->cb, 0, sizeof(skb->cb));
	skb->dev = dev;
	skb->protocol = proto;
	skb->ip_summed = CHECKSUM_NONE;
	skb_reset_mac_header(skb);
	skb->mac_len = r->eth ? ETH_HLEN : 0;
	/* Where the radio's queue selection reads the DSCP from. */
	skb_set_network_header(skb, skb->mac_len);

	if (desc->buffer_type == NSS_N2H_BUFFER_PACKET_VIRTUAL) {
		r->xmit++;
		dev_queue_xmit(skb);
		return true;
	}

	/* State attached before the packet went down would make conntrack
	 * take it for one it has seen.
	 */
	nf_reset_ct(skb);
	skb_dst_drop(skb);
	if (r->eth) {
		skb->protocol = eth_type_trans(skb, dev);
		skb_reset_network_header(skb);
	} else {
		skb->pkt_type = PACKET_HOST;
	}

	skb->skb_iif = dev->ifindex;

	r->back++;
	__this_cpu_write(nss_redir_reinject, true);
	/* The flow table's hook runs again, so a reply passing it lets it
	 * offload that direction too. An ingress shaper saw the packet
	 * already and is skipped.
	 */
	if (nf_hook_ingress(skb) >= 0) {
		skb->tc_skip_classify = 1;
		netif_receive_skb_core(skb);
	}
	__this_cpu_write(nss_redir_reinject, false);

	return true;

drop:
	r->drop++;
	dev_kfree_skb_any(skb);

	return true;
}

/* Under the RTNL, and under the core's lock when there is one. */
static void nss_redir_add(struct nss_core *core, struct net_device *dev)
{
	struct nss_redir *r;
	int i;

	if (!nss_redir_enable || !nss_redir_wanted(dev))
		return;

	r = nss_redir_find(dev);
	if (!r) {
		for (i = 0; i < NSS_REDIR_MAX && !r; i++)
			if (!nss_redir_tbl[i].dev)
				r = &nss_redir_tbl[i];
		if (!r) {
			netdev_warn(dev, "no room for another redirected device\n");
			return;
		}

		*r = (struct nss_redir){ .dev = dev, .n2h = -1, .h2n = -1,
					 .eth = dev->type == ARPHRD_ETHER };
		/* A radio's device is usually a bridge port, and the receive
		 * handler is the bridge's; the ingress hook alone takes its
		 * packets.
		 */
		if (!r->eth && netdev_rx_handler_register(dev, nss_redir_rx, r)) {
			netdev_warn(dev, "has a receive handler already\n");
			*r = (struct nss_redir){ .n2h = -1, .h2n = -1 };
			return;
		}
		WRITE_ONCE(r->ifindex, dev->ifindex);

		r->ops = (struct nf_hook_ops){
			.hook = nss_redir_hook,
			.pf = NFPROTO_NETDEV,
			.hooknum = NF_NETDEV_INGRESS,
			.priority = INT_MIN + 1,
			.dev = dev,
			.priv = r,
		};
		if (nf_register_net_hook(dev_net(dev), &r->ops)) {
			if (!r->eth)
				netdev_rx_handler_unregister(dev);
			*r = (struct nss_redir){ .n2h = -1, .h2n = -1 };
			return;
		}
	}

	if (!core)
		return;

	if (r->eth && !r->gro && (dev->wanted_features & NETIF_F_GRO)) {
		dev->wanted_features &= ~NETIF_F_GRO;
		netdev_update_features(dev);
		r->gro = true;
	}

	if (core->running && r->n2h < 0)
		nss_redir_pair(core, r);
}

static void nss_redir_del(struct nss_core *core, struct net_device *dev)
{
	struct nss_redir *r = nss_redir_find(dev);

	if (!r)
		return;

	nf_unregister_net_hook(dev_net(dev), &r->ops);
	if (core)
		nss_redir_unpair(core, r);
	if (r->gro) {
		dev->wanted_features |= NETIF_F_GRO;
		netdev_update_features(dev);
	}
	if (!r->eth)
		netdev_rx_handler_unregister(dev);
	WRITE_ONCE(r->ifindex, 0);
	WRITE_ONCE(r->n2h, -1);
	WRITE_ONCE(r->h2n, -1);
	r->dev = NULL;
}

/* The core the devices are paired on, which is the one the flow rules go
 * to. Neither the notifier nor the receive handler reaches a core after it
 * is unbound.
 */
void nss_redir_bind(struct nss_core *core)
{
	rtnl_lock();
	WRITE_ONCE(nss_redir_core, core);
	rtnl_unlock();
	synchronize_net();
}

/* Under the RTNL and the core's lock, as the arming is. */
void nss_redir_arm(struct nss_core *core)
{
	struct net_device *dev;

	ASSERT_RTNL();

	if (core != nss_redir_core || !core->running)
		return;

	for_each_netdev(&init_net, dev)
		if (dev->flags & IFF_UP)
			nss_redir_add(core, dev);
}

/* The nodes go with the core; the halt empties its interface table. */
void nss_redir_halt(struct nss_core *core)
{
	int i;

	if (READ_ONCE(nss_redir_core) != core)
		return;

	for (i = 0; i < NSS_REDIR_MAX; i++) {
		WRITE_ONCE(nss_redir_tbl[i].h2n, -1);
		WRITE_ONCE(nss_redir_tbl[i].n2h, -1);
	}
}

static int nss_redir_event(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct nss_core *core = READ_ONCE(nss_redir_core);

	switch (event) {
	case NETDEV_UP:
		if (!nss_redir_wanted(dev))
			break;
		if (core) {
			guard(mutex)(&core->lock);
			nss_redir_add(core, dev);
		} else {
			nss_redir_add(NULL, dev);
		}
		break;
	case NETDEV_GOING_DOWN:
	case NETDEV_UNREGISTER:
		/* Gone from the table by its slot, not by what it is now. */
		if (!nss_redir_find(dev))
			break;
		if (core) {
			guard(mutex)(&core->lock);
			nss_redir_del(core, dev);
		} else {
			nss_redir_del(NULL, dev);
		}
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nss_redir_nb = {
	.notifier_call = nss_redir_event,
};

void nss_redir_print(struct seq_file *s)
{
	int i;

	seq_printf(s, "enabled %d\n", nss_redir_enable);

	rtnl_lock();
	for (i = 0; i < NSS_REDIR_MAX; i++) {
		const struct nss_redir *r = &nss_redir_tbl[i];

		if (!r->dev)
			continue;
		seq_printf(s, "%s ifindex %d nodes %d/%d inject %llu inject-fail %llu back %llu xmit %llu drop %llu\n",
			   netdev_name(r->dev), r->ifindex, r->n2h, r->h2n,
			   r->inject, r->inject_fail, r->back, r->xmit,
			   r->drop);
	}
	rtnl_unlock();
}

int nss_redir_init(void)
{
	int i;

	/* A free slot must not match node 0. */
	for (i = 0; i < NSS_REDIR_MAX; i++)
		nss_redir_tbl[i] = (struct nss_redir){ .n2h = -1, .h2n = -1 };

	return register_netdevice_notifier(&nss_redir_nb);
}

/* After the cores are gone. Unregistering replays every device's going-down
 * and unregister events, which give back each slot.
 */
void nss_redir_exit(void)
{
	unregister_netdevice_notifier(&nss_redir_nb);
}
