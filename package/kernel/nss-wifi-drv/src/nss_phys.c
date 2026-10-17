// SPDX-License-Identifier: GPL-2.0-only
/* Handing a switch port to the firmware to route through.
 *
 * A running core already delivers everything arriving at the switch's CPU
 * port, and until a port is opened the firmware forwards that straight to the
 * host. That is what makes the exception path work, and it is also why no
 * connection rule can ever match: the packet never reaches the engine the rule
 * lives in. Opening a port points its receive at the firmware's own ethernet
 * node instead, which is where the IPv4 and IPv6 engines are.
 *
 * Two things have to be said before the port is opened, because neither comes
 * from the rule: the address, which appears as the source address of
 * everything transmitted there, and the maximum frame size. The link state
 * comes last, because a freshly opened interface starts with its link down and
 * nothing transmits on it until the link is up.
 *
 * The port is never given a VSI of the firmware's own: the firmware transmits
 * on a port by its number, and a VSI would have it create interfaces and
 * router addresses in switch tables the switch driver allocates.
 *
 * The port set is whatever the switch topology has: the driver already holds
 * one network device per user port, so a port is named by its index and the
 * caller asks for a mask. Arming is a deliberate runtime act, like starting
 * the core, and the host's own transmit path is untouched by it - the firmware
 * gains a way to transmit on the port, it does not take the host's.
 */

#include <linux/bitops.h>
#include <linux/cleanup.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/dsa.h>

#include "nss_drv.h"

/* Where the firmware sends what a port receives once the port is open: its
 * ethernet node, which is what feeds the connection engines.
 */
#define NSS_PHYS_RX_FORWARD	NSS_INTERFACE_ETH_RX

int nss_phys_msg(struct nss_core *core, int if_num, u32 type,
		 const void *body, size_t len)
{
	struct nss_if_msg *m __free(kfree) = kzalloc(sizeof(*m), GFP_KERNEL);
	int ret;

	if (!m)
		return -ENOMEM;

	m->cm.interface = if_num;
	m->cm.type = type;
	if (body)
		memcpy(&m->msg, body, len);

	ret = nss_msg_send(core, m, offsetof(struct nss_if_msg, msg) + len);
	if (!ret && m->cm.error)
		ret = -EIO;

	return ret;
}

static void nss_phys_port_close(struct nss_core *core, int if_num,
				struct net_device *dev)
{
	struct nss_if_link_state_notify link = {};

	nss_phys_msg(core, if_num, NSS_IF_LINK_STATE_NOTIFY, &link,
		     sizeof(link));
	nss_phys_msg(core, if_num, NSS_IF_CLOSE, NULL, 0);

	dev_info(core->dev, "%s: port %d back to the host\n",
		 netdev_name(dev), if_num);
}

static int nss_phys_port_open(struct nss_core *core, int if_num,
			      struct net_device *dev)
{
	struct nss_if_link_state_notify link = { .state = 1 };
	struct nss_if_mac_address_set mac = {};
	struct nss_if_mtu_change mtu = {};
	struct nss_if_open open = {};
	int ret;

	ether_addr_copy(mac.mac_addr, dev->dev_addr);
	ret = nss_phys_msg(core, if_num, NSS_IF_MAC_ADDR_SET, &mac, sizeof(mac));
	if (ret)
		goto err;

	mtu.min_buf_size = dev->mtu;
	ret = nss_phys_msg(core, if_num, NSS_IF_MTU_CHANGE, &mtu, sizeof(mtu));
	if (ret)
		goto err;

	open.rx_forward_if = NSS_PHYS_RX_FORWARD;
	open.alignment_mode = NSS_IF_DATA_ALIGN_2BYTE;
	ret = nss_phys_msg(core, if_num, NSS_IF_OPEN, &open, sizeof(open));
	if (ret)
		goto err;

	ret = nss_phys_msg(core, if_num, NSS_IF_LINK_STATE_NOTIFY, &link,
			   sizeof(link));
	if (ret)
		goto err;

	dev_info(core->dev, "%s: port %d routes in the firmware\n",
		 netdev_name(dev), if_num);

	return 0;

err:
	nss_phys_port_close(core, if_num, dev);
	return ret;
}

/* Bring the set of firmware-routed ports to exactly @mask.
 *
 * A port already in the state the mask asks for is left alone rather than
 * reopened: the firmware's view of a port changes only when it is changed,
 * and restating it costs a round trip and gains nothing.
 */
int nss_phys_arm(struct nss_core *core, unsigned long mask)
{
	unsigned long armed = core->phys_armed;
	unsigned long changed;
	int ret = 0;
	unsigned int i;

	if (!core->running)
		return -ENODEV;

	/* The port's address and MTU go to the firmware, and their writers
	 * hold rtnl.
	 */
	ASSERT_RTNL();

	/* Only what the mask changes, and only as far as a mask reaches: a
	 * port index beyond the width of one is not addressable and shifting
	 * by it does not mean what it looks like.
	 */
	changed = mask ^ armed;
	for_each_set_bit(i, &changed, BITS_PER_LONG) {
		bool want = mask & BIT(i);
		struct net_device *dev;

		dev = rcu_dereference_protected(core->iface[i],
						lockdep_is_held(&core->lock));
		if (!dev || !dsa_user_dev_check(dev)) {
			if (want)
				ret = -ENODEV;
			continue;
		}

		if (want) {
			int err = nss_phys_port_open(core, i, dev);

			if (err) {
				dev_warn(core->dev, "%s: port %d not armed: %d\n",
					 netdev_name(dev), i, err);
				ret = err;
				continue;
			}
			core->phys_armed |= BIT(i);
		} else {
			nss_phys_port_close(core, i, dev);
			core->phys_armed &= ~BIT(i);
		}
	}

	return ret;
}

/* A flow is pushed only between interfaces the firmware owns, so every switch
 * port is handed over unless the mask leaves it out.
 */
static unsigned long nss_phys_allowed = ~0UL;
module_param_named(arm_ports, nss_phys_allowed, ulong, 0644);
MODULE_PARM_DESC(arm_ports, "switch ports, by DSA index, handed to the firmware");

/* Arm every port on a running core. */
void nss_phys_arm_ports(struct nss_core *core)
{
	unsigned long mask = 0;
	unsigned int i;

	rtnl_lock();
	mutex_lock(&core->lock);
	if (core->running) {
		for (i = 0; i < BITS_PER_LONG && i < NSS_INTERFACE_MAX; i++) {
			struct net_device *dev;

			dev = rcu_dereference_protected(core->iface[i],
							lockdep_is_held(&core->lock));
			if (dev && dsa_user_dev_check(dev))
				mask |= BIT(i);
		}
		nss_phys_arm(core, mask & nss_phys_allowed);
	}
	nss_rawip_arm(core);
	mutex_unlock(&core->lock);
	rtnl_unlock();
}
