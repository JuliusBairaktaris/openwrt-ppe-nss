/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __QCA_CPU_PORT_H__
#define __QCA_CPU_PORT_H__

#include <linux/types.h>

struct dsa_switch;
struct sk_buff;
struct xdp_buff;

/* What the switch driver does with frames the conduit receives on the CPU
 * port before they reach the tagger. The switch driver points
 * ds->tagger_data at it; the out-of-band tagger keeps no data of its own.
 */
struct qca_cpu_port_ops {
	/* A frame the switch trapped with @cpu_code on @port, its Ethernet
	 * header pulled. Returns true to have the conduit drop it.
	 */
	bool (*trap_rcv)(struct dsa_switch *ds, struct sk_buff *skb, int port,
			 u8 cpu_code);
	/* A frame the switch routed on @flow to the CPU port, finished for an
	 * egress outside the switch. Returns true when it was taken.
	 */
	bool (*flow_xmit)(struct dsa_switch *ds, struct sk_buff *skb, u32 flow);
	/* The same before it has an skb, with only its headers synced for
	 * the CPU. Frames taken may wait for flow_xmit_flush, which the
	 * conduit runs before its poll returns.
	 */
	bool (*flow_xmit_xdp)(struct dsa_switch *ds, struct xdp_buff *xdp,
			      u32 flow);
	void (*flow_xmit_flush)(struct dsa_switch *ds);
};

#endif /* __QCA_CPU_PORT_H__ */
