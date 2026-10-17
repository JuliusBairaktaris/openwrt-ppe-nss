/* SPDX-License-Identifier: GPL-2.0-only */
/* What the qca-ppe DSA driver offers the host driver of the NSS firmware,
 * which shares the switch with it.
 */

#ifndef __LINUX_SOC_QCOM_QCA_PPE_H__
#define __LINUX_SOC_QCOM_QCA_PPE_H__

#include <linux/netdevice.h>

int qca_ppe_fw_booted(struct net_device *conduit);
int qca_ppe_fw_carrier_set(struct net_device *conduit,
			   bool (*carries)(int ifindex));

#endif /* __LINUX_SOC_QCOM_QCA_PPE_H__ */
