#
# WLAN.HK.2.12 firmware for the IPQ8074 Wi-Fi, from the 2.12 release of qosmio/upstream-wifi-fw (a
# fork of Qualcomm's upstream-wifi-fw, which carries IPQ8074 firmware up to 2.9.0.1 only).
#
include $(TOPDIR)/rules.mk

PKG_NAME:=ath11k-firmware-hk212
PKG_VERSION:=2.12.01460
PKG_RELEASE:=1

PKG_SOURCE:=ath11k-firmware-2.12-01460.tar.zst
PKG_SOURCE_URL:=https://github.com/qosmio/upstream-wifi-fw/releases/download/2.12-01460
PKG_HASH:=a2767b367a51e15c1ab4d303113a0d1e22e73adf727a418119f4509f0ef115dd
PKG_BUILD_DIR:=$(BUILD_DIR)/ath11k-firmware-2.12.01460

PKG_LICENSE_FILES:=IPQ8074/hw2.0/testing/2.12/WLAN.HK.2.12-01460-QCAHKSWPL_SILICONZ-1/Notice.txt
PKG_MAINTAINER:=Julius Bairaktaris <julius@bairaktaris.de>
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

FW_DIR:=IPQ8074/hw2.0/testing/2.12/WLAN.HK.2.12-01460-QCAHKSWPL_SILICONZ-1

define Package/ath11k-firmware-ipq8074-hk212
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=IPQ8074 ath11k firmware WLAN.HK.2.12-01460
  DEPENDS:=@TARGET_qualcommax_ipq807x
  PROVIDES:=ath11k-firmware-ipq8074
  CONFLICTS:=ath11k-firmware-ipq8074
endef

define Package/ath11k-firmware-ipq8074-hk212/description
  WLAN.HK.2.12-01460 for the IPQ8074 ath11k radios, in place of the
  2.9.0.1 firmware of linux-firmware. Board and calibration data are
  unchanged.
endef

define Build/Compile
endef

define Package/ath11k-firmware-ipq8074-hk212/install
	$(INSTALL_DIR) $(1)/lib/firmware/IPQ8074
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/$(FW_DIR)/q6_fw.* \
		$(PKG_BUILD_DIR)/$(FW_DIR)/m3_fw.* \
		$(PKG_BUILD_DIR)/$(FW_DIR)/Notice.txt \
		$(1)/lib/firmware/IPQ8074/
endef

$(eval $(call BuildPackage,ath11k-firmware-ipq8074-hk212))
