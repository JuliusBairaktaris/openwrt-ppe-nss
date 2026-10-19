#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sqm-scripts
PKG_SOURCE_VERSION:=13a10078015b08007850a394543dbe7151e94c18
PKG_VERSION:=1.8.0
PKG_RELEASE:=1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.zst

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/JuliusBairaktaris/sqm-scripts
PKG_MIRROR_HASH:=39a79826974252e27717a0fe2cd2a2c3d055e050b1a2ed9882fa3085c8c01686

PKG_MAINTAINER:=Toke Høiland-Jørgensen <toke@toke.dk>
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/sqm-scripts
  SECTION:=net
  CATEGORY:=Base system
  DEPENDS:=+tc +ip +kmod-sched-cake +kmod-ifb +nftables
  TITLE:=SQM Scripts (QoS)
  PKGARCH:=all
endef

define Package/sqm-scripts/description
 A set of scripts that does simple SQM configuration.
endef

define Package/sqm-scripts/conffiles
/etc/config/sqm
/etc/sqm/sqm.conf
endef

define Package/sqm-scripts/install
	make -C $(PKG_BUILD_DIR) DESTDIR=$(1) PLATFORM=openwrt install
endef

$(eval $(call BuildPackage,sqm-scripts))
