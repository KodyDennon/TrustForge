# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# OpenWRT package Makefile for TrustForge
#
# Upstream:  https://github.com/trustforge/trustforge
# Feed:      feeds/packages/utils/trustforge/Makefile
#
# This Makefile fetches a pre-built `tf-daemon` binary tarball from the
# upstream GitHub release for the active OpenWRT target architecture
# (mipsel, aarch64, armv7). Cross-compiling Rust inside the OpenWRT SDK
# is intentionally avoided here; users who want a from-source build
# should use the `tf-daemon` crate directly.
#
# NOTE (Phase 0): The release tarballs referenced below do not yet
# exist. They are produced by the upstream CI when v0.1.0 is tagged.
# See the README for the current status.

include $(TOPDIR)/rules.mk

PKG_NAME:=trustforge
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=TrustForge Maintainers <maintainers@trustforge.dev>
PKG_LICENSE:=Apache-2.0 OR MIT
PKG_LICENSE_FILES:=LICENSE-APACHE LICENSE-MIT

PKG_SOURCE_URL:=https://github.com/trustforge/trustforge/releases/download/v$(PKG_VERSION)
PKG_HASH:=skip

# Map OpenWRT arch names to the upstream Rust target tarball suffix.
ifeq ($(ARCH),mipsel)
  TF_ARCH:=mipsel-unknown-linux-musl
endif
ifeq ($(ARCH),mips)
  TF_ARCH:=mips-unknown-linux-musl
endif
ifeq ($(ARCH),aarch64)
  TF_ARCH:=aarch64-unknown-linux-musl
endif
ifeq ($(ARCH),arm)
  TF_ARCH:=armv7-unknown-linux-musleabihf
endif
ifeq ($(ARCH),x86_64)
  TF_ARCH:=x86_64-unknown-linux-musl
endif

PKG_SOURCE:=tf-daemon-$(TF_ARCH).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-$(TF_ARCH)

include $(INCLUDE_DIR)/package.mk

define Package/trustforge
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TrustForge identity, capability, and proof daemon
  URL:=https://github.com/trustforge/trustforge
  DEPENDS:=+libc +libpthread +librt +ca-bundle
  USERID:=trustforge=915:trustforge=915
endef

define Package/trustforge/description
  TrustForge is an open identity, capability, and proof protocol for
  humans, devices, agents, services, and packets. This package installs
  the reference daemon `tf-daemon`, the `decide.sock` decision endpoint,
  a procd init script, and a UCI config skeleton.

  The package is profile-driven: by default it ships the
  `tf-home-compatible` profile suitable for a residential router. Set
  `option profile` in /etc/config/trustforge to change.
endef

define Package/trustforge/config
  source "$(SOURCE)/Config.in"
endef

# Menu options surfaced into the OpenWRT menuconfig tree under the
# package selection. These translate to compile-time defines that the
# daemon reads at first run via /etc/config/trustforge.
PKG_CONFIG_DEPENDS:= \
	CONFIG_TRUSTFORGE_ENABLE_TLS \
	CONFIG_TRUSTFORGE_ENABLE_RELAY \
	CONFIG_TRUSTFORGE_ENABLE_DASHBOARD

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(TAR) -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE)
endef

# No compilation step: we ship a pre-built static-musl binary. The
# `Build/Compile` target is therefore a no-op other than ensuring the
# binary is executable and stripped.
define Build/Compile
	chmod +x $(PKG_BUILD_DIR)/tf-daemon
	$(STRIP) $(PKG_BUILD_DIR)/tf-daemon || true
endef

define Package/trustforge/conffiles
/etc/config/trustforge
/etc/trustforge/config.yaml
endef

define Package/trustforge/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tf-daemon $(1)/usr/bin/tf-daemon

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/trustforge $(1)/etc/init.d/trustforge

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/trustforge $(1)/etc/config/trustforge

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-trustforge \
		$(1)/etc/uci-defaults/99-trustforge

	$(INSTALL_DIR) $(1)/etc/trustforge
	# Build-option-driven feature gating, materialised into the on-disk
	# config so a stock `tf-daemon --config` reads it directly.
ifeq ($(CONFIG_TRUSTFORGE_ENABLE_TLS),y)
	echo "tls: { enabled: true }" >> $(1)/etc/trustforge/features.yaml
endif
ifeq ($(CONFIG_TRUSTFORGE_ENABLE_RELAY),y)
	echo "relay: { enabled: true }" >> $(1)/etc/trustforge/features.yaml
endif
ifeq ($(CONFIG_TRUSTFORGE_ENABLE_DASHBOARD),y)
	echo "dashboard: { enabled: true }" >> $(1)/etc/trustforge/features.yaml
endif
endef

define Package/trustforge/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	mkdir -p /var/run/trustforge
	chown trustforge:trustforge /var/run/trustforge
	/etc/init.d/trustforge enable
}
exit 0
endef

define Package/trustforge/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	/etc/init.d/trustforge disable
	/etc/init.d/trustforge stop
}
exit 0
endef

$(eval $(call BuildPackage,trustforge))


# -- Optional sub-package: LuCI web UI ---------------------------------
define Package/luci-app-trustforge
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI front-end for TrustForge
  DEPENDS:=+trustforge +luci-base
  PKGARCH:=all
endef

define Package/luci-app-trustforge/description
  LuCI controller and view providing a status dashboard for the
  TrustForge daemon: liveness, decision histogram, and recent
  proof events.
endef

define Package/luci-app-trustforge/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luci/luasrc/controller/trustforge.lua \
		$(1)/usr/lib/lua/luci/controller/trustforge.lua

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/trustforge
	$(INSTALL_DATA) ./luci/luasrc/view/trustforge/index.htm \
		$(1)/usr/lib/lua/luci/view/trustforge/index.htm
endef

$(eval $(call BuildPackage,luci-app-trustforge))
