# OpenWrt package — AF_XDP SNAT
#
# 集成方式：
#   把整个 openwrt/ 目录改名 xdp-nat 放到 OpenWrt SDK 的 package/ 下：
#   cp -r openwrt/ <SDK>/package/xdp-nat
#   cp ../xdp_nat*.c <SDK>/package/xdp-nat/src/
#   cd <SDK> && make package/xdp-nat/compile V=s
#   → bin/packages/*/base/xdp-nat_*.apk

include $(TOPDIR)/rules.mk

PKG_NAME:=xdp-nat
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/xdp-nat
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AF_XDP zero-copy SNAT (experimental, PoC)
  DEPENDS:=+libxdp +libbpf +libelf +zlib +luci-base +luci-compat
  URL:=https://github.com/
endef

define Package/xdp-nat/description
  用户态 AF_XDP SNAT/NAPT。LAN↔WAN 的 TCP/UDP/ICMP 在用户态处理
  （内核旁路，零拷贝），支持 IPv4 NAPT / DNAT / IPv6 NPTv6 / NAT64 / NAT46。
  本包同时含 LuCI 管理页面（网络 → XDP 加速 → XDP NAT）。
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
	    -o $(PKG_BUILD_DIR)/xdp_nat $(PKG_BUILD_DIR)/xdp_nat.c \
	    -lxdp -lbpf -lelf -lz -lpthread
	# BPF 字节码是架构中立的；用 host clang 即可，无需 OpenWrt 交叉 clang
	clang -O2 -g -target bpf \
	    -I/usr/include/$(shell uname -m)-linux-gnu \
	    -c $(PKG_BUILD_DIR)/xdp_nat_redirect.c \
	    -o $(PKG_BUILD_DIR)/xdp_nat_redirect.o
endef

define Package/xdp-nat/conffiles
/etc/config/xdp-nat
endef

define Package/xdp-nat/install
	# 二进制、BPF .o、init 脚本、默认 config、命令行工具
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/xdp-nat $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/xdp_nat                $(1)/usr/sbin/xdp_nat
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/xdp_nat_redirect.o     $(1)/etc/xdp-nat/xdp_nat_redirect.o
	$(INSTALL_BIN)  ./files/xdp-nat.init                    $(1)/etc/init.d/xdp-nat
	$(INSTALL_CONF) ./files/xdp-nat.config                  $(1)/etc/config/xdp-nat
	$(INSTALL_BIN)  ./files/xdp-nat-ctl                     $(1)/usr/sbin/xdp-nat-ctl

	# LuCI 管理页面：菜单 + ACL + 视图 JS
	$(INSTALL_DIR)  $(1)/usr/share/luci/menu.d \
	                $(1)/usr/share/rpcd/acl.d \
	                $(1)/www/luci-static/resources/view/xdp-nat
	$(INSTALL_DATA) ./files/xdp-nat-menu.json \
	                $(1)/usr/share/luci/menu.d/luci-app-xdp-nat.json
	$(INSTALL_DATA) ./files/xdp-nat-acl.json \
	                $(1)/usr/share/rpcd/acl.d/luci-app-xdp-nat.json
	$(INSTALL_DATA) ./files/xdp-nat-view.js \
	                $(1)/www/luci-static/resources/view/xdp-nat/manage.js
endef

$(eval $(call BuildPackage,xdp-nat))
