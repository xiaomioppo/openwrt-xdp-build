# OpenWrt package — xdp-fw: XDP 三合一（NAT + 防火墙 + 防 DDoS）
#
# 架构：快慢双路径
#   - 快路径: XDP BPF 程序 (xdp_fw_kern.o) 在内核里处理已建立连接
#             - 限速 / 黑白名单 / SYN flood / NAT fast-rewrite
#   - 慢路径: AF_XDP 用户态 daemon 处理新连接、ACL 复杂规则、DDoS 自学习

include $(TOPDIR)/rules.mk

PKG_NAME:=xdp-fw
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/xdp-fw
  SECTION:=net
  CATEGORY:=Network
  TITLE:=XDP firewall + NAT + DDoS defense (AF_XDP zero-copy)
  DEPENDS:=+libxdp +libbpf +libelf +zlib
  URL:=https://github.com/okkv
  PROVIDES:=xdp-nat
  CONFLICTS:=xdp-nat
endef

define Package/xdp-fw/description
  基于 XDP / AF_XDP 的一体化路由数据面，包含：
    - NAT: IPv4 NAPT + DNAT + IPv6 NPTv6 + NAT64 + NAT46
    - 防火墙: 源/目的 IP 黑白名单（LPM）、端口 ACL，WAN 入站默认 drop 可配
    - 防 DDoS: per-IP token-bucket 限速、SYN flood 检测、自适应黑名单
  快慢双路径：已建立连接全在内核 XDP BPF 里处理（零拷贝），
  新连接与复杂规则才进用户态 daemon。
  带 LuCI 管理页面（网络 → XDP 加速 → XDP 防火墙）。
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
	    -o $(PKG_BUILD_DIR)/xdp_fw $(PKG_BUILD_DIR)/xdp_fw.c \
	    -lxdp -lbpf -lelf -lz -lpthread
	# BPF 字节码是架构中立的；用 host clang 即可，无需 OpenWrt 交叉 clang
	clang -O2 -g -target bpf \
	    -I/usr/include/$(shell uname -m)-linux-gnu \
	    -c $(PKG_BUILD_DIR)/xdp_fw_kern.c \
	    -o $(PKG_BUILD_DIR)/xdp_fw_kern.o
endef

define Package/xdp-fw/conffiles
/etc/config/xdp-fw
endef

define Package/xdp-fw/install
	# 二进制、BPF .o、init 脚本、默认 config、命令行工具
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/xdp-fw $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN)  $(PKG_BUILD_DIR)/xdp_fw                $(1)/usr/sbin/xdp_fw
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/xdp_fw_kern.o     $(1)/etc/xdp-fw/xdp_fw_kern.o
	$(INSTALL_BIN)  ./files/xdp-fw.init                    $(1)/etc/init.d/xdp-fw
	$(INSTALL_CONF) ./files/xdp-fw.config                  $(1)/etc/config/xdp-fw
	$(INSTALL_BIN)  ./files/xdp-fw-ctl                     $(1)/usr/sbin/xdp-fw-ctl

	# LuCI 管理页面：菜单 + ACL + 视图 JS
	$(INSTALL_DIR)  $(1)/usr/share/luci/menu.d \
	                $(1)/usr/share/rpcd/acl.d \
	                $(1)/www/luci-static/resources/view/xdp-fw
	$(INSTALL_DATA) ./files/xdp-fw-menu.json \
	                $(1)/usr/share/luci/menu.d/luci-app-xdp-fw.json
	$(INSTALL_DATA) ./files/xdp-fw-acl.json \
	                $(1)/usr/share/rpcd/acl.d/luci-app-xdp-fw.json
	$(INSTALL_DATA) ./files/xdp-fw-view.js \
	                $(1)/www/luci-static/resources/view/xdp-fw/manage.js
endef

$(eval $(call BuildPackage,xdp-fw))
