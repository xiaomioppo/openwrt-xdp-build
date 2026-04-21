# OpenWrt x86_64 with XDP_SOCKETS + xdp-nat

> 一键编一个**启用 AF_XDP + 内置 xdp-nat 用户态 NAT** 的 OpenWrt 25.12.2 固件。
> 用 GitHub Actions 免费算力，~40 分钟完成（比本地老 CPU 快 3–5 倍）。

## 为什么要这个仓库

OpenWrt 25.12.2 官方 x86_64 镜像的内核默认 `CONFIG_XDP_SOCKETS=n`，导致：
- `/proc/net/xdp_sockets` 不存在
- `bpftool map create ... type xskmap` 失败 `Invalid argument`
- AF_XDP 协议家族在内核里根本没注册
- 用户态 xdp-nat 启动就 crash

本仓库：
1. 打 patch 把 `CONFIG_XDP_SOCKETS=y` + `CONFIG_XDP_SOCKETS_DIAG=y` 编进内核
2. 顺带把 `custom/xdp-nat/` 这个包（含 LuCI 管理页）直接塞进固件
3. 用 GitHub Actions 跑 `make world` 出固件，扔 artifact 给你下载

## 怎么用

### 触发一次 build

Actions 页面 → 左侧 `Build OpenWrt...` → 右上角 **Run workflow** → 绿色按钮

- `build_type=full`（默认）：完整固件 `*-generic-squashfs-combined-efi.img.gz`，可以 sysupgrade 或 dd 到硬盘
- `build_type=kernel`：只打包 `vmlinuz` + 模块树，适合热替换

### 下载产物

完成后 Actions 页面最下面 **Artifacts** 区块 → 点那个 zip 包下载。里面有：

- `openwrt-25.12.2-x86-64-generic-squashfs-combined-efi.img.gz` — 完整固件
- `xdp-nat-*.apk` / `libxdp*.apk` / `kmod-xdp-sockets-diag*.apk` — 单独的包（apk add 用）
- `*.manifest` — 这份固件里装了什么包，一览表

### 刷到路由器（完整固件）

```bash
# 1. 备份配置
ssh root@192.168.1.1 'tar -czf /tmp/backup.tgz /etc/config' 
scp root@192.168.1.1:/tmp/backup.tgz .

# 2. 上传新固件
scp openwrt-25.12.2-*-squashfs-combined-efi.img.gz root@192.168.1.1:/tmp/

# 3. sysupgrade（保留 /etc/config/）
ssh root@192.168.1.1 'sysupgrade -v /tmp/openwrt-*.img.gz'
# 路由器会自动重启
```

### 验证新内核有 XDP_SOCKETS

```bash
ssh root@192.168.1.1 '
  # AF_XDP 协议族存在
  ls /proc/net/xdp_sockets  # 应该存在
  # XSKMAP 可创建
  bpftool map create /sys/fs/bpf/xsk_test type xskmap key 4 value 4 entries 1 name xsk_test
  rm -f /sys/fs/bpf/xsk_test
  # xdp-nat 服务
  /etc/init.d/xdp-nat start
  sleep 2
  pgrep xdp_nat || echo "启动失败"
'
```

## 仓库结构

```
.
├── .github/workflows/build.yml   # GitHub Actions 工作流（~40 min build）
├── custom/xdp-nat/               # xdp-nat OpenWrt 包
│   ├── Makefile
│   ├── src/xdp_nat.c             # ~92KB，用户态 NAT daemon（直连 libbpf，不走 libxdp dispatcher）
│   ├── src/xdp_nat_redirect.c    # BPF 程序（XDP redirect 到 XSKMAP）
│   └── files/
│       ├── xdp-nat.init          # procd init 脚本
│       ├── xdp-nat.config        # 默认 UCI 配置
│       ├── xdp-nat-ctl           # CLI 工具（enable/start/stop/conns）
│       ├── xdp-nat-menu.json     # LuCI 菜单条目
│       ├── xdp-nat-acl.json      # rpcd ACL 白名单
│       └── xdp-nat-view.js       # LuCI 管理页（状态面板 + 一键启用）
├── README.md
└── .gitignore
```

## 已知限制

- NIC 驱动需支持 `NETDEV_XDP_ACT_REDIRECT`（intel ixgbe/i40e/ice/82599 均支持）
- 真正的 zero-copy 还需 `NETDEV_XDP_ACT_XSK_ZEROCOPY=yes`；否则退化为 copy mode（仍比内核栈快，但非零拷贝）
- xdp-nat 是 PoC 性质，不建议生产用

## 许可

xdp-nat 源码：MIT。其余遵循 OpenWrt 上游许可。
