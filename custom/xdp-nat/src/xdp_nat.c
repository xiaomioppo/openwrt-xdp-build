// xdp_nat.c — AF_XDP zero-copy SNAT/NAPT 用户态转发器
//
// 工作模式：
//   LAN (eth0) <-- AF_XDP ZC --> [本程序] <-- AF_XDP ZC --> WAN (eth1)
//   BPF xdp_nat_redirect.o 驱动层只 REDIRECT IPv4 TCP/UDP 到用户态；
//   其他协议 (ARP/ICMP/IPv6/DHCP/multicast) 走内核，无影响。
//
// 功能（极简 NAPT）：
//   - LAN→WAN 方向：根据 (src_ip,src_port,dst_ip,dst_port,proto) 五元组查连接；
//     无则分配 WAN 端口，改写 IP.src = WAN_IP, L4.src = WAN_PORT，重算 L3/L4 checksum
//   - WAN→LAN 方向：根据 (dst_port,proto) 查已建立连接；命中则反向改写到 LAN
//   - 5 元组连接跟踪使用哈希表，线性探测；周期清理超时条目
//   - TCP 60s / UDP 30s 无活跃即过期（可配）
//
// 编译（OpenWrt SDK / 目标机）：
//   musl-gcc -O2 -Wall -o xdp_nat xdp_nat.c -lxdp -lbpf -lelf -lz -lpthread
// 或 OpenWrt package Makefile（见同目录 Makefile）。
//
// 运行：
//   xdp_nat --wan eth1 --lan eth0 --wan-ip 192.168.1.220 --lan-cidr 192.168.1.0/24
//
// 注意：这是**教学/概念验证**实现，未做 ICMP、ALG、Fragment、
// 多队列 CPU pinning、PREROUTING iptables 兼容性等。

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <ifaddrs.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
/* 不再用 libxdp 的 dispatcher —— 它要求新版 vmlinux BTF；直接用 libbpf 的 bpf_xdp_attach
 * 绕过整个 dispatcher 栈，解决 "libxdp: Failed to load dispatcher: Invalid argument" */
#include <pthread.h>
#include <sched.h>

#define ATOMIC_ADD(p, v) __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
#define ATOMIC_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)
#define ATOMIC_LOAD(p)     __atomic_load_n((p),    __ATOMIC_RELAXED)

/* ========================= 配置 & 全局 ========================= */

#define NUM_FRAMES          4096
#define FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE  /* 4096 */
#define RX_BATCH_SIZE       64
#define INVALID_UMEM_FRAME  UINT64_MAX

#define NAT_TABLE_SIZE      65536      /* 哈希桶数（2^16） */
#define NAT_TABLE_MASK      (NAT_TABLE_SIZE - 1)
#define PORT_POOL_START     10000
#define PORT_POOL_END       60000
/* 按 TCP 状态细化超时 */
#define TCP_TIMEOUT_NEW         30
#define TCP_TIMEOUT_EST         3600
#define TCP_TIMEOUT_FIN         30
#define TCP_TIMEOUT_CLOSED      10
#define UDP_TIMEOUT_SEC         30
#define ICMP_TIMEOUT_SEC        30
#define CLEANUP_INTERVAL        10
#define STATS_INTERVAL          1

#define MAX_DNAT_RULES          256

enum tcp_state {
    TCP_ST_NEW    = 0,   /* 只见过 SYN */
    TCP_ST_EST    = 1,   /* 双向数据中 */
    TCP_ST_FIN    = 2,   /* 有一方 FIN */
    TCP_ST_CLOSED = 3,   /* RST */
};

/* DNAT 规则（命令行 --dnat 或 UCI forward section） */
struct dnat_rule {
    uint8_t  proto;       /* TCP/UDP */
    uint16_t wan_port;    /* network order */
    uint32_t lan_ip;      /* network order */
    uint16_t lan_port;
    uint64_t hits;
};

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_dump = 0;
static int g_verbose = 0;

static void handle_sig(int s)   { (void)s; g_stop = 1; }
static void handle_usr1(int s)  { (void)s; g_dump = 1; }

static struct dnat_rule g_dnat[MAX_DNAT_RULES];
static int g_dnat_n = 0;

/* 全局 NAT 表锁：读多写少，lookup 走 rdlock，insert/delete 走 wrlock
   update last_seen/pkts/bytes 用原子操作不占锁 */
static pthread_rwlock_t g_nat_lock = PTHREAD_RWLOCK_INITIALIZER;

/* 全局原子计数器（所有 worker 共享） */
static uint64_t g_stat_wan_rx, g_stat_wan_tx, g_stat_lan_rx, g_stat_lan_tx;
static uint64_t g_stat_wan_drop, g_stat_lan_drop, g_stat_dnat_hits;

static void log_msg(const char *prefix, const char *fmt, ...) {
    va_list ap;
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    fprintf(stderr, "[%s] %s ", ts, prefix);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
#define LOGE(...)  log_msg("ERR ", __VA_ARGS__)
#define LOGI(...)  log_msg("INFO", __VA_ARGS__)
#define LOGD(...)  do { if (g_verbose) log_msg("DBG ", __VA_ARGS__); } while (0)

/* ========================= UMEM & XSK ========================= */

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
    uint64_t frames[NUM_FRAMES];
    int frames_free;
};

struct xsk_port {
    const char *ifname;
    int ifindex;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    uint64_t rx_packets, tx_packets, rx_bytes, tx_bytes, dropped;
};

/* per-queue worker：独立 UMEM + 一对 XSK */
struct xdp_worker {
    int queue_id;
    int cpu;                     /* -1 = 不绑定 */
    pthread_t tid;
    struct xsk_umem_info *umem;
    struct xsk_port wan, lan;
    int started;
};

static struct xsk_umem_info *umem_init(void *buffer, uint64_t size) {
    struct xsk_umem_info *u = calloc(1, sizeof(*u));
    if (!u) return NULL;
    struct xsk_umem_config cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };
    int ret = xsk_umem__create(&u->umem, buffer, size, &u->fq, &u->cq, &cfg);
    if (ret) { LOGE("xsk_umem__create: %s", strerror(-ret)); free(u); return NULL; }
    u->buffer = buffer;
    for (int i = 0; i < NUM_FRAMES; i++)
        u->frames[i] = (uint64_t)i * FRAME_SIZE;
    u->frames_free = NUM_FRAMES;
    return u;
}

static uint64_t umem_alloc_frame(struct xsk_umem_info *u) {
    if (u->frames_free == 0) return INVALID_UMEM_FRAME;
    return u->frames[--u->frames_free];
}

static void umem_free_frame(struct xsk_umem_info *u, uint64_t addr) {
    u->frames[u->frames_free++] = addr & ~(FRAME_SIZE - 1);
}

static int xsk_port_open(struct xsk_port *p, struct xsk_umem_info *umem,
                         int queue_id, bool try_zc) {
    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, /* 程序外部加载 */
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = try_zc ? XDP_ZEROCOPY : XDP_COPY,
    };
    p->umem = umem;
    int ret = xsk_socket__create(&p->xsk, p->ifname, queue_id, umem->umem,
                                 &p->rx, &p->tx, &cfg);
    if (ret) {
        if (try_zc) {
            LOGI("%s: zero-copy 模式失败（%s），回退 copy 模式",
                 p->ifname, strerror(-ret));
            cfg.bind_flags = XDP_COPY;
            ret = xsk_socket__create(&p->xsk, p->ifname, queue_id, umem->umem,
                                     &p->rx, &p->tx, &cfg);
        }
    } else {
        LOGI("%s: AF_XDP zero-copy 已启用（队列 %d）", p->ifname, queue_id);
    }
    if (ret) { LOGE("%s: xsk_socket__create 失败: %s", p->ifname, strerror(-ret)); return -1; }

    /* 预先把一批 UMEM frame 放进 fill ring 等待 RX */
    uint32_t idx;
    uint32_t reserved = xsk_ring_prod__reserve(&umem->fq,
                                               XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                               &idx);
    if (reserved != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        LOGE("%s: fill ring 预留失败", p->ifname); return -1;
    }
    for (uint32_t i = 0; i < reserved; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = umem_alloc_frame(umem);
    xsk_ring_prod__submit(&umem->fq, reserved);
    return 0;
}

/* ========================= NAT 连接跟踪 ========================= */

enum { NAT_FREE = 0, NAT_USED = 1 };

/* 双向映射共用一个 table，通过两种 hash 查询（egress 5-tuple / ingress 2-tuple） */
struct nat_entry {
    uint8_t  state;         /* FREE / USED */
    uint8_t  proto;         /* IPPROTO_TCP / UDP / ICMP */
    uint8_t  tcp_state;     /* enum tcp_state（仅 TCP） */
    uint8_t  dnat;          /* 1 = 由 DNAT 规则生成 */

    /* LAN 侧（原始） */
    uint32_t lan_ip;        /* 网络序 */
    uint16_t lan_port;      /* 网络序 */

    /* 远端 */
    uint32_t rem_ip;
    uint16_t rem_port;

    /* WAN 侧（转换后） */
    uint16_t wan_port;      /* 网络序 */

    time_t   last_seen;
    uint64_t pkts, bytes;
};

/* 两张索引表 */
static struct nat_entry *g_table;  /* 池，大小 NAT_TABLE_SIZE */
/* 出向索引：hash(5-tuple) → entry 下标 */
static uint32_t *g_egress_idx;     /* NAT_TABLE_SIZE；值 = entry 下标 + 1，0 = 空 */
/* 入向索引：hash(wan_port, proto) → entry 下标 */
static uint32_t *g_ingress_idx;    /* NAT_TABLE_SIZE */

static uint32_t g_wan_ip;          /* 网络序 */
static uint32_t g_lan_net;         /* 网络序 */
static uint32_t g_lan_mask;        /* 网络序 */
static uint16_t g_next_port = PORT_POOL_START;

/* NPTv6 规则：inside_prefix/len → outside_prefix/len */
#define MAX_NPT6_RULES 8
struct npt6_rule {
    struct in6_addr inside;    /* /plen */
    struct in6_addr outside;
    int plen;
    uint64_t hits_in2out;
    uint64_t hits_out2in;
};
static struct npt6_rule g_npt6[MAX_NPT6_RULES];
static int g_npt6_n = 0;

/* ============ NAT66（v6↔v6 NAPT） ============ */
#define NAT6_TABLE_SIZE 65536
#define NAT6_TABLE_MASK (NAT6_TABLE_SIZE - 1)

struct nat6_entry {
    uint8_t state;
    uint8_t proto;
    uint8_t tcp_state;
    uint8_t _pad;
    struct in6_addr lan_ip6;
    struct in6_addr rem_ip6;
    uint16_t lan_port;
    uint16_t rem_port;
    uint16_t wan_port;
    time_t   last_seen;
    uint64_t pkts, bytes;
};

static struct nat6_entry *g_table6;
static uint32_t *g_egress6_idx;
static uint32_t *g_ingress6_idx;
static struct in6_addr g_wan_ip6;        /* NAT66 WAN 源 */
static bool g_wan_ip6_set = false;
static uint16_t g_v6_next_port = PORT_POOL_START;
static pthread_rwlock_t g_nat6_lock = PTHREAD_RWLOCK_INITIALIZER;
static bool g_nat66_enabled = false;

/* ============ NAT64 ============ */
/* NAT64 前缀（RFC 6052 默认 64:ff9b::/96） */
static struct in6_addr g_nat64_pfx;
static int g_nat64_pfx_len = 96;
static bool g_nat64_enabled = false;

/* NAT64 session：v6 客户端 ↔ v4 服务器 */
struct nat64_entry {
    uint8_t state;
    uint8_t proto;     /* IPPROTO_TCP/UDP/ICMP (注意：inside 是 ICMPv6 type，外转 ICMP) */
    uint8_t tcp_state;
    uint8_t _pad;
    struct in6_addr lan_ip6;   /* v6 客户端 */
    uint16_t         lan_port; /* 客户端端口 */
    uint32_t rem_ip4;          /* 远端 v4（从 dst_ip6 低 32 位提取） */
    uint16_t rem_port;
    uint16_t wan_port;         /* g_wan_ip 上的 NAT 端口 */
    time_t   last_seen;
    uint64_t pkts, bytes;
};

#define NAT64_TABLE_SIZE 32768
#define NAT64_TABLE_MASK (NAT64_TABLE_SIZE - 1)
static struct nat64_entry *g_table64;
static uint32_t *g_egress64_idx;   /* hash(v6_src, lan_port, rem_v4, rem_port, proto) */
static uint32_t *g_ingress64_idx;  /* hash(wan_port, proto) */
static pthread_rwlock_t g_nat64_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint16_t g_v64_next_port = PORT_POOL_START;

/* ============ NAT46 ============ */
#define MAX_NAT46_RULES 64
struct nat46_rule {
    uint32_t v4_target;         /* 外网 v4 地址（用户访问它） */
    struct in6_addr v6_real;    /* 实际 v6 主机 */
    uint64_t hits;
};
static struct nat46_rule g_nat46[MAX_NAT46_RULES];
static int g_nat46_n = 0;
/* NAT46 session：v4 客户端 ↔ v6 后端 */
struct nat46_entry {
    uint8_t state, proto, tcp_state, _pad;
    uint32_t rem_ip4;            /* v4 客户端 */
    uint16_t rem_port;
    uint32_t target_v4;          /* 客户端看到的 v4（对应 rule） */
    uint16_t target_port;        /* 客户端请求的端口（透传给 v6 后端） */
    struct in6_addr v6_real;     /* 真实 v6 主机 */
    struct in6_addr v6_src;      /* NAT46 合成的 v6 源（g_nat64_pfx + rem_ip4） */
    time_t   last_seen;
    uint64_t pkts, bytes;
};
#define NAT46_TABLE_SIZE 16384
#define NAT46_TABLE_MASK (NAT46_TABLE_SIZE - 1)
static struct nat46_entry *g_table46;
static uint32_t *g_egress46_idx;
static uint32_t *g_ingress46_idx;
static pthread_rwlock_t g_nat46_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint16_t g_v46_next_port = PORT_POOL_START;

/* 固定的 NAT46 IPv6 源：一组 v4 客户端共享此 v6 源出站 */
static struct in6_addr g_nat46_v6_src;
static bool g_nat46_v6_src_set = false;

/* 简单 FNV-1a hash */
static uint32_t fnv1a(const void *data, size_t n) {
    const uint8_t *p = data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static uint32_t hash_egress(uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp, uint8_t pr) {
    uint8_t buf[13];
    memcpy(buf,    &sip, 4);
    memcpy(buf+4,  &sp,  2);
    memcpy(buf+6,  &dip, 4);
    memcpy(buf+10, &dp,  2);
    buf[12] = pr;
    return fnv1a(buf, sizeof buf);
}
static uint32_t hash_ingress(uint16_t wp, uint8_t pr) {
    uint8_t buf[3];
    memcpy(buf, &wp, 2);
    buf[2] = pr;
    return fnv1a(buf, sizeof buf);
}

/* 线性探测。调用者持有 g_nat_lock 读锁（或更高） */
static struct nat_entry *lookup_egress_locked(uint32_t sip, uint16_t sp,
                                               uint32_t dip, uint16_t dp, uint8_t pr) {
    uint32_t h = hash_egress(sip, sp, dip, dp, pr) & NAT_TABLE_MASK;
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT_TABLE_MASK;
        uint32_t v = g_egress_idx[slot];
        if (v == 0) return NULL;
        struct nat_entry *e = &g_table[v - 1];
        if (e->state == NAT_USED && e->proto == pr &&
            e->lan_ip == sip && e->lan_port == sp &&
            e->rem_ip == dip && e->rem_port == dp)
            return e;
    }
    return NULL;
}
static struct nat_entry *lookup_ingress_locked(uint16_t wp, uint8_t pr) {
    uint32_t h = hash_ingress(wp, pr) & NAT_TABLE_MASK;
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT_TABLE_MASK;
        uint32_t v = g_ingress_idx[slot];
        if (v == 0) return NULL;
        struct nat_entry *e = &g_table[v - 1];
        if (e->state == NAT_USED && e->proto == pr && e->wan_port == wp)
            return e;
    }
    return NULL;
}

/* 外部调用接口：自动加读锁 */
static struct nat_entry *lookup_egress(uint32_t sip, uint16_t sp,
                                        uint32_t dip, uint16_t dp, uint8_t pr) {
    pthread_rwlock_rdlock(&g_nat_lock);
    struct nat_entry *e = lookup_egress_locked(sip, sp, dip, dp, pr);
    pthread_rwlock_unlock(&g_nat_lock);
    return e;
}
static struct nat_entry *lookup_ingress(uint16_t wp, uint8_t pr) {
    pthread_rwlock_rdlock(&g_nat_lock);
    struct nat_entry *e = lookup_ingress_locked(wp, pr);
    pthread_rwlock_unlock(&g_nat_lock);
    return e;
}

/* 在索引表里插入 */
static void insert_index(uint32_t *idx_table, uint32_t h, uint32_t entry_index) {
    uint32_t slot = h & NAT_TABLE_MASK;
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        uint32_t s = (slot + i) & NAT_TABLE_MASK;
        if (idx_table[s] == 0) { idx_table[s] = entry_index + 1; return; }
    }
}
static void remove_index(uint32_t *idx_table, uint32_t h, uint32_t entry_index) {
    uint32_t slot = h & NAT_TABLE_MASK;
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        uint32_t s = (slot + i) & NAT_TABLE_MASK;
        if (idx_table[s] == entry_index + 1) { idx_table[s] = 0; return; }
        if (idx_table[s] == 0) return;
    }
}

/* 分配一个 WAN 端口并创建 NAT entry。自带 wrlock */
static struct nat_entry *nat_create(uint32_t sip, uint16_t sp,
                                    uint32_t dip, uint16_t dp, uint8_t pr) {
    pthread_rwlock_wrlock(&g_nat_lock);
    static uint32_t cursor = 0;
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        uint32_t c = (cursor + i) % NAT_TABLE_SIZE;
        if (g_table[c].state == NAT_FREE) { idx = c; cursor = c + 1; break; }
    }
    if (idx == UINT32_MAX) { pthread_rwlock_unlock(&g_nat_lock); return NULL; }

    uint16_t try_port;
    int attempts = 0;
    while (attempts++ < (PORT_POOL_END - PORT_POOL_START)) {
        try_port = g_next_port++;
        if (g_next_port >= PORT_POOL_END) g_next_port = PORT_POOL_START;
        uint16_t wp_be = htons(try_port);
        if (!lookup_ingress_locked(wp_be, pr)) {
            struct nat_entry *e = &g_table[idx];
            e->state    = NAT_USED;
            e->proto    = pr;
            e->lan_ip   = sip; e->lan_port = sp;
            e->rem_ip   = dip; e->rem_port = dp;
            e->wan_port = wp_be;
            e->last_seen = time(NULL);

            insert_index(g_egress_idx,  hash_egress(sip, sp, dip, dp, pr), idx);
            insert_index(g_ingress_idx, hash_ingress(wp_be, pr),           idx);
            pthread_rwlock_unlock(&g_nat_lock);
            return e;
        }
    }
    pthread_rwlock_unlock(&g_nat_lock);
    return NULL;
}

/* DNAT 专用 create（固定 wan_port，不走端口池） */
static struct nat_entry *nat_create_dnat(uint32_t lan_ip, uint16_t lan_port,
                                          uint32_t rem_ip, uint16_t rem_port,
                                          uint16_t wan_port, uint8_t pr) {
    pthread_rwlock_wrlock(&g_nat_lock);
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        if (g_table[i].state == NAT_FREE) {
            struct nat_entry *e = &g_table[i];
            e->state     = NAT_USED;
            e->proto     = pr;
            e->tcp_state = TCP_ST_NEW;
            e->dnat      = 1;
            e->lan_ip    = lan_ip;  e->lan_port = lan_port;
            e->rem_ip    = rem_ip;  e->rem_port = rem_port;
            e->wan_port  = wan_port;
            e->last_seen = time(NULL);
            e->pkts = e->bytes = 0;
            insert_index(g_egress_idx,
                         hash_egress(lan_ip, lan_port, rem_ip, rem_port, pr), i);
            insert_index(g_ingress_idx, hash_ingress(wan_port, pr), i);
            pthread_rwlock_unlock(&g_nat_lock);
            return e;
        }
    }
    pthread_rwlock_unlock(&g_nat_lock);
    return NULL;
}

/* 调用者已持 wrlock */
static void nat_delete_locked(struct nat_entry *e) {
    uint32_t idx = e - g_table;
    remove_index(g_egress_idx,
                 hash_egress(e->lan_ip, e->lan_port, e->rem_ip, e->rem_port, e->proto),
                 idx);
    remove_index(g_ingress_idx, hash_ingress(e->wan_port, e->proto), idx);
    memset(e, 0, sizeof(*e));
}

static int nat_timeout(const struct nat_entry *e) {
    switch (e->proto) {
        case IPPROTO_UDP:  return UDP_TIMEOUT_SEC;
        case IPPROTO_ICMP: return ICMP_TIMEOUT_SEC;
        case IPPROTO_TCP:
            switch (e->tcp_state) {
                case TCP_ST_EST:    return TCP_TIMEOUT_EST;
                case TCP_ST_FIN:    return TCP_TIMEOUT_FIN;
                case TCP_ST_CLOSED: return TCP_TIMEOUT_CLOSED;
                default:            return TCP_TIMEOUT_NEW;
            }
    }
    return UDP_TIMEOUT_SEC;
}

static size_t nat_cleanup(void) {
    time_t now = time(NULL);
    size_t n = 0;
    pthread_rwlock_wrlock(&g_nat_lock);
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry *e = &g_table[i];
        if (e->state != NAT_USED) continue;
        if (now - e->last_seen > nat_timeout(e)) { nat_delete_locked(e); n++; }
    }
    pthread_rwlock_unlock(&g_nat_lock);
    return n;
}

static size_t nat_count(void) {
    size_t n = 0;
    pthread_rwlock_rdlock(&g_nat_lock);
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++)
        if (g_table[i].state == NAT_USED) n++;
    pthread_rwlock_unlock(&g_nat_lock);
    return n;
}

/* 按 TCP flags 更新 entry 状态 */
static void tcp_state_update(struct nat_entry *e, const struct tcphdr *tcp) {
    if (e->proto != IPPROTO_TCP) return;
    if (tcp->rst)                     { e->tcp_state = TCP_ST_CLOSED; return; }
    if (tcp->fin)                     { e->tcp_state = TCP_ST_FIN;    return; }
    if (tcp->syn && tcp->ack)         { e->tcp_state = TCP_ST_EST;    return; }
    if (e->tcp_state == TCP_ST_NEW && tcp->ack) e->tcp_state = TCP_ST_EST;
}

/* DNAT 规则查找 */
static const struct dnat_rule *dnat_lookup_in(uint8_t proto, uint16_t wan_port) {
    for (int i = 0; i < g_dnat_n; i++)
        if (g_dnat[i].proto == proto && g_dnat[i].wan_port == wan_port)
            return &g_dnat[i];
    return NULL;
}
static const struct dnat_rule *dnat_lookup_out(uint8_t proto, uint32_t lan_ip, uint16_t lan_port) {
    for (int i = 0; i < g_dnat_n; i++)
        if (g_dnat[i].proto == proto &&
            g_dnat[i].lan_ip == lan_ip &&
            g_dnat[i].lan_port == lan_port)
            return &g_dnat[i];
    return NULL;
}

/* ========================= 校验和增量更新（RFC1624） ========================= */

/* old & new 以反码累加；结果放回校验和字段 */
static inline uint16_t csum_fold(uint32_t s) {
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)s;
}
static inline uint16_t csum_update(uint16_t old_csum,
                                   uint32_t old_val, uint32_t new_val) {
    /* 增量更新；按 16-bit 反码 */
    uint32_t s = (uint16_t)~old_csum;
    s += (uint16_t)~(old_val & 0xFFFF);
    s += (uint16_t)~(old_val >> 16);
    s += (new_val & 0xFFFF);
    s += (new_val >> 16);
    return (uint16_t)~csum_fold(s);
}
/* IPv4 checksum 增量 */
static inline void ip_csum_replace4(struct iphdr *ip, uint32_t oldv, uint32_t newv) {
    ip->check = csum_update(ip->check, oldv, newv);
}

/* ========================= NAT66 函数 ========================= */
static uint32_t hash6_egress(const struct in6_addr *s, uint16_t sp,
                              const struct in6_addr *d, uint16_t dp, uint8_t pr) {
    uint8_t buf[37];
    memcpy(buf,    s->s6_addr, 16);
    memcpy(buf+16, &sp, 2);
    memcpy(buf+18, d->s6_addr, 16);
    memcpy(buf+34, &dp, 2);
    buf[36] = pr;
    return fnv1a(buf, sizeof buf);
}
static uint32_t hash6_ingress(uint16_t wp, uint8_t pr) {
    uint8_t buf[3]; memcpy(buf, &wp, 2); buf[2] = pr;
    return fnv1a(buf, sizeof buf);
}

static struct nat6_entry *lookup6_egress_l(const struct in6_addr *s, uint16_t sp,
                                            const struct in6_addr *d, uint16_t dp, uint8_t pr) {
    uint32_t h = hash6_egress(s, sp, d, dp, pr) & NAT6_TABLE_MASK;
    for (uint32_t i = 0; i < NAT6_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT6_TABLE_MASK;
        uint32_t v = g_egress6_idx[slot];
        if (v == 0) return NULL;
        struct nat6_entry *e = &g_table6[v - 1];
        if (e->state == NAT_USED && e->proto == pr &&
            memcmp(&e->lan_ip6, s, 16) == 0 && e->lan_port == sp &&
            memcmp(&e->rem_ip6, d, 16) == 0 && e->rem_port == dp)
            return e;
    }
    return NULL;
}
static struct nat6_entry *lookup6_ingress_l(uint16_t wp, uint8_t pr) {
    uint32_t h = hash6_ingress(wp, pr) & NAT6_TABLE_MASK;
    for (uint32_t i = 0; i < NAT6_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT6_TABLE_MASK;
        uint32_t v = g_ingress6_idx[slot];
        if (v == 0) return NULL;
        struct nat6_entry *e = &g_table6[v - 1];
        if (e->state == NAT_USED && e->proto == pr && e->wan_port == wp) return e;
    }
    return NULL;
}
static struct nat6_entry *lookup6_egress(const struct in6_addr *s, uint16_t sp,
                                          const struct in6_addr *d, uint16_t dp, uint8_t pr) {
    pthread_rwlock_rdlock(&g_nat6_lock);
    struct nat6_entry *e = lookup6_egress_l(s, sp, d, dp, pr);
    pthread_rwlock_unlock(&g_nat6_lock);
    return e;
}
static struct nat6_entry *lookup6_ingress(uint16_t wp, uint8_t pr) {
    pthread_rwlock_rdlock(&g_nat6_lock);
    struct nat6_entry *e = lookup6_ingress_l(wp, pr);
    pthread_rwlock_unlock(&g_nat6_lock);
    return e;
}
static struct nat6_entry *nat6_create(const struct in6_addr *s, uint16_t sp,
                                       const struct in6_addr *d, uint16_t dp, uint8_t pr) {
    pthread_rwlock_wrlock(&g_nat6_lock);
    static uint32_t cursor = 0;
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < NAT6_TABLE_SIZE; i++) {
        uint32_t c = (cursor + i) % NAT6_TABLE_SIZE;
        if (g_table6[c].state == NAT_FREE) { idx = c; cursor = c + 1; break; }
    }
    if (idx == UINT32_MAX) { pthread_rwlock_unlock(&g_nat6_lock); return NULL; }
    int tries = 0;
    while (tries++ < (PORT_POOL_END - PORT_POOL_START)) {
        uint16_t try_port = g_v6_next_port++;
        if (g_v6_next_port >= PORT_POOL_END) g_v6_next_port = PORT_POOL_START;
        uint16_t wp_be = htons(try_port);
        if (!lookup6_ingress_l(wp_be, pr)) {
            struct nat6_entry *e = &g_table6[idx];
            e->state = NAT_USED; e->proto = pr; e->tcp_state = TCP_ST_NEW;
            e->lan_ip6 = *s; e->lan_port = sp;
            e->rem_ip6 = *d; e->rem_port = dp;
            e->wan_port = wp_be; e->last_seen = time(NULL);
            e->pkts = e->bytes = 0;
            uint32_t slot;
            slot = hash6_egress(s, sp, d, dp, pr) & NAT6_TABLE_MASK;
            for (uint32_t i = 0; i < NAT6_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT6_TABLE_MASK;
                if (g_egress6_idx[s2] == 0) { g_egress6_idx[s2] = idx + 1; break; }
            }
            slot = hash6_ingress(wp_be, pr) & NAT6_TABLE_MASK;
            for (uint32_t i = 0; i < NAT6_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT6_TABLE_MASK;
                if (g_ingress6_idx[s2] == 0) { g_ingress6_idx[s2] = idx + 1; break; }
            }
            pthread_rwlock_unlock(&g_nat6_lock);
            return e;
        }
    }
    pthread_rwlock_unlock(&g_nat6_lock);
    return NULL;
}

/* ========================= NAT64/46 session helpers ========================= */
static uint32_t hash64_egress(const struct in6_addr *s, uint16_t sp,
                               uint32_t d4, uint16_t dp, uint8_t pr) {
    uint8_t buf[25];
    memcpy(buf, s->s6_addr, 16); memcpy(buf+16, &sp, 2);
    memcpy(buf+18, &d4, 4); memcpy(buf+22, &dp, 2); buf[24] = pr;
    return fnv1a(buf, sizeof buf);
}
static struct nat64_entry *lookup64_egress_l(const struct in6_addr *s, uint16_t sp,
                                              uint32_t d4, uint16_t dp, uint8_t pr) {
    uint32_t h = hash64_egress(s, sp, d4, dp, pr) & NAT64_TABLE_MASK;
    for (uint32_t i = 0; i < NAT64_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT64_TABLE_MASK;
        uint32_t v = g_egress64_idx[slot];
        if (v == 0) return NULL;
        struct nat64_entry *e = &g_table64[v - 1];
        if (e->state == NAT_USED && e->proto == pr &&
            memcmp(&e->lan_ip6, s, 16) == 0 && e->lan_port == sp &&
            e->rem_ip4 == d4 && e->rem_port == dp)
            return e;
    }
    return NULL;
}
static struct nat64_entry *lookup64_ingress_l(uint16_t wp, uint8_t pr) {
    uint32_t h = hash_ingress(wp, pr) & NAT64_TABLE_MASK;
    for (uint32_t i = 0; i < NAT64_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT64_TABLE_MASK;
        uint32_t v = g_ingress64_idx[slot];
        if (v == 0) return NULL;
        struct nat64_entry *e = &g_table64[v - 1];
        if (e->state == NAT_USED && e->proto == pr && e->wan_port == wp) return e;
    }
    return NULL;
}
static struct nat64_entry *nat64_create(const struct in6_addr *s, uint16_t sp,
                                         uint32_t d4, uint16_t dp, uint8_t pr) {
    pthread_rwlock_wrlock(&g_nat64_lock);
    static uint32_t cursor = 0;
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < NAT64_TABLE_SIZE; i++) {
        uint32_t c = (cursor + i) % NAT64_TABLE_SIZE;
        if (g_table64[c].state == NAT_FREE) { idx = c; cursor = c + 1; break; }
    }
    if (idx == UINT32_MAX) { pthread_rwlock_unlock(&g_nat64_lock); return NULL; }
    int tries = 0;
    while (tries++ < (PORT_POOL_END - PORT_POOL_START)) {
        uint16_t try_port = g_v64_next_port++;
        if (g_v64_next_port >= PORT_POOL_END) g_v64_next_port = PORT_POOL_START;
        uint16_t wp_be = htons(try_port);
        if (!lookup64_ingress_l(wp_be, pr)) {
            struct nat64_entry *e = &g_table64[idx];
            e->state = NAT_USED; e->proto = pr; e->tcp_state = TCP_ST_NEW;
            e->lan_ip6 = *s; e->lan_port = sp;
            e->rem_ip4 = d4; e->rem_port = dp;
            e->wan_port = wp_be; e->last_seen = time(NULL);
            e->pkts = e->bytes = 0;
            uint32_t slot = hash64_egress(s, sp, d4, dp, pr) & NAT64_TABLE_MASK;
            for (uint32_t i = 0; i < NAT64_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT64_TABLE_MASK;
                if (g_egress64_idx[s2] == 0) { g_egress64_idx[s2] = idx + 1; break; }
            }
            slot = hash_ingress(wp_be, pr) & NAT64_TABLE_MASK;
            for (uint32_t i = 0; i < NAT64_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT64_TABLE_MASK;
                if (g_ingress64_idx[s2] == 0) { g_ingress64_idx[s2] = idx + 1; break; }
            }
            pthread_rwlock_unlock(&g_nat64_lock);
            return e;
        }
    }
    pthread_rwlock_unlock(&g_nat64_lock);
    return NULL;
}

/* ========================= NAT46 session 操作 ========================= */
static uint32_t hash46_egress(uint32_t rem_v4, uint16_t rem_port,
                               uint32_t target_v4, uint16_t target_port, uint8_t pr) {
    uint8_t buf[13];
    memcpy(buf,    &rem_v4, 4);
    memcpy(buf+4,  &rem_port, 2);
    memcpy(buf+6,  &target_v4, 4);
    memcpy(buf+10, &target_port, 2);
    buf[12] = pr;
    return fnv1a(buf, sizeof buf);
}
static uint32_t hash46_ingress(uint16_t wp, uint8_t pr) {
    uint8_t buf[3]; memcpy(buf, &wp, 2); buf[2] = pr;
    return fnv1a(buf, sizeof buf);
}
static struct nat46_entry *lookup46_egress_l(uint32_t rem_v4, uint16_t rem_port,
                                              uint32_t target_v4, uint16_t target_port,
                                              uint8_t pr) {
    uint32_t h = hash46_egress(rem_v4, rem_port, target_v4, target_port, pr) & NAT46_TABLE_MASK;
    for (uint32_t i = 0; i < NAT46_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT46_TABLE_MASK;
        uint32_t v = g_egress46_idx[slot];
        if (v == 0) return NULL;
        struct nat46_entry *e = &g_table46[v - 1];
        if (e->state == NAT_USED && e->proto == pr &&
            e->rem_ip4 == rem_v4 && e->rem_port == rem_port &&
            e->target_v4 == target_v4 && e->target_port == target_port)
            return e;
    }
    return NULL;
}
static struct nat46_entry *lookup46_ingress_l(uint16_t wp, uint8_t pr) {
    uint32_t h = hash46_ingress(wp, pr) & NAT46_TABLE_MASK;
    for (uint32_t i = 0; i < NAT46_TABLE_SIZE; i++) {
        uint32_t slot = (h + i) & NAT46_TABLE_MASK;
        uint32_t v = g_ingress46_idx[slot];
        if (v == 0) return NULL;
        struct nat46_entry *e = &g_table46[v - 1];
        if (e->state == NAT_USED && e->proto == pr && e->target_port == wp)
            return e;
    }
    return NULL;
}
static struct nat46_entry *nat46_session_create(uint32_t rem_v4, uint16_t rem_port,
                                                  uint32_t target_v4, uint16_t target_port,
                                                  const struct in6_addr *v6_real,
                                                  const struct in6_addr *v6_src,
                                                  uint8_t pr) {
    pthread_rwlock_wrlock(&g_nat46_lock);
    static uint32_t cursor = 0;
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < NAT46_TABLE_SIZE; i++) {
        uint32_t c = (cursor + i) % NAT46_TABLE_SIZE;
        if (g_table46[c].state == NAT_FREE) { idx = c; cursor = c + 1; break; }
    }
    if (idx == UINT32_MAX) { pthread_rwlock_unlock(&g_nat46_lock); return NULL; }
    int tries = 0;
    while (tries++ < (PORT_POOL_END - PORT_POOL_START)) {
        uint16_t try_port = g_v46_next_port++;
        if (g_v46_next_port >= PORT_POOL_END) g_v46_next_port = PORT_POOL_START;
        uint16_t wp_be = htons(try_port);
        if (!lookup46_ingress_l(wp_be, pr)) {
            struct nat46_entry *e = &g_table46[idx];
            e->state = NAT_USED; e->proto = pr; e->tcp_state = TCP_ST_NEW;
            e->rem_ip4   = rem_v4;    e->rem_port    = rem_port;
            e->target_v4 = target_v4; e->target_port = wp_be;     /* 用端口池，不透传 */
            e->v6_real   = *v6_real;  e->v6_src      = *v6_src;
            e->last_seen = time(NULL);
            e->pkts = e->bytes = 0;
            uint32_t slot = hash46_egress(rem_v4, rem_port, target_v4, target_port, pr) & NAT46_TABLE_MASK;
            for (uint32_t i = 0; i < NAT46_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT46_TABLE_MASK;
                if (g_egress46_idx[s2] == 0) { g_egress46_idx[s2] = idx + 1; break; }
            }
            slot = hash46_ingress(wp_be, pr) & NAT46_TABLE_MASK;
            for (uint32_t i = 0; i < NAT46_TABLE_SIZE; i++) {
                uint32_t s2 = (slot + i) & NAT46_TABLE_MASK;
                if (g_ingress46_idx[s2] == 0) { g_ingress46_idx[s2] = idx + 1; break; }
            }
            pthread_rwlock_unlock(&g_nat46_lock);
            return e;
        }
    }
    pthread_rwlock_unlock(&g_nat46_lock);
    return NULL;
}

/* ========================= IPv6 NPTv6 ========================= */

static bool prefix_match6(const struct in6_addr *a, const struct in6_addr *prefix, int plen) {
    int full = plen / 8;
    int bits = plen % 8;
    if (memcmp(a->s6_addr, prefix->s6_addr, full) != 0) return false;
    if (bits) {
        uint8_t mask = (uint8_t)(0xff << (8 - bits));
        if ((a->s6_addr[full] & mask) != (prefix->s6_addr[full] & mask)) return false;
    }
    return true;
}

/* 返回匹配的 NPT 规则（按 inside 前缀匹配） */
static const struct npt6_rule *npt6_match_inside(const struct in6_addr *a) {
    for (int i = 0; i < g_npt6_n; i++)
        if (prefix_match6(a, &g_npt6[i].inside, g_npt6[i].plen))
            return &g_npt6[i];
    return NULL;
}
static const struct npt6_rule *npt6_match_outside(const struct in6_addr *a) {
    for (int i = 0; i < g_npt6_n; i++)
        if (prefix_match6(a, &g_npt6[i].outside, g_npt6[i].plen))
            return &g_npt6[i];
    return NULL;
}

/* 把 addr 的前 plen 位从 src_pref 替换为 dst_pref，保留 suffix 不变 */
static void npt6_rewrite(struct in6_addr *addr, const struct in6_addr *dst_pref, int plen) {
    int full = plen / 8;
    int bits = plen % 8;
    memcpy(addr->s6_addr, dst_pref->s6_addr, full);
    if (bits) {
        uint8_t mask = (uint8_t)(0xff << (8 - bits));
        addr->s6_addr[full] = (uint8_t)((dst_pref->s6_addr[full] & mask) |
                                        (addr->s6_addr[full]      & ~mask));
    }
}

/* 计算 16 位 words 的反码累加（用于 checksum 增量更新） */
static uint32_t sum16(const uint8_t *buf, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2)
        s += ((uint16_t)buf[i] << 8) | buf[i+1];
    if (n & 1) s += ((uint16_t)buf[n-1] << 8);
    return s;
}

/* 按 RFC 1624 增量更新 L4 csum：旧值换新值。
   这里 old16/new16 都是大端字节缓冲，每个 16B (IPv6 地址)。 */
static uint16_t csum_replace_v6(uint16_t old_csum,
                                const uint8_t *old16, const uint8_t *new16) {
    uint32_t s = (uint16_t)~old_csum;
    s += ~sum16(old16, 16) & 0xffff;
    s += sum16(new16, 16);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* ========================= 数据面：LAN→WAN & WAN→LAN ========================= */

static inline bool is_lan_addr(uint32_t ip_be) {
    return (ip_be & g_lan_mask) == (g_lan_net & g_lan_mask);
}

/* 处理 IPv6 包。三种模式：NAT66 (有状态 NAPT)、NPTv6 (无状态前缀)、透传 */

static bool prefix_is_nat64(const struct in6_addr *a) {
    return g_nat64_enabled && prefix_match6(a, &g_nat64_pfx, g_nat64_pfx_len);
}

/* L4 csum 增量：旧 IPv6 地址 → 新 IPv6 地址 + 旧端口 → 新端口 */
static uint16_t csum_v6_addr_port(uint16_t old_csum,
                                   const uint8_t *old16, const uint8_t *new16,
                                   uint16_t old_port, uint16_t new_port) {
    uint32_t s = (uint16_t)~old_csum;
    s += ~sum16(old16, 16) & 0xffff;
    s +=  sum16(new16, 16);
    s += (uint16_t)~ntohs(old_port);
    s +=  ntohs(new_port);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* NAT66：LAN→WAN，改 src_ip6 = g_wan_ip6, src_port = wan_port */
static bool handle_nat66_lan_to_wan(uint8_t *data, uint32_t len) {
    struct ethhdr  *eth = (void *)data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((uint8_t*)(ip6 + 1) > data + len) return false;

    uint16_t *sp_ptr = NULL, *dp_ptr = NULL, *l4csum_ptr = NULL;
    struct tcphdr *tcp_hdr = NULL;
    void *l4 = (uint8_t*)ip6 + sizeof(*ip6);
    uint8_t proto = ip6->nexthdr;

    if (proto == IPPROTO_TCP) {
        tcp_hdr = l4;
        if ((uint8_t*)(tcp_hdr + 1) > data + len) return false;
        sp_ptr = &tcp_hdr->source; dp_ptr = &tcp_hdr->dest; l4csum_ptr = &tcp_hdr->check;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((uint8_t*)(udp + 1) > data + len) return false;
        sp_ptr = &udp->source; dp_ptr = &udp->dest; l4csum_ptr = &udp->check;
    } else if (proto == IPPROTO_ICMPV6) {
        struct icmp6hdr *ic = l4;
        if ((uint8_t*)(ic + 1) > data + len) return false;
        if (ic->icmp6_type != ICMPV6_ECHO_REQUEST) return false;
        /* 用 echo id 做端口映射 */
        sp_ptr = &ic->icmp6_dataun.u_echo.identifier;
        dp_ptr = &ic->icmp6_dataun.u_echo.identifier;  /* 单值 */
        l4csum_ptr = &ic->icmp6_cksum;
    } else {
        return false;
    }

    struct nat6_entry *e = lookup6_egress(&ip6->saddr, *sp_ptr, &ip6->daddr,
                                           proto == IPPROTO_ICMPV6 ? 0 : *dp_ptr, proto);
    if (!e) {
        e = nat6_create(&ip6->saddr, *sp_ptr, &ip6->daddr,
                        proto == IPPROTO_ICMPV6 ? 0 : *dp_ptr, proto);
        if (!e) return false;
    }
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);
    if (tcp_hdr) tcp_state_update((struct nat_entry *)e, tcp_hdr);  /* 共用 state 枚举 */

    struct in6_addr old_src = ip6->saddr;
    uint16_t old_port = *sp_ptr;

    ip6->saddr = g_wan_ip6;
    *sp_ptr    = e->wan_port;
    if (proto == IPPROTO_ICMPV6)
        ((struct icmp6hdr *)l4)->icmp6_dataun.u_echo.identifier = e->wan_port;

    if (l4csum_ptr)
        *l4csum_ptr = csum_v6_addr_port(*l4csum_ptr, old_src.s6_addr, ip6->saddr.s6_addr,
                                         old_port, *sp_ptr);
    return true;
}

/* NAT66：WAN→LAN，改 dst_ip6 = e->lan_ip6, dst_port = e->lan_port */
static bool handle_nat66_wan_to_lan(uint8_t *data, uint32_t len) {
    struct ethhdr  *eth = (void *)data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((uint8_t*)(ip6 + 1) > data + len) return false;
    if (memcmp(&ip6->daddr, &g_wan_ip6, 16) != 0) return false;

    void *l4 = (uint8_t*)ip6 + sizeof(*ip6);
    uint8_t proto = ip6->nexthdr;
    uint16_t *dp_ptr = NULL, *l4csum_ptr = NULL;
    struct tcphdr *tcp_hdr = NULL;

    if (proto == IPPROTO_TCP) {
        tcp_hdr = l4;
        if ((uint8_t*)(tcp_hdr + 1) > data + len) return false;
        dp_ptr = &tcp_hdr->dest; l4csum_ptr = &tcp_hdr->check;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((uint8_t*)(udp + 1) > data + len) return false;
        dp_ptr = &udp->dest; l4csum_ptr = &udp->check;
    } else if (proto == IPPROTO_ICMPV6) {
        struct icmp6hdr *ic = l4;
        if ((uint8_t*)(ic + 1) > data + len) return false;
        if (ic->icmp6_type != ICMPV6_ECHO_REPLY) return false;
        dp_ptr = &ic->icmp6_dataun.u_echo.identifier;
        l4csum_ptr = &ic->icmp6_cksum;
    } else {
        return false;
    }

    struct nat6_entry *e = lookup6_ingress(*dp_ptr, proto);
    if (!e) return false;
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);
    if (tcp_hdr) tcp_state_update((struct nat_entry *)e, tcp_hdr);

    struct in6_addr old_dst = ip6->daddr;
    uint16_t old_port = *dp_ptr;

    ip6->daddr = e->lan_ip6;
    *dp_ptr    = e->lan_port;
    if (proto == IPPROTO_ICMPV6)
        ((struct icmp6hdr *)l4)->icmp6_dataun.u_echo.identifier = e->lan_port;

    if (l4csum_ptr)
        *l4csum_ptr = csum_v6_addr_port(*l4csum_ptr, old_dst.s6_addr, ip6->daddr.s6_addr,
                                         old_port, *dp_ptr);
    return true;
}

/* NPTv6 路径（保留原实现） */
static bool handle_npt6(uint8_t *data, uint32_t len, bool src_is_lan) {
    struct ethhdr *eth = (void *)data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((uint8_t*)(ip6 + 1) > data + len) return false;

    struct in6_addr *target = src_is_lan ? &ip6->saddr : &ip6->daddr;
    const struct npt6_rule *r = src_is_lan
        ? npt6_match_inside(target) : npt6_match_outside(target);
    if (!r) return true;

    uint8_t old_addr[16]; memcpy(old_addr, target->s6_addr, 16);
    npt6_rewrite(target, src_is_lan ? &r->outside : &r->inside, r->plen);
    if (src_is_lan) ATOMIC_ADD((uint64_t *)&((struct npt6_rule *)r)->hits_in2out, 1);
    else            ATOMIC_ADD((uint64_t *)&((struct npt6_rule *)r)->hits_out2in, 1);

    void *l4 = (uint8_t*)ip6 + sizeof(*ip6);
    uint16_t *l4csum_ptr = NULL;
    if      (ip6->nexthdr == IPPROTO_TCP)    l4csum_ptr = &((struct tcphdr *)l4)->check;
    else if (ip6->nexthdr == IPPROTO_UDP)    l4csum_ptr = &((struct udphdr *)l4)->check;
    else if (ip6->nexthdr == IPPROTO_ICMPV6) l4csum_ptr = &((struct icmp6hdr *)l4)->icmp6_cksum;
    if (l4csum_ptr && *l4csum_ptr)
        *l4csum_ptr = csum_replace_v6(*l4csum_ptr, old_addr, target->s6_addr);
    return true;
}

/* handle_v6 入口：按优先级调度 NAT64 / NAT66 / NPTv6 / 透传 */
static bool handle_v6(uint8_t *data, uint32_t len, bool src_is_lan);

static bool handle_v6(uint8_t *data, uint32_t len, bool src_is_lan) {
    if (len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) return false;
    struct ethhdr *eth = (void *)data;
    if (eth->h_proto != htons(ETH_P_IPV6)) return false;
    struct ipv6hdr *ip6 = (void *)(eth + 1);

    /* NAT64 outbound：LAN v6 客户端访问 64:ff9b::<v4>
       这里只识别意图；实际 L3 头重建在独立函数里（需要改 frame 长度）返回 false 让上层丢掉原包 */
    if (src_is_lan && g_nat64_enabled && prefix_is_nat64(&ip6->daddr)) {
        /* NAT64 转换由 worker 特殊路径处理；这里先不动 */
        return false;  /* 当前简化：不支持 in-place 长度变化，记日志并丢包 */
    }

    /* NAT66 */
    if (g_nat66_enabled && g_wan_ip6_set) {
        return src_is_lan ? handle_nat66_lan_to_wan(data, len)
                          : handle_nat66_wan_to_lan(data, len);
    }

    /* 其它：NPTv6 或透传 */
    if (g_npt6_n > 0) return handle_npt6(data, len, src_is_lan);
    return true;
}

/*
 * 处理一个从 LAN 收到的包 (in 位置 data，长度 len)。
 * 改写 src=WAN_IP, src_port=wan_port；返回 true 表示放行到 WAN TX。
 */
/* ========================= NAT64 / NAT46 数据路径 ========================= */
/* 策略：
 *   NAT64 LAN→WAN (v6→v4)：把 IPv6 头替换为 IPv4 头；frame len -20
 *   NAT64 WAN→LAN (v4→v6)：把 IPv4 头替换为 IPv6 头；frame len +20
 *   NAT46 LAN→WAN (v4→v6)：同上 +20
 *   NAT46 WAN→LAN (v6→v4)：-20
 *
 * ICMP/ICMPv6 的类型转换非常复杂（type/code 不对应），本版仅支持 TCP/UDP。
 * ICMP 报文直接丢。L4 伪头 checksum 完全重算更可靠（非增量）。
 */

/* v4 ICMP 校验和（无伪头） */
static uint16_t icmp_csum_v4(const void *data, uint16_t len) {
    uint32_t s = sum16(data, len);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons(~s);
}

/* 计算 IPv4 header checksum */
static uint16_t ipv4_csum(const struct iphdr *ip) {
    uint32_t s = 0;
    const uint16_t *p = (const uint16_t *)ip;
    for (size_t i = 0; i < sizeof(*ip) / 2; i++) s += ntohs(p[i]);
    /* 不包括自己的 check 字段，所以要减掉 */
    s -= ntohs(ip->check);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons(~s);
}

/* TCP/UDP checksum with pseudo header; len 是 L4 整段长度（TCP/UDP header + payload） */
static uint16_t l4_csum_v4(const struct iphdr *ip, const void *l4, uint16_t l4len) {
    uint32_t s = 0;
    s += (ntohl(ip->saddr) >> 16) + (ntohl(ip->saddr) & 0xffff);
    s += (ntohl(ip->daddr) >> 16) + (ntohl(ip->daddr) & 0xffff);
    s += ip->protocol;
    s += l4len;
    const uint8_t *p = l4;
    for (uint16_t i = 0; i + 1 < l4len; i += 2) s += ((uint16_t)p[i] << 8) | p[i+1];
    if (l4len & 1) s += ((uint16_t)p[l4len-1] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons(~s);
}

static uint16_t l4_csum_v6(const struct ipv6hdr *ip6, const void *l4, uint16_t l4len) {
    uint32_t s = 0;
    s += sum16(ip6->saddr.s6_addr, 16);
    s += sum16(ip6->daddr.s6_addr, 16);
    s += (l4len >> 16); s += (l4len & 0xffff);
    s += ip6->nexthdr;
    const uint8_t *p = l4;
    for (uint16_t i = 0; i + 1 < l4len; i += 2) s += ((uint16_t)p[i] << 8) | p[i+1];
    if (l4len & 1) s += ((uint16_t)p[l4len-1] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons(~s);
}

/* NAT64 LAN→WAN：IPv6 客户端 → 64:ff9b::<v4>，翻成 v4 发出 */
static int handle_nat64_lan_to_wan(uint8_t *data, uint32_t len, uint32_t buf_cap) {
    (void)buf_cap;
    if (len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) return -1;
    struct ethhdr *eth = (void *)data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((uint8_t*)(ip6 + 1) > data + len) return -1;
    if (!prefix_is_nat64(&ip6->daddr)) return -1;
    bool is_icmp = (ip6->nexthdr == IPPROTO_ICMPV6);
    if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP && !is_icmp) return -1;

    /* 抽取 v4 目的（NAT64 前缀最后 32 位） */
    uint32_t dst_v4 = *(uint32_t *)(&ip6->daddr.s6_addr[12]);

    /* 解析 L4 */
    void *l4 = (uint8_t *)ip6 + sizeof(*ip6);
    uint16_t l4len = ntohs(ip6->payload_len);
    if (l4 > (void *)(data + len) || (uint8_t*)l4 + l4len > data + len) return -1;
    uint16_t *sp_ptr = NULL, *dp_ptr = NULL, *l4csum_ptr = NULL;
    uint8_t  v4_proto = ip6->nexthdr;  /* 最终落到 v4 侧的 protocol */
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        sp_ptr = &tcp->source; dp_ptr = &tcp->dest; l4csum_ptr = &tcp->check;
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        sp_ptr = &udp->source; dp_ptr = &udp->dest; l4csum_ptr = &udp->check;
    } else {
        /* ICMPv6 */
        struct icmp6hdr *ic = l4;
        if (ic->icmp6_type != ICMPV6_ECHO_REQUEST && ic->icmp6_type != ICMPV6_ECHO_REPLY) return -1;
        sp_ptr = &ic->icmp6_dataun.u_echo.identifier;
        dp_ptr = &ic->icmp6_dataun.u_echo.identifier;
        l4csum_ptr = &ic->icmp6_cksum;
        v4_proto = IPPROTO_ICMP;  /* 转到 v4 后协议号变 */
    }

    /* session（两侧都用 v4_proto 作 key，方便反向查找） */
    struct nat64_entry *e = lookup64_egress_l(&ip6->saddr, *sp_ptr, dst_v4,
                                               is_icmp ? *sp_ptr : *dp_ptr, v4_proto);
    if (!e) {
        e = nat64_create(&ip6->saddr, *sp_ptr, dst_v4,
                         is_icmp ? *sp_ptr : *dp_ptr, v4_proto);
        if (!e) return -1;
    }
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);

    /* 把 L4 data 前移 20 字节 */
    uint8_t *l4_old = (uint8_t *)l4;
    uint8_t *l4_new = l4_old - 20;
    memmove(l4_new, l4_old, l4len);

    struct iphdr *ip4 = (struct iphdr *)((uint8_t *)eth + sizeof(*eth));
    memset(ip4, 0, sizeof(*ip4));
    ip4->version = 4; ip4->ihl = 5;
    ip4->tot_len = htons(20 + l4len);
    ip4->frag_off= htons(0x4000);
    ip4->ttl     = ip6->hop_limit ? ip6->hop_limit - 1 : 63;
    ip4->protocol= v4_proto;
    ip4->saddr   = g_wan_ip;
    ip4->daddr   = dst_v4;
    ip4->check   = ipv4_csum(ip4);

    void *nl4 = (uint8_t *)ip4 + sizeof(*ip4);
    if (v4_proto == IPPROTO_TCP) {
        struct tcphdr *t = nl4;
        t->source = e->wan_port;
        t->check = 0;
        t->check = l4_csum_v4(ip4, nl4, l4len);
    } else if (v4_proto == IPPROTO_UDP) {
        struct udphdr *u = nl4;
        u->source = e->wan_port;
        u->check = 0;
        u->check = l4_csum_v4(ip4, nl4, l4len);
    } else {
        /* ICMPv6 → ICMP：type 128→8, 129→0，id 改为 wan_port，重算 csum（无伪头） */
        struct icmphdr *ic = nl4;
        if (ic->type == 128) ic->type = 8;       /* ICMPv6 echo req → ICMP */
        else if (ic->type == 129) ic->type = 0;  /* echo reply */
        ic->un.echo.id = e->wan_port;
        ic->checksum = 0;
        ic->checksum = icmp_csum_v4(nl4, l4len);
    }

    eth->h_proto = htons(ETH_P_IP);
    return sizeof(*eth) + sizeof(*ip4) + l4len;
}

/* NAT64 WAN→LAN：v4 返回 → 构造 v6 发 LAN */
static int handle_nat64_wan_to_lan(uint8_t *data, uint32_t len, uint32_t buf_cap) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
    struct ethhdr *eth = (void *)data;
    struct iphdr *ip4 = (void *)(eth + 1);
    if (ip4->version != 4) return -1;
    if (ip4->daddr != g_wan_ip) return -1;
    bool is_icmp = (ip4->protocol == IPPROTO_ICMP);
    if (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP && !is_icmp) return -1;

    uint32_t ihl = ip4->ihl * 4;
    void *l4 = (uint8_t*)ip4 + ihl;
    uint16_t l4len = ntohs(ip4->tot_len) - ihl;
    if ((uint8_t*)l4 + l4len > data + len) return -1;
    uint16_t *sp_ptr = NULL, *dp_ptr = NULL;
    uint16_t lookup_port;
    if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        sp_ptr = &tcp->source; dp_ptr = &tcp->dest;
        lookup_port = *dp_ptr;
    } else if (ip4->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        sp_ptr = &udp->source; dp_ptr = &udp->dest;
        lookup_port = *dp_ptr;
    } else {
        /* ICMP echo reply/request */
        struct icmphdr *ic = l4;
        if (ic->type != 0 && ic->type != 8) return -1;
        lookup_port = ic->un.echo.id;  /* id 作为 "port" */
    }

    struct nat64_entry *e = lookup64_ingress_l(lookup_port, IPPROTO_ICMP == ip4->protocol ? IPPROTO_ICMP : ip4->protocol);
    if (!e) return -1;
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);

    /* 新长度：+20 字节（IPv6 头 40 比 IPv4 头 20 多 20） */
    uint32_t new_len = sizeof(*eth) + sizeof(struct ipv6hdr) + l4len;
    if (new_len > buf_cap) return -1;

    /* 把 L4 向后挪 20 字节 */
    uint8_t *l4_old = (uint8_t *)l4;
    uint8_t *l4_new = l4_old + (40 - (int)ihl);  /* 到 ipv6 头后的位置 */
    memmove(l4_new, l4_old, l4len);

    struct ipv6hdr *ip6 = (struct ipv6hdr *)((uint8_t *)eth + sizeof(*eth));
    memset(ip6, 0, sizeof(*ip6));
    ip6->version = 6;
    ip6->payload_len = htons(l4len);
    ip6->nexthdr = is_icmp ? IPPROTO_ICMPV6 : ip4->protocol;
    ip6->hop_limit = ip4->ttl;
    ip6->saddr = g_nat64_pfx;
    memcpy(&ip6->saddr.s6_addr[12], &ip4->saddr, 4);
    ip6->daddr = e->lan_ip6;

    if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *t = (void *)l4_new;
        t->dest  = e->lan_port;
        t->check = 0;
        t->check = l4_csum_v6(ip6, l4_new, l4len);
    } else if (ip4->protocol == IPPROTO_UDP) {
        struct udphdr *u = (void *)l4_new;
        u->dest  = e->lan_port;
        u->check = 0;
        u->check = l4_csum_v6(ip6, l4_new, l4len);
    } else {
        /* ICMP → ICMPv6：type 8→128, 0→129；id 改为 e->lan_port，重算 csum（带伪头） */
        struct icmp6hdr *ic = (void *)l4_new;
        if (ic->icmp6_type == 8)      ic->icmp6_type = 128;
        else if (ic->icmp6_type == 0) ic->icmp6_type = 129;
        ic->icmp6_dataun.u_echo.identifier = e->lan_port;
        ic->icmp6_cksum = 0;
        ic->icmp6_cksum = l4_csum_v6(ip6, l4_new, l4len);
    }

    eth->h_proto = htons(ETH_P_IPV6);
    (void)sp_ptr; (void)dp_ptr;
    return new_len;
}

/* NAT46 LAN→WAN：v4 客户端 → v4_target，翻 v6 发给 v6_real
   Session-aware：
     - 如果配置了 g_nat46_v6_src，所有 v4 客户端共享此 v6 源（SNAT46 池模式）
     - 否则每客户端合成 v6 源 = g_nat64_pfx + client_v4（每客户端独立）
   端口 NAPT：分配 wan_port，session 记录 5-tuple ↔ wan_port 映射 */
static int handle_nat46_lan_to_wan(uint8_t *data, uint32_t len, uint32_t buf_cap) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
    struct ethhdr *eth = (void *)data;
    struct iphdr *ip4 = (void *)(eth + 1);
    if (ip4->version != 4) return -1;
    if (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP) return -1;

    /* 查 v4 target 规则 */
    const struct nat46_rule *r = NULL;
    for (int i = 0; i < g_nat46_n; i++)
        if (g_nat46[i].v4_target == ip4->daddr) { r = &g_nat46[i]; break; }
    if (!r) return -1;

    uint32_t ihl = ip4->ihl * 4;
    void *l4 = (uint8_t*)ip4 + ihl;
    uint16_t l4len = ntohs(ip4->tot_len) - ihl;
    if ((uint8_t*)l4 + l4len > data + len) return -1;
    uint16_t *sp_ptr, *dp_ptr;
    if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *t = l4; sp_ptr = &t->source; dp_ptr = &t->dest;
    } else {
        struct udphdr *u = l4; sp_ptr = &u->source; dp_ptr = &u->dest;
    }

    /* 确定 v6 源：固定 or 每客户端合成 */
    struct in6_addr v6_src;
    if (g_nat46_v6_src_set) {
        v6_src = g_nat46_v6_src;                       /* 一组 v4 共享此源 */
    } else {
        v6_src = g_nat64_pfx;
        memcpy(&v6_src.s6_addr[12], &ip4->saddr, 4);   /* 每客户端独立合成 */
    }

    /* session 查找/建立 */
    struct nat46_entry *e = lookup46_egress_l(ip4->saddr, *sp_ptr,
                                                ip4->daddr, *dp_ptr, ip4->protocol);
    if (!e) {
        e = nat46_session_create(ip4->saddr, *sp_ptr, ip4->daddr, *dp_ptr,
                                  &r->v6_real, &v6_src, ip4->protocol);
        if (!e) return -1;
    }
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);
    ATOMIC_ADD((uint64_t *)&((struct nat46_rule *)r)->hits, 1);

    uint32_t new_len = sizeof(*eth) + sizeof(struct ipv6hdr) + l4len;
    if (new_len > buf_cap) return -1;

    /* 把 L4 向后搬 */
    uint8_t *l4_old = (uint8_t *)l4;
    uint8_t *l4_new = l4_old + (40 - (int)ihl);
    memmove(l4_new, l4_old, l4len);

    struct ipv6hdr *ip6 = (struct ipv6hdr *)((uint8_t *)eth + sizeof(*eth));
    memset(ip6, 0, sizeof(*ip6));
    ip6->version = 6;
    ip6->payload_len = htons(l4len);
    ip6->nexthdr = ip4->protocol;
    ip6->hop_limit = ip4->ttl;
    ip6->saddr = e->v6_src;          /* 固定或合成 */
    ip6->daddr = e->v6_real;

    /* L4 改：src_port = e->target_port（wan_port from pool），dst_port 透传 */
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *t = (void *)l4_new;
        t->source = e->target_port;
        t->check = 0;
        t->check = l4_csum_v6(ip6, l4_new, l4len);
    } else {
        struct udphdr *u = (void *)l4_new;
        u->source = e->target_port;
        u->check = 0;
        u->check = l4_csum_v6(ip6, l4_new, l4len);
    }

    eth->h_proto = htons(ETH_P_IPV6);
    return new_len;
}

/* NAT46 WAN→LAN：v6 返回 → 翻 v4 发 LAN
   session-based：按 wan_port 反查 client v4/port/target */
static int handle_nat46_wan_to_lan(uint8_t *data, uint32_t len, uint32_t buf_cap) {
    (void)buf_cap;
    if (len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) return -1;
    struct ethhdr *eth = (void *)data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((uint8_t*)(ip6 + 1) > data + len) return -1;
    if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP) return -1;

    /* 判定是否是 NAT46 返程：
       - 有固定 v6 源时：ip6.daddr == g_nat46_v6_src
       - 无固定 v6 源时：ip6.daddr 在 NAT64 前缀下（每客户端合成） */
    if (g_nat46_v6_src_set) {
        if (memcmp(&ip6->daddr, &g_nat46_v6_src, 16) != 0) return -1;
    } else {
        if (!prefix_is_nat64(&ip6->daddr)) return -1;
    }

    void *l4 = (uint8_t*)ip6 + sizeof(*ip6);
    uint16_t l4len = ntohs(ip6->payload_len);
    if ((uint8_t*)l4 + l4len > data + len) return -1;
    uint16_t *sp_ptr, *dp_ptr;
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *t = l4; sp_ptr = &t->source; dp_ptr = &t->dest;
    } else {
        struct udphdr *u = l4; sp_ptr = &u->source; dp_ptr = &u->dest;
    }
    (void)sp_ptr;

    /* 查 session by wan_port (存在 e->target_port 里) */
    struct nat46_entry *e = lookup46_ingress_l(*dp_ptr, ip6->nexthdr);
    if (!e) return -1;
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1); ATOMIC_ADD(&e->bytes, (uint64_t)len);

    uint8_t *l4_old = (uint8_t *)l4;
    uint8_t *l4_new = l4_old - 20;
    memmove(l4_new, l4_old, l4len);

    struct iphdr *ip4 = (struct iphdr *)((uint8_t *)eth + sizeof(*eth));
    memset(ip4, 0, sizeof(*ip4));
    ip4->version = 4; ip4->ihl = 5;
    ip4->tot_len = htons(20 + l4len);
    ip4->frag_off = htons(0x4000);
    ip4->ttl = ip6->hop_limit ? ip6->hop_limit - 1 : 63;
    ip4->protocol = ip6->nexthdr;
    ip4->saddr = e->target_v4;        /* 客户端看到的 target v4（入向规则） */
    ip4->daddr = e->rem_ip4;          /* 客户端本身的 v4 */
    ip4->check = ipv4_csum(ip4);

    /* L4 改：dst_port = 客户端原端口 */
    if (ip4->protocol == IPPROTO_TCP) {
        struct tcphdr *t = (void *)l4_new;
        t->dest = e->rem_port;
        t->check = 0; t->check = l4_csum_v4(ip4, l4_new, l4len);
    } else {
        struct udphdr *u = (void *)l4_new;
        u->dest = e->rem_port;
        u->check = 0; u->check = l4_csum_v4(ip4, l4_new, l4len);
    }

    eth->h_proto = htons(ETH_P_IP);
    return sizeof(*eth) + sizeof(*ip4) + l4len;
}


static bool handle_lan_to_wan(uint8_t *data, uint32_t *plen, uint32_t buf_cap) {
    uint32_t len = *plen;
    if (len < sizeof(struct ethhdr)) return false;
    struct ethhdr *eth = (void *)data;
    /* NAT46 优先：v4 包目的 = nat46 target → 翻 v6 发出 */
    if (eth->h_proto == htons(ETH_P_IP) && g_nat46_n > 0) {
        int nl = handle_nat46_lan_to_wan(data, len, buf_cap);
        if (nl > 0) { *plen = nl; return true; }
    }
    if (eth->h_proto == htons(ETH_P_IPV6)) {
        /* NAT64 优先：LAN v6 目的 = 64:ff9b::<v4> → 翻 v4 发出 */
        if (g_nat64_enabled) {
            struct ipv6hdr *ip6 = (void *)(eth + 1);
            if ((uint8_t*)(ip6 + 1) <= data + len && prefix_is_nat64(&ip6->daddr)) {
                int nl = handle_nat64_lan_to_wan(data, len, buf_cap);
                if (nl > 0) { *plen = nl; return true; }
                if (nl == 0) return false;
            }
        }
        return handle_v6(data, len, /*src_is_lan=*/true);
    }
    if (eth->h_proto != htons(ETH_P_IP)) return false;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return false;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->version != 4) return false;
    uint32_t ihl = ip->ihl * 4;
    if ((uint8_t*)ip + ihl > data + len) return false;

    /* 目的在 LAN 内网时不应 NAT */
    if (is_lan_addr(ip->daddr)) return false;

    void *l4 = (uint8_t *)ip + ihl;

    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((uint8_t*)(icmp + 1) > data + len) return false;
        /* 只处理 echo request；echo reply 从这侧出不应有，错误消息嵌入包暂不处理 */
        if (icmp->type != ICMP_ECHO) return false;

        uint16_t lan_id = icmp->un.echo.id;
        struct nat_entry *e = lookup_egress(ip->saddr, lan_id,
                                             ip->daddr, 0, IPPROTO_ICMP);
        if (!e) {
            e = nat_create(ip->saddr, lan_id, ip->daddr, 0, IPPROTO_ICMP);
            if (!e) { LOGD("NAT 表满 (ICMP)"); return false; }
            LOGD("新 ICMP 流 %u.%u.%u.%u id=%u -> WAN id=%u",
                 (ip->saddr)&0xff, (ip->saddr>>8)&0xff,
                 (ip->saddr>>16)&0xff, (ip->saddr>>24)&0xff,
                 ntohs(lan_id), ntohs(e->wan_port));
        }
        e->last_seen = time(NULL);

        uint32_t old_saddr = ip->saddr;
        uint16_t old_id    = icmp->un.echo.id;
        ip->saddr             = g_wan_ip;
        icmp->un.echo.id      = e->wan_port;

        ip_csum_replace4(ip, old_saddr, g_wan_ip);
        /* ICMP 校验和不含伪头；只因 id 改变而需要更新 */
        icmp->checksum = csum_update(icmp->checksum, old_id, e->wan_port);
        return true;
    }

    /* TCP / UDP */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return false;

    uint16_t *sp_ptr, *dp_ptr, *l4csum_ptr;
    struct tcphdr *tcp_hdr = NULL;
    if (ip->protocol == IPPROTO_TCP) {
        tcp_hdr = l4;
        if ((uint8_t*)(tcp_hdr + 1) > data + len) return false;
        sp_ptr = &tcp_hdr->source; dp_ptr = &tcp_hdr->dest; l4csum_ptr = &tcp_hdr->check;
    } else {
        struct udphdr *udp = l4;
        if ((uint8_t*)(udp + 1) > data + len) return false;
        sp_ptr = &udp->source; dp_ptr = &udp->dest; l4csum_ptr = &udp->check;
    }

    /* DNAT 反向：LAN 作为被 DNAT 的目标主动响应（src=lan_ip:lan_port） */
    const struct dnat_rule *dr = dnat_lookup_out(ip->protocol, ip->saddr, *sp_ptr);
    struct nat_entry *e = NULL;
    if (dr) {
        e = lookup_egress(ip->saddr, *sp_ptr, ip->daddr, *dp_ptr, ip->protocol);
        if (!e) {
            e = nat_create_dnat(ip->saddr, *sp_ptr, ip->daddr, *dp_ptr,
                                dr->wan_port, ip->protocol);
            if (!e) return false;
        }
    } else {
        /* 普通 NAPT：LAN 主动外连 */
        e = lookup_egress(ip->saddr, *sp_ptr, ip->daddr, *dp_ptr, ip->protocol);
        if (!e) {
            e = nat_create(ip->saddr, *sp_ptr, ip->daddr, *dp_ptr, ip->protocol);
            if (!e) { LOGD("NAT 表满"); return false; }
            LOGD("新连接 %u.%u.%u.%u:%u -> WAN:%u (proto=%u)",
                 (ip->saddr)&0xff, (ip->saddr>>8)&0xff, (ip->saddr>>16)&0xff, (ip->saddr>>24)&0xff,
                 ntohs(*sp_ptr), ntohs(e->wan_port), ip->protocol);
        }
    }
    ATOMIC_STORE(&e->last_seen, time(NULL));
    ATOMIC_ADD(&e->pkts, 1);
    ATOMIC_ADD(&e->bytes, (uint64_t)len);
    if (tcp_hdr) tcp_state_update(e, tcp_hdr);

    uint32_t old_saddr = ip->saddr;
    uint16_t old_sport = *sp_ptr;

    ip->saddr = g_wan_ip;
    *sp_ptr   = e->wan_port;

    ip_csum_replace4(ip, old_saddr, g_wan_ip);
    if (*l4csum_ptr != 0 || ip->protocol == IPPROTO_TCP) {
        uint32_t s = (uint16_t)~(*l4csum_ptr);
        s += (uint16_t)~(old_saddr & 0xFFFF) + (uint16_t)~(old_saddr >> 16);
        s += (uint16_t)~(old_sport);
        s += (g_wan_ip & 0xFFFF) + (g_wan_ip >> 16);
        s += e->wan_port;
        *l4csum_ptr = ~csum_fold(s);
    }
    return true;
}

static bool handle_wan_to_lan(uint8_t *data, uint32_t *plen, uint32_t buf_cap) {
    uint32_t len = *plen;
    if (len < sizeof(struct ethhdr)) return false;
    struct ethhdr *eth = (void *)data;
    /* NAT64 回程：v4 包到 wan_ip:wan_port → 查 session → 翻 v6 */
    if (eth->h_proto == htons(ETH_P_IP) && g_nat64_enabled) {
        int nl = handle_nat64_wan_to_lan(data, len, buf_cap);
        if (nl > 0) { *plen = nl; return true; }
    }
    /* NAT46 回程：v6 包 src = nat64_pfx + v4 客户端 → 翻回 v4 发 LAN */
    if (eth->h_proto == htons(ETH_P_IPV6) && g_nat46_n > 0) {
        int nl = handle_nat46_wan_to_lan(data, len, buf_cap);
        if (nl > 0) { *plen = nl; return true; }
    }
    if (eth->h_proto == htons(ETH_P_IPV6))
        return handle_v6(data, len, /*src_is_lan=*/false);
    if (eth->h_proto != htons(ETH_P_IP)) return false;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return false;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->version != 4) return false;
    if (ip->daddr != g_wan_ip) return false;    /* 不是给我们的，不动 */

    uint32_t ihl = ip->ihl * 4;
    if ((uint8_t*)ip + ihl > data + len) return false;
    void *l4 = (uint8_t *)ip + ihl;

    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((uint8_t*)(icmp + 1) > data + len) return false;
        /* 只处理 echo reply */
        if (icmp->type != ICMP_ECHOREPLY) return false;

        uint16_t wan_id = icmp->un.echo.id;
        struct nat_entry *e = lookup_ingress(wan_id, IPPROTO_ICMP);
        if (!e) return false;
        e->last_seen = time(NULL);

        uint32_t old_daddr = ip->daddr;
        uint16_t old_id    = icmp->un.echo.id;
        ip->daddr             = e->lan_ip;
        icmp->un.echo.id      = e->lan_port;  /* lan_port 对 ICMP 存的是原 id */

        ip_csum_replace4(ip, old_daddr, e->lan_ip);
        icmp->checksum = csum_update(icmp->checksum, old_id, e->lan_port);
        return true;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return false;

    uint16_t *sp_ptr, *dp_ptr, *l4csum_ptr;
    struct tcphdr *tcp_hdr = NULL;
    if (ip->protocol == IPPROTO_TCP) {
        tcp_hdr = l4;
        if ((uint8_t*)(tcp_hdr + 1) > data + len) return false;
        sp_ptr = &tcp_hdr->source; dp_ptr = &tcp_hdr->dest; l4csum_ptr = &tcp_hdr->check;
    } else {
        struct udphdr *udp = l4;
        if ((uint8_t*)(udp + 1) > data + len) return false;
        sp_ptr = &udp->source; dp_ptr = &udp->dest; l4csum_ptr = &udp->check;
    }

    /* 优先：DNAT 规则（任何远端都能打到这个端口） */
    const struct dnat_rule *dr = dnat_lookup_in(ip->protocol, *dp_ptr);
    uint32_t new_daddr;
    uint16_t new_dport;
    struct nat_entry *e = NULL;

    if (dr) {
        /* DNAT：wan_port → lan_ip:lan_port（静态规则） */
        new_daddr = dr->lan_ip;
        new_dport = dr->lan_port;
        e = lookup_egress(dr->lan_ip, dr->lan_port, ip->saddr, *sp_ptr, ip->protocol);
        if (!e)
            e = nat_create_dnat(dr->lan_ip, dr->lan_port, ip->saddr, *sp_ptr,
                                dr->wan_port, ip->protocol);
        ATOMIC_ADD((uint64_t *)&((struct dnat_rule *)dr)->hits, 1);
        ATOMIC_ADD(&g_stat_dnat_hits, 1);
    } else {
        /* 普通 NAPT 反向：查已建立的 LAN 主动出站会话 */
        e = lookup_ingress(*dp_ptr, ip->protocol);
        if (!e) return false;
        new_daddr = e->lan_ip;
        new_dport = e->lan_port;
    }

    if (e) {
        e->last_seen = time(NULL);
        e->pkts++; e->bytes += len;
        if (tcp_hdr) tcp_state_update(e, tcp_hdr);
    }

    uint32_t old_daddr = ip->daddr;
    uint16_t old_dport = *dp_ptr;

    ip->daddr = new_daddr;
    *dp_ptr   = new_dport;

    ip_csum_replace4(ip, old_daddr, new_daddr);
    if (*l4csum_ptr != 0 || ip->protocol == IPPROTO_TCP) {
        uint32_t s = (uint16_t)~(*l4csum_ptr);
        s += (uint16_t)~(old_daddr & 0xFFFF) + (uint16_t)~(old_daddr >> 16);
        s += (uint16_t)~(old_dport);
        s += (new_daddr & 0xFFFF) + (new_daddr >> 16);
        s += new_dport;
        *l4csum_ptr = ~csum_fold(s);
    }
    return true;
}

/* ========================= 转发主循环 ========================= */

static void submit_tx(struct xsk_port *dst, uint64_t addr, uint32_t len,
                      struct xsk_umem_info *src_umem) {
    /* 从 src_umem 把该 frame 搬到 dst 的 TX ring；AF_XDP 不支持跨 UMEM zero-copy，
       因此必须共享 UMEM —— 我们确实是共享一个 UMEM。 */
    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&dst->tx, 1, &tx_idx) != 1) {
        umem_free_frame(src_umem, addr);
        dst->dropped++;
        return;
    }
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&dst->tx, tx_idx);
    d->addr = addr;
    d->len  = len;
    xsk_ring_prod__submit(&dst->tx, 1);
    dst->tx_packets++;
    dst->tx_bytes += len;
    /* 提醒内核 */
    sendto(xsk_socket__fd(dst->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void handle_tx_completion(struct xsk_port *p) {
    uint32_t idx_cq;
    unsigned n = xsk_ring_cons__peek(&p->umem->cq, 64, &idx_cq);
    for (unsigned i = 0; i < n; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&p->umem->cq, idx_cq++);
        umem_free_frame(p->umem, addr);
    }
    if (n) xsk_ring_cons__release(&p->umem->cq, n);
}

static void handle_rx_batch(struct xsk_port *src, struct xsk_port *dst,
                            bool src_is_lan) {
    uint32_t idx_rx;
    unsigned n = xsk_ring_cons__peek(&src->rx, RX_BATCH_SIZE, &idx_rx);
    if (!n) return;

    /* 为 fill ring 预留 n 个 frame 补给（RX 处理完后 kernel 要地方放新 RX） */
    uint32_t idx_fq;
    unsigned reserved = xsk_ring_prod__reserve(&src->umem->fq, n, &idx_fq);
    while (reserved < n) {
        reserved = xsk_ring_prod__reserve(&src->umem->fq, n, &idx_fq);
    }

    for (unsigned i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&src->rx, idx_rx + i);
        uint64_t addr = d->addr;
        uint32_t len  = d->len;
        uint8_t *pkt  = xsk_umem__get_data(src->umem->buffer, addr);

        src->rx_packets++; src->rx_bytes += len;

        uint32_t new_len = len;
        bool ok = src_is_lan ? handle_lan_to_wan(pkt, &new_len, FRAME_SIZE)
                             : handle_wan_to_lan(pkt, &new_len, FRAME_SIZE);

        if (ok) {
            uint64_t new_frame = umem_alloc_frame(src->umem);
            if (new_frame == INVALID_UMEM_FRAME) {
                *xsk_ring_prod__fill_addr(&src->umem->fq, idx_fq + i) = addr;
                dst->dropped++;
            } else {
                submit_tx(dst, addr, new_len, src->umem);
                *xsk_ring_prod__fill_addr(&src->umem->fq, idx_fq + i) = new_frame;
            }
        } else {
            /* 丢弃：frame 直接回 fill ring */
            *xsk_ring_prod__fill_addr(&src->umem->fq, idx_fq + i) = addr;
            src->dropped++;
        }
    }
    xsk_ring_prod__submit(&src->umem->fq, n);
    xsk_ring_cons__release(&src->rx, n);
}

/* ========================= 主流程 ========================= */

static void usage(const char *prog) {
    fprintf(stderr,
        "用法: %s --wan <iface> --lan <iface> --wan-ip <IPv4> --lan-cidr <CIDR>\n"
        "  [--queues <N>|--queue <N>]  [--pin-cpus]  [--copy] [-v]\n"
        "  [--dnat proto:wan_port:lan_ip:lan_port ...]    # IPv4 DNAT，可重复\n"
        "  [--npt6 inside/plen,outside/plen ...]          # IPv6 NPTv6 前缀改写，可重复\n"
        "  [--wan-ip6 <IPv6>]                              # 启用 NAT66（v6 NAPT）\n"
        "  [--nat64-prefix <prefix/96>]                    # 启用 NAT64，默认 64:ff9b::/96\n"
        "  [--nat46 v4_target=v6_real ...]                 # NAT46 静态规则，可重复\n"
        "  [--nat46-v6-src <IPv6>]                         # NAT46 一组 v4 共享此 v6 源（SNAT46 池模式）\n"
        "\n"
        "  --queues N    并发 N 条 RX 队列（默认 1；每 queue 一个 worker 线程）\n"
        "  --queue  N    兼容旧版：只跑单个队列 ID N\n"
        "  --pin-cpus    把每个 worker 线程绑到对应 CPU 核\n"
        "\n"
        "  发送 SIGUSR1 导出连接表到 /run/xdp-nat.conns；\n"
        "  每秒写统计到 /run/xdp-nat.stats。\n"
        "\n"
        "示例:\n"
        "  %s --wan eth1 --lan eth0 --wan-ip 192.168.1.220 --lan-cidr 10.0.0.0/24 \\\n"
        "     --queues 4 --pin-cpus \\\n"
        "     --dnat tcp:2222:10.0.0.100:22 --dnat udp:53:10.0.0.10:53\n",
        prog, prog);
    exit(1);
}

static void parse_npt6_arg(const char *s) {
    /* 格式: inside_prefix/len,outside_prefix/len (逗号分隔两边) */
    char buf[128];
    strncpy(buf, s, sizeof buf - 1); buf[sizeof buf - 1] = 0;
    char *comma = strchr(buf, ',');
    if (!comma) { fprintf(stderr, "--npt6 格式: inside/plen,outside/plen\n"); exit(1); }
    *comma = 0;
    char *in_s = buf, *out_s = comma + 1;
    char *in_slash  = strchr(in_s,  '/');
    char *out_slash = strchr(out_s, '/');
    if (!in_slash || !out_slash) { fprintf(stderr, "--npt6 缺 /plen\n"); exit(1); }
    *in_slash = *out_slash = 0;
    int plen_in  = atoi(in_slash  + 1);
    int plen_out = atoi(out_slash + 1);
    if (plen_in != plen_out) { fprintf(stderr, "--npt6: inside 和 outside plen 必须一致\n"); exit(1); }
    if (plen_in < 1 || plen_in > 128) { fprintf(stderr, "--npt6: plen 非法\n"); exit(1); }
    if (g_npt6_n >= MAX_NPT6_RULES) { fprintf(stderr, "NPT6 规则超上限\n"); exit(1); }
    struct npt6_rule *r = &g_npt6[g_npt6_n++];
    if (inet_pton(AF_INET6, in_s,  &r->inside)  != 1) { fprintf(stderr, "非法 inside\n"); exit(1); }
    if (inet_pton(AF_INET6, out_s, &r->outside) != 1) { fprintf(stderr, "非法 outside\n"); exit(1); }
    r->plen = plen_in;
    r->hits_in2out = r->hits_out2in = 0;
    LOGI("NPTv6 规则: %s/%d → %s/%d", in_s, plen_in, out_s, plen_out);
}

static void parse_dnat_arg(const char *s) {
    char buf[128];
    strncpy(buf, s, sizeof buf - 1); buf[sizeof buf - 1] = 0;
    char *proto_s = strtok(buf, ":");
    char *wp_s    = strtok(NULL, ":");
    char *lip_s   = strtok(NULL, ":");
    char *lp_s    = strtok(NULL, ":");
    if (!proto_s || !wp_s || !lip_s || !lp_s) {
        fprintf(stderr, "--dnat 格式错: %s (需 proto:wport:lip:lport)\n", s);
        exit(1);
    }
    if (g_dnat_n >= MAX_DNAT_RULES) { fprintf(stderr, "DNAT 规则超上限\n"); exit(1); }
    struct dnat_rule *r = &g_dnat[g_dnat_n++];
    r->proto    = !strcasecmp(proto_s, "tcp") ? IPPROTO_TCP : IPPROTO_UDP;
    r->wan_port = htons(atoi(wp_s));
    struct in_addr a; if (!inet_aton(lip_s, &a)) { fprintf(stderr, "lan_ip 非法: %s\n", lip_s); exit(1); }
    r->lan_ip   = a.s_addr;
    r->lan_port = htons(atoi(lp_s));
    r->hits     = 0;
    LOGI("DNAT 规则: %s:%s -> %s:%s", proto_s, wp_s, lip_s, lp_s);
}

static void write_stats_file(void) {
    FILE *f = fopen("/run/xdp-nat.stats.tmp", "w");
    if (!f) return;
    fprintf(f, "timestamp %ld\n", (long)time(NULL));
    fprintf(f, "wan_rx_pkts %" PRIu64 "\n", g_stat_wan_rx);
    fprintf(f, "wan_tx_pkts %" PRIu64 "\n", g_stat_wan_tx);
    fprintf(f, "wan_drop %" PRIu64 "\n",    g_stat_wan_drop);
    fprintf(f, "lan_rx_pkts %" PRIu64 "\n", g_stat_lan_rx);
    fprintf(f, "lan_tx_pkts %" PRIu64 "\n", g_stat_lan_tx);
    fprintf(f, "lan_drop %" PRIu64 "\n",    g_stat_lan_drop);
    fprintf(f, "nat_active %zu\n",          nat_count());
    fprintf(f, "dnat_rules %d\n",           g_dnat_n);
    fprintf(f, "dnat_hits %" PRIu64 "\n",   g_stat_dnat_hits);
    fclose(f);
    rename("/run/xdp-nat.stats.tmp", "/run/xdp-nat.stats");
}

static void dump_conns_file(void) {
    FILE *f = fopen("/run/xdp-nat.conns.tmp", "w");
    if (!f) return;
    fprintf(f, "# proto lan_ip:lan_port  rem_ip:rem_port  wan_port  tcp_state  dnat  age_s  pkts  bytes\n");
    time_t now = time(NULL);
    for (uint32_t i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry *e = &g_table[i];
        if (e->state != NAT_USED) continue;
        const char *pr = e->proto == IPPROTO_TCP ? "tcp"
                      : e->proto == IPPROTO_UDP ? "udp"
                      : e->proto == IPPROTO_ICMP ? "icmp" : "?";
        char lip[16], rip[16];
        inet_ntop(AF_INET, &e->lan_ip, lip, sizeof lip);
        inet_ntop(AF_INET, &e->rem_ip, rip, sizeof rip);
        const char *ts_names[] = { "NEW", "EST", "FIN", "CLOSED" };
        const char *ts = (e->proto == IPPROTO_TCP && e->tcp_state < 4) ? ts_names[e->tcp_state] : "-";
        fprintf(f, "%-4s %s:%-5u  %s:%-5u  %-5u  %-6s  %d  %5lds  %" PRIu64 "  %" PRIu64 "\n",
                pr, lip, ntohs(e->lan_port), rip, ntohs(e->rem_port),
                ntohs(e->wan_port), ts, e->dnat, (long)(now - e->last_seen),
                e->pkts, e->bytes);
    }
    fclose(f);
    rename("/run/xdp-nat.conns.tmp", "/run/xdp-nat.conns");
    LOGI("已 dump 连接表到 /run/xdp-nat.conns");
}

static int parse_cidr(const char *s, uint32_t *net_out, uint32_t *mask_out) {
    char tmp[64]; strncpy(tmp, s, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
    char *slash = strchr(tmp, '/');
    int prefix = 24;
    if (slash) { *slash = 0; prefix = atoi(slash + 1); }
    struct in_addr a;
    if (!inet_aton(tmp, &a)) return -1;
    uint32_t m = prefix == 0 ? 0 : htonl(0xffffffff << (32 - prefix));
    *net_out  = a.s_addr & m;
    *mask_out = m;
    return 0;
}

/* worker 线程主函数 */
static void *worker_main(void *arg) {
    struct xdp_worker *w = arg;
    if (w->cpu >= 0) {
        cpu_set_t set; CPU_ZERO(&set); CPU_SET(w->cpu, &set);
        if (pthread_setaffinity_np(pthread_self(), sizeof set, &set) == 0)
            LOGI("  worker[q=%d] 绑定 CPU %d", w->queue_id, w->cpu);
    }
    int wan_fd = xsk_socket__fd(w->wan.xsk);
    int lan_fd = xsk_socket__fd(w->lan.xsk);
    struct pollfd fds[2] = {
        { .fd = wan_fd, .events = POLLIN },
        { .fd = lan_fd, .events = POLLIN },
    };
    while (!g_stop) {
        int pr = poll(fds, 2, 500);
        if (pr < 0 && errno != EINTR) { perror("poll"); break; }
        handle_rx_batch(&w->wan, &w->lan, /*src_is_lan=*/false);
        handle_rx_batch(&w->lan, &w->wan, /*src_is_lan=*/true);
        handle_tx_completion(&w->wan);
        handle_tx_completion(&w->lan);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *wan_if = NULL, *lan_if = NULL, *wan_ip_s = NULL, *lan_cidr = NULL;
    int queues = 1;
    int single_queue = -1;
    bool pin_cpus = false;
    bool force_copy = false;

    static struct option opts[] = {
        {"wan",      required_argument, 0, 'w'},
        {"lan",      required_argument, 0, 'l'},
        {"wan-ip",   required_argument, 0, 'a'},
        {"lan-cidr", required_argument, 0, 'c'},
        {"queue",    required_argument, 0, 'q'},
        {"queues",   required_argument, 0, 'Q'},
        {"pin-cpus", no_argument,       0, 'P'},
        {"copy",     no_argument,       0, 'C'},
        {"verbose",  no_argument,       0, 'v'},
        {"dnat",         required_argument, 0, 'D'},
        {"npt6",         required_argument, 0, 'N'},
        {"wan-ip6",      required_argument, 0, '6'},
        {"nat64-prefix", required_argument, 0, '4'},
        {"nat46",        required_argument, 0, 'M'},
        {"nat46-v6-src", required_argument, 0, 'S'},
        {0,0,0,0}
    };
    int o, idx;
    while ((o = getopt_long(argc, argv, "w:l:a:c:q:Q:PD:N:6:4:M:S:Cv", opts, &idx)) != -1) {
        switch (o) {
            case 'w': wan_if   = optarg; break;
            case 'l': lan_if   = optarg; break;
            case 'a': wan_ip_s = optarg; break;
            case 'c': lan_cidr = optarg; break;
            case 'q': single_queue = atoi(optarg); break;
            case 'Q': queues   = atoi(optarg); if (queues < 1) queues = 1; break;
            case 'P': pin_cpus = true; break;
            case 'C': force_copy = true; break;
            case 'v': g_verbose = 1; break;
            case 'D': parse_dnat_arg(optarg); break;
            case 'N': parse_npt6_arg(optarg); break;
            case '6':
                if (inet_pton(AF_INET6, optarg, &g_wan_ip6) != 1) {
                    fprintf(stderr, "非法 --wan-ip6: %s\n", optarg); return 1;
                }
                g_wan_ip6_set = true; g_nat66_enabled = true;
                break;
            case '4': {
                char buf[64]; strncpy(buf, optarg, 63); buf[63]=0;
                char *slash = strchr(buf, '/');
                if (slash) { *slash = 0; g_nat64_pfx_len = atoi(slash+1); }
                if (inet_pton(AF_INET6, buf, &g_nat64_pfx) != 1) {
                    fprintf(stderr, "非法 --nat64-prefix: %s\n", optarg); return 1;
                }
                g_nat64_enabled = true;
                break;
            }
            case 'M': {
                /* 格式: v4_target=v6_real */
                char buf[128]; strncpy(buf, optarg, 127); buf[127]=0;
                char *eq = strchr(buf, '='); if (!eq) { fprintf(stderr, "--nat46: v4=v6\n"); return 1; }
                *eq = 0;
                if (g_nat46_n >= MAX_NAT46_RULES) { fprintf(stderr, "nat46 超上限\n"); return 1; }
                struct nat46_rule *r = &g_nat46[g_nat46_n++];
                struct in_addr a; if (!inet_aton(buf, &a)) { fprintf(stderr, "非法 v4\n"); return 1; }
                r->v4_target = a.s_addr;
                if (inet_pton(AF_INET6, eq+1, &r->v6_real) != 1) { fprintf(stderr, "非法 v6\n"); return 1; }
                LOGI("NAT46: %s -> %s", buf, eq+1);
                break;
            }
            case 'S':
                if (inet_pton(AF_INET6, optarg, &g_nat46_v6_src) != 1) {
                    fprintf(stderr, "非法 --nat46-v6-src: %s\n", optarg); return 1;
                }
                g_nat46_v6_src_set = true;
                LOGI("NAT46 固定 v6 源: %s（一组 v4 客户端共享此源出站）", optarg);
                break;
            default:  usage(argv[0]);
        }
    }
    if (!wan_if || !lan_if || !wan_ip_s || !lan_cidr) usage(argv[0]);
    if (single_queue >= 0) queues = 1;  /* 兼容老 --queue */

    struct in_addr wa;
    if (!inet_aton(wan_ip_s, &wa)) { fprintf(stderr, "非法 WAN IP: %s\n", wan_ip_s); return 1; }
    g_wan_ip = wa.s_addr;
    if (parse_cidr(lan_cidr, &g_lan_net, &g_lan_mask)) {
        fprintf(stderr, "非法 LAN CIDR: %s\n", lan_cidr); return 1;
    }

    /* rlimit */
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) perror("setrlimit");

    /* 分配 NAT 表（v4 + v6 + nat64 + nat46） */
    g_table       = calloc(NAT_TABLE_SIZE,   sizeof(*g_table));
    g_egress_idx  = calloc(NAT_TABLE_SIZE,   sizeof(*g_egress_idx));
    g_ingress_idx = calloc(NAT_TABLE_SIZE,   sizeof(*g_ingress_idx));
    g_table6      = calloc(NAT6_TABLE_SIZE,  sizeof(*g_table6));
    g_egress6_idx = calloc(NAT6_TABLE_SIZE,  sizeof(*g_egress6_idx));
    g_ingress6_idx= calloc(NAT6_TABLE_SIZE,  sizeof(*g_ingress6_idx));
    g_table64     = calloc(NAT64_TABLE_SIZE, sizeof(*g_table64));
    g_egress64_idx= calloc(NAT64_TABLE_SIZE, sizeof(*g_egress64_idx));
    g_ingress64_idx=calloc(NAT64_TABLE_SIZE, sizeof(*g_ingress64_idx));
    g_table46     = calloc(NAT46_TABLE_SIZE, sizeof(*g_table46));
    g_egress46_idx= calloc(NAT46_TABLE_SIZE, sizeof(*g_egress46_idx));
    g_ingress46_idx=calloc(NAT46_TABLE_SIZE, sizeof(*g_ingress46_idx));
    if (!g_table || !g_table6 || !g_table64 || !g_table46) { perror("calloc"); return 1; }

    /* 默认 NAT64 前缀 64:ff9b:: */
    inet_pton(AF_INET6, "64:ff9b::", &g_nat64_pfx);

    /* 每个接口单独加载一份 BPF 程序（确保各自独立的 xsks_map）
     * 直连 libbpf：open_file → load → find prog → bpf_xdp_attach */
    struct bpf_object *wan_obj = bpf_object__open_file(
        "/etc/xdp-nat/xdp_nat_redirect.o", NULL);
    struct bpf_object *lan_obj = bpf_object__open_file(
        "/etc/xdp-nat/xdp_nat_redirect.o", NULL);
    if (libbpf_get_error(wan_obj) || libbpf_get_error(lan_obj)) {
        LOGE("打开 BPF 对象失败: %s", strerror(errno)); return 1;
    }
    if (bpf_object__load(wan_obj)) {
        LOGE("加载 WAN BPF 对象失败: %s", strerror(errno)); return 1;
    }
    if (bpf_object__load(lan_obj)) {
        LOGE("加载 LAN BPF 对象失败: %s", strerror(errno)); return 1;
    }
    struct bpf_program *wan_prog = bpf_object__find_program_by_name(wan_obj, "xdp_nat_redirect");
    struct bpf_program *lan_prog = bpf_object__find_program_by_name(lan_obj, "xdp_nat_redirect");
    if (!wan_prog || !lan_prog) { LOGE("BPF 对象中找不到 xdp_nat_redirect"); return 1; }
    int wan_prog_fd = bpf_program__fd(wan_prog);
    int lan_prog_fd = bpf_program__fd(lan_prog);
    if (wan_prog_fd < 0 || lan_prog_fd < 0) { LOGE("BPF 程序 fd 无效"); return 1; }

    int wan_ifidx = if_nametoindex(wan_if);
    int lan_ifidx = if_nametoindex(lan_if);
    if (!wan_ifidx || !lan_ifidx) { perror("if_nametoindex"); return 1; }

    /* XDP flags：先试 native（驱动层零拷贝），不行就 skb（通用、较慢但一定能用） */
    unsigned int wan_mode_flags = XDP_FLAGS_DRV_MODE;
    unsigned int lan_mode_flags = XDP_FLAGS_DRV_MODE;
    for (int pass = 0; pass < 2; pass++) {
        int prog_fd = pass ? lan_prog_fd : wan_prog_fd;
        int idxif = pass ? lan_ifidx : wan_ifidx;
        const char *nm = pass ? lan_if : wan_if;
        unsigned int flags = XDP_FLAGS_DRV_MODE;
        int ret = bpf_xdp_attach(idxif, prog_fd, flags, NULL);
        if (ret) {
            LOGI("%s: native(drv) attach 失败（%s），回退 skb 模式", nm, strerror(-ret));
            flags = XDP_FLAGS_SKB_MODE;
            ret = bpf_xdp_attach(idxif, prog_fd, flags, NULL);
        }
        if (ret) { LOGE("%s: XDP attach 失败: %s", nm, strerror(-ret)); return 1; }
        if (pass) lan_mode_flags = flags; else wan_mode_flags = flags;
        LOGI("BPF redirect 已 attach 到 %s (mode=%s)", nm,
             flags == XDP_FLAGS_DRV_MODE ? "native" : "skb");
    }

    int wan_map_fd = bpf_object__find_map_fd_by_name(wan_obj, "xsks_map");
    int lan_map_fd = bpf_object__find_map_fd_by_name(lan_obj, "xsks_map");
    if (wan_map_fd < 0 || lan_map_fd < 0) { LOGE("找不到 xsks_map"); return 1; }

    /* 填充 local_ips (v4) 和 local_ips6 */
    int wan_local_fd  = bpf_object__find_map_fd_by_name(wan_obj, "local_ips");
    int lan_local_fd  = bpf_object__find_map_fd_by_name(lan_obj, "local_ips");
    int wan_local6_fd = bpf_object__find_map_fd_by_name(wan_obj, "local_ips6");
    int lan_local6_fd = bpf_object__find_map_fd_by_name(lan_obj, "local_ips6");

    struct ifaddrs *ifap, *ifa;
    int n_local = 0, n_local6 = 0;
    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            uint8_t one = 1;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                uint32_t a = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
                if (wan_local_fd >= 0) bpf_map_update_elem(wan_local_fd, &a, &one, 0);
                if (lan_local_fd >= 0) bpf_map_update_elem(lan_local_fd, &a, &one, 0);
                n_local++;
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                uint8_t key[16];
                memcpy(key, ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr.s6_addr, 16);
                if (wan_local6_fd >= 0) bpf_map_update_elem(wan_local6_fd, key, &one, 0);
                if (lan_local6_fd >= 0) bpf_map_update_elem(lan_local6_fd, key, &one, 0);
                n_local6++;
            }
        }
        freeifaddrs(ifap);
    }
    LOGI("已写入 %d 条 local_ips / %d 条 local_ips6", n_local, n_local6);

    /* ===== 创建 queues 个 worker ===== */
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    struct xdp_worker *workers = calloc(queues, sizeof(*workers));
    if (!workers) { perror("calloc workers"); return 1; }
    uint64_t umem_size = (uint64_t)NUM_FRAMES * FRAME_SIZE;

    for (int i = 0; i < queues; i++) {
        int qid = (single_queue >= 0) ? single_queue : i;
        workers[i].queue_id = qid;
        workers[i].cpu      = pin_cpus ? (i % ncpu) : -1;
        workers[i].wan.ifname = wan_if; workers[i].wan.ifindex = wan_ifidx;
        workers[i].lan.ifname = lan_if; workers[i].lan.ifindex = lan_ifidx;

        /* 每 worker 独立 UMEM */
        void *buf = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) { perror("mmap"); return 1; }
        workers[i].umem = umem_init(buf, umem_size);
        if (!workers[i].umem) { LOGE("umem_init 失败 q=%d", qid); return 1; }

        if (xsk_port_open(&workers[i].wan, workers[i].umem, qid, !force_copy)) return 1;
        if (xsk_port_open(&workers[i].lan, workers[i].umem, qid, !force_copy)) return 1;

        if (xsk_socket__update_xskmap(workers[i].wan.xsk, wan_map_fd) ||
            xsk_socket__update_xskmap(workers[i].lan.xsk, lan_map_fd)) {
            LOGE("update_xskmap 失败 q=%d", qid); return 1;
        }
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGUSR1, handle_usr1);

    LOGI("启动：WAN=%s(%s) LAN=%s CIDR=%s zc=%s queues=%d pin_cpus=%d dnat=%d npt6=%d",
         wan_if, wan_ip_s, lan_if, lan_cidr,
         force_copy ? "off" : "auto", queues, pin_cpus, g_dnat_n, g_npt6_n);

    /* 启动所有 worker 线程 */
    for (int i = 0; i < queues; i++) {
        if (pthread_create(&workers[i].tid, NULL, worker_main, &workers[i]) != 0) {
            LOGE("pthread_create 失败 q=%d", workers[i].queue_id); g_stop = 1; break;
        }
        workers[i].started = 1;
    }

    /* 主线程：stats/cleanup/signal handling */
    time_t last_cleanup = time(NULL);
    time_t last_stats   = time(NULL);
    while (!g_stop) {
        usleep(200 * 1000);  /* 200ms tick */

        /* 汇总 worker 计数到全局 */
        uint64_t wr=0, wt=0, wd=0, lr=0, lt=0, ld=0;
        for (int i = 0; i < queues; i++) {
            wr += workers[i].wan.rx_packets; wt += workers[i].wan.tx_packets; wd += workers[i].wan.dropped;
            lr += workers[i].lan.rx_packets; lt += workers[i].lan.tx_packets; ld += workers[i].lan.dropped;
        }
        ATOMIC_STORE(&g_stat_wan_rx, wr);  ATOMIC_STORE(&g_stat_wan_tx, wt); ATOMIC_STORE(&g_stat_wan_drop, wd);
        ATOMIC_STORE(&g_stat_lan_rx, lr);  ATOMIC_STORE(&g_stat_lan_tx, lt); ATOMIC_STORE(&g_stat_lan_drop, ld);

        time_t now = time(NULL);
        if (now - last_stats >= STATS_INTERVAL) { write_stats_file(); last_stats = now; }
        if (g_dump) { g_dump = 0; dump_conns_file(); }
        if (now - last_cleanup >= CLEANUP_INTERVAL) {
            size_t cleaned = nat_cleanup();
            last_cleanup = now;
            if (g_verbose || cleaned)
                LOGD("cleanup: 过期 %zu 活跃 %zu  WAN rx=%"PRIu64"/tx=%"PRIu64"  LAN rx=%"PRIu64"/tx=%"PRIu64,
                     cleaned, nat_count(), wr, wt, lr, lt);
        }
    }

    /* 等所有 worker 退出 */
    for (int i = 0; i < queues; i++)
        if (workers[i].started) pthread_join(workers[i].tid, NULL);
    /* 清理 stats/conns 文件 */
    unlink("/run/xdp-nat.stats");
    unlink("/run/xdp-nat.conns");

    LOGI("退出中...");
    bpf_xdp_detach(wan_ifidx, wan_mode_flags, NULL);
    bpf_xdp_detach(lan_ifidx, lan_mode_flags, NULL);
    for (int i = 0; i < queues; i++) {
        if (workers[i].wan.xsk) xsk_socket__delete(workers[i].wan.xsk);
        if (workers[i].lan.xsk) xsk_socket__delete(workers[i].lan.xsk);
        if (workers[i].umem && workers[i].umem->umem) xsk_umem__delete(workers[i].umem->umem);
    }
    free(workers);
    bpf_object__close(wan_obj);
    bpf_object__close(lan_obj);
    return 0;
}
