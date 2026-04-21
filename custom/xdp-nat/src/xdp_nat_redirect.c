// xdp_nat_redirect.c
// BPF 程序：驱动层决定哪些包送用户态 AF_XDP
//   - 非 IPv4/IPv6 → PASS
//   - 非 TCP/UDP/ICMP/ICMPv6 → PASS
//   - IPv4: 目的是本机（在 local_ips）→ PASS
//   - IPv6: 目的是本机（在 local_ips6）→ PASS
//   - IPv6: 链路本地 fe80::/10 → PASS（NDP）
//   - 其它 → REDIRECT 到 xsks_map（用户态 AF_XDP NAT）

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SOCKS 64

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SOCKS);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* 本机 IPv4 列表（网络字节序） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 64);
} local_ips SEC(".maps");

/* 本机 IPv6 列表（16 字节地址整体作为 key） */
struct in6_key { __u8 b[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_key);
    __type(value, __u8);
    __uint(max_entries, 64);
} local_ips6 SEC(".maps");

SEC("xdp")
int xdp_nat_redirect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* ---- IPv4 路径 ---- */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol != IPPROTO_TCP &&
            ip->protocol != IPPROTO_UDP &&
            ip->protocol != IPPROTO_ICMP)
            return XDP_PASS;

        __u32 dst = ip->daddr;
        if (bpf_map_lookup_elem(&local_ips, &dst))
            return XDP_PASS;

        goto redirect;
    }

    /* ---- IPv6 路径 ---- */
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

        /* 只处理无扩展头的 TCP/UDP/ICMPv6 */
        if (ip6->nexthdr != IPPROTO_TCP &&
            ip6->nexthdr != IPPROTO_UDP &&
            ip6->nexthdr != IPPROTO_ICMPV6)
            return XDP_PASS;

        /* 链路本地 fe80::/10 → 让内核处理（NDP/RS/RA） */
        if (ip6->daddr.in6_u.u6_addr8[0] == 0xfe &&
            (ip6->daddr.in6_u.u6_addr8[1] & 0xc0) == 0x80)
            return XDP_PASS;
        /* 组播 ff00::/8 → 让内核（MLD、NDP Neighbor Solicitation 等） */
        if (ip6->daddr.in6_u.u6_addr8[0] == 0xff)
            return XDP_PASS;

        /* 目的是本机 → PASS */
        struct in6_key key;
        __builtin_memcpy(key.b, ip6->daddr.in6_u.u6_addr8, 16);
        if (bpf_map_lookup_elem(&local_ips6, &key))
            return XDP_PASS;

        goto redirect;
    }

    return XDP_PASS;

redirect: ;
    __u32 idx = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
