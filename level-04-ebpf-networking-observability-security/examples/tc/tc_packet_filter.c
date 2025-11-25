// SPDX-License-Identifier: GPL-2.0
/* TC (Traffic Control) Packet Filter
 *
 * Demonstrates:
 * - TC BPF program (clsact qdisc)
 * - Packet classification and filtering
 * - Connection tracking
 * - Rate limiting patterns
 * - Integration with Linux tc subsystem
 *
 * TC vs XDP:
 * - TC: After packet enters network stack (sees sk_buff)
 * - XDP: Before network stack (raw packet data)
 * - TC: Can modify packets more easily
 * - XDP: Better performance for early drop
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Configuration
const volatile __u16 blocked_port = 8080;
const volatile __u32 rate_limit_pps = 10000;  // Packets per second

// Per-IP rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // Source IP
    __type(value, __u64); // Last packet time (ns)
} rate_limit SEC(".maps");

// Connection tracking
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
};

struct conn_info {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} connections SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_TOTAL_BYTES,
    STAT_TCP_PACKETS,
    STAT_UDP_PACKETS,
    STAT_RATE_LIMITED,
    STAT_BLOCKED_PORT,
    STAT_PASSED,
    STAT_DROPPED,
};

static __always_inline void update_stat(__u32 key, __u64 increment)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        __sync_fetch_and_add(value, increment);
}

static __always_inline int check_rate_limit(__u32 src_ip)
{
    __u64 *last_time = bpf_map_lookup_elem(&rate_limit, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    __u64 interval = 1000000000ULL / rate_limit_pps;  // ns per packet

    if (last_time) {
        if (now - *last_time < interval) {
            update_stat(STAT_RATE_LIMITED, 1);
            return 1;  // Rate limit exceeded
        }
    }

    bpf_map_update_elem(&rate_limit, &src_ip, &now, BPF_ANY);
    return 0;
}

static __always_inline void track_connection(struct conn_key *key, __u32 len)
{
    struct conn_info *info = bpf_map_lookup_elem(&connections, key);
    __u64 now = bpf_ktime_get_ns();

    if (info) {
        __sync_fetch_and_add(&info->packets, 1);
        __sync_fetch_and_add(&info->bytes, len);
        info->last_seen = now;
    } else {
        struct conn_info new_info = {
            .packets = 1,
            .bytes = len,
            .first_seen = now,
            .last_seen = now,
        };
        bpf_map_update_elem(&connections, key, &new_info, BPF_NOEXIST);
    }
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct conn_key key = {};

    // Update packet counter
    update_stat(STAT_TOTAL_PACKETS, 1);
    update_stat(STAT_TOTAL_BYTES, skb->len);

    // Parse Ethernet header
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Rate limiting check
    if (check_rate_limit(ip->saddr)) {
        return TC_ACT_SHOT;  // Drop packet
    }

    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    // Handle TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        key.sport = tcp->source;
        key.dport = tcp->dest;

        update_stat(STAT_TCP_PACKETS, 1);

        // Block specific port
        if (tcp->dest == bpf_htons(blocked_port)) {
            update_stat(STAT_BLOCKED_PORT, 1);
            update_stat(STAT_DROPPED, 1);
            return TC_ACT_SHOT;
        }

        track_connection(&key, skb->len);
    }
    // Handle UDP
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        key.sport = udp->source;
        key.dport = udp->dest;

        update_stat(STAT_UDP_PACKETS, 1);

        track_connection(&key, skb->len);
    }

    update_stat(STAT_PASSED, 1);
    return TC_ACT_OK;  // Allow packet
}

/*
 * Learning Notes:
 *
 * TC (Traffic Control) BPF:
 * - Hooks into Linux tc (traffic control) subsystem
 * - Access to sk_buff (socket buffer) structure
 * - Can modify packet data
 * - Two attachment points: ingress and egress
 *
 * TC Actions:
 * - TC_ACT_OK: Allow packet to continue
 * - TC_ACT_SHOT: Drop packet
 * - TC_ACT_REDIRECT: Redirect to another interface
 * - TC_ACT_PIPE: Continue to next tc action
 *
 * TC vs XDP Comparison:
 * ┌────────────────────┬──────────────┬──────────────┐
 * │                    │ XDP          │ TC           │
 * ├────────────────────┼──────────────┼──────────────┤
 * │ Hook point         │ Driver RX    │ After stack  │
 * │ Performance        │ Highest      │ High         │
 * │ Access to          │ Raw packet   │ sk_buff      │
 * │ Packet modify      │ Limited      │ Full         │
 * │ Use case           │ Early drop   │ Complex QoS  │
 * └────────────────────┴──────────────┴──────────────┘
 *
 * Rate Limiting Pattern:
 * - Store last packet time per source IP
 * - Calculate minimum interval between packets
 * - Drop if packets arrive too fast
 * - LRU map auto-evicts old entries
 *
 * Connection Tracking:
 * - Track 5-tuple: src IP, dst IP, src port, dst port, proto
 * - Count packets and bytes per connection
 * - Useful for network visibility
 * - Similar to Cilium's connection tracking
 *
 * Deployment:
 * 1. Create clsact qdisc:
 *    tc qdisc add dev eth0 clsact
 *
 * 2. Attach BPF program:
 *    tc filter add dev eth0 ingress bpf da obj tc_packet_filter.o sec tc
 *
 * 3. View stats:
 *    tc filter show dev eth0 ingress
 *
 * 4. Remove:
 *    tc filter del dev eth0 ingress
 *    tc qdisc del dev eth0 clsact
 *
 * Production Use (Cilium pattern):
 * - Pod-to-pod policy enforcement
 * - Service load balancing
 * - Network observability
 * - Rate limiting and QoS
 */
