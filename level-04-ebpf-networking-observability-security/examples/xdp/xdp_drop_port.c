// SPDX-License-Identifier: GPL-2.0
/* XDP Port Filter - Drop packets to specific TCP port
 *
 * Demonstrates:
 * - XDP packet parsing
 * - Protocol header access
 * - Verifier-compliant bounds checking
 * - XDP_DROP action
 * - Statistics tracking
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Configuration: port to drop
const volatile __u16 target_port = 80;

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum {
    STAT_RX_PACKETS = 0,
    STAT_TX_PACKETS,
    STAT_DROPPED,
    STAT_PASSED,
};

static __always_inline void update_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

SEC("xdp")
int xdp_drop_port_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    update_stat(STAT_RX_PACKETS);

    // Parse Ethernet header
    struct ethhdr *eth = data;

    // Bounds check #1: Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);

    // Bounds check #2: IP header
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Check if TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)(ip + 1);

    // Bounds check #3: TCP header
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Check destination port (network byte order)
    if (tcp->dest == bpf_htons(target_port)) {
        update_stat(STAT_DROPPED);
        return XDP_DROP;
    }

    update_stat(STAT_PASSED);
    return XDP_PASS;
}

/*
 * Learning Notes:
 *
 * XDP Actions:
 * - XDP_DROP: Drop packet immediately (DDoS mitigation)
 * - XDP_PASS: Continue to network stack
 * - XDP_TX: Bounce packet back same interface
 * - XDP_REDIRECT: Send to another interface
 * - XDP_ABORTED: Drop (error case)
 *
 * Bounds Checking (Critical!):
 * - Verifier requires proof that all memory accesses are safe
 * - Must check: (ptr + size) <= data_end
 * - Check before dereferencing ANY pointer
 *
 * Performance:
 * - XDP runs before sk_buff allocation
 * - Minimal overhead
 * - Can handle 10M+ packets/sec
 *
 * Per-CPU Maps:
 * - Avoid lock contention
 * - Each CPU has its own copy
 * - User-space must aggregate
 *
 * Deployment:
 * - ip link set dev eth0 xdp obj xdp_drop_port.o sec xdp
 * - Or use libbpf in user-space loader
 */
