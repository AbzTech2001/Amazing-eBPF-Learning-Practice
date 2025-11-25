# XDP (eXpress Data Path) Fundamentals

## Overview

XDP provides **programmable packet processing at the earliest point** in the Linux network stack - right when the network driver receives packets, before sk_buff allocation.

---

## Why XDP?

### Performance Benefits

```
Traditional Stack:               XDP:
┌──────────────┐               ┌──────────────┐
│ Packet RX    │               │ Packet RX    │
│      ↓       │               │      ↓       │
│ DMA          │               │ DMA          │
│      ↓       │               │      ↓       │
│ sk_buff      │               │ XDP Program  │← Process here!
│ alloc        │               │   (decision) │
│      ↓       │               │      ↓       │
│ iptables     │               │ DROP/PASS/TX │
│      ↓       │               └──────────────┘
│ netfilter    │
│      ↓       │               10-20M pps possible!
│ application  │               vs 1-2M pps traditional
└──────────────┘
```

**Key Advantage**: Process packets before expensive sk_buff allocation.

---

## XDP Actions

```c
enum xdp_action {
    XDP_ABORTED = 0,    // Drop + trace_xdp_exception
    XDP_DROP,           // Drop packet (DDoS mitigation)
    XDP_PASS,           // Continue to network stack
    XDP_TX,             // Bounce back same NIC
    XDP_REDIRECT,       // Send to another NIC/CPU
};
```

---

## Basic XDP Program

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tcp_80(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only process TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Drop HTTP traffic (port 80)
    if (tcp->dest == bpf_htons(80))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## Packet Parsing Pattern

**Critical**: Every pointer dereference needs bounds checking!

```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Step 1: Check Ethernet header fits
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

// Step 2: Check protocol
if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

// Step 3: Check IP header fits
struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

// Step 4: Now safe to read ip fields
```

---

## Use Cases

### 1. DDoS Mitigation

```c
// Drop SYN floods
if (tcp->syn && !tcp->ack) {
    // Check if source is blacklisted
    __u32 src_ip = ip->saddr;
    void *is_blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (is_blocked)
        return XDP_DROP;
}
```

### 2. Load Balancing

```c
// Simple round-robin load balancing
__u32 backend_idx = bpf_get_prandom_u32() % NUM_BACKENDS;
__u32 *backend_ip = bpf_map_lookup_elem(&backends, &backend_idx);
if (backend_ip) {
    ip->daddr = *backend_ip;
    // Recalculate checksum...
    return XDP_TX;  // Bounce back
}
```

### 3. Packet Sampling

```c
// Sample 1 in 1000 packets for monitoring
if (bpf_get_prandom_u32() % 1000 == 0) {
    // Send to monitoring system
    return XDP_REDIRECT;
}
return XDP_PASS;
```

---

## XDP Maps for State

```c
// Count packets per protocol
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

SEC("xdp")
int xdp_stats(struct xdp_md *ctx)
{
    // ... parse packet ...

    __u32 proto = ip->protocol;
    __u64 *count = bpf_map_lookup_elem(&proto_stats, &proto);
    if (count)
        __sync_fetch_and_add(count, 1);

    return XDP_PASS;
}
```

---

## Attaching XDP Programs

### Using iproute2

```bash
# Attach XDP program
sudo ip link set dev eth0 xdp obj my_xdp.bpf.o sec xdp

# Check status
ip link show dev eth0

# Detach
sudo ip link set dev eth0 xdp off
```

### Using libbpf

```c
int ifindex = if_nametoindex("eth0");

struct bpf_link *link = bpf_program__attach_xdp(
    skel->progs.xdp_drop_tcp_80,
    ifindex
);

// Detach
bpf_link__destroy(link);
```

---

## XDP Modes

### SKB Mode (Generic)
- Works on any NIC
- Slowest (no performance benefit)
- Good for testing

```bash
sudo ip link set dev eth0 xdpgeneric obj prog.bpf.o sec xdp
```

### Native Mode (Driver)
- Requires driver support (most modern NICs)
- Best performance
- Runs in driver context

```bash
sudo ip link set dev eth0 xdpdrv obj prog.bpf.o sec xdp
```

### Offload Mode (NIC)
- Runs on NIC hardware
- Highest performance
- Limited NIC support (Netronome, etc.)

```bash
sudo ip link set dev eth0 xdpoffload obj prog.bpf.o sec xdp
```

---

## Best Practices

1. **Always bounds check**: `if ((void *)(header + 1) > data_end)`
2. **Use bpf_htons/bpf_ntohs** for network byte order
3. **Keep programs small** - complexity affects performance
4. **Use per-CPU maps** for statistics (no lock contention)
5. **Test in generic mode first**, then native
6. **Use XDP_DROP for DDoS**, not iptables

---

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium XDP Guide](https://docs.cilium.io/en/stable/bpf/)
- [Kernel XDP Documentation](https://www.kernel.org/doc/html/latest/networking/xdp.html)
