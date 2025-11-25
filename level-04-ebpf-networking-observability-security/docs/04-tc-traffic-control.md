# TC (Traffic Control) with eBPF

## Overview

TC (Traffic Control) eBPF programs provide **packet filtering and modification** at the Linux traffic control layer - after sk_buff allocation but before routing decisions.

---

## TC vs XDP

```
Packet Flow:

NIC → XDP → sk_buff alloc → TC (ingress) → Routing
                              ↓
                            Application
                              ↓
                           TC (egress) → NIC
```

| Feature | XDP | TC |
|---------|-----|-----|
| When | Before sk_buff | After sk_buff |
| Performance | Highest | High |
| Packet modification | Limited | Full |
| Context | xdp_md | __sk_buff |
| Use case | Drop, redirect | Modify, filter, QoS |

---

## Basic TC Program

```c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("tc")
int tc_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Drop packets from specific IP
    if (ip->saddr == bpf_htonl(0xC0A80101)) {  // 192.168.1.1
        return TC_ACT_SHOT;  // Drop
    }

    return TC_ACT_OK;  // Pass
}

char LICENSE[] SEC("license") = "GPL";
```

---

## TC Actions

```c
#define TC_ACT_OK          0  // Pass to next layer
#define TC_ACT_SHOT        2  // Drop packet
#define TC_ACT_STOLEN      4  // Consume (don't process further)
#define TC_ACT_REDIRECT    7  // Redirect to another device
```

---

## Attaching TC Programs

### Using tc command

```bash
# Attach to ingress (incoming packets)
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 ingress bpf da obj tc_filter.bpf.o sec tc

# Attach to egress (outgoing packets)
sudo tc filter add dev eth0 egress bpf da obj tc_filter.bpf.o sec tc

# Show filters
sudo tc filter show dev eth0 ingress

# Remove
sudo tc filter del dev eth0 ingress
sudo tc qdisc del dev eth0 clsact
```

### Using libbpf

```c
#include <linux/if_link.h>
#include <net/if.h>

int ifindex = if_nametoindex("eth0");
int prog_fd = bpf_program__fd(skel->progs.tc_filter);

// Create clsact qdisc
DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
    .ifindex = ifindex,
    .attach_point = BPF_TC_INGRESS,
);
bpf_tc_hook_create(&hook);

// Attach program
DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
    .prog_fd = prog_fd,
);
bpf_tc_attach(&hook, &opts);
```

---

## Use Cases

### 1. Packet Modification

```c
SEC("tc")
int tc_nat(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // NAT: Change source IP
    __be32 old_ip = ip->saddr;
    __be32 new_ip = bpf_htonl(0x0A000001);  // 10.0.0.1

    ip->saddr = new_ip;

    // Update checksum (simplified)
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
                        old_ip, new_ip, sizeof(new_ip));

    return TC_ACT_OK;
}
```

### 2. Service Mesh / Load Balancing

```c
struct backend {
    __be32 ip;
    __be16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

SEC("tc")
int tc_lb(struct __sk_buff *skb)
{
    // Parse packet...

    // Select backend (round-robin)
    __u32 idx = bpf_get_prandom_u32() % 4;
    struct backend *be = bpf_map_lookup_elem(&backends, &idx);
    if (!be)
        return TC_ACT_OK;

    // Rewrite destination
    ip->daddr = be->ip;
    tcp->dest = be->port;

    // Update checksums
    // ...

    return TC_ACT_OK;
}
```

### 3. Traffic Shaping

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // Flow ID
    __type(value, __u64); // Last packet time
} flow_tracker SEC(".maps");

SEC("tc")
int tc_rate_limit(struct __sk_buff *skb)
{
    __u32 flow_id = skb->mark;  // Or derive from packet

    __u64 *last_time = bpf_map_lookup_elem(&flow_tracker, &flow_id);
    __u64 now = bpf_ktime_get_ns();

    if (last_time) {
        // Rate limit: max 1 packet per millisecond
        if (now - *last_time < 1000000) {  // 1ms in ns
            return TC_ACT_SHOT;  // Drop
        }
    }

    bpf_map_update_elem(&flow_tracker, &flow_id, &now, BPF_ANY);
    return TC_ACT_OK;
}
```

---

## Accessing sk_buff Fields

```c
SEC("tc")
int tc_inspector(struct __sk_buff *skb)
{
    // Protocol
    __u32 protocol = skb->protocol;

    // Interface index
    __u32 ifindex = skb->ifindex;

    // Packet mark (for policy routing)
    __u32 mark = skb->mark;

    // Priority
    __u32 priority = skb->priority;

    // Queue mapping
    __u16 queue_mapping = skb->queue_mapping;

    // Ingress interface (if redirected)
    __u32 ingress_ifindex = skb->ingress_ifindex;

    return TC_ACT_OK;
}
```

---

## Redirect Packets

```c
SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
    // Redirect to another interface
    int target_ifindex = if_nametoindex("eth1");

    return bpf_redirect(target_ifindex, 0);
}
```

---

## Best Practices

1. **Use TC for packet modification** (XDP can't modify easily)
2. **Ingress for filtering**, egress for NAT/encapsulation
3. **Update checksums** after IP/TCP modifications
4. **Use bpf_skb_change_proto** to change L2 protocol
5. **Test with tcpdump** to verify packet changes

---

## References

- [Kernel TC BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_tc.html)
- [Cilium Service Mesh](https://docs.cilium.io/)
- [tc-bpf man page](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)
