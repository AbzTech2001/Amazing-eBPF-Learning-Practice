# Level 04: eBPF in Networking, Observability & Security

## Overview

This level focuses on **real-world applications** of eBPF: high-performance networking (XDP, tc), production observability pipelines, and runtime security. You'll learn patterns used by Cilium, Tetragon, Falco, and other production systems.

**Goal**: Build packet processors, integrate eBPF with observability stacks (Prometheus/Grafana/OTel), implement security policies, and understand production deployment patterns.

---

## Prerequisites

Complete **Levels 01-03**:
- eBPF fundamentals and libbpf programming
- CO-RE and skeleton usage
- Ring buffers and advanced maps
- Verifier debugging skills

---

## Topics Covered

### 1. **XDP (eXpress Data Path)** - Networking
- Packet processing at driver level
- Drop, pass, redirect actions
- DDoS mitigation patterns
- Load balancing basics

### 2. **tc (Traffic Control)** - Networking
- Ingress/egress filtering
- Packet modification
- Connection tracking
- Service meshes

### 3. **Observability Pipelines**
- Metrics export to Prometheus
- Distributed tracing with OpenTelemetry
- Custom exporters
- Grafana dashboards

### 4. **Security & Runtime Enforcement**
- LSM (Linux Security Modules) hooks
- Process execution monitoring
- File access policies
- Network security policies
- Patterns from Tetragon, Falco

### 5. **Kubernetes Integration**
- DaemonSet deployment
- RBAC and security contexts
- Container-aware tracing
- Service mesh observability

---

## Architecture Patterns

### XDP Data Path

```
┌─────────────────────────────────────────────────────┐
│                 Network Stack                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  NIC Driver receives packet                         │
│      ↓                                               │
│  ┌──────────────────────────────────────────────┐  │
│  │  XDP Program (attached to driver)            │  │
│  │  - Earliest packet processing point          │  │
│  │  - Before sk_buff allocation                 │  │
│  │  - Direct memory access to packet            │  │
│  │                                                │  │
│  │  Actions:                                      │  │
│  │    XDP_DROP    → Drop packet (DDoS mitigation)│  │
│  │    XDP_PASS    → Continue to network stack    │  │
│  │    XDP_TX      → Bounce back same interface   │  │
│  │    XDP_REDIRECT→ Send to another interface    │  │
│  │    XDP_ABORTED → Drop (error case)            │  │
│  └────────┬─────────────────────────────────────┘  │
│           │                                          │
│           ├─ XDP_DROP ────► Packet dropped          │
│           │                                          │
│           ├─ XDP_TX ──────► Back to NIC             │
│           │                                          │
│           └─ XDP_PASS ───► Continue to stack        │
│                                  ↓                   │
│                          ┌──────────────────────┐   │
│                          │  sk_buff allocated   │   │
│                          │  iptables/nftables   │   │
│                          │  tc (traffic control)│   │
│                          │  Socket layer        │   │
│                          └──────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Observability Pipeline

```
┌──────────────────────────────────────────────────────┐
│              Kernel Space (eBPF)                     │
├──────────────────────────────────────────────────────┤
│  Events from:                                        │
│  - Syscalls (process exec, file access)             │
│  - Network (connections, packets, DNS)              │
│  - Security (LSM hooks, capability checks)          │
│  - Performance (CPU, latency, errors)               │
│                                                       │
│  ↓ Collect & Filter                                  │
│                                                       │
│  eBPF Maps / Ring Buffers                           │
│  - Aggregate metrics                                 │
│  - Stream events                                     │
│  - Enrich with context (PID, container ID, etc.)    │
└─────────────────┬────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────┐
│              User Space (Agent)                      │
├──────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────┐ │
│  │  Event Processing & Enrichment                 │ │
│  │  - Add Kubernetes metadata (pod, namespace)    │ │
│  │  - Correlate events                            │ │
│  │  - Apply policies                              │ │
│  │  - Format for export                           │ │
│  └──────────────────┬─────────────────────────────┘ │
│                     │                                │
│                     ▼                                │
│  ┌────────────────────────────────────────────────┐ │
│  │  Export to Observability Backends             │ │
│  │  ┌──────────────┐ ┌────────────┐ ┌─────────┐ │ │
│  │  │ Prometheus   │ │ OpenTelemetry│ │ Grafana│ │ │
│  │  │ (metrics)    │ │ (traces)     │ │ (logs) │ │ │
│  │  └──────────────┘ └────────────┘ └─────────┘ │ │
│  └────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

---

## Practical Tasks (15)

### XDP Tasks

#### Task 1: XDP Packet Drop (DDoS Mitigation)
**Objective**: Build a basic packet filter with XDP.

```c
SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Drop TCP port 80 (example)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(80))
            return XDP_DROP;
    }

    return XDP_PASS;
}
```

**Deliverable**: XDP program that drops specific traffic, measure drop rate.

---

#### Task 2: XDP Packet Counter by Protocol
**Objective**: Count packets by protocol (TCP, UDP, ICMP).

Use maps to track:
- Packets per protocol
- Bytes per protocol
- Expose via user-space

**Deliverable**: Real-time packet statistics per protocol.

---

#### Task 3: XDP Load Balancer (Simple)
**Objective**: Distribute packets across backend servers.

Pattern:
1. Hash packet 5-tuple (src IP, dst IP, src port, dst port, proto)
2. Select backend based on hash
3. Rewrite destination MAC/IP
4. XDP_TX or XDP_REDIRECT

**Deliverable**: Working XDP load balancer for HTTP traffic.

---

### tc (Traffic Control) Tasks

#### Task 4: tc Ingress Filter
**Objective**: Filter incoming packets at tc layer.

```c
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Parse packet
    // Apply filtering logic
    // Return TC_ACT_OK (pass) or TC_ACT_SHOT (drop)

    return TC_ACT_OK;
}
```

**Deliverable**: tc program filtering based on custom rules.

---

#### Task 5: Packet Modification with tc
**Objective**: Modify packet headers (TTL, TOS, etc.).

Use `bpf_skb_store_bytes()` to modify packet data.

**Deliverable**: tc program that modifies packet headers.

---

### Observability Tasks

#### Task 6: Prometheus Exporter
**Objective**: Export eBPF metrics to Prometheus.

Pattern:
1. eBPF program collects metrics in maps
2. User-space agent reads maps periodically
3. Expose HTTP endpoint for Prometheus scraping
4. Format metrics in Prometheus text format

```
# HELP ebpf_syscalls_total Total syscalls
# TYPE ebpf_syscalls_total counter
ebpf_syscalls_total{syscall="open"} 12345
ebpf_syscalls_total{syscall="read"} 67890
```

**Deliverable**: Working Prometheus exporter for eBPF metrics.

---

#### Task 7: Grafana Dashboard
**Objective**: Visualize eBPF data in Grafana.

Steps:
1. Set up Prometheus + Grafana
2. Configure Prometheus to scrape your exporter
3. Create Grafana dashboard with panels:
   - Syscall rate
   - Network connections
   - Process execution timeline

**Deliverable**: Grafana dashboard showing live eBPF data.

---

#### Task 8: OpenTelemetry Integration
**Objective**: Send eBPF traces to OTel collector.

Pattern:
1. eBPF captures spans (e.g., request start/end)
2. User-space constructs OTel spans
3. Send to OTel collector via OTLP

**Deliverable**: eBPF-based application tracing in OTel.

---

#### Task 9: Distributed Tracing with eBPF
**Objective**: Trace requests across services using eBPF.

Capture:
- HTTP requests (uprobe on curl/httpd)
- Syscall latency
- Network latency
- Generate trace IDs and span IDs

**Deliverable**: End-to-end trace visualization.

---

### Security Tasks

#### Task 10: Process Execution Monitor (LSM)
**Objective**: Use LSM hooks to monitor process execution.

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm)
{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // Log execution attempt
    bpf_printk("Exec attempt: %s\n", bprm->filename);

    // Could deny: return -EPERM;
    return 0;  // Allow
}
```

**Deliverable**: LSM-based process monitor with alerting.

---

#### Task 11: File Access Policy
**Objective**: Monitor/restrict file access with LSM hooks.

Hooks:
- `lsm/file_open` - File open attempts
- `lsm/file_permission` - Permission checks

**Deliverable**: Policy engine that logs/blocks sensitive file access.

---

#### Task 12: Network Connection Policy
**Objective**: Enforce network connection policies.

Patterns:
- Allow/deny connections to specific IPs/ports
- Log all outbound connections
- Alert on suspicious activity

**Deliverable**: Network policy enforcement agent.

---

### Kubernetes Integration Tasks

#### Task 13: Deploy as DaemonSet
**Objective**: Deploy eBPF agent to Kubernetes.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-agent
spec:
  selector:
    matchLabels:
      app: ebpf-agent
  template:
    metadata:
      labels:
        app: ebpf-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: agent
        image: my-ebpf-agent:latest
        securityContext:
          privileged: true
          capabilities:
            add: ["SYS_ADMIN", "SYS_RESOURCE", "NET_ADMIN"]
        volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: debugfs
          mountPath: /sys/kernel/debug
      volumes:
      - name: bpffs
        hostPath:
          path: /sys/fs/bpf
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
```

**Deliverable**: Working DaemonSet deployment with RBAC.

---

#### Task 14: Container-Aware Tracing
**Objective**: Correlate eBPF events with Kubernetes pods.

Enrich events with:
- Pod name
- Namespace
- Container ID
- Labels

Use cgroup IDs to map to containers.

**Deliverable**: Container-aware event stream.

---

#### Task 15: Service Mesh Observability
**Objective**: Implement basic service mesh observability.

Track:
- Service-to-service calls
- Request latencies
- Error rates
- Generate service dependency graph

**Deliverable**: Service mesh topology visualization.

---

## Real-World Challenges (8)

### Challenge 1: XDP Performance Under Load
**Scenario**: Your XDP program causes packet drops under high load (10Gbps+).

**Causes**:
- Per-packet map lookups (expensive)
- Complex logic
- Insufficient CPU

**Your Task**:
1. Benchmark with `pktgen` or `t-rex`
2. Profile XDP program performance
3. Optimize:
   - Use per-CPU maps
   - Minimize map lookups
   - Use direct packet access
   - Consider XDP native mode vs generic

**Deliverable**: Optimized XDP program handling 10Gbps+.

---

### Challenge 2: Packet Parsing Verifier Errors
**Scenario**: Verifier rejects packet parsing due to bounds checks.

**Problem**:
```c
struct ethhdr *eth = data;
// ERROR: Verifier wants bounds check!
if (eth->h_proto == ...)
```

**Your Task**:
Implement proper bounds checking for all packet accesses.

```c
if (data + sizeof(struct ethhdr) > data_end)
    return XDP_PASS;

struct ethhdr *eth = data;
// Now safe to access eth->*
```

**Deliverable**: Verifier-compliant packet parser.

---

### Challenge 3: Metrics Export Overhead
**Scenario**: Reading eBPF maps causes latency spikes.

**Problem**:
- Large maps (millions of entries)
- Frequent scraping (every 1s)
- Map iteration blocks other operations

**Your Task**:
1. Implement incremental map reading
2. Use batch operations
3. Add caching
4. Consider ring buffer for hot metrics

**Deliverable**: Low-overhead metrics export (<1% CPU).

---

### Challenge 4: LSM Hook Not Available
**Scenario**: Your target kernel doesn't have LSM BPF support.

**Problem**:
- Kernel < 5.7
- CONFIG_BPF_LSM not enabled

**Your Task**:
1. Detect LSM availability
2. Implement fallback using kprobes
3. Document feature requirements
4. Handle gracefully

**Deliverable**: Security agent with kernel compatibility layer.

---

### Challenge 5: Container Context Loss
**Scenario**: You can't correlate eBPF events to containers/pods.

**Problem**:
- cgroup IDs change
- Missing Kubernetes metadata
- Namespace isolation

**Your Task**:
1. Read cgroup ID from task
2. Map cgroup to container ID (via /proc)
3. Query Kubernetes API for pod metadata
4. Cache mappings

**Deliverable**: Reliable container-to-pod mapping.

---

### Challenge 6: Distributed Tracing Context Propagation
**Scenario**: Trace context gets lost across services.

**Problem**:
- eBPF can't access HTTP headers easily
- Trace ID propagation breaks
- Spans not correlated

**Your Task**:
1. Use uprobes to extract trace IDs from app
2. Correlate via timing/connection info
3. Implement trace context injection

**Deliverable**: Working distributed tracing across services.

---

### Challenge 7: Prometheus Cardinality Explosion
**Scenario**: Your metrics have too many unique label combinations.

**Problem**:
```
ebpf_requests{pod="x", namespace="y", method="z", path="/api/users/123"}
```
Millions of unique paths → Prometheus overload!

**Your Task**:
1. Limit label cardinality
2. Aggregate high-cardinality dimensions
3. Use exemplars for sampling
4. Implement metric relabeling

**Deliverable**: Cardinality-safe metrics.

---

### Challenge 8: XDP on Virtual Interfaces
**Scenario**: XDP doesn't work on veth pairs (containers).

**Problem**:
- Only generic XDP mode on veth
- Lower performance
- Some features unavailable

**Your Task**:
1. Understand XDP modes (native, offload, generic)
2. Test on physical NIC vs veth
3. Implement tc as fallback for veth
4. Document limitations

**Deliverable**: Network program working on both physical and virtual interfaces.

---

## Production Patterns

### 1. Cilium/Hubble Pattern: Network Observability

```
┌─────────────────────────────────────────────────┐
│  XDP/tc programs attached to all interfaces     │
│  - Capture packet metadata (5-tuple, flags)     │
│  - Track connection states                      │
│  - Map packets to pods                          │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  User-space Agent (Hubble)                      │
│  - Reads events from ring buffer                │
│  - Enriches with K8s metadata                   │
│  - Stores in local cache                        │
│  - Exposes gRPC API                             │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Hubble UI / CLI                                 │
│  - Service graph visualization                   │
│  - Flow logs                                     │
│  - Latency metrics                              │
└─────────────────────────────────────────────────┘
```

### 2. Tetragon/Falco Pattern: Security Monitoring

```
┌─────────────────────────────────────────────────┐
│  LSM + kprobe hooks                             │
│  - Process execution (execve)                   │
│  - File access (open, read, write)             │
│  - Network (connect, accept)                    │
│  - Capabilities (cap_capable)                   │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Policy Engine                                   │
│  - Match events against policies                │
│  - Generate alerts                              │
│  - Take enforcement actions (deny, kill)        │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Export                                          │
│  - SIEM integration                             │
│  - Slack/PagerDuty alerts                       │
│  - Audit logs                                   │
└─────────────────────────────────────────────────┘
```

---

## Learning Checklist

By the end of Level 04, you should be able to:

- [ ] Write XDP programs for packet processing
- [ ] Implement tc-based packet filters and modifiers
- [ ] Build Prometheus exporters for eBPF metrics
- [ ] Create Grafana dashboards for eBPF data
- [ ] Integrate eBPF with OpenTelemetry
- [ ] Use LSM hooks for security policies
- [ ] Deploy eBPF agents as Kubernetes DaemonSets
- [ ] Implement container-aware tracing
- [ ] Handle high-performance packet processing
- [ ] Build production observability pipelines
- [ ] Understand Cilium/Hubble architecture patterns
- [ ] Implement Tetragon/Falco-style security monitoring

---

## Next Steps

**Level 05**: Production Agent & Hardening
- Build complete production-ready eBPF agent
- Kernel feature detection and graceful degradation
- Performance tuning and overhead management
- CI/CD for eBPF programs
- Multi-tenancy and security hardening
- Operational best practices

---

## References

### XDP & Networking
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Cilium Documentation](https://docs.cilium.io/)
- [Katran Load Balancer](https://github.com/facebookincubator/katran)

### Observability
- [Prometheus Documentation](https://prometheus.io/docs/)
- [OpenTelemetry eBPF](https://github.com/open-telemetry/opentelemetry-ebpf)
- [Pixie Documentation](https://docs.px.dev/)

### Security
- [Tetragon](https://github.com/cilium/tetragon)
- [Falco](https://falco.org/docs/)
- [LSM BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)

---

**Ready to start? Run `./tools/setup-level04.sh` to install dependencies!**
