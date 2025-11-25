# BCC vs bpftrace: Decision Guide

## When to Use What?

This guide helps you choose the right tool for your tracing needs.

---

## Decision Tree

```
Need eBPF tracing?
│
├─ Quick debugging / ad-hoc analysis?
│  └─> Use bpftrace
│
├─ Complex logic / state machines?
│  └─> Use BCC
│
├─ One-time investigation?
│  └─> Use bpftrace
│
├─ Reusable tool / production agent?
│  └─> Use BCC (or libbpf for Level 03)
│
├─ Learning eBPF concepts?
│  └─> Start with bpftrace
│
└─ Maximum performance / portability?
   └─> Use libbpf + CO-RE (Level 03)
```

---

## Use bpftrace When:

### ✓ Quick Ad-Hoc Analysis

**Scenario**: "Why is this server slow right now?"

```bash
# One-liner to find CPU hogs
sudo bpftrace -e 'profile:hz:99 { @[comm] = count(); }'
```

**Why bpftrace**: Answer in seconds, not hours.

---

### ✓ Prototyping

**Scenario**: "I want to explore what data is available before building a full tool."

```bash
# See what openat gives you
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat {
    printf("%s: %s\n", comm, str(args->filename));
}'
```

**Why bpftrace**: Iterate quickly, discover probe points.

---

### ✓ One-Liners

**Scenario**: "Just need a quick answer."

```bash
# Count syscalls by process
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```

**Why bpftrace**: Minimal typing, immediate results.

---

### ✓ Learning eBPF

**Scenario**: "I'm new to eBPF and want to understand concepts."

**Why bpftrace**: Simpler syntax, less boilerplate, faster feedback loop.

---

### ✓ Simple Logic

**Scenario**: Count, histogram, simple filtering.

```bash
# Histogram of read sizes
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_read {
    @bytes = hist(args->count);
}'
```

**Why bpftrace**: Expressive, built-in aggregations.

---

## Use BCC When:

### ✓ Complex Logic

**Scenario**: Multi-step processing, state machines, complex filtering.

```python
# Track connection state over time
prog = """
BPF_HASH(connections, u64, struct conn_info_t, 10000);

int trace_connect(struct pt_regs *ctx) {
    // Complex logic: check state, update multiple maps, etc.
    struct conn_info_t info = {};

    // Populate from multiple sources
    // Update connection state
    // Check thresholds
    // ...

    connections.update(&key, &info);
    return 0;
}
"""
```

**Why BCC**: Full C programming, no restrictions.

---

### ✓ Post-Processing in Python

**Scenario**: Process data, store in database, generate reports.

```python
b = BPF(text=prog)
# ... attach ...

while True:
    sleep(1)

    # Read map
    for k, v in b["stats"].items():
        # Write to PostgreSQL
        # Send to monitoring system
        # Generate JSON report
        # ...
```

**Why BCC**: Python integration, rich ecosystem.

---

### ✓ Reusable Tools

**Scenario**: Build a tool others will use.

**Why BCC**: Better for packaging, distribution, maintainability.

Example: Many BCC tools (`/usr/share/bcc/tools/`) are production-ready.

---

### ✓ Long Strings / Binary Data

**Scenario**: Capture full file paths (>64 chars), binary protocol data.

**Why BCC**: No string length limit, flexible data handling.

---

### ✓ Production Monitoring

**Scenario**: Long-running agent collecting metrics.

**Why BCC**: More mature, better tested in production environments.

**Note**: For production at scale, consider libbpf (Level 03) for CO-RE portability.

---

## Comparative Analysis

### Scenario 1: "I want to see which processes are opening files"

**bpftrace** (recommended):
```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat {
    printf("%s: %s\n", comm, str(args->filename));
}'
```
- **Time to result**: 5 seconds
- **Lines of code**: 1

**BCC**:
```python
#!/usr/bin/env python3
from bcc import BPF

prog = """
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[256];
    bpf_probe_read_user_str(&filename, sizeof(filename), args->filename);
    bpf_trace_printk("%s\\n", filename);
    return 0;
}
"""

b = BPF(text=prog)
b.trace_print()
```
- **Time to result**: 2 minutes
- **Lines of code**: 15+

**Winner**: bpftrace (unless you need >256 char paths or complex filtering)

---

### Scenario 2: "Count TCP retransmissions per destination IP, alert if >100/sec"

**BCC** (recommended):
```python
#!/usr/bin/env python3
from bcc import BPF
import socket

prog = """
#include <net/sock.h>
BPF_HASH(retrans, u32, u64);

int count_retrans(struct pt_regs *ctx, struct sock *sk) {
    u32 daddr = sk->__sk_common.skc_daddr;
    u64 zero = 0, *val;

    val = retrans.lookup_or_try_init(&daddr, &zero);
    if (val) (*val)++;

    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="count_retrans")

while True:
    sleep(1)
    for k, v in b["retrans"].items():
        ip = socket.inet_ntoa(struct.pack("I", k.value))
        if v.value > 100:
            print(f"ALERT: {ip} has {v.value} retransmissions!")
    b["retrans"].clear()
```

**bpftrace**:
```bash
#!/usr/bin/env bpftrace
#include <net/sock.h>

kprobe:tcp_retransmit_skb {
    $sk = (struct sock *)arg0;
    @retrans[ntop($sk->__sk_common.skc_daddr)] = count();
}

interval:s:1 {
    print(@retrans);
    clear(@retrans);
}
```

**Winner**: BCC (alerts require Python, bpftrace `system()` is hacky)

---

### Scenario 3: "Profile CPU usage for 30 seconds, generate flame graph"

**bpftrace** (recommended):
```bash
sudo bpftrace -e 'profile:hz:99 { @[kstack, ustack, comm] = count(); }' > out.txt
# Process out.txt into flame graph format
```

**BCC**:
```bash
sudo /usr/share/bcc/tools/profile -F 99 -f 30 > out.txt
```

**Winner**: Tie (both work well, BCC tool is ready-to-use)

---

## Feature Comparison Matrix

| Feature | bpftrace | BCC | libbpf (Level 03) |
|---------|----------|-----|-------------------|
| **Syntax complexity** | ★☆☆ | ★★☆ | ★★★ |
| **Startup time** | ★★★ | ★☆☆ | ★★★ |
| **String handling** | 64 char limit | Unlimited | Unlimited |
| **Loops** | Unroll only | Full C | Full C |
| **Python integration** | No | Yes | Manual |
| **Production ready** | Quick debug only | Yes | Best choice |
| **Portability** | Headers required | Headers required | CO-RE (no headers) |
| **Map management** | Automatic | Manual | Manual |
| **Dependencies** | Minimal | Python, LLVM | Minimal |
| **Package size** | ~5MB | ~50MB+ | ~1MB |

---

## Migration Path

### Start: bpftrace

Use for:
- Learning
- Quick investigations
- Prototyping

### Grow: BCC

Move to BCC when you need:
- Complex logic
- Python integration
- Reusable tools

### Scale: libbpf (Level 03)

Transition to libbpf when:
- Deploying to production at scale
- Need portability across kernel versions (CO-RE)
- Minimizing dependencies
- Performance critical

---

## Real-World Examples

### Example 1: Debugging Slow Database Queries

**Use**: bpftrace

```bash
# Quick check: are queries slow because of disk I/O?
sudo bpftrace -e 'tracepoint:block:block_rq_issue /comm == "mysqld"/ {
    @latency = hist(args->bytes);
}'
```

If you need more detail → BCC tool with query correlation.

---

### Example 2: Production Monitoring

**Use**: BCC (or libbpf)

- Needs to run 24/7
- Send metrics to Prometheus
- Alert on thresholds
- Handle restarts gracefully

---

### Example 3: "Why is this container slow?"

**Use**: bpftrace

```bash
# Quick CPU profile for specific cgroup
sudo bpftrace -e 'profile:hz:99 /cgroup == <id>/ { @[comm] = count(); }'
```

Fast answer, no need for complex tool.

---

## Summary Table

| Situation | Tool | Reason |
|-----------|------|--------|
| Quick debugging | bpftrace | Fast, minimal typing |
| Ad-hoc analysis | bpftrace | Iterative exploration |
| Learning eBPF | bpftrace | Simpler syntax |
| Complex logic | BCC | Full C capabilities |
| Python integration | BCC | Native support |
| Production monitoring | BCC/libbpf | Mature, stable |
| Reusable tools | BCC | Distribution, packaging |
| Kernel portability | libbpf | CO-RE support |
| Minimal dependencies | bpftrace/libbpf | Small footprint |

---

## The "Both" Approach

Often, the best strategy is:

1. **Prototype with bpftrace**: Validate idea, explore data
2. **Implement in BCC**: Add complex logic, Python processing
3. **Productionize with libbpf**: Port to CO-RE for deployment

---

## Next Steps

1. Try both tools for the same task (see examples in `../examples/`)
2. Compare development time and code complexity
3. Choose based on your specific needs
4. Remember: you can always switch tools as requirements evolve

When in doubt:
- **Debugging**: bpftrace
- **Production**: BCC or libbpf (Level 03)

---

## References

- [bpftrace Documentation](https://github.com/iovisor/bpftrace)
- [BCC Documentation](https://github.com/iovisor/bcc)
- [Choosing the Right Tool](https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html)
