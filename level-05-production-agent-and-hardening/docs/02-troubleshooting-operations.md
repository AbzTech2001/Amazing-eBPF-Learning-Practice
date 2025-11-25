# eBPF Troubleshooting & Operations Guide

## Overview

This guide covers common production issues with eBPF agents and how to diagnose and resolve them.

---

## Quick Diagnostics Checklist

```bash
# 1. Check kernel version
uname -r

# 2. Check BTF availability
ls -la /sys/kernel/btf/vmlinux

# 3. Check loaded BPF programs
sudo bpftool prog list

# 4. Check BPF maps
sudo bpftool map list

# 5. Check for errors in dmesg
sudo dmesg | grep -i bpf

# 6. Check agent logs
journalctl -u ebpf-agent -f

# 7. Check resource usage
top -p $(pgrep ebpf-agent)

# 8. Check for dropped events
sudo bpftool map dump name events | grep -i drop
```

---

## Common Issues

### Issue 1: Program Fails to Load

**Symptoms:**
```
libbpf: failed to load program: Permission denied
libbpf: -- BEGIN PROG LOAD LOG --
libbpf: verifier error...
```

**Diagnosis:**
```bash
# Check capabilities
getcap /usr/bin/ebpf-agent

# Try loading manually with verbose logs
sudo bpftool prog load program.bpf.o /sys/fs/bpf/test \
    type kprobe \
    log_level 2 \
    log_file /tmp/verifier.log
```

**Common Causes:**

1. **Missing Capabilities**
   ```bash
   # Fix: Add CAP_BPF and CAP_PERFMON
   sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/ebpf-agent
   ```

2. **Verifier Rejection**
   ```
   # Check verifier log
   cat /tmp/verifier.log

   # Common fixes:
   - Add NULL checks after map lookups
   - Add bounds checks for array access
   - Reduce stack usage (< 512 bytes)
   - Unroll loops with #pragma unroll
   ```

3. **Kernel Too Old**
   ```bash
   # Check minimum kernel version
   uname -r  # Should be 5.2+ for CO-RE, 4.18+ for basic BPF
   ```

---

### Issue 2: High CPU Usage

**Symptoms:**
- Agent consuming >10% CPU
- System slowdown

**Diagnosis:**
```bash
# Profile the agent
sudo perf record -p $(pgrep ebpf-agent) -g -- sleep 10
sudo perf report

# Check event rate
sudo bpftool map dump name events | wc -l

# Check if eBPF programs are hot
sudo bpftool prog profile name my_program duration 10
```

**Common Causes:**

1. **Too Many Events**
   ```c
   // Fix: Add sampling
   if (bpf_get_prandom_u32() % 100 != 0)
       return 0;  // Sample 1 in 100
   ```

2. **Inefficient Processing**
   ```go
   // Fix: Batch events
   for i := 0; i < 1000; i++ {
       event, err := rb.Read()
       if err != nil {
           break
       }
       batch = append(batch, event)
   }
   processBatch(batch)
   ```

3. **Busy Polling**
   ```go
   // Fix: Use timeout
   rb.SetDeadline(time.Now().Add(100 * time.Millisecond))
   ```

---

### Issue 3: Events Being Dropped

**Symptoms:**
```
ringbuf: dropped events: 12345
```

**Diagnosis:**
```bash
# Check ring buffer stats
sudo bpftool map dump name events

# Monitor in real-time
watch -n 1 'sudo bpftool map dump name events | tail -5'
```

**Solutions:**

1. **Increase Ring Buffer Size**
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_RINGBUF);
       __uint(max_entries, 1024 * 1024);  // 1MB instead of 256KB
   } events SEC(".maps");
   ```

2. **Process Events Faster**
   ```go
   // Increase poll frequency
   rb.Poll(10 * time.Millisecond)  // Instead of 100ms
   ```

3. **Add Backpressure**
   ```c
   // Use BPF_RB_NO_WAKEUP and BPF_RB_FORCE_WAKEUP strategically
   e = bpf_ringbuf_reserve(&events, sizeof(*e), BPF_RB_NO_WAKEUP);
   ```

---

### Issue 4: Memory Leak

**Symptoms:**
- Agent RSS grows over time
- OOM kills

**Diagnosis:**
```bash
# Monitor memory
watch -n 1 'ps aux | grep ebpf-agent'

# Use pprof (if instrumented)
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Check BPF map sizes
sudo bpftool map dump name process_cache | wc -l
```

**Common Causes:**

1. **Unbounded Maps**
   ```c
   // Fix: Use LRU maps
   struct {
       __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Auto-evicts old entries
       __uint(max_entries, 10000);
       __type(key, __u32);
       __type(value, struct data);
   } cache SEC(".maps");
   ```

2. **Not Cleaning Up**
   ```go
   // Fix: Periodic cleanup
   go func() {
       ticker := time.NewTicker(5 * time.Minute)
       for range ticker.C {
           cleanupOldEntries(skel.maps.Cache)
       }
   }()
   ```

---

### Issue 5: Kernel Upgrade Breaks Agent

**Symptoms:**
- Agent worked on kernel 5.10, fails on 5.15
- `libbpf: CO-RE relocation failed`

**Diagnosis:**
```bash
# Check what changed
diff <(cat /boot/config-5.10) <(cat /boot/config-5.15) | grep BPF

# Check specific struct
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'task_struct'"
```

**Solutions:**

1. **Use Field Existence Checks**
   ```c
   if (bpf_core_field_exists(struct task_struct, new_field)) {
       // Use new field
   } else {
       // Fallback for older kernels
   }
   ```

2. **Test on Multiple Kernels**
   ```yaml
   # CI matrix testing
   strategy:
     matrix:
       kernel: [5.4, 5.10, 5.15, 6.1]
   ```

---

### Issue 6: Permission Denied in Kubernetes

**Symptoms:**
```
Error: failed to load program: operation not permitted
```

**Diagnosis:**
```bash
# Check pod security context
kubectl get pod ebpf-agent -o yaml | grep -A 10 securityContext

# Check node kernel
kubectl debug node/worker-1 -it --image=ubuntu -- uname -r
```

**Solutions:**

1. **Add Capabilities**
   ```yaml
   securityContext:
     capabilities:
       add:
         - SYS_ADMIN  # Or CAP_BPF + CAP_PERFMON on 5.8+
         - SYS_RESOURCE
         - NET_ADMIN
   ```

2. **Use Privileged Mode** (last resort)
   ```yaml
   securityContext:
     privileged: true
   ```

3. **Host PID Namespace**
   ```yaml
   spec:
     hostPID: true
     hostNetwork: true
   ```

---

## Performance Tuning

### Reduce Overhead

```c
// 1. Use per-CPU maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    // No lock contention
} stats SEC(".maps");

// 2. Minimize data collection
SEC("kprobe/sys_read")
int trace_read(struct pt_regs *ctx)
{
    // Collect only what you need
    if (filter_out_event())
        return 0;

    // Minimal data structure
    struct event e = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .timestamp = bpf_ktime_get_ns(),
    };

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

// 3. Use tail calls for complex logic
bpf_tail_call(ctx, &prog_array, next_prog_index);
```

---

## Monitoring Best Practices

### Agent Health Metrics

```go
var (
    // Program health
    programLoaded = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{Name: "bpf_program_loaded"},
        []string{"program"},
    )

    // Event metrics
    eventsReceived = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "bpf_events_received_total"},
        []string{"type"},
    )

    eventsDropped = prometheus.NewCounter(
        prometheus.CounterOpts{Name: "bpf_events_dropped_total"},
    )

    // Performance metrics
    eventProcessingLatency = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "bpf_event_processing_seconds",
            Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
        },
    )

    // Resource metrics
    mapSize = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{Name: "bpf_map_entries"},
        []string{"map"},
    )
)
```

### Alerting Rules

```yaml
# prometheus-rules.yaml
groups:
  - name: ebpf-agent
    rules:
      - alert: eBPFAgentDown
        expr: up{job="ebpf-agent"} == 0
        for: 1m
        annotations:
          summary: "eBPF agent is down"

      - alert: eBPFHighEventDropRate
        expr: rate(bpf_events_dropped_total[5m]) > 100
        for: 5m
        annotations:
          summary: "High event drop rate: {{ $value }}/s"

      - alert: eBPFMapNearFull
        expr: bpf_map_entries / bpf_map_max_entries > 0.9
        for: 5m
        annotations:
          summary: "BPF map {{ $labels.map }} is {{ $value }}% full"
```

---

## Debugging Tools

### 1. bpftool

```bash
# List programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id 123

# Dump program instructions
sudo bpftool prog dump xlated id 123

# Dump program with JIT
sudo bpftool prog dump jited id 123

# Show maps
sudo bpftool map list

# Dump map contents
sudo bpftool map dump id 456

# Pin program (survive agent restart)
sudo bpftool prog pin id 123 /sys/fs/bpf/my_prog
```

### 2. perf

```bash
# Trace BPF program execution
sudo perf record -e bpf:bpf_prog_load -a
sudo perf script

# Profile BPF overhead
sudo perf stat -e cycles,instructions -p $(pgrep ebpf-agent)
```

### 3. Custom Debugging

```c
// Add debug logs (visible in /sys/kernel/debug/tracing/trace_pipe)
bpf_printk("Debug: pid=%d value=%llu\n", pid, value);
```

```bash
# View debug logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## Runbook Examples

### Runbook: High CPU Usage

1. Check current CPU usage: `top -p $(pgrep ebpf-agent)`
2. Profile: `sudo perf record -p $(pgrep ebpf-agent) -g -- sleep 10`
3. Check event rate: `sudo bpftool map dump name events | wc -l`
4. If event rate >100k/s: Enable sampling in BPF program
5. If user-space processing slow: Batch events
6. If nothing helps: Reduce monitored processes/connections

### Runbook: Events Dropped

1. Check drop count: `sudo bpftool map dump name events`
2. Increase ring buffer size (requires reload)
3. Increase poll frequency
4. Add more processing workers
5. If still dropping: Add event filtering in BPF

---

## Best Practices

1. **Always log errors** with context
2. **Export metrics** about agent health
3. **Set resource limits** (CPU, memory)
4. **Test on target kernel** before deploying
5. **Use feature flags** for gradual rollout
6. **Document runbooks** for common issues
7. **Monitor the monitor** - watch agent metrics
8. **Plan for failure** - graceful degradation

---

## References

- [bpftool Documentation](https://www.mankier.com/8/bpftool)
- [Cilium Troubleshooting](https://docs.cilium.io/en/stable/operations/troubleshooting/)
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html)
