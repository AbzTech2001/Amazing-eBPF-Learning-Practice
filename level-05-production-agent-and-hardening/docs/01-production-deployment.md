# Production eBPF Deployment Guide

## Overview

Deploying eBPF to production requires careful attention to **reliability, performance, security, and operations**. This guide covers production-ready patterns used by Cilium, Datadog, and other major eBPF deployments.

---

## Architecture Considerations

### Production Agent Architecture

```
┌─────────────────────────────────────────────────┐
│  Production eBPF Agent                          │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────────────────────────────────┐  │
│  │ Feature Detection                        │  │
│  │  - Kernel version check                  │  │
│  │  - BTF availability                      │  │
│  │  - Helper function support               │  │
│  │  - Program type support                  │  │
│  └──────────────┬───────────────────────────┘  │
│                 ↓                                │
│  ┌──────────────────────────────────────────┐  │
│  │ Configuration Management                  │  │
│  │  - YAML/JSON config                      │  │
│  │  - Environment variables                 │  │
│  │  - Feature flags                         │  │
│  │  - Runtime tuning                        │  │
│  └──────────────┬───────────────────────────┘  │
│                 ↓                                │
│  ┌──────────────────────────────────────────┐  │
│  │ eBPF Program Management                  │  │
│  │  - Load/unload programs                  │  │
│  │  - Attach/detach hooks                   │  │
│  │  - Graceful degradation                  │  │
│  └──────────────┬───────────────────────────┘  │
│                 ↓                                │
│  ┌──────────────────────────────────────────┐  │
│  │ Event Processing Pipeline                │  │
│  │  - Ring buffer polling                   │  │
│  │  - Aggregation                           │  │
│  │  - Filtering                             │  │
│  │  - Rate limiting                         │  │
│  └──────────────┬───────────────────────────┘  │
│                 ↓                                │
│  ┌──────────────────────────────────────────┐  │
│  │ Export & Telemetry                       │  │
│  │  - Metrics export                        │  │
│  │  - Logging                               │  │
│  │  - Health checks                         │  │
│  │  - Profiling                             │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Feature Detection

### Kernel Capability Detection

```go
package detector

import (
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/btf"
)

type Capabilities struct {
    KernelVersion   string
    HasBTF          bool
    HasRingBuf      bool
    HasKprobeMulti  bool
    HasLSM          bool
    HelperFunctions map[string]bool
}

func DetectCapabilities() (*Capabilities, error) {
    caps := &Capabilities{
        HelperFunctions: make(map[string]bool),
    }

    // Check kernel version
    caps.KernelVersion = getKernelVersion()

    // Check BTF support
    _, err := btf.LoadKernelSpec()
    caps.HasBTF = (err == nil)

    // Check ring buffer support (5.8+)
    caps.HasRingBuf = checkMapType(ebpf.RingBuf)

    // Check kprobe multi-attach (5.18+)
    caps.HasKprobeMulti = checkProgramType(ebpf.KprobeMulti)

    // Check LSM support (5.7+)
    caps.HasLSM = checkProgramType(ebpf.LSM)

    // Probe helper functions
    caps.HelperFunctions["bpf_get_current_comm"] = probeHelper("bpf_get_current_comm")
    caps.HelperFunctions["bpf_ringbuf_output"] = probeHelper("bpf_ringbuf_output")

    return caps, nil
}

func checkMapType(mt ebpf.MapType) bool {
    spec := &ebpf.MapSpec{
        Type:       mt,
        KeySize:    4,
        ValueSize:  4,
        MaxEntries: 1,
    }
    m, err := ebpf.NewMap(spec)
    if err != nil {
        return false
    }
    m.Close()
    return true
}
```

### Graceful Degradation

```go
func loadWithFallback(caps *Capabilities) error {
    if caps.HasRingBuf {
        return loadRingBufVersion()
    } else if checkKernelVersion(">= 4.18") {
        return loadPerfBufVersion()  // Fallback to perf buffer
    } else {
        return loadLegacyVersion()    // Oldest compatible version
    }
}
```

---

## Configuration Management

### Production Config Structure

```yaml
# config.yaml
agent:
  name: ebpf-agent
  log_level: info
  health_check_port: 8080

features:
  process_monitoring:
    enabled: true
    sample_rate: 100  # 1 in 100 events
  network_monitoring:
    enabled: true
    protocols: [tcp, udp]
  file_monitoring:
    enabled: false

kernel:
  auto_detect: true
  fallback_mode: warn  # warn, disable, fail
  btf_required: false

performance:
  ring_buffer_size: 262144  # 256KB
  poll_timeout_ms: 100
  max_events_per_poll: 1000
  cpu_limit_percent: 10

export:
  prometheus:
    enabled: true
    port: 9090
  otlp:
    enabled: false
    endpoint: "localhost:4317"

limits:
  max_tracked_processes: 10000
  max_tracked_connections: 50000
```

### Configuration Validation

```go
type Config struct {
    Agent       AgentConfig       `yaml:"agent"`
    Features    FeaturesConfig    `yaml:"features"`
    Performance PerformanceConfig `yaml:"performance"`
}

func (c *Config) Validate() error {
    if c.Performance.RingBufferSize < 4096 {
        return fmt.Errorf("ring_buffer_size too small: minimum 4096")
    }

    if c.Performance.CPULimitPercent > 50 {
        return fmt.Errorf("cpu_limit_percent too high: maximum 50")
    }

    return nil
}
```

---

## Reliability Patterns

### 1. Health Checks

```go
type HealthChecker struct {
    skel *MySkel
}

func (h *HealthChecker) Check() error {
    // Check programs are loaded
    if h.skel.progs.trace_exec == nil {
        return fmt.Errorf("program not loaded")
    }

    // Check programs are attached
    if h.skel.links.trace_exec == nil {
        return fmt.Errorf("program not attached")
    }

    // Check ring buffer is responsive
    if !h.checkRingBuffer() {
        return fmt.Errorf("ring buffer not responsive")
    }

    // Check map accessibility
    if !h.checkMaps() {
        return fmt.Errorf("maps not accessible")
    }

    return nil
}
```

### 2. Graceful Shutdown

```go
func runAgent(ctx context.Context) error {
    skel, err := LoadAndAttach()
    if err != nil {
        return err
    }
    defer skel.Destroy()

    // Set up ring buffer
    rb, err := ringbuf.NewReader(skel.maps.Events)
    if err != nil {
        return err
    }
    defer rb.Close()

    // Handle graceful shutdown
    shutdownCh := make(chan os.Signal, 1)
    signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

    for {
        select {
        case <-ctx.Done():
            log.Info("Context cancelled, shutting down")
            return ctx.Err()

        case <-shutdownCh:
            log.Info("Received shutdown signal")
            return nil

        default:
            // Process events with timeout
            err := rb.ReadWithTimeout(100 * time.Millisecond)
            if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
                log.Errorf("Read error: %v", err)
            }
        }
    }
}
```

### 3. Error Recovery

```go
func (a *Agent) runWithRecovery() {
    for {
        err := a.run()
        if err == nil {
            return  // Clean shutdown
        }

        log.Errorf("Agent error: %v", err)

        // Exponential backoff
        backoff := time.Second
        maxBackoff := time.Minute

        select {
        case <-time.After(backoff):
            backoff = min(backoff*2, maxBackoff)
            log.Info("Restarting agent...")
        case <-a.shutdownCh:
            return
        }
    }
}
```

---

## Performance Optimization

### 1. Ring Buffer Tuning

```c
// BPF side: Use appropriate ring buffer size
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // Tune based on event rate
} events SEC(".maps");
```

```go
// User-space: Batch processing
func processEvents(rb *ringbuf.Reader) {
    batch := make([]Event, 0, 1000)

    for len(batch) < cap(batch) {
        record, err := rb.Read()
        if err != nil {
            break
        }

        var event Event
        parseEvent(record.RawSample, &event)
        batch = append(batch, event)
    }

    // Process batch
    processBatch(batch)
}
```

### 2. CPU Pinning

```go
// Pin goroutines to specific CPUs
runtime.LockOSThread()
defer runtime.UnlockOSThread()
```

### 3. Memory Management

```go
// Use sync.Pool for frequently allocated objects
var eventPool = sync.Pool{
    New: func() interface{} {
        return &Event{}
    },
}

func getEvent() *Event {
    return eventPool.Get().(*Event)
}

func putEvent(e *Event) {
    eventPool.Put(e)
}
```

---

## Security Hardening

### 1. Capability Dropping

```go
import "github.com/syndtr/gocapability/capability"

func dropCapabilities() error {
    caps, err := capability.NewPid2(0)
    if err != nil {
        return err
    }

    // Keep only required capabilities
    caps.Clear(capability.CAPS)
    caps.Set(capability.CAPS, capability.CAP_BPF, capability.CAP_PERFMON)

    return caps.Apply(capability.CAPS)
}
```

### 2. Sandboxing

```dockerfile
# Run as non-root in container
FROM ubuntu:22.04
RUN groupadd -r ebpf && useradd -r -g ebpf ebpf

COPY --chmod=755 agent /usr/local/bin/agent

# Grant BPF capabilities
RUN setcap cap_bpf,cap_perfmon+ep /usr/local/bin/agent

USER ebpf
ENTRYPOINT ["/usr/local/bin/agent"]
```

### 3. Read-Only Root Filesystem

```yaml
# Kubernetes
apiVersion: v1
kind: Pod
spec:
  securityContext:
    readOnlyRootFilesystem: true
  volumes:
    - name: tmp
      emptyDir: {}
  volumeMounts:
    - name: tmp
      mountPath: /tmp
```

---

## Monitoring the Monitor

### Agent Self-Metrics

```go
var (
    eventsProcessed = promauto.NewCounter(prometheus.CounterOpts{
        Name: "agent_events_processed_total",
    })

    eventProcessingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
        Name: "agent_event_processing_seconds",
    })

    ringBufferDrops = promauto.NewCounter(prometheus.CounterOpts{
        Name: "agent_ringbuf_drops_total",
    })
)

func processEvent(event *Event) {
    start := time.Now()
    defer func() {
        eventProcessingDuration.Observe(time.Since(start).Seconds())
        eventsProcessed.Inc()
    }()

    // Process...
}
```

---

## CI/CD Integration

### Automated Testing

```yaml
# .github/workflows/test.yml
name: eBPF Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm libbpf-dev

      - name: Build BPF programs
        run: make bpf

      - name: Run verifier tests
        run: make test-verifier

      - name: Run integration tests
        run: sudo make test-integration
```

---

## Best Practices Summary

1. **Feature detection**: Always detect kernel capabilities
2. **Graceful degradation**: Fallback when features unavailable
3. **Configuration**: Externalize all tunables
4. **Health checks**: Monitor agent health continuously
5. **Error handling**: Retry with exponential backoff
6. **Resource limits**: Prevent resource exhaustion
7. **Security**: Drop unnecessary capabilities
8. **Monitoring**: Instrument the agent itself
9. **Testing**: Automated tests in CI/CD
10. **Documentation**: Runbooks for operations

---

## References

- [Cilium Production Best Practices](https://docs.cilium.io/en/stable/operations/)
- [Datadog eBPF](https://www.datadoghq.com/blog/engineering/introducing-ebpf-agent/)
- [eBPF Summit Talks](https://ebpf.io/summit-2023/)
