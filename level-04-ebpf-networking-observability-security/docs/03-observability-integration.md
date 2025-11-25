# eBPF Observability Integration

## Overview

Integrating eBPF with observability stacks (Prometheus, Grafana, OpenTelemetry) enables production-grade monitoring and distributed tracing.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Kernel Space                                   │
│  ┌──────────────────────────────────────────┐  │
│  │ eBPF Programs                            │  │
│  │  - Trace syscalls, network, etc.         │  │
│  │  - Aggregate metrics                     │  │
│  │  - Output to ring buffer/maps            │  │
│  └──────────────┬───────────────────────────┘  │
└─────────────────┼───────────────────────────────┘
                  │
┌─────────────────┼───────────────────────────────┐
│  User Space     ↓                               │
│  ┌──────────────────────────────────────────┐  │
│  │ eBPF Exporter                            │  │
│  │  - Reads ring buffers/maps               │  │
│  │  - Converts to metrics                   │  │
│  │  - Exports to backend                    │  │
│  └──────────────┬───────────────────────────┘  │
└─────────────────┼───────────────────────────────┘
                  │
        ┌─────────┼─────────┬─────────────┐
        ↓         ↓         ↓             ↓
  ┌──────────┐ ┌─────┐ ┌────────┐  ┌──────────┐
  │Prometheus│ │ OTel │ │ Jaeger │  │ Custom   │
  │          │ │      │ │        │  │ Backend  │
  └────┬─────┘ └──────┘ └────────┘  └──────────┘
       │
  ┌────┴─────┐
  │ Grafana  │
  │Dashboard │
  └──────────┘
```

---

## Prometheus Integration

### eBPF Metrics Collector

```c
// BPF side: Collect HTTP request metrics
struct http_metric {
    __u64 request_count;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 latency_sum;  // Microseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // PID
    __type(value, struct http_metric);
} http_stats SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int trace_http(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct http_metric *metric = bpf_map_lookup_elem(&http_stats, &pid);
    if (!metric) {
        struct http_metric new_metric = {0};
        bpf_map_update_elem(&http_stats, &pid, &new_metric, BPF_ANY);
        metric = bpf_map_lookup_elem(&http_stats, &pid);
        if (!metric)
            return 0;
    }

    __sync_fetch_and_add(&metric->request_count, 1);
    // ... collect other metrics

    return 0;
}
```

### User-Space Prometheus Exporter

```c
#include <stdio.h>
#include <microhttpd.h>
#include "http_monitor.skel.h"

#define PORT 9101

static int answer_to_connection(void *cls, struct MHD_Connection *conn,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls)
{
    struct http_monitor_bpf *skel = cls;
    char response[8192];
    int len = 0;

    // Prometheus exposition format
    len += snprintf(response + len, sizeof(response) - len,
                    "# HELP http_requests_total Total HTTP requests\n"
                    "# TYPE http_requests_total counter\n");

    // Iterate over map
    __u32 pid = 0, next_pid;
    struct http_metric metric;

    while (bpf_map_get_next_key(bpf_map__fd(skel->maps.http_stats),
                                &pid, &next_pid) == 0) {
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.http_stats),
                                &next_pid, &metric) == 0) {
            len += snprintf(response + len, sizeof(response) - len,
                          "http_requests_total{pid=\"%u\"} %llu\n",
                          next_pid, metric.request_count);
        }
        pid = next_pid;
    }

    struct MHD_Response *mhd_response =
        MHD_create_response_from_buffer(len, response, MHD_RESPMEM_MUST_COPY);
    int ret = MHD_queue_response(conn, MHD_HTTP_OK, mhd_response);
    MHD_destroy_response(mhd_response);

    return ret;
}

int main(void)
{
    struct http_monitor_bpf *skel = http_monitor_bpf__open_and_load();
    http_monitor_bpf__attach(skel);

    // Start HTTP server for Prometheus scraping
    struct MHD_Daemon *daemon =
        MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                        &answer_to_connection, skel, MHD_OPTION_END);

    printf("Prometheus exporter listening on :9101/metrics\n");
    getchar();  // Wait for Ctrl+C

    MHD_stop_daemon(daemon);
    http_monitor_bpf__destroy(skel);
    return 0;
}
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ebpf-exporter'
    static_configs:
      - targets: ['localhost:9101']
    scrape_interval: 15s
```

---

## OpenTelemetry Integration

### Span Creation from eBPF

```c
// BPF side: Capture trace context
struct span_event {
    __u64 timestamp;
    __u64 duration;
    __u32 pid;
    __u32 tid;
    char operation[32];
    char trace_id[16];
    char span_id[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} spans SEC(".maps");

SEC("kprobe/http_handler")
int trace_http_span(struct pt_regs *ctx)
{
    struct span_event *e = bpf_ringbuf_reserve(&spans, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->operation, sizeof(e->operation));

    // Extract trace context from HTTP headers (simplified)
    // In reality, parse from actual HTTP request

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### User-Space OTel Exporter

```go
package main

import (
    "context"
    "github.com/cilium/ebpf/ringbuf"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
    // Set up OTel exporter
    exp, _ := otlptracegrpc.New(context.Background())
    tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
    otel.SetTracerProvider(tp)

    tracer := tp.Tracer("ebpf-tracer")

    // Read eBPF events
    rd, _ := ringbuf.NewReader(bpfMap)
    defer rd.Close()

    for {
        record, err := rd.Read()
        if err != nil {
            continue
        }

        var event SpanEvent
        parseEvent(record.RawSample, &event)

        // Create OTel span
        ctx, span := tracer.Start(context.Background(), event.Operation)
        span.SetAttributes(
            attribute.Int("pid", int(event.PID)),
            attribute.String("trace_id", event.TraceID),
        )
        span.End()
    }
}
```

---

## Grafana Dashboard

### Query Prometheus Metrics

```promql
# HTTP request rate
rate(http_requests_total[5m])

# P95 latency
histogram_quantile(0.95, rate(http_latency_bucket[5m]))

# Error rate
rate(http_errors_total[5m]) / rate(http_requests_total[5m])
```

### Dashboard JSON (simplified)

```json
{
  "dashboard": {
    "title": "eBPF HTTP Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{
          "expr": "rate(http_requests_total[5m])"
        }],
        "type": "graph"
      },
      {
        "title": "Latency P95",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(http_latency_bucket[5m]))"
        }],
        "type": "graph"
      }
    ]
  }
}
```

---

## Best Practices

### 1. Use Per-CPU Maps for Counters

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");
```

### 2. Pre-Aggregate in BPF

```c
// Don't send every event - aggregate first
__u64 *count = bpf_map_lookup_elem(&stats, &key);
if (count)
    __sync_fetch_and_add(count, 1);
```

### 3. Use Histograms for Latency

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64[10]);  // Latency buckets
} latency_histogram SEC(".maps");
```

### 4. Sample High-Frequency Events

```c
// Sample 1 in 100 events
if (bpf_get_prandom_u32() % 100 != 0)
    return 0;
```

---

## Production Patterns

### Multi-Tenant Metrics

```c
struct metric_key {
    __u32 tenant_id;
    char metric_name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct metric_key);
    __type(value, __u64);
} tenant_metrics SEC(".maps");
```

### Cardinality Control

```c
// Limit unique metric combinations
#define MAX_UNIQUE_KEYS 10000

if (bpf_map_get_num_keys(&metrics) >= MAX_UNIQUE_KEYS) {
    // Drop or aggregate
    return 0;
}
```

---

## References

- [Prometheus Exposition Format](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [OpenTelemetry eBPF](https://opentelemetry.io/docs/specs/otel/trace/sdk_exporters/ebpf/)
- [Pixie (Kubernetes Observability)](https://px.dev/)
- [Parca (Continuous Profiling)](https://www.parca.dev/)
