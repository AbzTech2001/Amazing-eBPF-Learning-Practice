package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Agent metrics
	AgentInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_agent_info",
			Help: "Agent version and configuration info",
		},
		[]string{"version", "hostname"},
	)

	ModulesLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_modules_loaded",
			Help: "Number of eBPF modules loaded",
		},
	)

	ProgramsAttached = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_programs_attached",
			Help: "Number of eBPF programs attached",
		},
		[]string{"module", "type"},
	)

	// Event metrics
	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_events_processed_total",
			Help: "Total number of eBPF events processed",
		},
		[]string{"module", "type"},
	)

	EventsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_events_dropped_total",
			Help: "Total number of eBPF events dropped",
		},
		[]string{"module", "reason"},
	)

	EventProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_event_processing_duration_seconds",
			Help:    "Duration of event processing",
			Buckets: prometheus.ExponentialBuckets(0.00001, 2, 15), // 10µs to 163ms
		},
		[]string{"module"},
	)

	// Map metrics
	MapSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_size_bytes",
			Help: "Current size of eBPF maps",
		},
		[]string{"map_name"},
	)

	MapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_map_entries",
			Help: "Number of entries in eBPF maps",
		},
		[]string{"map_name"},
	)

	// Performance metrics
	CPUUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_cpu_usage_percent",
			Help: "CPU usage by module",
		},
		[]string{"module"},
	)

	MemoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_memory_usage_bytes",
			Help: "Memory usage by module",
		},
		[]string{"module"},
	)

	// Security metrics
	SecurityViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_security_violations_total",
			Help: "Total number of security policy violations",
		},
		[]string{"policy", "action"},
	)

	// Network metrics
	NetworkPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_network_packets_total",
			Help: "Total network packets processed",
		},
		[]string{"direction", "action"},
	)

	NetworkBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_network_bytes_total",
			Help: "Total network bytes processed",
		},
		[]string{"direction"},
	)

	TCPConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_tcp_connections_total",
			Help: "Total TCP connections observed",
		},
		[]string{"state"},
	)
)

func init() {
	// Register all metrics
	prometheus.MustRegister(AgentInfo)
	prometheus.MustRegister(ModulesLoaded)
	prometheus.MustRegister(ProgramsAttached)
	prometheus.MustRegister(EventsProcessed)
	prometheus.MustRegister(EventsDropped)
	prometheus.MustRegister(EventProcessingDuration)
	prometheus.MustRegister(MapSize)
	prometheus.MustRegister(MapEntries)
	prometheus.MustRegister(CPUUsage)
	prometheus.MustRegister(MemoryUsage)
	prometheus.MustRegister(SecurityViolations)
	prometheus.MustRegister(NetworkPackets)
	prometheus.MustRegister(NetworkBytes)
	prometheus.MustRegister(TCPConnections)
}

// MetricsServer serves Prometheus metrics
type MetricsServer struct {
	port   int
	server *http.Server
}

func NewMetricsServer(port int) (*MetricsServer, error) {
	return &MetricsServer{
		port: port,
	}, nil
}

func (m *MetricsServer) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", m.port),
		Handler: mux,
	}

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()

	return nil
}

func (m *MetricsServer) Stop() error {
	if m.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.server.Shutdown(ctx)
}

/*
 * Metric Types:
 *
 * 1. Counter - Monotonically increasing value
 *    - events_processed_total
 *    - events_dropped_total
 *    - security_violations_total
 *
 * 2. Gauge - Value that can go up or down
 *    - modules_loaded
 *    - map_entries
 *    - cpu_usage_percent
 *
 * 3. Histogram - Distribution of values
 *    - event_processing_duration_seconds
 *    - Used for percentiles (p50, p95, p99)
 *
 * Prometheus Queries:
 *
 * Event rate:
 *   rate(ebpf_events_processed_total[5m])
 *
 * Drop rate:
 *   rate(ebpf_events_dropped_total[5m]) / rate(ebpf_events_processed_total[5m])
 *
 * P99 latency:
 *   histogram_quantile(0.99, rate(ebpf_event_processing_duration_seconds_bucket[5m]))
 *
 * Memory usage:
 *   sum by (module) (ebpf_memory_usage_bytes)
 *
 * Grafana Dashboards:
 * - Overview: modules loaded, event rate, error rate
 * - Performance: CPU, memory, latency
 * - Security: violations by policy, action taken
 * - Network: throughput, connections, drops
 */
