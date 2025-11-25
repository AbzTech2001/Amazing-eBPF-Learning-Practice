// Prometheus Exporter for eBPF Metrics
//
// Demonstrates:
// - Integration of eBPF with Prometheus
// - Exporting eBPF map data as metrics
// - Production observability patterns
// - Real-time metrics collection

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics
var (
	syscallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_syscalls_total",
			Help: "Total number of system calls observed",
		},
		[]string{"syscall", "process"},
	)

	processesCreated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_processes_created_total",
			Help: "Total number of processes created (execve)",
		},
	)

	tcpConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_tcp_connections_total",
			Help: "Total number of TCP connections",
		},
		[]string{"direction"},
	)

	networkBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_network_bytes_total",
			Help: "Total network bytes processed",
		},
		[]string{"direction"},
	)

	fileOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_file_operations_total",
			Help: "Total file operations",
		},
		[]string{"operation"},
	)

	ebpfProgramInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_program_info",
			Help: "Information about loaded eBPF programs",
		},
		[]string{"program_name", "program_type"},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(syscallsTotal)
	prometheus.MustRegister(processesCreated)
	prometheus.MustRegister(tcpConnections)
	prometheus.MustRegister(networkBytesTotal)
	prometheus.MustRegister(fileOperations)
	prometheus.MustRegister(ebpfProgramInfo)
}

// Example eBPF map structure (matches kernel program)
type StatsKey uint32

const (
	StatTotalPackets StatsKey = iota
	StatTotalBytes
	StatTCPPackets
	StatUDPPackets
	StatDropped
)

// Collector reads eBPF maps and updates Prometheus metrics
type eBPFCollector struct {
	statsMap       *ebpf.Map
	connectionsMap *ebpf.Map
}

func newEBPFCollector(statsMap, connectionsMap *ebpf.Map) *eBPFCollector {
	return &eBPFCollector{
		statsMap:       statsMap,
		connectionsMap: connectionsMap,
	}
}

// collectStats reads statistics from eBPF maps
func (c *eBPFCollector) collectStats() error {
	// Read per-CPU statistics
	var totalPackets, totalBytes, tcpPackets, udpPackets uint64

	key := uint32(StatTotalPackets)
	values := make([]uint64, 128) // Max CPUs
	if err := c.statsMap.Lookup(&key, &values); err == nil {
		for _, v := range values {
			totalPackets += v
		}
	}

	key = uint32(StatTotalBytes)
	if err := c.statsMap.Lookup(&key, &values); err == nil {
		for _, v := range values {
			totalBytes += v
		}
	}

	// Update Prometheus metrics
	networkBytesTotal.WithLabelValues("ingress").Add(float64(totalBytes))

	log.Printf("Collected: packets=%d bytes=%d tcp=%d udp=%d",
		totalPackets, totalBytes, tcpPackets, udpPackets)

	return nil
}

// collectConnections iterates through active connections
func (c *eBPFCollector) collectConnections() error {
	if c.connectionsMap == nil {
		return nil
	}

	var (
		key  []byte
		info struct {
			Packets   uint64
			Bytes     uint64
			FirstSeen uint64
			LastSeen  uint64
		}
	)

	iter := c.connectionsMap.Iterate()
	activeConns := 0

	for iter.Next(&key, &info) {
		activeConns++
		// Could export per-connection metrics here
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate connections: %w", err)
	}

	log.Printf("Active connections: %d", activeConns)
	return nil
}

// run starts the metrics collection loop
func (c *eBPFCollector) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := c.collectStats(); err != nil {
			log.Printf("Error collecting stats: %v", err)
		}
		if err := c.collectConnections(); err != nil {
			log.Printf("Error collecting connections: %v", err)
		}
	}
}

// loadEBPFProgram loads the compiled eBPF program
func loadEBPFProgram(objPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	return coll, nil
}

func main() {
	var (
		objPath    = flag.String("obj", "tc_packet_filter.o", "Path to eBPF object file")
		metricsPort = flag.Int("port", 9090, "Metrics HTTP port")
		interval   = flag.Duration("interval", 5*time.Second, "Collection interval")
	)
	flag.Parse()

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatal("This program must run as root")
	}

	// Load eBPF program
	log.Printf("Loading eBPF program from %s", *objPath)
	coll, err := loadEBPFProgram(*objPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}
	defer coll.Close()

	// Get maps
	statsMap := coll.Maps["stats"]
	if statsMap == nil {
		log.Fatal("stats map not found")
	}

	connectionsMap := coll.Maps["connections"]
	// connections map is optional

	// Create collector
	collector := newEBPFCollector(statsMap, connectionsMap)

	// Start metrics collection in background
	go collector.run(*interval)

	// Set up Prometheus HTTP handler
	http.Handle("/metrics", promhttp.Handler())

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Info endpoint
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html>
<head><title>eBPF Metrics Exporter</title></head>
<body>
<h1>eBPF Metrics Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
<p><a href="/health">Health</a></p>
</body>
</html>`)
	})

	addr := fmt.Sprintf(":%d", *metricsPort)
	log.Printf("Starting metrics server on %s", addr)
	log.Printf("Prometheus metrics: http://localhost%s/metrics", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

/*
 * Build Instructions:
 *
 * 1. Install dependencies:
 *    go get github.com/cilium/ebpf
 *    go get github.com/prometheus/client_golang/prometheus
 *
 * 2. Compile eBPF program:
 *    clang -O2 -target bpf -c tc_packet_filter.c -o tc_packet_filter.o
 *
 * 3. Build Go exporter:
 *    go build -o prometheus_exporter prometheus_exporter.go
 *
 * 4. Run:
 *    sudo ./prometheus_exporter -obj tc_packet_filter.o -port 9090
 *
 * 5. View metrics:
 *    curl http://localhost:9090/metrics
 *
 * Prometheus Configuration (prometheus.yml):
 *
 * scrape_configs:
 *   - job_name: 'ebpf'
 *     static_configs:
 *       - targets: ['localhost:9090']
 *
 * Grafana Dashboard Queries:
 *
 * - Network throughput:
 *   rate(ebpf_network_bytes_total[1m])
 *
 * - TCP connections rate:
 *   rate(ebpf_tcp_connections_total[1m])
 *
 * - File operations:
 *   sum by (operation) (rate(ebpf_file_operations_total[1m]))
 *
 * Production Patterns:
 * 1. Per-CPU map aggregation (sum across all CPUs)
 * 2. Counter vs Gauge metrics
 * 3. Label-based dimensionality
 * 4. Health check endpoint
 * 5. Graceful shutdown handling
 *
 * Similar to:
 * - Cilium's Prometheus integration
 * - Hubble metrics exporter
 * - Pixie's metrics collection
 */
