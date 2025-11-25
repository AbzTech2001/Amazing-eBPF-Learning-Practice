// Production eBPF Agent - Main Entry Point
//
// This is a production-grade eBPF observability and security agent
// that demonstrates real-world patterns used in Cilium, Tetragon, and Falco.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-agent/pkg/config"
	"ebpf-agent/pkg/modules"
	"ebpf-agent/pkg/observability"
	"ebpf-agent/pkg/health"
)

const (
	version = "1.0.0"
	banner  = `
╔═══════════════════════════════════════╗
║   Production eBPF Agent v%s       ║
║   Observability | Security | Network  ║
╚═══════════════════════════════════════╝
`
)

var (
	configPath  = flag.String("config", "/etc/ebpf-agent/config.yaml", "Configuration file path")
	showVersion = flag.Bool("version", false, "Show version and exit")
	debugMode   = flag.Bool("debug", false, "Enable debug logging")
	healthPort  = flag.Int("health-port", 8080, "Health check port")
)

type Agent struct {
	config  *config.Config
	modules map[string]modules.Module
	health  *health.Server
	metrics *observability.MetricsServer
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	ctx, cancel := context.WithCancel(context.Background())

	agent := &Agent{
		config:  cfg,
		modules: make(map[string]modules.Module),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Initialize health server
	var err error
	agent.health, err = health.NewServer(*healthPort)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create health server: %w", err)
	}

	// Initialize metrics server
	if cfg.Export.Prometheus.Enabled {
		agent.metrics, err = observability.NewMetricsServer(cfg.Export.Prometheus.Port)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create metrics server: %w", err)
		}
	}

	return agent, nil
}

func (a *Agent) LoadModules() error {
	log.Println("Loading eBPF modules...")

	// Observability module
	if a.config.Features.Observability.Enabled {
		log.Println("  [+] Loading observability module")
		obsModule, err := modules.NewObservabilityModule(a.ctx, a.config)
		if err != nil {
			return fmt.Errorf("failed to load observability module: %w", err)
		}
		a.modules["observability"] = obsModule
		a.health.RegisterCheck("observability", obsModule.HealthCheck)
	}

	// Security module
	if a.config.Features.Security.Enabled {
		log.Println("  [+] Loading security module")
		secModule, err := modules.NewSecurityModule(a.ctx, a.config)
		if err != nil {
			return fmt.Errorf("failed to load security module: %w", err)
		}
		a.modules["security"] = secModule
		a.health.RegisterCheck("security", secModule.HealthCheck)
	}

	// Networking module
	if a.config.Features.Networking.Enabled {
		log.Println("  [+] Loading networking module")
		netModule, err := modules.NewNetworkingModule(a.ctx, a.config)
		if err != nil {
			return fmt.Errorf("failed to load networking module: %w", err)
		}
		a.modules["networking"] = netModule
		a.health.RegisterCheck("networking", netModule.HealthCheck)
	}

	log.Printf("Loaded %d modules successfully\n", len(a.modules))
	return nil
}

func (a *Agent) Start() error {
	log.Println("Starting agent...")

	// Start health server
	if err := a.health.Start(); err != nil {
		return fmt.Errorf("failed to start health server: %w", err)
	}
	log.Printf("Health server listening on :%d", *healthPort)

	// Start metrics server
	if a.metrics != nil {
		if err := a.metrics.Start(); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		log.Printf("Metrics server listening on :%d", a.config.Export.Prometheus.Port)
	}

	// Start all modules
	for name, module := range a.modules {
		log.Printf("Starting module: %s", name)
		if err := module.Start(); err != nil {
			return fmt.Errorf("failed to start module %s: %w", name, err)
		}
	}

	log.Println("Agent started successfully")
	return nil
}

func (a *Agent) Stop() error {
	log.Println("Stopping agent...")

	// Stop all modules
	for name, module := range a.modules {
		log.Printf("Stopping module: %s", name)
		if err := module.Stop(); err != nil {
			log.Printf("Error stopping module %s: %v", name, err)
		}
	}

	// Stop servers
	if a.health != nil {
		a.health.Stop()
	}
	if a.metrics != nil {
		a.metrics.Stop()
	}

	a.cancel()
	log.Println("Agent stopped")
	return nil
}

func (a *Agent) Run() error {
	// Start the agent
	if err := a.Start(); err != nil {
		return err
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	select {
	case sig := <-sigCh:
		log.Printf("Received signal: %v", sig)
	case <-a.ctx.Done():
		log.Println("Context cancelled")
	}

	return a.Stop()
}

func checkPrerequisites() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must run as root")
	}

	// Check if BPF filesystem is mounted
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}

	// Check kernel version (basic check)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		log.Println("WARNING: BTF not available, CO-RE may not work")
	}

	return nil
}

func main() {
	flag.Parse()

	// Print banner
	fmt.Printf(banner, version)

	// Version flag
	if *showVersion {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}

	// Set up logging
	if *debugMode {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}

	// Check prerequisites
	log.Println("Checking prerequisites...")
	if err := checkPrerequisites(); err != nil {
		log.Fatalf("Prerequisites check failed: %v", err)
	}

	// Load configuration
	log.Printf("Loading configuration from: %s", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if *debugMode {
		cfg.Agent.LogLevel = "debug"
	}

	log.Printf("Configuration loaded: log_level=%s, features=%v",
		cfg.Agent.LogLevel,
		[]string{
			fmt.Sprintf("observability=%v", cfg.Features.Observability.Enabled),
			fmt.Sprintf("security=%v", cfg.Features.Security.Enabled),
			fmt.Sprintf("networking=%v", cfg.Features.Networking.Enabled),
		})

	// Create agent
	agent, err := NewAgent(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Load modules
	if err := agent.LoadModules(); err != nil {
		log.Fatalf("Failed to load modules: %v", err)
	}

	// Run agent
	log.Println("Starting agent... (Press Ctrl+C to stop)")
	if err := agent.Run(); err != nil {
		log.Fatalf("Agent error: %v", err)
	}

	log.Println("Agent exited cleanly")
}

/*
 * Production Patterns Demonstrated:
 *
 * 1. Graceful Shutdown:
 *    - Signal handling (SIGINT, SIGTERM)
 *    - Context cancellation propagation
 *    - Ordered cleanup of resources
 *
 * 2. Module System:
 *    - Pluggable architecture
 *    - Independent module lifecycle
 *    - Feature flags for enabling/disabling
 *
 * 3. Observability:
 *    - Health checks for all modules
 *    - Prometheus metrics export
 *    - Structured logging
 *
 * 4. Configuration Management:
 *    - External YAML configuration
 *    - Runtime parameter override
 *    - Validation on load
 *
 * 5. Error Handling:
 *    - Proper error wrapping
 *    - Graceful degradation
 *    - Detailed error messages
 *
 * 6. Prerequisites Check:
 *    - Root privilege verification
 *    - BPF filesystem mounted
 *    - Kernel feature detection
 *
 * Build:
 *   go build -o ebpf-agent main.go
 *
 * Run:
 *   sudo ./ebpf-agent -config config.yaml
 *
 * Similar to:
 *   - Tetragon agent architecture
 *   - Falco driver loader
 *   - Cilium agent structure
 */
