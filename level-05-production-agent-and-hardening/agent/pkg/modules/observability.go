package modules

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"ebpf-agent/pkg/config"
)

// ObservabilityModule handles process, file, and syscall tracing
type ObservabilityModule struct {
	*BaseModule
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	stopCh     chan struct{}
}

// ProcessEvent represents a process execution event
type ProcessEvent struct {
	PID     uint32
	PPID    uint32
	UID     uint32
	GID     uint32
	Comm    [16]byte
	Filename [256]byte
}

func NewObservabilityModule(ctx context.Context, cfg *config.Config) (Module, error) {
	base := NewBaseModule(ctx, "observability", cfg)

	module := &ObservabilityModule{
		BaseModule: base,
		links:      make([]link.Link, 0),
		stopCh:     make(chan struct{}),
	}

	// Load eBPF programs
	if err := module.loadPrograms(); err != nil {
		return nil, err
	}

	return module, nil
}

func (m *ObservabilityModule) loadPrograms() error {
	// In production, you would load compiled eBPF object file
	// For this example, we'll outline the structure

	spec, err := ebpf.LoadCollectionSpec("bpf/observability.o")
	if err != nil {
		// Graceful degradation: if eBPF programs not found, log warning
		log.Printf("WARNING: Failed to load observability eBPF programs: %v", err)
		log.Println("Module will run in degraded mode")
		return nil
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	m.collection = coll
	return nil
}

func (m *ObservabilityModule) Start() error {
	if m.collection == nil {
		log.Println("Observability module: no eBPF programs loaded, running in degraded mode")
		return nil
	}

	// Attach to execve tracepoint
	prog := m.collection.Programs["handle_execve"]
	if prog != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			return fmt.Errorf("attach execve tracepoint: %w", err)
		}
		m.links = append(m.links, l)
		log.Println("  Attached to execve tracepoint")
	}

	// Open ring buffer for events
	eventsMap := m.collection.Maps["events"]
	if eventsMap != nil {
		reader, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			return fmt.Errorf("open ringbuf: %w", err)
		}
		m.reader = reader

		// Start event processing goroutine
		go m.processEvents()
		log.Println("  Started event processing")
	}

	return nil
}

func (m *ObservabilityModule) Stop() error {
	close(m.stopCh)

	// Close ring buffer reader
	if m.reader != nil {
		m.reader.Close()
	}

	// Detach all programs
	for _, l := range m.links {
		l.Close()
	}

	// Close collection
	if m.collection != nil {
		m.collection.Close()
	}

	return nil
}

func (m *ObservabilityModule) processEvents() {
	if m.reader == nil {
		return
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-m.Context().Done():
			return
		default:
			record, err := m.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ringbuf: %v", err)
				continue
			}

			// Parse and handle event
			m.handleEvent(record.RawSample)
		}
	}
}

func (m *ObservabilityModule) handleEvent(data []byte) {
	// Parse event based on structure
	// In production: proper event parsing, enrichment, and export

	// For now, just log
	if m.Config().Agent.LogLevel == "debug" {
		log.Printf("Observability event: %d bytes", len(data))
	}

	// TODO: Export to Prometheus/OTLP
	// TODO: Enrich with Kubernetes metadata
	// TODO: Apply filters
}

func (m *ObservabilityModule) HealthCheck() error {
	if m.collection == nil {
		return fmt.Errorf("no eBPF programs loaded")
	}

	// Check if programs are still attached
	if len(m.links) == 0 {
		return fmt.Errorf("no programs attached")
	}

	return nil
}

func init() {
	RegisterModule("observability", func(ctx context.Context, cfg *config.Config) (Module, error) {
		return NewObservabilityModule(ctx, cfg)
	})
}

/*
 * Production Patterns:
 *
 * 1. Graceful Degradation:
 *    - Module loads even if eBPF programs missing
 *    - Logs warnings but doesn't fail
 *    - Allows other modules to function
 *
 * 2. Event Processing:
 *    - Dedicated goroutine for ring buffer reading
 *    - Non-blocking event handling
 *    - Proper shutdown coordination
 *
 * 3. Resource Management:
 *    - Track all links for cleanup
 *    - Close ring buffer reader
 *    - Release eBPF collection
 *
 * 4. Health Checks:
 *    - Verify programs loaded
 *    - Check attachments active
 *    - Return specific errors
 *
 * Similar to:
 *   - Tetragon's TracingPolicy
 *   - Falco's rule engine
 *   - Pixie's PEM (Process Execution Monitor)
 */
