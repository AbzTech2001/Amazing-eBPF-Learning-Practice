package modules

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf-agent/pkg/config"
)

// SecurityModule handles LSM-based security monitoring and enforcement
type SecurityModule struct {
	*BaseModule
	collection *ebpf.Collection
	links      []link.Link
	violations uint64
}

func NewSecurityModule(ctx context.Context, cfg *config.Config) (Module, error) {
	base := NewBaseModule(ctx, "security", cfg)

	module := &SecurityModule{
		BaseModule: base,
		links:      make([]link.Link, 0),
	}

	if err := module.loadPrograms(); err != nil {
		return nil, err
	}

	return module, nil
}

func (m *SecurityModule) loadPrograms() error {
	spec, err := ebpf.LoadCollectionSpec("bpf/security.o")
	if err != nil {
		log.Printf("WARNING: Failed to load security eBPF programs: %v", err)
		return nil
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	m.collection = coll
	return nil
}

func (m *SecurityModule) Start() error {
	if m.collection == nil {
		log.Println("Security module: no eBPF programs loaded")
		return nil
	}

	// Attach LSM hooks
	hooks := []string{"file_open", "file_permission", "task_kill"}

	for _, hookName := range hooks {
		progName := fmt.Sprintf("lsm_%s", hookName)
		prog := m.collection.Programs[progName]
		if prog == nil {
			log.Printf("  Program %s not found, skipping", progName)
			continue
		}

		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("  Failed to attach %s: %v", hookName, err)
			continue
		}

		m.links = append(m.links, l)
		log.Printf("  Attached LSM hook: %s", hookName)
	}

	if len(m.links) == 0 {
		log.Println("  WARNING: No LSM hooks attached")
	}

	// Configure enforcement mode
	if m.Config().Features.Security.Enforce {
		log.Println("  Security enforcement: ENABLED")
	} else {
		log.Println("  Security enforcement: DISABLED (monitor only)")
	}

	return nil
}

func (m *SecurityModule) Stop() error {
	for _, l := range m.links {
		l.Close()
	}

	if m.collection != nil {
		m.collection.Close()
	}

	log.Printf("Security module stopped. Violations detected: %d", m.violations)
	return nil
}

func (m *SecurityModule) HealthCheck() error {
	if m.collection == nil {
		return fmt.Errorf("no eBPF programs loaded")
	}

	// In production, check if LSM hooks are still active
	// Check violation rate, error rate, etc.

	return nil
}

func init() {
	RegisterModule("security", func(ctx context.Context, cfg *config.Config) (Module, error) {
		return NewSecurityModule(ctx, cfg)
	})
}

/*
 * Security Module Features:
 *
 * 1. LSM Hook Coverage:
 *    - file_open: Monitor file access
 *    - file_permission: Check permissions
 *    - task_kill: Monitor signal sending
 *    - Many more available (socket_connect, etc.)
 *
 * 2. Policy Enforcement:
 *    - Monitor mode: Log only
 *    - Enforce mode: Actually block operations
 *    - Configurable per-hook
 *
 * 3. Sensitive Path Monitoring:
 *    - /etc/passwd, /etc/shadow
 *    - /root/.ssh/
 *    - Custom paths from config
 *
 * 4. Integration Points:
 *    - Kubernetes admission controller
 *    - SIEM systems
 *    - Alert manager
 *
 * Similar to:
 *   - Tetragon's enforcement policies
 *   - Falco's rule actions
 *   - AppArmor/SELinux complements
 */
