package modules

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"ebpf-agent/pkg/config"
)

// NetworkingModule handles XDP, tc, and network tracing
type NetworkingModule struct {
	*BaseModule
	collection    *ebpf.Collection
	xdpLinks      []link.Link
	tcLinks       []link.Link
	interfaceName string
}

func NewNetworkingModule(ctx context.Context, cfg *config.Config) (Module, error) {
	base := NewBaseModule(ctx, "networking", cfg)

	module := &NetworkingModule{
		BaseModule:    base,
		xdpLinks:      make([]link.Link, 0),
		tcLinks:       make([]link.Link, 0),
		interfaceName: "eth0", // TODO: make configurable
	}

	if err := module.loadPrograms(); err != nil {
		return nil, err
	}

	return module, nil
}

func (m *NetworkingModule) loadPrograms() error {
	spec, err := ebpf.LoadCollectionSpec("bpf/networking.o")
	if err != nil {
		log.Printf("WARNING: Failed to load networking eBPF programs: %v", err)
		return nil
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}

	m.collection = coll
	return nil
}

func (m *NetworkingModule) Start() error {
	if m.collection == nil {
		log.Println("Networking module: no eBPF programs loaded")
		return nil
	}

	// Attach XDP programs
	if err := m.attachXDP(); err != nil {
		log.Printf("  Failed to attach XDP: %v", err)
	}

	// Attach TC programs
	if err := m.attachTC(); err != nil {
		log.Printf("  Failed to attach TC: %v", err)
	}

	// Attach kprobes for connection tracking
	if err := m.attachKprobes(); err != nil {
		log.Printf("  Failed to attach kprobes: %v", err)
	}

	return nil
}

func (m *NetworkingModule) attachXDP() error {
	prog := m.collection.Programs["xdp_filter"]
	if prog == nil {
		return fmt.Errorf("xdp_filter program not found")
	}

	// Get interface index
	iface, err := link.LoadInterface(m.interfaceName)
	if err != nil {
		return fmt.Errorf("load interface: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Use generic mode for compatibility
	})
	if err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}

	m.xdpLinks = append(m.xdpLinks, l)
	log.Printf("  Attached XDP to interface: %s", m.interfaceName)
	return nil
}

func (m *NetworkingModule) attachTC() error {
	prog := m.collection.Programs["tc_ingress"]
	if prog == nil {
		return fmt.Errorf("tc_ingress program not found")
	}

	// Get interface index
	iface, err := link.LoadInterface(m.interfaceName)
	if err != nil {
		return fmt.Errorf("load interface: %w", err)
	}

	// Attach TC ingress
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attach tc: %w", err)
	}

	m.tcLinks = append(m.tcLinks, l)
	log.Printf("  Attached TC ingress to interface: %s", m.interfaceName)
	return nil
}

func (m *NetworkingModule) attachKprobes() error {
	// Attach to tcp_connect for connection tracking
	prog := m.collection.Programs["kprobe_tcp_connect"]
	if prog != nil {
		l, err := link.Kprobe("tcp_connect", prog, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_connect kprobe: %w", err)
		}
		m.xdpLinks = append(m.xdpLinks, l)
		log.Println("  Attached kprobe: tcp_connect")
	}

	// Attach to tcp_sendmsg for throughput monitoring
	prog = m.collection.Programs["kprobe_tcp_sendmsg"]
	if prog != nil {
		l, err := link.Kprobe("tcp_sendmsg", prog, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_sendmsg kprobe: %w", err)
		}
		m.xdpLinks = append(m.xdpLinks, l)
		log.Println("  Attached kprobe: tcp_sendmsg")
	}

	return nil
}

func (m *NetworkingModule) Stop() error {
	// Detach all XDP programs
	for _, l := range m.xdpLinks {
		l.Close()
	}

	// Detach all TC programs
	for _, l := range m.tcLinks {
		l.Close()
	}

	if m.collection != nil {
		m.collection.Close()
	}

	return nil
}

func (m *NetworkingModule) HealthCheck() error {
	if m.collection == nil {
		return fmt.Errorf("no eBPF programs loaded")
	}

	// Check if programs are still attached
	if len(m.xdpLinks) == 0 && len(m.tcLinks) == 0 {
		return fmt.Errorf("no network programs attached")
	}

	return nil
}

func init() {
	RegisterModule("networking", func(ctx context.Context, cfg *config.Config) (Module, error) {
		return NewNetworkingModule(ctx, cfg)
	})
}

/*
 * Networking Module Features:
 *
 * 1. XDP Layer:
 *    - Early packet filtering
 *    - DDoS mitigation
 *    - Load balancing
 *
 * 2. TC Layer:
 *    - Network policies
 *    - Traffic shaping
 *    - Connection tracking
 *
 * 3. Kprobes:
 *    - TCP connection tracking
 *    - Throughput monitoring
 *    - Latency measurement
 *
 * 4. Service Mesh Integration:
 *    - L7 protocol parsing
 *    - Distributed tracing
 *    - Service dependencies
 *
 * Similar to:
 *   - Cilium's datapath
 *   - Hubble's network observability
 *   - Pixie's network stats
 */
