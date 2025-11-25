package modules

import (
	"context"
	"fmt"

	"ebpf-agent/pkg/config"
)

// Module interface that all eBPF modules must implement
type Module interface {
	// Start starts the module
	Start() error

	// Stop stops the module
	Stop() error

	// HealthCheck returns module health status
	HealthCheck() error

	// Name returns the module name
	Name() string
}

// BaseModule provides common functionality for all modules
type BaseModule struct {
	name   string
	ctx    context.Context
	config *config.Config
}

func NewBaseModule(ctx context.Context, name string, cfg *config.Config) *BaseModule {
	return &BaseModule{
		name:   name,
		ctx:    ctx,
		config: cfg,
	}
}

func (m *BaseModule) Name() string {
	return m.name
}

func (m *BaseModule) Context() context.Context {
	return m.ctx
}

func (m *BaseModule) Config() *config.Config {
	return m.config
}

// Module registry
var moduleRegistry = make(map[string]func(context.Context, *config.Config) (Module, error))

// RegisterModule registers a module constructor
func RegisterModule(name string, constructor func(context.Context, *config.Config) (Module, error)) {
	moduleRegistry[name] = constructor
}

// CreateModule creates a module by name
func CreateModule(name string, ctx context.Context, cfg *config.Config) (Module, error) {
	constructor, ok := moduleRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return constructor(ctx, cfg)
}
