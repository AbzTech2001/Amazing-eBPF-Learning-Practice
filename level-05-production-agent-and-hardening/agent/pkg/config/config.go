package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent    AgentConfig    `yaml:"agent"`
	Features FeaturesConfig `yaml:"features"`
	Filters  FiltersConfig  `yaml:"filters"`
	Export   ExportConfig   `yaml:"export"`
}

type AgentConfig struct {
	LogLevel       string        `yaml:"log_level"`
	ExportInterval time.Duration `yaml:"export_interval"`
}

type FeaturesConfig struct {
	Observability ObservabilityConfig `yaml:"observability"`
	Security      SecurityConfig      `yaml:"security"`
	Networking    NetworkingConfig    `yaml:"networking"`
}

type ObservabilityConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Syscalls []string `yaml:"syscalls"`
}

type SecurityConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Enforce         bool     `yaml:"enforce"`
	SensitivePaths  []string `yaml:"sensitive_paths"`
}

type NetworkingConfig struct {
	Enabled    bool `yaml:"enabled"`
	CaptureDNS bool `yaml:"capture_dns"`
}

type FiltersConfig struct {
	MinPID            int      `yaml:"min_pid"`
	ExcludeNamespaces []string `yaml:"exclude_namespaces"`
}

type ExportConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"`
	OTLP       OTLPConfig       `yaml:"otlp"`
}

type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type OTLPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Set defaults
	if cfg.Agent.LogLevel == "" {
		cfg.Agent.LogLevel = "info"
	}
	if cfg.Agent.ExportInterval == 0 {
		cfg.Agent.ExportInterval = 30 * time.Second
	}
	if cfg.Export.Prometheus.Port == 0 {
		cfg.Export.Prometheus.Port = 9090
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Agent.ExportInterval < time.Second {
		return fmt.Errorf("export_interval must be >= 1s")
	}

	if c.Export.Prometheus.Enabled && (c.Export.Prometheus.Port < 1 || c.Export.Prometheus.Port > 65535) {
		return fmt.Errorf("invalid prometheus port: %d", c.Export.Prometheus.Port)
	}

	return nil
}
