# Makefile for Production eBPF Agent

BINARY = ebpf-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME = $(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS = -X main.version=$(VERSION) \
          -X main.commit=$(COMMIT) \
          -X main.buildTime=$(BUILD_TIME)

# Directories
BPF_DIR = bpf
PKG_DIR = pkg
BUILD_DIR = build

# Tools
CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go

.PHONY: all clean build build-bpf build-go test lint docker-build

all: build

# Build everything
build: build-bpf build-go

# Build eBPF programs
build-bpf:
	@echo "Building eBPF programs..."
	@mkdir -p $(BUILD_DIR)/bpf
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_x86_64 \
		-c $(BPF_DIR)/observability.bpf.c \
		-o $(BUILD_DIR)/bpf/observability.o
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_x86_64 \
		-c $(BPF_DIR)/security.bpf.c \
		-o $(BUILD_DIR)/bpf/security.o
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_x86_64 \
		-c $(BPF_DIR)/networking.bpf.c \
		-o $(BUILD_DIR)/bpf/networking.o
	@echo "eBPF programs built successfully"

# Build Go binary
build-go:
	@echo "Building Go binary..."
	CGO_ENABLED=0 $(GO) build \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY) \
		main.go
	@echo "Binary built: $(BUILD_DIR)/$(BINARY)"

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -cover ./...

# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run ./...

# Check eBPF programs with verifier
verify-bpf: build-bpf
	@echo "Verifying eBPF programs..."
	$(BPFTOOL) prog load $(BUILD_DIR)/bpf/observability.o /sys/fs/bpf/test_obs || true
	rm -f /sys/fs/bpf/test_obs

# Build Docker image
docker-build:
	docker build -t ebpf-agent:$(VERSION) .

# Build multi-arch Docker images
docker-build-multi:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t ebpf-agent:$(VERSION) \
		--push .

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod verify

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean

# Run locally (requires root)
run: build
	sudo $(BUILD_DIR)/$(BINARY) -config config.yaml -debug

# Install to system
install: build
	sudo install -m 755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/
	sudo mkdir -p /etc/ebpf-agent
	sudo install -m 644 config.yaml /etc/ebpf-agent/

# Generate release archives
release: build
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/releases
	tar -czf $(BUILD_DIR)/releases/$(BINARY)-$(VERSION)-linux-amd64.tar.gz \
		-C $(BUILD_DIR) $(BINARY)
	@echo "Release archives created in $(BUILD_DIR)/releases/"

.PHONY: help
help:
	@echo "eBPF Agent Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build everything (default)"
	@echo "  build          - Build eBPF programs and Go binary"
	@echo "  build-bpf      - Build only eBPF programs"
	@echo "  build-go       - Build only Go binary"
	@echo "  test           - Run tests"
	@echo "  lint           - Run linters"
	@echo "  verify-bpf     - Verify eBPF programs with verifier"
	@echo "  docker-build   - Build Docker image"
	@echo "  run            - Build and run locally (requires root)"
	@echo "  install        - Install to /usr/local/bin"
	@echo "  clean          - Remove build artifacts"
	@echo "  help           - Show this help message"
