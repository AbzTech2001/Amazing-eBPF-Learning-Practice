# Multi-stage Dockerfile for Production eBPF Agent

# Stage 1: Build eBPF programs
FROM ubuntu:22.04 AS bpf-builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY agent/bpf/ ./bpf/

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -c bpf/observability.bpf.c -o observability.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -c bpf/security.bpf.c -o security.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -c bpf/networking.bpf.c -o networking.o

# Stage 2: Build Go binary
FROM golang:1.21 AS go-builder

WORKDIR /build

# Copy go mod files first for better caching
COPY agent/go.mod agent/go.sum ./
RUN go mod download

# Copy source code
COPY agent/ ./

# Build binary
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -a -installsuffix cgo \
    -o ebpf-agent \
    main.go

# Stage 3: Final minimal image
FROM gcr.io/distroless/static-debian12:nonroot

# Copy eBPF programs
COPY --from=bpf-builder /build/*.o /opt/ebpf-agent/bpf/

# Copy Go binary
COPY --from=go-builder /build/ebpf-agent /usr/local/bin/ebpf-agent

# Copy default config
COPY agent/config.yaml /etc/ebpf-agent/config.yaml

# User is 'nonroot' (65532)
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/ebpf-agent"]
CMD ["-config", "/etc/ebpf-agent/config.yaml"]

# Metadata
LABEL maintainer="your-team@example.com"
LABEL description="Production eBPF Observability and Security Agent"
LABEL org.opencontainers.image.source="https://github.com/your-org/ebpf-agent"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ebpf-agent", "-version"]

# Expose ports
EXPOSE 8080 9090

/*
 * Docker Build Best Practices:
 *
 * 1. Multi-Stage Build:
 *    - Separate stages for eBPF compilation and Go build
 *    - Final image contains only runtime artifacts
 *    - Reduces image size from ~1GB to ~20MB
 *
 * 2. Distroless Base:
 *    - No shell, package manager, or unnecessary tools
 *    - Minimal attack surface
 *    - Similar to what Google uses internally
 *
 * 3. Non-Root User:
 *    - Runs as UID 65532 (nonroot)
 *    - Best practice for security
 *    - Requires proper capabilities in Kubernetes
 *
 * 4. Layer Caching:
 *    - go.mod copied first for dependency caching
 *    - Source code copied later
 *    - Faster rebuilds when only code changes
 *
 * Build:
 *   docker build -t ebpf-agent:latest \
 *     --build-arg VERSION=$(git describe --tags) \
 *     --build-arg COMMIT=$(git rev-parse --short HEAD) \
 *     -f deployment/Dockerfile .
 *
 * Multi-arch build:
 *   docker buildx build --platform linux/amd64,linux/arm64 \
 *     -t your-registry/ebpf-agent:latest --push .
 *
 * Image scanning:
 *   trivy image ebpf-agent:latest
 *   docker scan ebpf-agent:latest
 */
