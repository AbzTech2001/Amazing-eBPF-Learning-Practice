# Level 05: Production Agent & Hardening

## Overview

This is the **capstone level** where you build a complete, production-ready eBPF-based observability/security agent. You'll implement everything learned in previous levels and add production hardening, CI/CD, performance tuning, and operational excellence.

**Goal**: Design, build, deploy, and operate a production-grade eBPF agent that runs reliably at scale in Kubernetes environments.

---

## Prerequisites

Complete **Levels 01-04**:
- libbpf programming with CO-RE
- XDP, tc, LSM hooks
- Observability integration (Prometheus/Grafana/OTel)
- Kubernetes deployment

---

## What You'll Build

### The Production Agent

A complete eBPF-based agent with:

**Observability Module**:
- Process execution tracing
- Network connection monitoring
- File I/O metrics
- CPU/memory profiling
- Export to Prometheus/OpenTelemetry

**Security Module**:
- LSM-based access control
- Suspicious activity detection
- Policy enforcement
- Audit logging

**Networking Module**:
- Service-to-service communication map
- Network latency tracking
- DNS monitoring
- Connection state tracking

**Core Infrastructure**:
- Multi-component architecture
- Configuration management
- Health monitoring
- Graceful degradation
- Hot reload capabilities

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    eBPF Production Agent                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  eBPF Programs (Kernel Space)                       │   │
│  │  ┌────────────┐ ┌────────────┐ ┌──────────────┐   │   │
│  │  │ Observ.    │ │ Security   │ │ Networking   │   │   │
│  │  │ - execve   │ │ - LSM      │ │ - XDP        │   │   │
│  │  │ - kprobes  │ │ - file mon │ │ - tc filter  │   │   │
│  │  │ - tracing  │ │ - policies │ │ - conntrack  │   │   │
│  │  └────────────┘ └────────────┘ └──────────────┘   │   │
│  │                                                       │   │
│  │  Maps & Ring Buffers                                │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │  Agent Core (User Space)                            │   │
│  │  ┌────────────────────────────────────────────────┐ │   │
│  │  │  Event Processing & Enrichment                 │ │   │
│  │  │  - Kubernetes metadata                         │ │   │
│  │  │  - Container context                           │ │   │
│  │  │  - Policy evaluation                           │ │   │
│  │  └────────────────────────────────────────────────┘ │   │
│  │                                                       │   │
│  │  ┌────────────────┐ ┌──────────────┐               │   │
│  │  │ Config Manager │ │ Health Check │               │   │
│  │  └────────────────┘ └──────────────┘               │   │
│  │                                                       │   │
│  │  ┌────────────────────────────────────────────────┐ │   │
│  │  │  Export Layer                                  │ │   │
│  │  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ │ │   │
│  │  │  │ Prometheus │ │ OTel       │ │ Logs       │ │ │   │
│  │  │  │ (metrics)  │ │ (traces)   │ │ (events)   │ │ │   │
│  │  │  └────────────┘ └────────────┘ └────────────┘ │ │   │
│  │  └────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Topics Covered

### 1. Production Architecture
- Multi-component design
- Separation of concerns
- Module system
- Plugin architecture

### 2. Feature Detection & Graceful Degradation
- Kernel version detection
- BTF availability checking
- Feature probing
- Fallback strategies
- Compatibility matrix

### 3. Performance Tuning
- Overhead measurement
- Event sampling strategies
- Map sizing optimization
- Ring buffer tuning
- CPU affinity
- Memory management

### 4. Configuration Management
- YAML/JSON configuration
- Runtime reconfiguration
- Feature flags
- Policy definition

### 5. Observability of the Observer
- Self-monitoring
- Performance metrics
- Error tracking
- Health endpoints

### 6. CI/CD Pipeline
- Build automation
- Testing strategies (unit, integration, e2e)
- Container image building
- Multi-arch support
- Release process

### 7. Security Hardening
- Least privilege
- Capabilities management
- SELinux/AppArmor integration
- Secrets management
- Supply chain security

### 8. Multi-Tenancy
- Namespace isolation
- Resource limits
- Network policies
- Tenant labeling

### 9. Operations
- Deployment strategies
- Monitoring and alerting
- Troubleshooting guides
- Upgrade procedures
- Rollback strategies

### 10. Scale Considerations
- Large cluster deployment (1000+ nodes)
- High event rate handling
- Data aggregation
- Backend integration

---

## Practical Projects (10)

### Project 1: Core Agent Framework
**Objective**: Build the foundational agent structure.

**Components**:
- Main event loop
- Module loader
- Configuration parser
- Logging system
- Signal handling

**Deliverable**: Agent skeleton that loads/unloads modules.

---

### Project 2: Feature Detection System
**Objective**: Detect kernel features and adapt behavior.

**Detection**:
```go
type FeatureSet struct {
    HasBTF           bool
    HasLSM           bool
    HasRingBuffer    bool
    HasFentry        bool
    KernelVersion    string
    AvailableHelpers []string
}

func DetectFeatures() (*FeatureSet, error) {
    // Check BTF
    if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
        features.HasBTF = true
    }

    // Probe LSM
    if canAttachLSM() {
        features.HasLSM = true
    }

    // ... more checks
}
```

**Deliverable**: Feature detection library with fallbacks.

---

### Project 3: Configuration System
**Objective**: Flexible configuration with hot reload.

**Example config.yaml**:
```yaml
agent:
  log_level: info
  export_interval: 30s

features:
  observability:
    enabled: true
    syscalls: [execve, openat, connect]
  security:
    enabled: true
    enforce: false
  networking:
    enabled: true
    capture_dns: true

filters:
  min_pid: 1000
  exclude_namespaces: [kube-system]

export:
  prometheus:
    enabled: true
    port: 9090
  otlp:
    enabled: true
    endpoint: "otlp-collector:4317"
```

**Deliverable**: Config system with validation and hot reload.

---

### Project 4: Performance Profiling & Optimization
**Objective**: Measure and optimize agent overhead.

**Metrics to track**:
- CPU usage (per module)
- Memory usage
- Event processing latency
- Map lookup time
- Ring buffer utilization

**Optimization targets**:
- <1% CPU overhead
- <100MB memory
- <1ms event latency (p99)

**Deliverable**: Performance dashboard and optimization report.

---

### Project 5: Comprehensive Testing
**Objective**: Build test suite for reliability.

**Test types**:
- Unit tests (Go/C)
- Integration tests (agent + eBPF)
- E2E tests (Kubernetes)
- Load tests
- Chaos tests (node failures, kernel upgrades)

**Deliverable**: CI pipeline with test coverage >80%.

---

### Project 6: CI/CD Pipeline
**Objective**: Automated build, test, deploy.

**Pipeline stages**:
```yaml
# .github/workflows/ci.yaml
stages:
  - lint:
      - go fmt
      - clang-format
      - shellcheck
  - build:
      - compile eBPF programs
      - compile agent
      - multi-arch (amd64, arm64)
  - test:
      - unit tests
      - integration tests
      - e2e tests (kind cluster)
  - image:
      - build container
      - scan for vulnerabilities
      - push to registry
  - deploy:
      - staging environment
      - smoke tests
      - production (manual approval)
```

**Deliverable**: Complete CI/CD pipeline with automated deployments.

---

### Project 7: Kubernetes Operator
**Objective**: Manage agent lifecycle with operator pattern.

**Features**:
- Custom Resource Definitions (CRDs)
- Reconciliation loop
- Health monitoring
- Auto-remediation
- Version upgrades

**Example CRD**:
```yaml
apiVersion: ebpf.io/v1
kind: EbpfAgent
metadata:
  name: cluster-agent
spec:
  version: "1.0.0"
  modules:
    - observability
    - security
  config:
    exporters:
      - prometheus
      - otlp
```

**Deliverable**: Kubernetes operator managing agent lifecycle.

---

### Project 8: Security Hardening
**Objective**: Minimize attack surface.

**Hardening steps**:
- Run as non-root where possible
- Use minimal capabilities (not `privileged: true`)
- Read-only root filesystem
- Drop unnecessary capabilities
- Network policies
- Pod security standards
- Image scanning and signing

**Security checklist**:
- [ ] Minimal container image (distroless)
- [ ] No secrets in env vars
- [ ] TLS for external communication
- [ ] RBAC least privilege
- [ ] Audit logging enabled

**Deliverable**: Hardened deployment with security assessment.

---

### Project 9: Multi-Tenancy Support
**Objective**: Safe operation in multi-tenant clusters.

**Requirements**:
- Namespace isolation
- Resource quotas per tenant
- Network isolation
- Data segregation
- Tenant-specific policies

**Implementation**:
- Tenant labeling
- Policy per namespace
- Separate data paths
- Resource limits

**Deliverable**: Multi-tenant capable agent.

---

### Project 10: Operations Runbook
**Objective**: Comprehensive operational documentation.

**Contents**:
- Deployment procedures
- Configuration guide
- Troubleshooting flowcharts
- Common issues and fixes
- Performance tuning guide
- Upgrade procedures
- Disaster recovery
- Monitoring and alerting setup

**Deliverable**: Production operations runbook.

---

## Real-World Challenges (5)

### Challenge 1: Kernel Upgrade Breaks Agent
**Scenario**: Production cluster upgrades kernel, agent fails.

**Issues**:
- CO-RE relocations fail
- Helper function removed
- Tracepoint changed

**Your Task**:
1. Detect kernel version mismatch
2. Implement feature detection
3. Add compatibility layer
4. Create migration guide

**Deliverable**: Resilient agent handling kernel upgrades.

---

### Challenge 2: High Event Rate Overwhelms Backend
**Scenario**: 1000-node cluster generates 1M events/sec.

**Problems**:
- Prometheus scraping timeout
- OTel collector overload
- Network saturation

**Your Task**:
1. Implement aggregation in agent
2. Add sampling strategies
3. Local caching
4. Batch export

**Deliverable**: Scalable export handling 10M events/sec.

---

### Challenge 3: Memory Leak in Production
**Scenario**: Agent memory grows unbounded after 24h.

**Investigation**:
- Map not cleaned up
- Ring buffer full
- Go goroutine leak

**Your Task**:
1. Profile memory usage
2. Identify leak source
3. Implement cleanup
4. Add monitoring

**Deliverable**: Memory-stable agent (<100MB resident).

---

### Challenge 4: Partial Kubernetes API Failure
**Scenario**: K8s API intermittently unavailable, metadata enrichment fails.

**Impact**:
- Events without pod context
- Incorrect routing
- Missing labels

**Your Task**:
1. Implement local caching
2. Retry with exponential backoff
3. Graceful degradation
4. Alerting on metadata misses

**Deliverable**: Resilient metadata enrichment.

---

### Challenge 5: Multi-Arch Deployment
**Scenario**: Need to support amd64, arm64, ppc64le.

**Challenges**:
- Different instruction sets
- Endianness
- Build system
- Testing

**Your Task**:
1. Multi-arch build pipeline
2. Architecture detection
3. Test matrix
4. Unified images

**Deliverable**: Multi-arch container images.

---

## Production Checklist

Before deploying to production:

### Code Quality
- [ ] Code reviewed
- [ ] Test coverage >80%
- [ ] Linting passing
- [ ] Documentation complete

### Security
- [ ] Vulnerability scan passing
- [ ] Minimal privileges
- [ ] Secrets management
- [ ] Network policies defined

### Performance
- [ ] Load tested
- [ ] Overhead <1% CPU
- [ ] Memory <100MB per pod
- [ ] Latency p99 <10ms

### Observability
- [ ] Prometheus metrics exposed
- [ ] Health checks implemented
- [ ] Logging configured
- [ ] Tracing instrumented

### Operations
- [ ] Deployment automation
- [ ] Rollback procedure documented
- [ ] Runbook complete
- [ ] On-call trained

### Kubernetes
- [ ] RBAC configured
- [ ] Resource limits set
- [ ] Pod disruption budget
- [ ] Node affinity rules

---

## Learning Checklist

By completing Level 05, you should:

- [ ] Built a complete production-grade eBPF agent
- [ ] Implemented graceful degradation
- [ ] Created CI/CD pipeline
- [ ] Performance tuned for production
- [ ] Security hardened deployment
- [ ] Multi-tenancy support
- [ ] Comprehensive testing
- [ ] Operations runbook
- [ ] Deployed to production Kubernetes
- [ ] Operated at scale (100+ nodes)

---

## Career Readiness

### You Can Now:
✓ **Design** production eBPF systems from scratch
✓ **Build** complex multi-component agents
✓ **Deploy** to Kubernetes with confidence
✓ **Operate** eBPF at scale
✓ **Debug** production issues
✓ **Optimize** for performance
✓ **Secure** eBPF deployments
✓ **Lead** eBPF projects

### Portfolio Projects:
- Complete eBPF-based observability agent
- Security monitoring system
- Network visibility platform
- Performance profiling toolkit

### Interview Readiness:
- Deep eBPF technical knowledge
- Production experience (simulated)
- System design skills
- Operational excellence

---

## Next Steps

### Continuous Learning:
1. Contribute to open source (Cilium, Falco, etc.)
2. Write blog posts about eBPF
3. Build custom projects
4. Attend eBPF Summit / conferences
5. Stay updated with kernel changes

### Production Deployment:
1. Deploy to staging
2. Monitor and iterate
3. Gradual rollout to production
4. Collect feedback
5. Continuous improvement

---

## References

- [Production Best Practices](https://cilium.io/blog/2020/11/10/ebpf-future-of-networking/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Observability Patterns](https://www.oreilly.com/library/view/distributed-tracing-in/9781492056621/)
- [Site Reliability Engineering](https://sre.google/books/)

---

## Congratulations! 🎉

You've completed the **eBPF Mastery** curriculum. You now have the skills to:
- Design production eBPF systems
- Build observability, security, and networking solutions
- Deploy and operate at scale
- Contribute to the eBPF ecosystem

**Your journey doesn't end here - it's just beginning. Go build amazing things with eBPF!**
