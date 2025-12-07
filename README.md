# Amazing eBPF Learning & Practice

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Powered-orange.svg)](https://ebpf.io/)

**A comprehensive, production-oriented curriculum for mastering eBPF from foundations to production deployment**

[Getting Started](#getting-started) •
[Learning Path](#learning-path) •
[Documentation](#documentation) •
[Contributing](#contributing) •
[Community](#community)

</div>

---

## Table of Contents

- [About](#about)
- [Why This Repository?](#why-this-repository)
- [Who Is This For?](#who-is-this-for)
- [What You'll Learn](#what-youll-learn)
- [Repository Structure](#repository-structure)
- [Learning Path](#learning-path)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Quick Start Examples](#quick-start-examples)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Community & Support](#community--support)

---

## About

**Amazing eBPF Learning & Practice** is a world-class educational resource that systematically teaches eBPF (extended Berkeley Packet Filter) from foundational concepts to production deployment. This repository contains **real, working code examples** (not pseudocode), comprehensive documentation, hands-on labs, and production-grade patterns used by industry-leading projects like Cilium, Tetragon, Falco, and Pixie.

### Key Features

- **Structured 5-Level Curriculum**: Progressive learning from Linux fundamentals to production systems
- **28+ Working Code Examples**: Real implementations in C, Go, Python, and bpftrace
- **3000+ Lines of Documentation**: Extensive guides, tutorials, and explanations
- **Hands-On Labs**: Practical exercises and real-world challenges
- **Production Patterns**: Enterprise-grade patterns with CI/CD, monitoring, and deployment
- **Multiple Toolchains**: Coverage of BCC, bpftrace, and libbpf frameworks
- **Cloud-Native Ready**: Kubernetes deployments, observability integration, and security enforcement

---

## Why This Repository?

eBPF is revolutionizing how we build observability, networking, and security tools in Linux. However, learning eBPF can be challenging due to:

- Fragmented learning resources scattered across blogs and docs
- Outdated examples using deprecated APIs
- Lack of production-grade patterns and best practices
- Missing integration with modern cloud-native ecosystems

**This repository solves these problems** by providing:

1. **Complete Learning Path**: From "What is eBPF?" to building production agents
2. **Modern APIs**: libbpf, CO-RE (Compile Once Run Everywhere), and BPF skeletons
3. **Production Focus**: Real-world patterns, error handling, and operational practices
4. **Cloud-Native Integration**: Kubernetes, Prometheus, OpenTelemetry, and more

---

## Who Is This For?

This repository is designed for:

- **Software Engineers** wanting to learn eBPF systematically
- **DevOps/SRE Engineers** building observability and networking solutions
- **Security Engineers** implementing runtime security monitoring
- **Kernel Developers** understanding modern kernel tracing and instrumentation
- **Students & Researchers** learning systems programming and performance analysis

### Prerequisites Level

- **Required**: Basic Linux command-line knowledge
- **Recommended**: Understanding of C programming and system calls
- **Optional**: Kernel development experience (helpful but not required)

---

## What You'll Learn

By completing this curriculum, you will:

### Technical Skills

- eBPF architecture, verifier, JIT compilation, and BTF (BPF Type Format)
- Writing production-grade eBPF programs with libbpf and CO-RE
- XDP (eXpress Data Path) for high-performance packet processing
- LSM (Linux Security Modules) for runtime security enforcement
- Traffic control (tc) for network filtering and QoS
- Ring buffers, maps, and efficient data structures
- BPF skeletons for type-safe user-space integration
- Debugging verifier errors systematically

### Practical Applications

- Building observability pipelines (Prometheus, Grafana, OpenTelemetry)
- Implementing DDoS mitigation and firewall functionality
- Creating runtime security monitors for file access and process execution
- Performance profiling and latency analysis
- Container and Kubernetes networking solutions

### Production Engineering

- CI/CD pipelines for eBPF programs
- Graceful degradation and feature detection
- Multi-tenancy and security hardening
- Monitoring, health checks, and operational practices
- Kubernetes deployments with DaemonSets and RBAC

---

## Repository Structure

```
Amazing-eBPF-learning-Practice/
│
├── LEARNING_PATH.md              # Complete learning roadmap (448 lines)
├── README.md                     # This file
├── CONTRIBUTING.md               # Contribution guidelines
├── LICENSE                       # MIT License
│
├── level-01-linux-and-ebpf-foundations/
│   ├── README.md                 # eBPF architecture, verifier, BTF (506 lines)
│   ├── docs/                     # Linux fundamentals, kernel configs
│   ├── lab/                      # Hands-on kernel support checks
│   ├── src/                      # Minimal eBPF programs
│   └── tools/                    # Setup and verification scripts
│
├── level-02-bcc-and-bpftrace-tooling/
│   ├── README.md                 # BCC and bpftrace deep dives (725 lines)
│   ├── docs/                     # Tool-specific guides
│   ├── examples/
│   │   ├── bcc/                  # Python BCC examples
│   │   └── bpftrace/             # bpftrace one-liners and scripts
│   └── tools/                    # Tool installation scripts
│
├── level-03-libbpf-and-core-programming/
│   ├── README.md                 # libbpf, CO-RE, skeletons (762 lines)
│   ├── docs/                     # Production eBPF programming
│   ├── examples/
│   │   ├── 01-hello-libbpf/      # Basic libbpf program
│   │   ├── 02-ringbuf-events/    # Ring buffer event streaming
│   │   └── 03-fentry-fexit/      # Function latency tracing
│   └── tools/                    # libbpf setup and vmlinux generation
│
├── level-04-ebpf-networking-observability-security/
│   ├── README.md                 # Real-world applications
│   ├── docs/                     # XDP, LSM, tc, observability guides
│   ├── examples/
│   │   ├── xdp/                  # XDP packet filtering
│   │   ├── tc/                   # Traffic control examples
│   │   ├── lsm/                  # Security monitoring
│   │   └── observability/        # Prometheus exporter (Go)
│   ├── k8s/                      # Kubernetes manifests
│   └── tools/                    # Networking setup and helpers
│
└── level-05-production-agent-and-hardening/
    ├── README.md                 # Production deployment guide
    ├── agent/                    # Complete Go-based agent
    │   ├── main.go               # Agent entry point
    │   ├── pkg/                  # Modules (observability, security, networking)
    │   ├── config.yaml           # Configuration example
    │   └── Makefile              # Build system
    ├── deployment/               # Docker and Kubernetes deployments
    ├── ci-cd/                    # GitHub Actions workflows
    ├── docs/                     # Production operations guides
    └── tools/                    # Deployment and health check scripts
```

---

## Learning Path

This curriculum is organized into **5 progressive levels**, designed to be completed in **3-4 months** of focused learning:

### Level 01: Linux & eBPF Foundations (1-2 weeks)

**Time Estimate**: 1-2 weeks
**Focus**: Understanding eBPF architecture and kernel fundamentals

**Topics**:

- Linux kernel concepts for eBPF
- eBPF virtual machine, verifier, and JIT compilation
- BTF (BPF Type Format) and type information
- Kernel configuration requirements
- Loading and inspecting basic eBPF programs

**Deliverables**:

- Set up eBPF development environment
- Load and run minimal eBPF program
- Use bpftool for program inspection
- Understand verifier requirements

**[Start Level 01 →](level-01-linux-and-ebpf-foundations/)**

---

### Level 02: BCC & bpftrace Tooling (1-2 weeks)

**Time Estimate**: 1-2 weeks
**Focus**: High-level tracing tools for rapid development

**Topics**:

- BCC (BPF Compiler Collection) with Python
- bpftrace language and one-liners
- Syscall tracing, latency analysis, and profiling
- Tool overhead evaluation
- Choosing the right tool for the job

**Deliverables**:

- Write BCC tools for custom tracing
- Create bpftrace scripts for profiling
- Understand when to use BCC vs bpftrace vs libbpf
- Build performance monitoring dashboards

**[Start Level 02 →](level-02-bcc-and-bpftrace-tooling/)**

---

### Level 03: libbpf & CO-RE Programming (2-3 weeks)

**Time Estimate**: 2-3 weeks
**Focus**: Production-grade eBPF with portability

**Topics**:

- libbpf library fundamentals
- CO-RE (Compile Once, Run Everywhere)
- BPF skeletons for type-safe integration
- Ring buffers for efficient event streaming
- fentry/fexit for low-overhead tracing
- Verifier error debugging strategies

**Deliverables**:

- Build portable eBPF programs with CO-RE
- Implement ring buffer-based event collectors
- Generate and use BPF skeletons
- Debug complex verifier errors

**[Start Level 03 →](level-03-libbpf-and-core-programming/)**

---

### Level 04: Networking, Observability & Security (3-4 weeks)

**Time Estimate**: 3-4 weeks
**Focus**: Real-world applications and integrations

**Topics**:

- XDP (eXpress Data Path) for packet processing
- Traffic control (tc) for filtering and QoS
- LSM (Linux Security Modules) for runtime security
- Observability pipeline integration (Prometheus, Grafana, OpenTelemetry)
- Kubernetes deployment patterns

**Deliverables**:

- Build XDP-based DDoS mitigation
- Implement LSM file monitoring
- Create Prometheus eBPF exporter
- Deploy eBPF agents in Kubernetes

**[Start Level 04 →](level-04-ebpf-networking-observability-security/)**

---

### Level 05: Production Agent & Hardening (4-5 weeks)

**Time Estimate**: 4-5 weeks
**Focus**: Enterprise deployment and operations

**Topics**:

- Production agent architecture (modular design)
- Feature detection and graceful degradation
- CI/CD pipelines for eBPF (GitHub Actions)
- Health checks, metrics, and monitoring
- Security hardening and multi-tenancy
- Troubleshooting and operations

**Deliverables**:

- Complete production-ready eBPF agent
- Automated CI/CD pipeline
- Kubernetes deployment with monitoring
- Operational runbooks

**[Start Level 05 →](level-05-production-agent-and-hardening/)**

---

## Prerequisites

### System Requirements

- **Operating System**: Linux kernel 5.10+ (recommended: 5.15+ for all features)
- **Architecture**: x86_64 or ARM64
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Disk Space**: 10GB for tools, dependencies, and build artifacts

### Required Knowledge

- Basic Linux command-line skills (ls, cd, grep, etc.)
- Understanding of C programming (variables, pointers, structs)
- Familiarity with system calls and processes
- Basic networking concepts (TCP/IP, packets, ports)

### Optional Knowledge (Helpful)

- Kernel development experience
- Go programming (for Level 05)
- Python (for Level 02 BCC examples)
- Container and Kubernetes concepts (for Level 04-05)

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Amazing-eBPF-learning-Practice.git
cd Amazing-eBPF-learning-Practice
```

### 2. Check Kernel Support

Verify your kernel has eBPF support:

```bash
cd level-01-linux-and-ebpf-foundations/tools
./verify-setup.sh
```

This script checks:

- Kernel version (5.10+ recommended)
- eBPF-related kernel configurations
- BPF filesystem mount
- BTF (BPF Type Format) support
- Required tools (clang, llvm, bpftool)

### 3. Install Development Tools

#### Ubuntu/Debian:

```bash
cd level-01-linux-and-ebpf-foundations/tools
sudo ./setup-environment.sh
```

#### Fedora/RHEL:

```bash
# Install base tools
sudo dnf install -y clang llvm kernel-devel bpftool \
  libbpf-devel elfutils-libelf-devel zlib-devel

# Install BCC and bpftrace (Level 02)
sudo dnf install -y bcc-tools python3-bcc bpftrace
```

#### From Source (any distribution):

```bash
# See level-01-linux-and-ebpf-foundations/docs/01-linux-fundamentals.md
# for detailed build-from-source instructions
```

### 4. Start with Level 01

```bash
cd level-01-linux-and-ebpf-foundations
cat README.md  # Read the comprehensive guide
cd src
make           # Build minimal eBPF example
sudo ./minimal_loader  # Run your first eBPF program!
```

### 5. Follow the Learning Path

Read **[LEARNING_PATH.md](LEARNING_PATH.md)** for the complete roadmap with:

- Detailed time estimates per level
- Learning principles and best practices
- Recommended study approach
- Progress tracking guidance

---

## Quick Start Examples

### Example 1: Trace Process Execution

```bash
# Using bpftrace (Level 02)
cd level-02-bcc-and-bpftrace-tooling/examples/bpftrace
sudo bpftrace syscall_count.bt

# Press Ctrl-C after a few seconds to see syscall statistics
```

### Example 2: Count File Opens

```bash
# Using BCC Python (Level 02)
cd level-02-bcc-and-bpftrace-tooling/examples/bcc
sudo python3 opencount.py

# In another terminal, create some file activity:
# ls /tmp && cat /etc/hosts
```

### Example 3: Monitor Network Connections

```bash
# Using libbpf (Level 03)
cd level-03-libbpf-and-core-programming/examples/01-hello-libbpf
make
sudo ./hello

# In another terminal:
# curl https://example.com
```

### Example 4: XDP Packet Filter

```bash
# Drop traffic on specific port (Level 04)
cd level-04-ebpf-networking-observability-security/examples/xdp

# See xdp_drop_port.c for implementation
# Requires manual compilation and loading (see Level 04 README)
```

---

## Documentation

This repository includes extensive documentation:

### Main Guides

- **[LEARNING_PATH.md](LEARNING_PATH.md)** - Complete learning roadmap with time estimates
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute to this project
- **[LICENSE](LICENSE)** - MIT License terms

### Level-Specific Documentation

Each level contains:

- **README.md** - Comprehensive guide for that level (500-750 lines)
- **docs/** - Deep-dive technical documentation
- **examples/** - Working code with inline comments
- **lab/** - Hands-on exercises and challenges

### Additional Resources

- **Architecture Diagrams**: `level-01-linux-and-ebpf-foundations/architecture/`
- **Setup Scripts**: Each level's `tools/` directory
- **Configuration Examples**: `level-05-production-agent-and-hardening/agent/config.yaml`

---

## Contributing

We welcome contributions! This project thrives on community involvement.

### How to Contribute

1. **Report Issues**: Found a bug or typo? [Open an issue](https://github.com/yourusername/Amazing-eBPF-learning-Practice/issues)
2. **Submit Examples**: Have a great eBPF example? Submit a PR!
3. **Improve Documentation**: Fix typos, clarify explanations, add examples
4. **Add Labs**: Create hands-on exercises for learners
5. **Share Feedback**: What worked? What was confusing? Let us know!

### Contribution Guidelines

Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for:

- Code standards and style guide
- Testing requirements
- Documentation conventions
- Pull request process
- Community guidelines

### Areas We Need Help With

- [ ] Testing on different kernel versions (5.10, 5.15, 6.0+)
- [ ] ARM64 compatibility verification
- [ ] Additional real-world examples
- [ ] Translation to other languages
- [ ] Video tutorials and walkthroughs
- [ ] Performance benchmarking

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Note**: Individual eBPF programs may use GPL-2.0 license (required by kernel) as indicated in their headers.

### Why MIT?

We chose MIT license to:

- Maximize learning and reusability
- Allow both open source and commercial use
- Encourage widespread adoption and contributions
- Align with industry-standard educational resources

---

## Acknowledgments

This repository builds upon the incredible work of the eBPF community:

### Inspiration & Reference Projects

- **[Cilium](https://github.com/cilium/cilium)** - CNI and service mesh with eBPF
- **[Tetragon](https://github.com/cilium/tetragon)** - Runtime security observability
- **[Falco](https://github.com/falcosecurity/falco)** - Cloud-native runtime security
- **[Pixie](https://github.com/pixie-io/pixie)** - Kubernetes observability
- **[BCC](https://github.com/iovisor/bcc)** - Tools for BPF-based tracing
- **[libbpf](https://github.com/libbpf/libbpf)** - Library for eBPF programs
- **[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)** - Scaffolding for libbpf
- **[bpftrace](https://github.com/iovisor/bpftrace)** - High-level tracing language

### Learning Resources

- **[ebpf.io](https://ebpf.io/)** - Official eBPF documentation
- **[Cilium eBPF Go Library](https://github.com/cilium/ebpf)** - Go eBPF library
- **Brendan Gregg's Blog** - Performance analysis and eBPF insights
- **Linux Kernel Documentation** - BPF subsystem docs

### Contributors

Thank you to all contributors who help make this resource better!

<!-- ALL-CONTRIBUTORS-LIST:START -->
<!-- This will be automatically generated -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

---

## Community & Support

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/yourusername/Amazing-eBPF-learning-Practice/issues) for bugs and questions
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/Amazing-eBPF-learning-Practice/discussions) for general questions
- **Documentation**: Extensive docs in each level's README and `docs/` folder

### Community Guidelines

- Be respectful and inclusive
- Help others learn - we all started somewhere
- Share your experiences and learnings
- Report issues constructively
- Contribute back when you can

### Stay Connected

- Star this repository to stay updated
- Watch for new releases and examples
- Share your learning journey (blog posts, tweets, etc.)
- Consider contributing your own examples

---

## Roadmap

### Current Status: v1.0

- [x] Complete 5-level curriculum
- [x] 28+ working code examples
- [x] 3000+ lines of documentation
- [x] Production agent implementation
- [x] Kubernetes deployment examples
- [x] CI/CD pipeline templates

### Planned Improvements (v1.1)

- [ ] Fix critical issues identified in code review
- [ ] Video walkthroughs for each level
- [ ] Interactive web-based tutorials
- [ ] Performance benchmarking suite
- [ ] Additional cloud platform examples (AWS, GCP, Azure)
- [ ] Windows WSL2 support guide

### Future Vision (v2.0)

- [ ] eBPF for ARM64 deep dive
- [ ] Advanced topics: eBPF JIT internals
- [ ] eBPF for embedded systems
- [ ] Machine learning with eBPF data
- [ ] Multi-language examples (Rust, C++)

---

## Statistics

- **Total Files**: 234
- **Code Examples**: 28+
- **Documentation Lines**: 3000+
- **Programming Languages**: C, Go, Python, bpftrace, Bash
- **Levels**: 5 (Foundation + 4 Progressive)
- **Estimated Time**: 3-4 months
- **Kubernetes Manifests**: 2 (DaemonSet, ServiceMonitor)

---

## Star History

If you find this repository useful, please consider giving it a star! ⭐

Your support helps more people discover this resource and motivates continued development.

---

<div align="center">

**Happy eBPF Learning!** 🚀

Made with ❤️ by the eBPF community

[⬆ Back to Top](#amazing-ebpf-learning--practice)

</div>
