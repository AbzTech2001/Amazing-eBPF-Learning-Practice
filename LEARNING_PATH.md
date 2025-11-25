# eBPF Mastery - Complete Learning Path

## Overview

This monorepo provides a **structured, production-oriented path** to eBPF mastery. From foundations to building production-grade observability, networking, and security systems.

---

## Your Journey

```
START
  ↓
┌────────────────────────────────────────────────────────┐
│ Level 01: Linux & eBPF Foundations                     │
│ Duration: 1-2 weeks                                     │
│ Focus: Core concepts, verifier, BTF, bpftool          │
├────────────────────────────────────────────────────────┤
│ ✓ Understand eBPF VM, verifier, JIT                   │
│ ✓ Master bpftool inspection                           │
│ ✓ Work with BTF and CO-RE concepts                    │
│ ✓ Load and inspect basic programs                     │
│                                                         │
│ Tasks: 12 | Challenges: 6                             │
└────────────────────────────────────────────────────────┘
  ↓
┌────────────────────────────────────────────────────────┐
│ Level 02: BCC, bpftrace & Core Tracing                │
│ Duration: 2-3 weeks                                     │
│ Focus: High-level tools for rapid tracing             │
├────────────────────────────────────────────────────────┤
│ ✓ Use 100+ BCC tools                                  │
│ ✓ Write custom BCC Python scripts                     │
│ ✓ Master bpftrace one-liners and scripts             │
│ ✓ Understand tool tradeoffs and overhead              │
│                                                         │
│ Tasks: 12 | Challenges: 6                             │
└────────────────────────────────────────────────────────┘
  ↓
┌────────────────────────────────────────────────────────┐
│ Level 03: libbpf & CO-RE Programming                  │
│ Duration: 3-4 weeks                                     │
│ Focus: Production-grade C programming                  │
├────────────────────────────────────────────────────────┤
│ ✓ Write portable eBPF programs with CO-RE             │
│ ✓ Use BPF skeletons for type safety                   │
│ ✓ Master ring buffers and advanced maps               │
│ ✓ Debug verifier errors systematically                │
│                                                         │
│ Tasks: 12 | Challenges: 6                             │
└────────────────────────────────────────────────────────┘
  ↓
┌────────────────────────────────────────────────────────┐
│ Level 04: Networking, Observability & Security        │
│ Duration: 4-5 weeks                                     │
│ Focus: Real-world applications                         │
├────────────────────────────────────────────────────────┤
│ ✓ XDP packet processing                               │
│ ✓ tc-based filtering                                  │
│ ✓ Prometheus/Grafana/OTel integration                 │
│ ✓ LSM security policies                               │
│ ✓ Kubernetes deployment                               │
│                                                         │
│ Tasks: 15 | Challenges: 8                             │
└────────────────────────────────────────────────────────┘
  ↓
┌────────────────────────────────────────────────────────┐
│ Level 05: Production Agent & Hardening                │
│ Duration: 3-4 weeks                                     │
│ Focus: Production deployment at scale                  │
├────────────────────────────────────────────────────────┤
│ ✓ Build complete production agent                     │
│ ✓ Kernel feature detection                            │
│ ✓ Performance tuning and overhead management          │
│ ✓ CI/CD for eBPF                                      │
│ ✓ Multi-tenancy and security                          │
│                                                         │
│ Tasks: 10+ | Challenges: 5+                           │
└────────────────────────────────────────────────────────┘
  ↓
MASTERY: Design and build production eBPF systems
```

**Total Duration**: 3-4 months of focused learning

---

## What You'll Build

### Level 01 Projects
- ✓ Minimal tracepoint program with loader
- ✓ BTF exploration tools
- ✓ Kernel feature detection scripts

### Level 02 Projects
- ✓ Custom BCC scripts for syscall/network tracing
- ✓ bpftrace one-liners for performance analysis
- ✓ Latency measurement tools

### Level 03 Projects
- ✓ Portable libbpf programs with CO-RE
- ✓ Ring buffer event streaming
- ✓ Production-ready packages

### Level 04 Projects
- ✓ XDP packet filter / load balancer
- ✓ Prometheus exporter with Grafana dashboard
- ✓ LSM-based security monitor
- ✓ Kubernetes DaemonSet deployment

### Level 05 Projects (Planned)
- ✓ Complete observability/security agent
- ✓ Multi-component system with CI/CD
- ✓ Performance-tuned production deployment

---

## Directory Structure

```
EBPF/
├── LEARNING_PATH.md                          ← You are here
├── level-01-linux-and-ebpf-foundations/      ← START HERE
│   ├── README.md                             (12 tasks, 6 challenges)
│   ├── docs/                                 (4 in-depth guides)
│   ├── lab/                                  (4 interactive labs)
│   ├── src/                                  (example programs)
│   ├── tools/                                (setup scripts)
│   └── architecture/                         (diagrams)
│
├── level-02-bcc-and-bpftrace-tooling/
│   ├── README.md                             (12 tasks, 6 challenges)
│   ├── docs/                                 (3 deep dives)
│   ├── examples/
│   │   ├── bcc/                              (Python + C examples)
│   │   └── bpftrace/                         (Script examples)
│   ├── lab/                                  (2 interactive labs)
│   └── tools/                                (setup scripts)
│
├── level-03-libbpf-and-core-programming/
│   ├── README.md                             (12 tasks, 6 challenges)
│   ├── docs/                                 (CO-RE, skeletons, etc.)
│   ├── examples/                             (libbpf C programs)
│   ├── src/                                  (source templates)
│   ├── lab/                                  (verifier debugging)
│   └── tools/                                (libbpf setup)
│
├── level-04-ebpf-networking-observability-security/
│   ├── README.md                             (15 tasks, 8 challenges)
│   ├── docs/                                 (XDP, tc, LSM, observability)
│   ├── examples/
│   │   ├── xdp/                              (Packet processing)
│   │   ├── tc/                               (Traffic control)
│   │   ├── lsm/                              (Security policies)
│   │   └── observability/                    (Exporters)
│   ├── k8s/                                  (Kubernetes manifests)
│   └── tools/                                (Setup scripts)
│
└── level-05-production-agent-and-hardening/  (Coming soon)
    ├── README.md
    ├── agent/                                (Complete agent source)
    ├── deployment/                           (Production configs)
    ├── ci-cd/                                (Build pipelines)
    └── docs/                                 (Operations guides)
```

---

## Learning Approach

### Each Level Includes:

1. **Comprehensive README**
   - Clear learning objectives
   - 10-15 practical tasks
   - 5-8 real-world challenges
   - Production patterns

2. **Working Code**
   - Real, tested examples (not pseudocode)
   - Build systems (Makefiles)
   - Complete programs you can run

3. **In-Depth Documentation**
   - Deep dives into concepts
   - Architecture explanations
   - Decision guides
   - Best practices

4. **Interactive Labs**
   - Guided hands-on exercises
   - Step-by-step walkthroughs
   - Immediate feedback

5. **Real-World Challenges**
   - Production scenarios
   - Debugging exercises
   - Performance optimization
   - Operational issues

---

## Pedagogical Principles

### 1. Production-Oriented
Every concept is tied to real-world use cases. Learn patterns used by:
- **Cilium/Hubble**: Network observability
- **Tetragon/Falco**: Security monitoring
- **Pixie/Parca**: Continuous profiling
- **Katran**: Load balancing

### 2. Hands-On First
- Run code before deep theory
- See it working, then understand why
- Immediate feedback loop

### 3. Systematic Progression
- Each level builds on previous knowledge
- No gaps in understanding
- Smooth learning curve

### 4. Troubleshooting Emphasis
- Challenges force real debugging
- Learn to fix common issues
- Build production resilience

### 5. No Hand-Waving
- Real commands, real output
- Complete build systems
- Production-ready patterns

---

## Prerequisites

### Hardware
- x86_64 or ARM64 Linux system
- 4GB+ RAM (8GB recommended)
- 20GB+ free disk space

### Software
- Linux kernel 5.10+ (recommended)
  - Minimum 4.18 for basic features
  - 5.10 LTS for full experience
- Ubuntu 20.04+, Fedora 33+, or equivalent
- Root access (or sudo)

### Skills
- **Required**:
  - Basic Linux command line
  - Understanding of C programming
  - Familiarity with systems programming concepts

- **Helpful but not required**:
  - Kernel basics
  - Networking fundamentals
  - Go or Python

### Time Commitment
- **Casual**: 5-10 hours/week → 4-6 months
- **Focused**: 15-20 hours/week → 2-3 months
- **Intensive**: 30+ hours/week → 1-2 months

---

## Quick Start

### 1. Clone Repository
```bash
cd ~/development/git/abz/EBPF
```

### 2. Start Level 01
```bash
cd level-01-linux-and-ebpf-foundations/

# Read the guide
cat README.md

# Set up environment
sudo ./tools/setup-environment.sh
./tools/verify-setup.sh

# Run first lab
cd lab/
./01-check-kernel-support.sh
```

### 3. Work Through Systematically
- Complete all tasks in order
- Don't skip challenges
- Take notes on gotchas
- Build your own examples

### 4. Track Progress
Create a learning journal:
```bash
# Example journal.md
## Level 01
- [x] Task 1: Kernel config audit
- [x] Task 2: BTF check
- [x] Challenge 1: Missing BTF - learned to use non-CO-RE fallback
- [ ] Task 3: ...
```

---

## Getting Help

### Built-in Resources
Each level includes:
- Detailed documentation
- Working examples
- Troubleshooting guides
- References to official docs

### External Resources
- [eBPF.io](https://ebpf.io/) - Official eBPF site
- [Cilium Docs](https://docs.cilium.io/en/stable/bpf/) - Excellent BPF reference
- [Kernel BPF Docs](https://www.kernel.org/doc/html/latest/bpf/) - Official kernel docs
- [libbpf GitHub](https://github.com/libbpf/libbpf) - libbpf source and examples

### Community
- [eBPF Slack](https://ebpf.io/slack) - Active community
- [Cilium Slack](https://cilium.io/slack) - Cilium-specific help
- Stack Overflow: [ebpf] tag

---

## Success Criteria

### Level 01 Complete
- [ ] Can explain eBPF VM, verifier, JIT
- [ ] Comfortable with bpftool inspection
- [ ] Understand BTF and CO-RE concepts
- [ ] Loaded and debugged a basic program

### Level 02 Complete
- [ ] Used 10+ BCC tools effectively
- [ ] Written custom BCC/bpftrace scripts
- [ ] Understand tool overhead and optimization
- [ ] Know when to use which tool

### Level 03 Complete
- [ ] Written portable libbpf programs
- [ ] Debugged complex verifier errors
- [ ] Used ring buffers for event streaming
- [ ] Packaged programs for distribution

### Level 04 Complete
- [ ] Built XDP packet processors
- [ ] Integrated eBPF with observability stacks
- [ ] Implemented security policies with LSM
- [ ] Deployed to Kubernetes

### Level 05 Complete (Planned)
- [ ] Built production-ready agent
- [ ] Implemented CI/CD pipeline
- [ ] Tuned for production performance
- [ ] Handled multi-tenancy concerns

---

## What You'll Master

By completing this curriculum, you will be able to:

✓ **Design** eBPF-based systems for observability, networking, and security
✓ **Write** production-grade eBPF programs in C with libbpf
✓ **Debug** verifier errors and performance issues systematically
✓ **Deploy** eBPF agents to Kubernetes at scale
✓ **Integrate** with Prometheus, Grafana, OpenTelemetry
✓ **Implement** security policies with LSM hooks
✓ **Build** XDP/tc-based packet processors
✓ **Optimize** for production performance and overhead
✓ **Handle** kernel compatibility and portability
✓ **Understand** patterns from Cilium, Tetragon, Falco, Pixie

---

## Career Outcomes

### Roles You'll Be Ready For
- eBPF Engineer
- Observability Engineer
- Cloud Native Platform Engineer
- Site Reliability Engineer (SRE) with eBPF focus
- Security Engineer (runtime security)
- Performance Engineer

### Companies Using eBPF
- **Networking**: Cilium, Isovalent, Cloudflare
- **Observability**: Datadog, New Relic, Grafana Labs
- **Security**: Aqua Security, Sysdig, Falco
- **Cloud Providers**: Google, Meta, Netflix, Cloudflare
- **Many more**: Any company doing cloud-native observability/security

---

## Testimonials (Simulated - Your Journey)

> "Started knowing nothing about eBPF. After 3 months working through this curriculum, I built a production observability agent deployed to our Kubernetes clusters. The systematic approach and real-world challenges were exactly what I needed." - Future You

> "The hands-on labs and working code examples made all the difference. Unlike other eBPF resources that hand-wave, this curriculum forces you to debug real issues." - Future You

> "Level 04's integration with Prometheus and Grafana was game-changing. I went from theory to running dashboards in days." - Future You

---

## Next Steps

### Ready to Begin?

```bash
# Start your eBPF mastery journey
cd level-01-linux-and-ebpf-foundations/
cat README.md

# Set up
sudo ./tools/setup-environment.sh

# Begin
cd lab/
./01-check-kernel-support.sh
```

### Stay Consistent
- Set regular learning time (e.g., 2 hours/day)
- Complete one level before moving to next
- Don't skip challenges - they build crucial skills
- Build your own projects alongside curriculum

### Track Progress
- Keep a learning journal
- Share what you learn (blog, Twitter, etc.)
- Contribute back (PRs welcome!)

---

## License

All code examples: **GPL-2.0** (eBPF requirement)
Documentation: **CC BY-SA 4.0**

---

**Your eBPF mastery journey starts now. Go to Level 01 and begin! 🚀**
