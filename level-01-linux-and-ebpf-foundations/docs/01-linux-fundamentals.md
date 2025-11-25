# Linux Fundamentals for eBPF

## Overview

Understanding key Linux kernel concepts is essential for effective eBPF development. This document covers the fundamental building blocks that eBPF programs interact with.

---

## 1. System Calls (syscalls)

### What are syscalls?

System calls are the interface between user-space applications and the kernel. When a program needs to perform privileged operations (file I/O, network, process creation), it makes a syscall.

### Common syscalls:

| Syscall | Purpose | eBPF Relevance |
|---------|---------|----------------|
| `open`, `openat` | Open files | File access monitoring |
| `read`, `write` | I/O operations | Performance tracing |
| `execve` | Execute programs | Process monitoring, security |
| `clone`, `fork` | Create processes | Process lineage tracking |
| `connect`, `accept` | Network operations | Network observability |
| `bpf` | Load/manage eBPF programs | How your programs get loaded! |

### How eBPF traces syscalls:

1. **Tracepoints**: Stable hooks at syscall entry/exit
   ```
   /sys/kernel/debug/tracing/events/syscalls/
   ├── sys_enter_open
   ├── sys_exit_open
   ├── sys_enter_execve
   └── ... (hundreds more)
   ```

2. **Kprobes**: Dynamic instrumentation of syscall handlers
   ```c
   SEC("kprobe/__x64_sys_open")
   int trace_open(struct pt_regs *ctx) { ... }
   ```

### Viewing syscalls:

```bash
# See all syscalls a program makes
strace ls /tmp

# Count syscalls
strace -c ls /tmp

# Trace specific syscall
strace -e open ls /tmp
```

---

## 2. procfs (/proc)

### What is procfs?

`/proc` is a virtual filesystem that exposes kernel and process information as files.

### Key directories:

```
/proc/
├── [PID]/              # Per-process information
│   ├── cmdline         # Command line arguments
│   ├── exe             # Symlink to executable
│   ├── fd/             # Open file descriptors
│   ├── maps            # Memory mappings
│   ├── stat            # Process statistics
│   └── status          # Human-readable status
├── sys/                # Kernel parameters (sysctl)
│   └── kernel/
│       └── bpf_stats_enabled   # Enable BPF statistics
├── kallsyms            # Kernel symbol addresses
└── config.gz           # Kernel configuration (if enabled)
```

### eBPF-relevant entries:

```bash
# Kernel symbols (for finding kprobe targets)
cat /proc/kallsyms | grep tcp_

# Kernel config (check BPF features)
zcat /proc/config.gz | grep BPF

# Enable BPF statistics
echo 1 | sudo tee /proc/sys/kernel/bpf_stats_enabled
```

### Using procfs in eBPF:

eBPF programs can't directly read `/proc`, but user-space loaders can use it to:
- Find process information for correlation
- Check kernel features before loading programs
- Read kernel symbols for kprobe attachment

---

## 3. cgroups (Control Groups)

### What are cgroups?

cgroups organize processes into hierarchical groups and apply resource limits and controls.

### cgroup v2 hierarchy:

```
/sys/fs/cgroup/
├── cgroup.controllers      # Available controllers
├── cgroup.procs            # Processes in this cgroup
├── user.slice/             # User sessions
│   └── user-1000.slice/
│       └── session-1.scope/
├── system.slice/           # System services
│   └── docker-xyz.scope/
└── kubepods.slice/         # Kubernetes pods (if applicable)
```

### eBPF and cgroups:

eBPF programs can attach to cgroups for **per-cgroup policy enforcement**:

```c
// Program types that attach to cgroups:
BPF_PROG_TYPE_CGROUP_SKB     // Socket buffer filtering
BPF_PROG_TYPE_CGROUP_SOCK    // Socket creation/binding
BPF_PROG_TYPE_CGROUP_DEVICE  // Device access control
BPF_PROG_TYPE_CGROUP_SYSCTL  // Sysctl access control
```

### Use cases:

- **Network policies**: Allow/deny network traffic per container
- **Resource monitoring**: Track I/O, network, CPU per cgroup
- **Security**: Restrict syscalls, file access per cgroup

### Example:

```bash
# List cgroups for a process
cat /proc/$$/cgroup

# Attach BPF to cgroup (example with bpftool)
bpftool cgroup attach /sys/fs/cgroup/user.slice/ \
    ingress pinned /sys/fs/bpf/my_filter

# List BPF programs attached to cgroups
bpftool cgroup tree
```

---

## 4. Namespaces

### What are namespaces?

Namespaces provide **isolation** of global system resources. Each namespace has its own isolated view.

### Namespace types:

| Namespace | Isolates | eBPF Use Case |
|-----------|----------|---------------|
| **PID** | Process IDs | Track processes across containers |
| **NET** | Network stack | Network tracing per container |
| **MNT** | Mount points | File system observability |
| **UTS** | Hostname | Identify container by hostname |
| **IPC** | IPC resources | Inter-process communication tracing |
| **USER** | User/group IDs | Security monitoring |
| **CGROUP** | cgroup hierarchy | Container isolation |

### Viewing namespaces:

```bash
# List namespaces for a process
ls -l /proc/$$/ns/

# Output:
# lrwxrwxrwx 1 user user 0 ... cgroup -> 'cgroup:[4026531835]'
# lrwxrwxrwx 1 user user 0 ... ipc -> 'ipc:[4026531839]'
# lrwxrwxrwx 1 user user 0 ... mnt -> 'mnt:[4026531840]'
# lrwxrwxrwx 1 user user 0 ... net -> 'net:[4026531992]'
# lrwxrwxrwx 1 user user 0 ... pid -> 'pid:[4026531836]'
```

### eBPF and namespaces:

eBPF programs **run in the init namespace** (host context), not in the process's namespace.

**Challenge**: Correlate events to the correct namespace.

**Solution**: Read namespace ID in eBPF program:

```c
// Example: Get network namespace ID
u64 netns = 0;
struct task_struct *task = (void *)bpf_get_current_task();
BPF_CORE_READ_INTO(&netns, task, nsproxy, net_ns, ns.inum);
```

### Use case: Container observability

When tracing in Kubernetes:
1. eBPF program captures event + namespace ID
2. User-space correlates namespace ID → container → pod name
3. Metrics/logs are tagged with pod name

---

## 5. Network Namespaces (netns)

### What is netns?

Network namespaces provide isolated network stacks: interfaces, routes, firewall rules, sockets.

### Common in containers:

Each Docker container or Kubernetes pod runs in its own netns.

### Viewing netns:

```bash
# List named network namespaces
ip netns list

# Execute command in netns
ip netns exec mynetns ip addr

# Docker containers' netns (hidden by default)
ls /var/run/docker/netns/
```

### eBPF XDP and netns:

XDP programs attach to **physical interfaces** (or veth pairs), which belong to a netns.

```bash
# Attach XDP program to interface in specific netns
ip netns exec mynetns ip link set dev eth0 xdp obj prog.o
```

### Tracing across netns:

When using kprobes/tracepoints, you capture events from **all netns**. To filter:

```c
// Get network namespace ID
u64 netns_id = ...;  // Read from task or socket

// Filter in eBPF or user-space
if (netns_id != target_netns) {
    return 0;  // Ignore
}
```

---

## 6. File Descriptors (FDs)

### What are file descriptors?

FDs are integer handles that represent open files, sockets, pipes, etc.

### Viewing FDs:

```bash
# List all FDs for a process
ls -l /proc/$$/fd/

# See what file descriptor 3 points to
readlink /proc/$$/fd/3
```

### eBPF and FDs:

- **BPF maps/programs** are represented as FDs in user-space
- User-space uses FDs to interact with eBPF objects:
  - Read/write maps
  - Attach programs
  - Pin objects to filesystem

```c
// User-space: open a BPF map
int map_fd = bpf_obj_get("/sys/fs/bpf/my_map");
```

---

## 7. Debugging Interfaces

### trace_pipe

Output from `bpf_printk()` goes here:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### dmesg

Verifier logs and kernel messages:

```bash
sudo dmesg | tail -50
```

### bpftool

Inspect loaded programs and maps:

```bash
sudo bpftool prog list
sudo bpf map dump id 123
```

---

## Summary: Why These Matter for eBPF

| Concept | Why It's Important |
|---------|-------------------|
| **Syscalls** | Most tracing targets; stable tracepoints available |
| **procfs** | Check kernel features, find symbols, debug |
| **cgroups** | Attach per-container policies, resource monitoring |
| **Namespaces** | Container isolation; correlate events to containers |
| **netns** | Network isolation in containers; XDP attachment |
| **File descriptors** | How eBPF objects are accessed in user-space |

---

## Next Steps

1. Explore your system's tracepoints:
   ```bash
   ls /sys/kernel/debug/tracing/events/
   ```

2. Check your cgroup setup:
   ```bash
   mount | grep cgroup
   cat /proc/$$/cgroup
   ```

3. Examine a process's namespaces:
   ```bash
   ls -l /proc/1/ns/
   ```

4. Read the next doc: **02-ebpf-architecture.md**
