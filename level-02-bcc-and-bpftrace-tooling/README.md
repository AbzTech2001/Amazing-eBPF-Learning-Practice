# Level 02: BCC, bpftrace & Core Tracing Tools

## Overview

This level teaches you to use **high-level eBPF tracing tools** that abstract away the complexity of raw eBPF programming. You'll learn to write powerful tracing scripts in minutes instead of hours.

**Goal**: Master BCC and bpftrace for rapid prototyping, performance analysis, and troubleshooting. Understand when to use high-level tools vs. low-level libbpf programming.

---

## Prerequisites

Complete **Level 01** and ensure you have:
- Understanding of eBPF architecture, verifier, BTF
- Working eBPF environment (kernel 4.18+, preferably 5.10+)
- bpftool installed and working

---

## Tools Covered

### BCC (BPF Compiler Collection)

**What**: Python framework for writing eBPF programs with embedded C
- **Pros**: Rich ecosystem, many ready-to-use tools, good for complex logic
- **Cons**: Python dependency, slower startup, larger footprint
- **Use case**: Complex tracing, custom analysis tools, production monitoring

### bpftrace

**What**: High-level scripting language for one-liners and quick scripts
- **Pros**: Concise syntax, fast prototyping, awk-like simplicity
- **Cons**: Limited for complex logic, less suitable for long-running agents
- **Use case**: Ad-hoc analysis, one-liners, quick debugging

### Comparison Table

| Feature | BCC | bpftrace | libbpf (Level 03) |
|---------|-----|----------|-------------------|
| **Language** | Python + C | Domain-specific | C |
| **Learning curve** | Medium | Easy | Hard |
| **Startup time** | Slow (compiles at runtime) | Fast | Fastest (pre-compiled) |
| **Flexibility** | High | Medium | Highest |
| **Portability** | Requires headers | Requires headers | CO-RE (portable) |
| **Production use** | Yes (with caveats) | Quick debugging | Preferred |
| **Dependencies** | Python, LLVM, headers | LLVM, headers | Minimal |

---

## Concepts Introduced

### 1. BCC Architecture

```
┌─────────────────────────────────────────────────────┐
│  Python User-Space Script                           │
│  ┌──────────────────────────────────────────┐      │
│  │  from bcc import BPF                      │      │
│  │                                            │      │
│  │  prog = """                                │      │
│  │  int kprobe__sys_clone(void *ctx) {       │      │
│  │      bpf_trace_printk("clone called");    │      │
│  │      return 0;                             │      │
│  │  }                                         │      │
│  │  """                                       │      │
│  │                                            │      │
│  │  b = BPF(text=prog)                       │      │
│  │  b.trace_print()                          │      │
│  └──────────────────────────────────────────┘      │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  BCC Framework       │
        │  - Compiles C code   │
        │  - Loads into kernel │
        │  - Manages maps      │
        │  - Reads output      │
        └──────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Kernel eBPF Program │
        └──────────────────────┘
```

### 2. bpftrace Architecture

```
┌─────────────────────────────────────────────────────┐
│  bpftrace One-Liner or Script                       │
│                                                      │
│  bpftrace -e 'kprobe:sys_clone {                   │
│      printf("clone by PID %d\n", pid);             │
│  }'                                                  │
│                                                      │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  bpftrace Runtime    │
        │  - Parses script     │
        │  - Generates BPF     │
        │  - Compiles (LLVM)   │
        │  - Loads & runs      │
        └──────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Kernel eBPF Program │
        └──────────────────────┘
```

### 3. Probe Types

Both BCC and bpftrace support multiple probe types:

| Probe Type | Syntax (bpftrace) | Syntax (BCC) | Use Case |
|------------|-------------------|--------------|----------|
| **kprobe** | `kprobe:func_name` | `kprobe__func_name` | Trace any kernel function |
| **kretprobe** | `kretprobe:func_name` | `kretprobe__func_name` | Trace kernel function returns |
| **tracepoint** | `tracepoint:category:name` | `TRACEPOINT_PROBE(category, name)` | Stable kernel tracing points |
| **uprobe** | `uprobe:/path:func` | `attach_uprobe(name=...)` | Trace user-space functions |
| **uretprobe** | `uretprobe:/path:func` | `attach_uretprobe(name=...)` | Trace user-space returns |
| **USDT** | `usdt:/path:probe` | `attach_usdt(...)` | User Statically Defined Tracepoints |
| **software** | `software:event:count` | `attach_perf_event(...)` | CPU cycles, instructions, etc. |
| **hardware** | `hardware:event:count` | `attach_perf_event(...)` | Hardware performance counters |

---

## Tools & Dependencies

### Install BCC

```bash
# Ubuntu/Debian
sudo apt install bpfcc-tools python3-bpfcc libbpfcc-dev

# Fedora
sudo dnf install bcc-tools python3-bcc bcc-devel

# Arch
sudo pacman -S bcc bcc-tools python-bcc
```

### Install bpftrace

```bash
# Ubuntu 20.04+
sudo apt install bpftrace

# Fedora
sudo dnf install bpftrace

# Or build from source for latest features
git clone https://github.com/iovisor/bpftrace
cd bpftrace
./build.sh
```

### Verify Installation

```bash
# Check BCC
python3 -c "from bcc import BPF; print('BCC OK')"

# Check bpftrace
bpftrace --version

# List BCC tools
ls /usr/share/bcc/tools/

# Run bpftrace one-liner
sudo bpftrace -e 'BEGIN { printf("bpftrace works!\n"); exit(); }'
```

---

## BCC Deep Dive

### BCC Tool Collection

BCC ships with **100+ ready-to-use tools**:

```bash
/usr/share/bcc/tools/
├── execsnoop        # Trace process execution
├── opensnoop        # Trace file opens
├── biolatency       # Block I/O latency histogram
├── tcpconnect       # Trace TCP active connections
├── tcpaccept        # Trace TCP passive connections
├── runqlat          # Scheduler run queue latency
├── profile          # CPU profiler
├── funccount        # Count kernel/user function calls
└── ... (90+ more)
```

### BCC Script Structure

```python
#!/usr/bin/env python3
from bcc import BPF

# 1. Define eBPF program (C code as string)
prog = """
#include <uapi/linux/ptrace.h>

int kprobe__sys_clone(struct pt_regs *ctx) {
    bpf_trace_printk("Process cloned!\\n");
    return 0;
}
"""

# 2. Compile and load
b = BPF(text=prog)

# 3. Read output
print("Tracing sys_clone... Ctrl-C to stop")
b.trace_print()
```

### BCC Maps

```python
# Define map in C code
prog = """
BPF_HASH(counts, u32, u64);  // key=PID, value=count

int count_events(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *val, zero = 0;

    val = counts.lookup_or_try_init(&pid, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
"""

b = BPF(text=prog)
# ... attach to probe ...

# Read map from Python
for k, v in b["counts"].items():
    print(f"PID {k.value}: {v.value} events")
```

---

## bpftrace Deep Dive

### bpftrace Syntax

```bash
# One-liner format
bpftrace -e 'probe_type:target { actions }'

# Script format
bpftrace script.bt
```

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `pid` | Process ID |
| `tid` | Thread ID |
| `uid` | User ID |
| `gid` | Group ID |
| `comm` | Process name (16 chars) |
| `nsecs` | Nanosecond timestamp |
| `cpu` | CPU ID |
| `curtask` | Current task_struct pointer |
| `arg0..argN` | Function arguments |
| `retval` | Return value (kretprobe) |

### Built-in Functions

| Function | Purpose |
|----------|---------|
| `printf()` | Print formatted output |
| `time()` | Print timestamp |
| `system()` | Execute shell command |
| `exit()` | Exit bpftrace |
| `@map[key] = value` | Store in map |
| `count()` | Count events |
| `hist()` | Create histogram |
| `lhist()` | Linear histogram |
| `sum()` | Sum values |
| `avg()` | Average values |

### Examples

```bash
# Trace syscalls by process
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Measure syscall latency
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @start[tid] = nsecs; }
             tracepoint:raw_syscalls:sys_exit /@start[tid]/ {
                 @latency = hist(nsecs - @start[tid]);
                 delete(@start[tid]);
             }'

# Trace file opens with filename
bpftrace -e 'tracepoint:syscalls:sys_enter_openat {
                 printf("%s opened %s\n", comm, str(args->filename));
             }'
```

---

## Practical Tasks (12)

### Task 1: Trace Process Execution with BCC
**Objective**: Use BCC's execsnoop to monitor process execution.

```bash
# Run execsnoop
sudo /usr/share/bcc/tools/execsnoop

# In another terminal, run commands
ls /tmp
echo "test"

# Observe output
```

**Deliverable**: Screenshot showing execsnoop capturing your commands.

---

### Task 2: Write a Custom BCC Script
**Objective**: Create a BCC script to count open() syscalls per process.

Use the template in `examples/bcc/opencount.py`.

**Steps**:
1. Copy template
2. Attach to openat syscall tracepoint
3. Count per PID
4. Print results

**Deliverable**: Working script that shows top processes by open() calls.

---

### Task 3: bpftrace One-Liner for TCP Connections
**Objective**: Trace TCP connection attempts.

```bash
sudo bpftrace -e 'kprobe:tcp_connect {
    printf("TCP connect by PID %d (%s)\n", pid, comm);
}'
```

**Challenge**: Modify to print destination IP and port.

**Deliverable**: Enhanced one-liner showing IP:port.

---

### Task 4: Block I/O Latency Histogram
**Objective**: Measure disk I/O latency distribution.

```bash
sudo /usr/share/bcc/tools/biolatency
```

**Steps**:
1. Run biolatency
2. Generate I/O load: `dd if=/dev/zero of=/tmp/test bs=1M count=100`
3. Observe histogram

**Deliverable**: Explain the histogram output (usecs, distribution).

---

### Task 5: CPU Profiling with BCC profile
**Objective**: Profile CPU usage and generate flame graphs.

```bash
# Profile all CPUs for 10 seconds
sudo /usr/share/bcc/tools/profile -F 99 -f 10

# Profile specific PID
sudo /usr/share/bcc/tools/profile -p <PID> 10
```

**Deliverable**: Identify hottest kernel/user functions in your system.

---

### Task 6: Write a bpftrace Script for Syscall Tracing
**Objective**: Create a script that tracks syscall frequency per process.

Template in `examples/bpftrace/syscall_count.bt`.

**Deliverable**: Script showing top 10 processes by syscall count.

---

### Task 7: Trace File I/O Latency
**Objective**: Measure read/write latency for files.

Use `examples/bpftrace/file_io_latency.bt`.

**Steps**:
1. Run script
2. Create file I/O: `cat /var/log/syslog > /dev/null`
3. Observe latency histogram

**Deliverable**: Histogram showing read latency distribution.

---

### Task 8: Monitor Network Packet Drops
**Objective**: Detect when/why packets are dropped.

```bash
sudo bpftrace -e 'tracepoint:skb:kfree_skb {
    @drops[stack] = count();
}'
```

**Deliverable**: Generate drops (e.g., firewall rules) and capture stack traces.

---

### Task 9: Scheduler Run Queue Latency
**Objective**: Measure how long processes wait in run queue.

```bash
sudo /usr/share/bcc/tools/runqlat
```

**Deliverable**: Explain why high runqlat indicates CPU saturation.

---

### Task 10: Trace Memory Allocations
**Objective**: Track memory allocations by function.

```bash
sudo /usr/share/bcc/tools/stackcount -P t:kmem:kmalloc
```

**Deliverable**: Identify top allocation sites.

---

### Task 11: Custom Uprobe for User-Space Function
**Objective**: Trace a function in a user-space binary.

Example: Trace `malloc()` in a running process.

```bash
sudo bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc {
    printf("malloc(%d) by %s\n", arg0, comm);
}'
```

**Deliverable**: Trace malloc in a specific process and show output.

---

### Task 12: Compare BCC vs bpftrace for Same Task
**Objective**: Implement the same functionality (e.g., count opens) in both.

- BCC: `examples/bcc/opencount.py`
- bpftrace: `examples/bpftrace/opencount.bt`

**Deliverable**: Compare code size, readability, performance, startup time.

---

## Real-World Challenges (6)

### Challenge 1: High Overhead - Event Flood
**Scenario**: You attach to a high-frequency event (e.g., all syscalls on a busy server).

**Problem**:
- System becomes unresponsive
- bpftrace/BCC outputs megabytes per second
- Potential event loss

**Your Task**:
1. Reproduce: `sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { printf("%s\n", comm); }'`
2. Observe system load
3. Implement solutions:
   - **Sampling**: Only trace 1 in 100 events
   - **Filtering**: Only trace specific PIDs/comms
   - **Aggregation**: Use maps instead of printing every event

**Deliverable**: Show before/after CPU usage with optimized tracing.

---

### Challenge 2: Missing Kernel Headers
**Scenario**: BCC script fails with "failed to compile BPF text".

**Problem**:
```
error: 'struct task_struct' has no member named 'some_field'
```

**Cause**: BCC needs kernel headers, but they don't match running kernel.

**Your Task**:
1. Identify kernel version: `uname -r`
2. Check headers: `ls /usr/src/linux-headers-$(uname -r)`
3. Install if missing: `sudo apt install linux-headers-$(uname -r)`
4. If headers unavailable (e.g., custom kernel), use BTF/CO-RE approach (Level 03)

**Deliverable**: Document kernel header troubleshooting steps.

---

### Challenge 3: Interpreting Histograms
**Scenario**: You run biolatency and see:

```
     usecs               : count     distribution
         0 -> 1          : 0        |                    |
         2 -> 3          : 5        |**                  |
         4 -> 7          : 50       |********************|
         8 -> 15         : 30       |************        |
        16 -> 31         : 10       |****                |
        32 -> 63         : 2        |*                   |
```

**Your Task**:
1. Explain what this histogram tells you
2. Calculate median, p95, p99
3. Determine if I/O is fast or slow
4. Identify if it's SSD or HDD based on latency profile

**Deliverable**: Analysis report with performance assessment.

---

### Challenge 4: Stack Trace Interpretation
**Scenario**: You trace kernel panics or packet drops and get stack traces:

```
@drops[
    ip_rcv+0x1c
    __netif_receive_skb+0x85
    process_backlog+0x9a
]: 42
```

**Your Task**:
1. Look up functions in kernel source or `/proc/kallsyms`
2. Understand the call chain (bottom = deepest)
3. Correlate with kernel subsystem (networking, filesystem, etc.)
4. Identify root cause (e.g., firewall dropping, socket buffer full)

**Deliverable**: Root cause analysis of a real or simulated drop scenario.

---

### Challenge 5: Probe Point Doesn't Exist
**Scenario**: Your bpftrace script fails:

```
bpftrace -e 'kprobe:some_function { ... }'
Error: Could not resolve symbol: some_function
```

**Causes**:
- Function inlined (no separate symbol)
- Function name changed in your kernel version
- Function in a module not loaded

**Your Task**:
1. List available kprobes: `sudo bpftrace -l 'kprobe:*some*'`
2. Check if function exists: `grep some_function /proc/kallsyms`
3. Find alternative: Use tracepoint instead (more stable)
4. Use wildcard: `kprobe:*partial_name*`

**Deliverable**: Document how to find correct probe points for any kernel version.

---

### Challenge 6: Production Performance Impact
**Scenario**: You deploy a BCC script in production. After hours, you notice:
- 5% CPU overhead
- Memory usage growing
- Occasional "lost events" messages

**Your Task**:
1. **Profile the profiler**: Check BCC script's own CPU/memory usage
2. **Identify issues**:
   - Too many events?
   - Map not being cleared?
   - Printing to stdout (slow)?
3. **Optimize**:
   - Add rate limiting
   - Clear maps periodically
   - Use ring buffer instead of printk
   - Sample instead of tracing 100%

**Deliverable**: Optimized production-ready version with <1% overhead.

---

## When to Use What?

### Use bpftrace when:
- Quick debugging, ad-hoc analysis
- One-liners or short scripts
- Exploring what to trace before building full tool
- You need answer in minutes, not hours

### Use BCC when:
- Complex logic (multi-map, state machines)
- Need Python integration (post-processing, databases)
- Building reusable tools
- Production monitoring with long-running agents

### Use libbpf (Level 03) when:
- Production deployment at scale
- Need portability across kernel versions (CO-RE)
- Minimal dependencies required
- Performance critical (no runtime compilation)

---

## Performance Considerations

### Overhead Sources

1. **Event frequency**: More events = more overhead
2. **Per-event work**: Complex logic per event
3. **Data copying**: Sending large data to user-space
4. **Output**: `printf()` is expensive

### Optimization Strategies

```bash
# BAD: Prints every syscall (massive overhead)
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { printf("%s\n", comm); }'

# BETTER: Aggregate, then print
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# BEST: Filter + aggregate
bpftrace -e 'tracepoint:raw_syscalls:sys_enter /comm == "nginx"/ { @[comm] = count(); }'
```

### Sampling

```bash
# Trace 1 in 100 events
bpftrace -e 'kprobe:tcp_sendmsg /rand() % 100 == 0/ { ... }'

# Time-based sampling (every 10ms)
bpftrace -e 'profile:ms:10 { ... }'
```

---

## Gotchas and Limitations

### BCC Gotchas
1. **Compile time**: Compiles on every run (slow startup)
2. **Kernel headers**: Required and must match kernel
3. **Python dependency**: Not ideal for minimal environments
4. **LLVM/clang**: Large dependencies

### bpftrace Gotcas
1. **Limited string support**: 64-char limit for strings
2. **No loops**: Must use unrolling or alternative approaches
3. **Map limitations**: Harder to build complex state
4. **Verifier friendly**: Must follow eBPF constraints

### Both
1. **Lost events**: High event rates can overflow buffers
2. **No persistent state**: Restart = lose all data
3. **Kernel version differences**: Probes may not exist on all kernels

---

## Learning Checklist

By the end of Level 02, you should be able to:

- [ ] Install and verify BCC and bpftrace
- [ ] Use BCC tools for CPU, disk, network, and process analysis
- [ ] Write custom BCC Python scripts with maps and probes
- [ ] Write bpftrace one-liners for common tracing tasks
- [ ] Create bpftrace scripts with histograms and aggregation
- [ ] Interpret histogram outputs and stack traces
- [ ] Understand overhead implications and optimization strategies
- [ ] Choose appropriate tool (BCC vs bpftrace vs libbpf) for each use case
- [ ] Debug common issues (missing headers, probe points, high overhead)
- [ ] Apply filtering and sampling to reduce performance impact

---

## Next Steps

Once you've mastered BCC and bpftrace:

**Level 03**: Programming eBPF with libbpf & CO-RE
- Write C-based eBPF programs with libbpf
- Use CO-RE for portability across kernel versions
- Master skeletons, ring buffers, and advanced maps
- Handle verifier errors systematically

---

## References

- [BCC Documentation](https://github.com/iovisor/bcc)
- [BCC Tool Reference](https://github.com/iovisor/bcc/tree/master/tools)
- [bpftrace Documentation](https://github.com/iovisor/bpftrace)
- [bpftrace Reference Guide](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [BCC Python Developer Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)

---

**Ready to start? Run `./tools/setup-bcc-bpftrace.sh` to install all dependencies!**
