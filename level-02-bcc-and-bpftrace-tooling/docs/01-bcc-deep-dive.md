# BCC (BPF Compiler Collection) Deep Dive

## Overview

BCC is a toolkit for creating efficient kernel tracing and manipulation programs using eBPF. It provides Python and Lua bindings for writing the user-space portion while embedding C code for the kernel-space eBPF program.

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│          User Application (Python/Lua)             │
│  ┌──────────────────────────────────────────────┐ │
│  │  High-level logic:                           │ │
│  │  - Define eBPF program (C code as string)    │ │
│  │  - Load and attach                           │ │
│  │  - Process events/maps                       │ │
│  │  - Format output                             │ │
│  └───────────────────┬──────────────────────────┘ │
└────────────────────────┼──────────────────────────┘
                         │
                         ▼
          ┌──────────────────────────┐
          │    BCC Framework         │
          │  ┌────────────────────┐  │
          │  │ - Parse C code     │  │
          │  │ - Rewrite helpers  │  │
          │  │ - Call clang/LLVM  │  │
          │  │ - Load via libbpf  │  │
          │  │ - Manage maps      │  │
          │  └────────────────────┘  │
          └──────────┬───────────────┘
                     │
                     ▼
          ┌──────────────────────────┐
          │   Kernel (eBPF Runtime)  │
          │  - Verifier              │
          │  - JIT compiler          │
          │  - Program execution     │
          │  - Maps                  │
          └──────────────────────────┘
```

---

## Installation

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc libbpfcc-dev
```

### Fedora/RHEL

```bash
sudo dnf install -y bcc-tools python3-bcc bcc-devel
```

### From Source

```bash
git clone https://github.com/iovisor/bcc.git
cd bcc
mkdir build && cd build
cmake ..
make
sudo make install
```

---

## BCC Script Structure

### Minimal Example

```python
#!/usr/bin/env python3
from bcc import BPF

# eBPF program (C code)
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Compile and load
b = BPF(text=prog)

# Attach to kprobe
b.attach_kprobe(event="sys_clone", fn_name="hello")

# Read trace output
print("Tracing... Ctrl-C to stop")
b.trace_print()
```

### Components Explained

1. **Import BCC**: `from bcc import BPF`

2. **Define eBPF program**: C code as a Python string
   - Must be valid C
   - Can use BCC macros and helpers
   - Embedded in Python for flexibility

3. **Compile and load**: `b = BPF(text=prog)`
   - Parses C code
   - Compiles with clang/LLVM
   - Loads into kernel
   - Verifier checks

4. **Attach**: `b.attach_kprobe(...)` or similar
   - Connects program to hook point
   - Multiple attach methods for different probe types

5. **Process output**: Maps, perf buffers, or trace_print()

---

## BCC Macros and Data Structures

### Maps

```python
# Hash map
BPF_HASH(name, key_type, value_type, max_entries)

# Example:
BPF_HASH(counts, u32, u64, 10240);
```

Map types:

| Macro | Type | Use Case |
|-------|------|----------|
| `BPF_HASH` | Hash table | General key-value storage |
| `BPF_ARRAY` | Array | Index-based access |
| `BPF_PERCPU_HASH` | Per-CPU hash | High-performance counters |
| `BPF_PERCPU_ARRAY` | Per-CPU array | Per-CPU data |
| `BPF_STACK_TRACE` | Stack trace | Store stack traces |
| `BPF_PERF_OUTPUT` | Perf buffer | Stream events to user-space |
| `BPF_RING_BUF` | Ring buffer | Modern event streaming (kernel 5.8+) |

### Map Operations (in C)

```c
// Lookup
value_type *val = map.lookup(&key);

// Update
map.update(&key, &value);

// Delete
map.delete(&key);

// Increment (atomic)
map.increment(key);

// Lookup or init
value_type *val = map.lookup_or_try_init(&key, &zero);
```

### Tracepoint Probe

```c
TRACEPOINT_PROBE(category, event)
{
    // Access fields via args->field_name
    u32 pid = args->common_pid;

    return 0;
}
```

### Kprobe/Kretprobe

```c
// Kprobe (function entry)
int kprobe__function_name(struct pt_regs *ctx)
{
    // arg0 = PT_REGS_PARM1(ctx)
    // arg1 = PT_REGS_PARM2(ctx)
    // ...

    return 0;
}

// Kretprobe (function return)
int kretprobe__function_name(struct pt_regs *ctx)
{
    // retval = PT_REGS_RC(ctx)

    return 0;
}
```

---

## Python API

### Loading

```python
# From text
b = BPF(text=prog)

# From file
b = BPF(src_file="program.c")

# With debug
b = BPF(text=prog, debug=0x3)  # Show verifier log
```

### Attaching

```python
# Kprobe
b.attach_kprobe(event="function_name", fn_name="bpf_function")

# Kretprobe
b.attach_kretprobe(event="function_name", fn_name="bpf_function")

# Tracepoint (automatic from TRACEPOINT_PROBE macro)

# Uprobe (user-space)
b.attach_uprobe(name="/bin/bash", sym="readline", fn_name="trace_readline")

# USDT
b.attach_usdt(pid=pid, path="/path/to/binary", provider="provider", probe="probe", fn_name="bpf_func")
```

### Reading Maps

```python
# Get map
counts = b["counts"]

# Iterate
for k, v in counts.items():
    print(f"Key: {k.value}, Value: {v.value}")

# Lookup specific key
val = counts[ctypes.c_uint(123)]

# Clear map
counts.clear()

# Print histogram
b["latency"].print_log2_hist("Latency (us)")
```

### Perf Buffer

```python
# Define callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, Comm: {event.comm.decode()}")

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll for events
while True:
    b.perf_buffer_poll()
```

---

## Common Patterns

### Pattern 1: Count Events per Key

```python
prog = """
BPF_HASH(counts, u32);  // Key: PID

int count_events(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0, *val;

    val = counts.lookup_or_try_init(&pid, &zero);
    if (val) {
        (*val)++;
    }

    return 0;
}
"""
```

### Pattern 2: Measure Latency

```python
prog = """
BPF_HASH(start, u64);  // Key: TID, Value: timestamp

int trace_entry(void *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

int trace_exit(void *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;

    tsp = start.lookup(&tid);
    if (tsp) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("Latency: %llu ns\\n", delta);
        start.delete(&tid);
    }

    return 0;
}
"""
```

### Pattern 3: Stream Events

```python
prog = """
struct event_t {
    u32 pid;
    char comm[16];
    u64 ts;
};

BPF_PERF_OUTPUT(events);

int trace_event(void *ctx) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.ts = bpf_ktime_get_ns();

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""

b = BPF(text=prog)
# ... attach ...

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{event.ts}: {event.comm.decode()} (PID {event.pid})")

b["events"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
```

---

## BCC Tools

BCC ships with 100+ ready-to-use tools in `/usr/share/bcc/tools/`:

### Process Monitoring

- `execsnoop` - Trace process execution
- `killsnoop` - Trace kill signals
- `offcputime` - Measure off-CPU time
- `profile` - CPU profiler

### File I/O

- `opensnoop` - Trace file opens
- `filetop` - File reads/writes top
- `filelife` - File lifetime tracking
- `vfsstat` - VFS statistics

### Networking

- `tcpconnect` - Trace TCP active connections
- `tcpaccept` - Trace TCP passive connections
- `tcpretrans` - Trace TCP retransmissions
- `tcpdrop` - Trace TCP packet drops
- `tcplife` - TCP connection lifespan

### Disk I/O

- `biolatency` - Block I/O latency histogram
- `biosnoop` - Block I/O tracing
- `biotop` - Block I/O top

### System

- `runqlat` - Run queue latency
- `cpudist` - CPU usage distribution
- `syscount` - System call counts
- `argdist` - Argument distribution

---

## Performance Considerations

### Overhead Sources

1. **Compilation time**: BCC compiles at runtime (slow startup)
2. **Python overhead**: Interpreted language adds latency
3. **Data copying**: Events copied to user-space
4. **Print overhead**: `bpf_trace_printk` is slow

### Optimization Strategies

1. **Aggregate in kernel**:
   ```c
   // Bad: send every event
   events.perf_submit(ctx, &event, sizeof(event));

   // Good: aggregate in map
   counts.increment(key);
   ```

2. **Use per-CPU maps**: Avoid lock contention
   ```c
   BPF_PERCPU_HASH(counts, u32, u64);
   ```

3. **Filter early**: Reduce events processed
   ```c
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   if (pid != target_pid) {
       return 0;
   }
   ```

4. **Sample**: Don't trace every event
   ```c
   if (bpf_get_prandom_u32() % 100 != 0) {
       return 0;  // Sample 1%
   }
   ```

---

## Debugging

### Enable Debug Output

```python
b = BPF(text=prog, debug=0x3)
```

Debug levels:
- `0x1`: LLVM IR
- `0x2`: BPF bytecode
- `0x4`: Verifier log

### Common Errors

**Error**: `"error: unknown type name 'u32'"`
**Fix**: Include proper headers or use `__u32`

**Error**: `"failed to compile BPF text"`
**Fix**: Check C syntax, includes, and BCC version

**Error**: `"invalid argument for function call"`
**Fix**: Check helper function availability for your probe type

---

## Summary

| Feature | Details |
|---------|---------|
| **Language** | Python + embedded C |
| **Pros** | Rich ecosystem, 100+ tools, good for complex logic |
| **Cons** | Slow startup, Python dependency, kernel headers required |
| **Best for** | Complex analysis, production monitoring, reusable tools |

---

## Next Steps

1. Explore BCC tools: `ls /usr/share/bcc/tools/`
2. Read tool source code to learn patterns
3. Write your own custom BCC scripts
4. Move to `02-bpftrace-deep-dive.md`

---

## References

- [BCC GitHub](https://github.com/iovisor/bcc)
- [BCC Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [BCC Python Developer Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)
