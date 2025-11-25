# bpftrace Deep Dive

## Overview

bpftrace is a high-level tracing language for Linux eBPF. It's inspired by awk and C, and designed for quick ad-hoc analysis and debugging.

**Philosophy**: Express tracing logic in as few characters as possible.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  bpftrace Script or One-Liner                       │
│  ┌───────────────────────────────────────────────┐ │
│  │  kprobe:tcp_connect {                         │ │
│  │      printf("TCP connect by %s\n", comm);     │ │
│  │  }                                             │ │
│  └────────────────────┬──────────────────────────┘ │
└─────────────────────────┼────────────────────────────┘
                          │
                          ▼
           ┌──────────────────────────┐
           │  bpftrace Runtime        │
           │  ┌────────────────────┐  │
           │  │ - Parse script     │  │
           │  │ - Generate BPF     │  │
           │  │ - Compile (LLVM)   │  │
           │  │ - Load & attach    │  │
           │  │ - Format output    │  │
           │  └────────────────────┘  │
           └──────────┬───────────────┘
                      │
                      ▼
           ┌──────────────────────────┐
           │  Kernel (eBPF Runtime)   │
           └──────────────────────────┘
```

---

## Installation

### Ubuntu/Debian 20.04+

```bash
sudo apt-get install bpftrace
```

### Fedora

```bash
sudo dnf install bpftrace
```

### Build from Source

```bash
git clone https://github.com/iovisor/bpftrace
cd bpftrace
docker run -ti -v $(pwd):/build:z ubuntu:focal /build/build.sh
```

---

## Syntax Basics

### Structure

```bash
probe_type:target [/filter/] { actions }
```

### One-Liner

```bash
sudo bpftrace -e 'kprobe:sys_clone { printf("clone!\n"); }'
```

### Script File

```bash
#!/usr/bin/env bpftrace

BEGIN
{
    printf("Starting trace...\n");
}

kprobe:sys_clone
{
    @clones = count();
}

END
{
    printf("Total clones: %d\n", @clones);
}
```

Run: `sudo bpftrace script.bt`

---

## Probe Types

### Kprobes

Trace kernel functions dynamically:

```bash
# Entry
kprobe:function_name { }

# Return
kretprobe:function_name { }

# Wildcards
kprobe:vfs_* { }
```

### Tracepoints

Stable kernel instrumentation points:

```bash
tracepoint:category:name { }

# Examples:
tracepoint:syscalls:sys_enter_open { }
tracepoint:sched:sched_switch { }
tracepoint:block:block_rq_issue { }
```

### Uprobes

Trace user-space functions:

```bash
uprobe:/path/to/binary:function { }
uretprobe:/path/to/binary:function { }

# Example:
uprobe:/bin/bash:readline { printf("readline called\n"); }
```

### USDT (User Statically Defined Tracepoints)

```bash
usdt:/path/to/binary:provider:probe { }

# Example (MySQL):
usdt:/usr/sbin/mysqld:mysql:query__start { }
```

### Software/Hardware Events

```bash
# Timer-based profiling
profile:hz:99 { }        # Sample at 99Hz
profile:ms:100 { }       # Every 100ms

# Software events
software:cpu-clock:     { }
software:page-faults:   { }

# Hardware counters
hardware:cpu-cycles:    { }
hardware:instructions:  { }
```

### Special Probes

```bash
BEGIN { }   # Execute once at start
END { }     # Execute once at end
interval:s:1 { }  # Execute every second
```

---

## Built-in Variables

| Variable | Type | Description |
|----------|------|-------------|
| `pid` | int | Process ID |
| `tid` | int | Thread ID |
| `uid` | int | User ID |
| `gid` | int | Group ID |
| `nsecs` | uint64 | Nanosecond timestamp |
| `elapsed` | uint64 | Nanoseconds since bpftrace start |
| `cpu` | int | CPU ID |
| `comm` | string | Process name (16 chars) |
| `kstack` | int | Kernel stack trace |
| `ustack` | int | User stack trace |
| `arg0..argN` | int | Function arguments (kprobes) |
| `args` | struct | Tracepoint arguments |
| `retval` | int | Return value (kretprobe) |
| `func` | string | Function name |
| `probe` | string | Full probe name |
| `curtask` | uint64 | Current task_struct address |
| `cgroup` | uint64 | Cgroup ID |

---

## Built-in Functions

### Output

```bash
printf(fmt, args...)    # Print formatted
print(var)              # Print variable
time(fmt)               # Print timestamp
```

### Aggregations

```bash
@map[key] = count()     # Count occurrences
@map[key] = sum(val)    # Sum values
@map[key] = avg(val)    # Average
@map[key] = min(val)    # Minimum
@map[key] = max(val)    # Maximum
@map[key] = hist(val)   # Histogram (power-of-2)
@map[key] = lhist(val, min, max, step)  # Linear histogram
```

### Data Access

```bash
str(ptr)                # Read null-terminated string
buf(ptr, len)           # Read buffer
ntop(addr)              # Network address to string (IPv4/6)
kstack                  # Kernel stack trace
ustack                  # User stack trace
```

### Utilities

```bash
exit()                  # Exit bpftrace
system(cmd)             # Execute shell command
clear(@map)             # Clear map
delete(@map[key])       # Delete entry
print(@map)             # Print map
print(@map, top)        # Print top N entries
```

---

## Operators and Syntax

### Assignment

```bash
$var = value            # Local variable (scratch space)
@map[key] = value       # Global map
```

### Conditionals

```bash
# Filters (before action block)
probe /filter/ { }

# Examples:
kprobe:sys_open /pid == 1234/ { }
kprobe:sys_open /comm == "nginx"/ { }

# If statements (inside action block)
if (pid > 1000) {
    printf("User process\n");
}
```

### Loops

```bash
# No traditional loops!
# Use unrolling:
unroll(10) {
    // Repeated 10 times
}
```

---

## Practical Examples

### Example 1: Count Syscalls per Process

```bash
#!/usr/bin/env bpftrace

tracepoint:raw_syscalls:sys_enter
{
    @syscalls[comm] = count();
}

END
{
    print(@syscalls, 10);  # Top 10
    clear(@syscalls);
}
```

### Example 2: TCP Connection Latency

```bash
#!/usr/bin/env bpftrace

#include <net/sock.h>

kprobe:tcp_connect
{
    @start[tid] = nsecs;
}

kretprobe:tcp_connect
/@start[tid]/
{
    $duration_us = (nsecs - @start[tid]) / 1000;
    @connect_latency = hist($duration_us);
    delete(@start[tid]);
}

END
{
    print(@connect_latency);
}
```

### Example 3: File Opens by Process

```bash
#!/usr/bin/env bpftrace

tracepoint:syscalls:sys_enter_openat
{
    printf("%-16s %-6d %s\n", comm, pid, str(args->filename));
}
```

### Example 4: CPU Profiling

```bash
#!/usr/bin/env bpftrace

profile:hz:99
{
    @samples[kstack, ustack, comm] = count();
}

END
{
    print(@samples, 20);
}
```

### Example 5: Block I/O Size Distribution

```bash
#!/usr/bin/env bpftrace

tracepoint:block:block_rq_issue
{
    @bytes = hist(args->bytes);
}

END
{
    print(@bytes);
}
```

---

## Advanced Techniques

### Multi-Key Maps

```bash
@map[key1, key2, key3] = value;

# Example:
@latency[comm, pid, cpu] = hist(nsecs);
```

### Stack Traces

```bash
# Kernel stack
kprobe:some_func
{
    @stack[kstack] = count();
}

# User stack
kprobe:some_func
{
    @stack[ustack] = count();
}

# Both
kprobe:some_func
{
    @stack[kstack, ustack] = count();
}
```

### Positional Parameters

Access script arguments:

```bash
#!/usr/bin/env bpftrace

BEGIN
{
    printf("Tracing PID: %d\n", $1);
}

kprobe:sys_open /pid == $1/
{
    printf("open by PID %d\n", pid);
}
```

Run: `sudo bpftrace script.bt 1234`

### Struct Access

```bash
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
    $file = (struct file *)arg0;
    $dentry = $file->f_path.dentry;
    printf("File: %s\n", str($dentry->d_name.name));
}
```

---

## Probe Discovery

### List All Probes

```bash
sudo bpftrace -l
```

### List by Type

```bash
# Kprobes
sudo bpftrace -l 'kprobe:*'

# Tracepoints
sudo bpftrace -l 'tracepoint:*'

# Uprobes for a binary
sudo bpftrace -l 'uprobe:/bin/bash:*'

# USDT
sudo bpftrace -l 'usdt:/usr/sbin/mysqld:*'
```

### Search

```bash
# Find TCP-related kprobes
sudo bpftrace -l 'kprobe:*tcp*'

# Find syscall tracepoints
sudo bpftrace -l 'tracepoint:syscalls:*'
```

### Show Arguments

```bash
# Tracepoint format
sudo bpftrace -lv tracepoint:syscalls:sys_enter_open
```

---

## Common Patterns

### Pattern 1: Filter by PID

```bash
kprobe:func /pid == 1234/ { }
```

### Pattern 2: Filter by Process Name

```bash
kprobe:func /comm == "nginx"/ { }
```

### Pattern 3: Measure Latency

```bash
kprobe:start_func { @start[tid] = nsecs; }
kretprobe:start_func /@start[tid]/ {
    $lat = nsecs - @start[tid];
    @latency = hist($lat);
    delete(@start[tid]);
}
```

### Pattern 4: Aggregate by Key

```bash
event {
    @count[key1, key2] = count();
}
```

### Pattern 5: Print Top N

```bash
END {
    print(@map, 10);  # Top 10 entries
}
```

---

## Performance Considerations

### Overhead

bpftrace has **lower startup overhead** than BCC (faster compilation), but:
- Still uses LLVM (compile time)
- Event processing overhead depends on frequency
- String operations are expensive
- Stack traces are expensive

### Optimization

```bash
# BAD: Print every event
kprobe:func { printf(...); }

# BETTER: Aggregate
kprobe:func { @count = count(); }

# BEST: Filter + aggregate
kprobe:func /pid == target/ { @count = count(); }
```

### Sampling

```bash
# Sample 1% of events
kprobe:func /rand() % 100 == 0/ { }

# Time-based sampling
profile:hz:99 { }  # 99 times per second
```

---

## Limitations

1. **String length**: 64 characters max
2. **No loops**: Must use unrolling
3. **Stack depth**: Limited stack size (512 bytes)
4. **Map size**: Default 10,000 entries (tunable)
5. **No floating point**: Integer arithmetic only
6. **Limited control flow**: No while, for loops

---

## Debugging

### Verbose Mode

```bash
sudo bpftrace -v script.bt
```

### List Mode (dry run)

```bash
sudo bpftrace -l 'kprobe:*tcp*'
```

### Print Verifier Log

```bash
sudo bpftrace -d script.bt
```

---

## Comparison: bpftrace vs BCC

| Feature | bpftrace | BCC |
|---------|----------|-----|
| **Syntax** | Concise DSL | Python + C |
| **Startup** | Fast | Slow (runtime compilation) |
| **Use case** | Quick analysis, debugging | Complex tools, production agents |
| **Learning curve** | Easy | Medium |
| **String support** | 64 chars | Unlimited |
| **Loops** | No (unroll only) | Yes |
| **Maps** | Automatic | Manual management |
| **Dependencies** | Minimal | Python, headers |
| **Best for** | Ad-hoc, one-liners | Reusable tools, complex logic |

---

## Summary

| Aspect | Details |
|--------|---------|
| **Philosophy** | Concise, awk-like |
| **Strengths** | Fast startup, easy syntax, quick prototyping |
| **Weaknesses** | Limited for complex logic, string limitations |
| **Best for** | Ad-hoc analysis, quick debugging, learning eBPF |

---

## Next Steps

1. Try one-liners from examples
2. Write your own scripts for common tasks
3. Explore probe points with `-l`
4. Combine with BCC for complex analysis
5. Read `03-bcc-vs-bpftrace-decision-guide.md`

---

## References

- [bpftrace GitHub](https://github.com/iovisor/bpftrace)
- [bpftrace Reference Guide](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [bpftrace Tutorial](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)
- [One-Liners](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)
