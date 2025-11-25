# Level 03: Programming eBPF with libbpf & CO-RE

## Overview

This level teaches you to write **production-grade eBPF programs** using libbpf and CO-RE (Compile Once, Run Everywhere). You'll move beyond high-level tools to write portable, efficient eBPF applications in C.

**Goal**: Master libbpf programming, CO-RE portability, skeleton generation, ring buffers, and verifier debugging. Build programs ready for production deployment.

---

## Prerequisites

Complete **Level 01** and **Level 02**:
- eBPF fundamentals (VM, verifier, BTF)
- Experience with BCC and bpftrace
- Understanding of kprobes, tracepoints, maps

---

## Why libbpf?

### BCC/bpftrace Limitations

| Issue | Impact | libbpf Solution |
|-------|--------|-----------------|
| **Runtime compilation** | Slow startup (seconds) | Pre-compiled binaries (instant) |
| **Kernel headers required** | Breaks on missing/mismatched headers | CO-RE (BTF-based, no headers needed) |
| **Large dependencies** | Python, LLVM, clang on target | Minimal (just libbpf) |
| **Not portable** | Recompile for each kernel | CO-RE (works across kernel versions) |
| **Resource usage** | High memory, CPU for compilation | Minimal overhead |

### libbpf Advantages

✓ **Production-ready**: Used by Cilium, Katran, Facebook, Google
✓ **Portable**: CO-RE works across kernel versions without recompilation
✓ **Fast**: No runtime compilation, instant startup
✓ **Minimal dependencies**: Small footprint
✓ **Modern APIs**: Ring buffers, BTF-aware maps, skeletons

---

## Concepts Introduced

### 1. libbpf Architecture

```
┌──────────────────────────────────────────────────────┐
│              Development Time                        │
├──────────────────────────────────────────────────────┤
│  1. Write eBPF C program (prog.bpf.c)               │
│  2. Compile with clang:                             │
│     clang -target bpf -D__TARGET_ARCH_x86           │
│           -g -O2 -c prog.bpf.c -o prog.bpf.o        │
│  3. Generate skeleton:                              │
│     bpftool gen skeleton prog.bpf.o > prog.skel.h   │
│  4. Write user-space loader (prog.c)                │
│  5. Compile loader:                                 │
│     gcc prog.c -o prog -lbpf -lelf                  │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│              Runtime (Target System)                 │
├──────────────────────────────────────────────────────┤
│  1. Run: ./prog                                      │
│  2. libbpf reads prog.bpf.o embedded in binary      │
│  3. Performs CO-RE relocations using target BTF     │
│  4. Loads program into kernel                       │
│  5. Attaches to hooks                               │
│  6. User-space reads maps/ring buffers             │
└──────────────────────────────────────────────────────┘
```

### 2. CO-RE (Compile Once, Run Everywhere)

**Problem**: Kernel structs change between versions

```c
// Kernel 5.4
struct task_struct {
    int pid;           // offset 0
    char comm[16];     // offset 4
};

// Kernel 5.10
struct task_struct {
    long state;        // offset 0
    int pid;           // offset 8  ← DIFFERENT!
    char comm[16];     // offset 12 ← DIFFERENT!
};
```

**Traditional approach**: Breaks when compiled for one kernel, run on another.

**CO-RE solution**:
1. Compiler emits **relocation records** for struct field accesses
2. At load time, libbpf reads BTF from target kernel
3. libbpf **patches the bytecode** with correct offsets for that kernel

**Result**: One binary works everywhere!

### 3. BPF Skeletons

Auto-generated C headers that provide type-safe access to your BPF program.

**Without skeleton** (manual, error-prone):
```c
int fd = bpf_obj_get("/sys/fs/bpf/my_prog");
// Manual map lookups, type casting, etc.
```

**With skeleton** (type-safe, auto-generated):
```c
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();
skel->maps.my_map;  // Type-safe access!
skel->links.handle_event = my_prog_bpf__attach(skel);
```

### 4. Ring Buffer vs Perf Buffer

| Feature | Perf Buffer (old) | Ring Buffer (new, 5.8+) |
|---------|-------------------|-------------------------|
| **Performance** | Good | Better (lock-free) |
| **Memory efficiency** | Per-CPU buffers | Shared buffer |
| **Event ordering** | Per-CPU order only | Global order possible |
| **Memory waste** | Can be significant | Minimal |
| **API complexity** | More complex | Simpler |
| **Recommendation** | Legacy code | Use for new code |

---

## Tools & Dependencies

### Install libbpf

```bash
# Ubuntu/Debian
sudo apt install libbpf-dev linux-headers-$(uname -r)

# Fedora
sudo dnf install libbpf-devel kernel-devel

# From source (latest features)
git clone https://github.com/libbpf/libbpf
cd libbpf/src
make
sudo make install
```

### Install libbpf-bootstrap (Templates)

```bash
git clone https://github.com/libbpf/libbpf-bootstrap
cd libbpf-bootstrap
git submodule update --init --recursive
```

### Verify

```bash
# Check libbpf
pkg-config --modversion libbpf

# Check bpftool (for skeleton generation)
bpftool version

# Check BTF
ls /sys/kernel/btf/vmlinux
```

---

## libbpf Program Structure

### eBPF Side (prog.bpf.c)

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// License required
char LICENSE[] SEC("license") = "GPL";

// Map definition
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} my_map SEC(".maps");

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Event structure
struct event {
    u32 pid;
    char comm[16];
};

// Program
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit event
    bpf_ringbuf_submit(e, 0);

    return 0;
}
```

### User-Space Side (prog.c)

```c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "prog.skel.h"  // Generated skeleton

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("PID %d executed: %s\n", e->pid, e->comm);
    return 0;
}

int main(void)
{
    struct prog_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF program (skeleton API)
    skel = prog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach tracepoint
    err = prog_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Tracing execve... Ctrl-C to stop\n");

    // Main event loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    prog_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

### Build System (Makefile)

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS := -g -O2 -Wall

# eBPF program
prog.bpf.o: prog.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) -c $< -o $@

# Skeleton
prog.skel.h: prog.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# User-space loader
prog: prog.c prog.skel.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

# Generate vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f *.o *.skel.h prog vmlinux.h
```

---

## Practical Tasks (12)

### Task 1: Set Up libbpf Development Environment
**Objective**: Install all dependencies and verify setup.

```bash
# Run setup script
./tools/setup-libbpf.sh

# Verify
./tools/verify-libbpf.sh
```

**Deliverable**: Working libbpf environment with BTF support.

---

### Task 2: Generate vmlinux.h
**Objective**: Create the portable kernel types header.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

**Deliverable**: vmlinux.h file with all kernel types.

---

### Task 3: Build Your First libbpf Program
**Objective**: Compile and run the example tracepoint program.

```bash
cd examples/01-hello-libbpf/
make
sudo ./hello
```

**Deliverable**: Working hello-world libbpf program.

---

### Task 4: Understand Skeleton Generation
**Objective**: Examine generated skeleton code.

```bash
# Generate skeleton
bpftool gen skeleton prog.bpf.o > prog.skel.h

# Study the skeleton
cat prog.skel.h
```

**Deliverable**: Explain what the skeleton provides (open, load, attach, destroy functions).

---

### Task 5: Use CO-RE to Read Kernel Structs
**Objective**: Write a program that reads task_struct fields portably.

```c
SEC("kprobe/do_exit")
int trace_exit(struct pt_regs *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    pid_t pid;

    // CO-RE: works across kernel versions
    pid = BPF_CORE_READ(task, pid);

    bpf_printk("Process %d exiting\n", pid);
    return 0;
}
```

**Deliverable**: Program that works on multiple kernel versions.

---

### Task 6: Implement Ring Buffer Event Streaming
**Objective**: Send structured events from kernel to user-space.

Use template in `examples/02-ringbuf-events/`.

**Deliverable**: Program streaming process events via ring buffer.

---

### Task 7: Use Per-CPU Maps for Performance
**Objective**: Implement high-performance counters with per-CPU maps.

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");
```

**Deliverable**: Benchmark per-CPU vs regular maps.

---

### Task 8: Handle Verifier Errors Systematically
**Objective**: Debug and fix common verifier rejections.

Intentionally break the program, then fix:
- Unbounded loops
- Invalid pointer arithmetic
- Stack limit exceeded
- Helper function misuse

**Deliverable**: Document 5 verifier errors and fixes.

---

### Task 9: Implement fentry/fexit Programs
**Objective**: Use modern low-overhead tracing (kernel 5.5+).

```c
SEC("fentry/do_unlinkat")
int BPF_PROG(trace_unlink_entry, int dfd, struct filename *name)
{
    // Direct function arguments, no pt_regs!
    bpf_printk("Unlink: %s\n", name->name);
    return 0;
}
```

**Deliverable**: Compare overhead: kprobe vs fentry.

---

### Task 10: Build a kprobe with Auto-Attach
**Objective**: Use libbpf auto-attach for kprobes.

```c
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
    // Auto-attached by libbpf
    // ...
    return 0;
}
```

**Deliverable**: Program with automatic attachment.

---

### Task 11: Implement Global Variables
**Objective**: Use global variables for configuration.

```c
// eBPF side
const volatile pid_t target_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int trace_write(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // Filter using global variable
    if (target_pid && pid != target_pid)
        return 0;

    // ...
}

// User-space side
skel->rodata->target_pid = 1234;  // Set before load
```

**Deliverable**: Configurable program using global variables.

---

### Task 12: Package for Distribution
**Objective**: Create a standalone binary for deployment.

Steps:
1. Embed BPF object in binary (skeleton does this)
2. Static linking (optional)
3. Test on different kernel versions
4. Create README with requirements

**Deliverable**: Distributable binary with instructions.

---

## Real-World Challenges (6)

### Challenge 1: CO-RE Struct Field Doesn't Exist
**Scenario**: Your program reads a kernel struct field that doesn't exist on an older kernel.

**Problem**:
```c
// This field was added in kernel 5.8
int value = BPF_CORE_READ(task, some_new_field);
// Fails to load on kernel 5.4!
```

**Your Task**:
1. Use `bpf_core_field_exists()` to check field existence
2. Implement fallback logic for older kernels
3. Handle gracefully without crashing

```c
if (bpf_core_field_exists(struct task_struct, some_new_field)) {
    value = BPF_CORE_READ(task, some_new_field);
} else {
    // Fallback for older kernels
    value = 0;
}
```

**Deliverable**: Program that adapts to kernel version.

---

### Challenge 2: Verifier Rejects Complex Loop
**Scenario**: Your program needs to iterate, but verifier rejects unbounded loops.

**Problem**:
```c
// Verifier rejects this
for (int i = 0; i < count; i++) {  // count is runtime value!
    // process
}
```

**Your Task**:
1. Understand bounded loop requirements
2. Use `#pragma unroll` or bounded iterations
3. Implement workarounds (state machines, tail calls)

**Solutions**:
```c
// Solution 1: Bounded loop
#pragma unroll
for (int i = 0; i < 10; i++) {  // Fixed bound
    if (i >= count) break;
    // process
}

// Solution 2: Tail calls
bpf_tail_call(ctx, &prog_array, next_index);
```

**Deliverable**: Working program with complex iteration logic.

---

### Challenge 3: Ring Buffer Event Loss
**Scenario**: Under high load, ring buffer drops events.

**Problem**:
- `bpf_ringbuf_reserve()` returns NULL (buffer full)
- Critical events are lost
- No visibility into loss

**Your Task**:
1. Add drop counters
2. Implement sampling under pressure
3. Increase buffer size appropriately
4. Add backpressure handling

```c
static __always_inline bool should_sample(void)
{
    // Sample 10% when under pressure
    return bpf_get_prandom_u32() % 10 == 0;
}

e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) {
    __sync_fetch_and_add(&drop_count, 1);
    if (should_sample()) {
        // Send at least some events
        e = bpf_ringbuf_reserve(&events, sizeof(*e), BPF_RB_FORCE_WAKEUP);
    }
    if (!e) return 0;
}
```

**Deliverable**: Resilient event streaming under load.

---

### Challenge 4: Stack Size Exceeded
**Scenario**: Verifier rejects: "combined stack size of X programs is Y bytes, exceeds 512 bytes"

**Problem**:
```c
char large_buf[512];  // Too big for stack!
```

**Your Task**:
1. Understand 512-byte stack limit per program
2. Use maps for large data structures
3. Split into smaller chunks
4. Use per-CPU arrays as scratch space

```c
// Solution: Use map as scratch space
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[1024]);  // Large buffer in map, not stack
} scratch SEC(".maps");

SEC("kprobe/func")
int trace(void *ctx)
{
    u32 key = 0;
    char *buf = bpf_map_lookup_elem(&scratch, &key);
    if (!buf) return 0;

    // Use buf as scratch space
    // ...
}
```

**Deliverable**: Program optimized for stack usage.

---

### Challenge 5: Helper Not Available for Program Type
**Scenario**: Your XDP program calls a helper that's not allowed.

**Problem**:
```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    bpf_get_current_comm(...);  // ERROR: Not allowed in XDP!
    // ...
}
```

**Your Task**:
1. Understand helper restrictions per program type
2. Find allowed alternatives
3. Restructure program if needed

Check allowed helpers:
```bash
bpftool feature probe | grep "program_type xdp" -A 50
```

**Deliverable**: Correct helper usage for each program type.

---

### Challenge 6: BTF Not Available on Target System
**Scenario**: You deploy to an older kernel without BTF.

**Problem**:
- `/sys/kernel/btf/vmlinux` doesn't exist
- CO-RE relocations fail
- Program won't load

**Your Task**:
1. Detect BTF availability at runtime
2. Fallback to non-CO-RE mode (pre-compiled for specific kernel)
3. Or require minimum kernel version
4. Document requirements clearly

```c
// Detect BTF
if (access("/sys/kernel/btf/vmlinux", F_OK) != 0) {
    fprintf(stderr, "BTF not available. Kernel 5.2+ required.\n");
    return 1;
}
```

**Deliverable**: Strategy for handling BTF-less systems.

---

## Learning Checklist

By the end of Level 03, you should be able to:

- [ ] Set up libbpf development environment
- [ ] Generate and use vmlinux.h
- [ ] Write eBPF programs with CO-RE portability
- [ ] Use BPF skeletons for type-safe access
- [ ] Implement ring buffer event streaming
- [ ] Debug and fix verifier errors systematically
- [ ] Use fentry/fexit for low-overhead tracing
- [ ] Optimize programs (per-CPU maps, stack usage)
- [ ] Handle BTF and kernel version compatibility
- [ ] Package programs for distribution
- [ ] Understand helper restrictions per program type
- [ ] Build production-ready eBPF applications

---

## Next Steps

**Level 04**: eBPF in Networking, Observability & Security
- XDP and tc for packet processing
- Integrate with Prometheus/Grafana/OpenTelemetry
- LSM hooks for security policies
- Build observability pipelines
- Learn Cilium/Hubble patterns

---

## References

- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
- [CO-RE Documentation](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [BPF CO-RE reference](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/)
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)

---

**Ready to start? Run `./tools/setup-libbpf.sh` to install dependencies!**
