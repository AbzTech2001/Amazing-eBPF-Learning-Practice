# CO-RE (Compile Once - Run Everywhere)

## Overview

CO-RE is the **portability solution** for eBPF that allows you to write BPF programs that work across different kernel versions without recompilation. It's the technology that enables production deployment of eBPF applications.

---

## The Portability Problem

### Without CO-RE

```
┌────────────────────────────────────────────────────────┐
│  Traditional eBPF (BCC approach)                       │
├────────────────────────────────────────────────────────┤
│                                                         │
│  Kernel 5.4          Kernel 5.10         Kernel 5.15   │
│  ┌─────────┐        ┌─────────┐        ┌─────────┐    │
│  │ struct  │        │ struct  │        │ struct  │    │
│  │ task:   │        │ task:   │        │ task:   │    │
│  │  pid@8  │        │  pid@12 │        │  pid@16 │    │
│  │  comm@16│        │  comm@20│        │  comm@24│    │
│  └─────────┘        └─────────┘        └─────────┘    │
│       ↑                  ↑                  ↑          │
│       │                  │                  │          │
│  Recompile          Recompile          Recompile       │
│  on target          on target          on target       │
│  with correct       with correct       with correct    │
│  headers            headers            headers         │
│                                                         │
│  Problem: Need kernel headers + LLVM on every target!  │
└────────────────────────────────────────────────────────┘
```

### With CO-RE

```
┌────────────────────────────────────────────────────────┐
│  CO-RE Approach                                        │
├────────────────────────────────────────────────────────┤
│                                                         │
│  Compile ONCE (development machine):                   │
│  ┌──────────────────────────────────────┐             │
│  │ BPF program + BTF relocations        │             │
│  │  "Read task->pid" (field name)       │             │
│  │  "Read task->comm" (field name)      │             │
│  └──────────────────────────────────────┘             │
│                    │                                    │
│                    ↓                                    │
│         Deploy to ANY kernel                           │
│         (with BTF support)                             │
│                    │                                    │
│      ┌─────────────┼─────────────┐                     │
│      ↓             ↓             ↓                      │
│  Kernel 5.4    Kernel 5.10   Kernel 5.15               │
│  Runtime:      Runtime:      Runtime:                  │
│  Offset=8      Offset=12     Offset=16                 │
│  (auto)        (auto)        (auto)                    │
│                                                         │
│  Single binary works everywhere!                       │
└────────────────────────────────────────────────────────┘
```

---

## How CO-RE Works

### 1. BTF Type Information

BTF (BPF Type Format) provides complete kernel type information:

```bash
# Check if BTF is available
ls /sys/kernel/btf/vmlinux

# Generate vmlinux.h with all kernel types
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Example BTF data:
```
[1234] STRUCT 'task_struct' size=9216 vlen=230
    'state' type_id=12 bits_offset=0
    'stack' type_id=45 bits_offset=64
    'flags' type_id=23 bits_offset=128
    'pid' type_id=78 bits_offset=256      ← Offset varies by kernel!
    'comm' type_id=456 bits_offset=1024
    ...
```

### 2. BPF CO-RE Relocations

When you write:
```c
struct task_struct *task = (void *)bpf_get_current_task();
int pid = BPF_CORE_READ(task, pid);
```

The compiler generates:
```
Relocation entry:
  Instruction offset: 42
  Type: FIELD_BYTE_OFFSET
  Field: "task_struct::pid"
```

### 3. libbpf Runtime Relocation

When loading the BPF program:
```
1. libbpf reads BTF from /sys/kernel/btf/vmlinux
2. Finds actual offset of task_struct->pid (e.g., 256 bits = 32 bytes)
3. Patches BPF instruction at offset 42 with correct offset
4. Loads patched program into kernel
```

---

## Using CO-RE

### Step 1: Generate vmlinux.h

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

This creates a header with **all kernel types**:
```c
struct task_struct {
    unsigned int state;
    void *stack;
    atomic_t usage;
    unsigned int flags;
    // ... 200+ more fields
    pid_t pid;
    char comm[16];
    // ...
};
```

### Step 2: Use CO-RE Macros

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // CO-RE field access (SAFE - relocatable)
    pid_t pid = BPF_CORE_READ(task, pid);

    // Read string field
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    bpf_printk("execve: pid=%d comm=%s\n", pid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Step 3: Compile with BTF

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
    -c my_prog.bpf.c -o my_prog.bpf.o
```

The `-g` flag includes BTF debug info in the .o file.

---

## CO-RE Helper Macros

### 1. BPF_CORE_READ

Read a field from a struct (handles pointers and relocations):

```c
struct task_struct *task;
pid_t pid = BPF_CORE_READ(task, pid);

// Nested field access
struct mm_struct *mm = BPF_CORE_READ(task, mm);
unsigned long start_code = BPF_CORE_READ(mm, start_code);

// Or chained:
unsigned long start_code = BPF_CORE_READ(task, mm, start_code);
```

### 2. BPF_CORE_READ_STR_INTO

Read a string field:

```c
char comm[16];
BPF_CORE_READ_STR_INTO(&comm, task, comm);
```

### 3. BPF_CORE_READ_INTO

Read into a buffer:

```c
struct path p;
BPF_CORE_READ_INTO(&p, file, f_path);
```

### 4. bpf_core_field_exists

Check if a field exists (for conditional compilation):

```c
if (bpf_core_field_exists(struct task_struct, mempolicy)) {
    // This field only exists in some kernel versions
    void *policy = BPF_CORE_READ(task, mempolicy);
    // ...
}
```

### 5. bpf_core_type_exists

Check if a type exists:

```c
if (bpf_core_type_exists(struct io_uring_task)) {
    // io_uring support available
}
```

---

## Advanced CO-RE Features

### Field Existence Checks

Handle kernel version differences:

```c
SEC("kprobe/do_exit")
int kprobe_exit(struct pt_regs *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    // Older kernels: task->thread_pid->numbers[0].nr
    // Newer kernels: task->pid

    pid_t pid;
    if (bpf_core_field_exists(struct task_struct, thread_pid)) {
        struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
        pid = BPF_CORE_READ(thread_pid, numbers[0].nr);
    } else {
        pid = BPF_CORE_READ(task, pid);
    }

    bpf_printk("Process exit: %d\n", pid);
    return 0;
}
```

### Type Variants

```c
// Handle renamed structs
typedef struct old_name new_name;

if (bpf_core_type_exists(struct new_name)) {
    // Use new_name
} else {
    // Use old_name
}
```

### Enum Values

```c
// Get enum value (portable across kernels)
int val = bpf_core_enum_value(enum tcp_ca_state, TCP_CA_Open);
```

---

## CO-RE Relocation Types

### 1. FIELD_BYTE_OFFSET

Most common - field offset in struct:
```c
pid_t pid = BPF_CORE_READ(task, pid);
// Generates: FIELD_BYTE_OFFSET relocation for "task_struct::pid"
```

### 2. FIELD_BYTE_SIZE

Size of a field:
```c
int size = bpf_core_field_size(struct task_struct, comm);
```

### 3. FIELD_EXISTS

Check field existence:
```c
bool has_field = bpf_core_field_exists(struct task_struct, some_field);
```

### 4. TYPE_ID_LOCAL / TYPE_ID_TARGET

Type ID for BTF operations:
```c
int type_id = bpf_core_type_id_kernel(struct task_struct);
```

### 5. ENUMVAL_EXISTS / ENUMVAL_VALUE

Enum handling:
```c
bool exists = bpf_core_enum_value_exists(enum tcp_state, TCP_LISTEN);
int val = bpf_core_enum_value(enum tcp_state, TCP_LISTEN);
```

---

## Common Pitfalls

### Pitfall 1: Direct Pointer Dereference

```c
// BAD - Not CO-RE compatible!
struct task_struct *task = (void *)bpf_get_current_task();
pid_t pid = task->pid;  // WILL BREAK on different kernels

// GOOD - Use CO-RE macros
pid_t pid = BPF_CORE_READ(task, pid);
```

### Pitfall 2: Assuming Struct Layout

```c
// BAD - Assumes field ordering
char *comm_ptr = (char *)task + 1024;  // Hardcoded offset

// GOOD - Let CO-RE handle it
char comm[16];
BPF_CORE_READ_STR_INTO(&comm, task, comm);
```

### Pitfall 3: Using Non-BTF Types

```c
// BAD - Custom struct without BTF
struct my_event {
    int pid;
    char comm[16];
};
// This works, but you can't read FROM kernel structs portably

// GOOD - Use vmlinux.h types
#include "vmlinux.h"
```

### Pitfall 4: Forgetting to Generate vmlinux.h

```c
// If you see errors like:
// error: unknown type name 'struct task_struct'

// You forgot to:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

---

## Debugging CO-RE Relocations

### Check Relocations in Object File

```bash
# List all CO-RE relocations
bpftool gen object my_prog.bpf.o my_prog.bpf.c
readelf -x .BTF.ext my_prog.bpf.o

# Or use llvm-objdump
llvm-objdump -d my_prog.bpf.o
```

### Enable libbpf Debug Logs

```c
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level <= LIBBPF_DEBUG)  // Show all logs
        return vfprintf(stderr, format, args);
    return 0;
}

int main(void) {
    libbpf_set_print(libbpf_print_fn);

    // You'll see logs like:
    // libbpf: CO-RE relocating [123] struct task_struct: found target candidate [456]
    // libbpf: relo #0: <byte_off> [123] struct task_struct.pid (0:34 @ offset 256)

    // ...
}
```

### Test on Different Kernels

```bash
# Docker approach
docker run --rm -v $(pwd):/work ubuntu:20.04 ./my_prog  # Kernel 5.4
docker run --rm -v $(pwd):/work ubuntu:22.04 ./my_prog  # Kernel 5.15

# VM approach
# Test on VMs with different kernel versions
```

---

## CO-RE Best Practices

### 1. Always Use vmlinux.h

```c
// Generate once during build
#include "vmlinux.h"
```

### 2. Use BPF_CORE_READ for All Kernel Struct Access

```c
// Never direct dereference
pid_t pid = BPF_CORE_READ(task, pid);
```

### 3. Handle Field Existence

```c
if (bpf_core_field_exists(struct task_struct, new_field)) {
    // Use new field (kernel 5.15+)
} else {
    // Fallback for older kernels
}
```

### 4. Include BTF in Build

```bash
# Ensure -g flag for BTF debug info
clang -g -O2 -target bpf -c my_prog.bpf.c -o my_prog.bpf.o
```

### 5. Test on Multiple Kernels

Use CI/CD with different kernel versions.

---

## Real-World Example: Process Monitoring

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    u32 pid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Get current task (CO-RE compatible)
    task = (struct task_struct *)bpf_get_current_task();

    // Read PID (works across all kernels with BTF)
    e->pid = BPF_CORE_READ(task, tgid);

    // Read parent PID (accessing nested struct)
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    // Read comm string
    BPF_CORE_READ_STR_INTO(&e->comm, task, comm);

    // Read filename from syscall args
    const char __user *filename_ptr = (const char __user *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

This program:
- Works on kernels 5.2+ (with BTF)
- No recompilation needed
- Single binary deployment
- Handles kernel struct layout changes automatically

---

## Performance Impact

CO-RE has **zero runtime overhead**:

```
Compilation time:
  Without CO-RE: Instant (but per-kernel)
  With CO-RE: +BTF processing (one-time)

Runtime:
  Both: Identical (relocations done at load time)
```

The relocation happens **once** when loading the program, not during execution.

---

## Kernel Version Requirements

| Feature | Minimum Kernel |
|---------|---------------|
| BTF | 5.2+ |
| BTF for modules | 5.11+ |
| Full CO-RE support | 5.2+ |
| Recommended | 5.10+ LTS |

### Fallback for Older Kernels

If BTF unavailable:
1. Ship multiple pre-compiled BPF objects (per kernel version)
2. Use BCC's runtime compilation
3. Require specific kernel version

---

## CO-RE vs Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| **CO-RE** | ✓ Single binary<br>✓ No dependencies<br>✓ Production-ready | ✗ Requires BTF (5.2+) |
| **BCC** | ✓ Works on older kernels | ✗ Needs LLVM on target<br>✗ Large dependencies<br>✗ Runtime overhead |
| **Multiple binaries** | ✓ Works everywhere | ✗ Maintenance nightmare<br>✗ Large package size |

---

## Next Steps

After mastering CO-RE:
1. Study **BPF skeletons** for type-safe loading
2. Learn **verifier constraints** and debugging
3. Explore **advanced relocation types**
4. Practice **multi-kernel testing**
5. Build **production-ready portable programs**

---

## References

- [BPF CO-RE Reference](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Kernel BTF Documentation](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [libbpf CO-RE Helpers](https://github.com/libbpf/libbpf/blob/master/src/bpf_core_read.h)
- [Cilium CO-RE Guide](https://docs.cilium.io/en/stable/bpf/)
