# BTF (BPF Type Format) and Type Information

## Overview

BTF is the **type metadata format** for eBPF that enables portable, type-safe programs. This document explains why BTF is critical and how to use it.

---

## What is BTF?

**BTF (BPF Type Format)** is a compact format for encoding:
- **Types**: structs, unions, enums, typedefs, pointers
- **Function signatures**: parameters and return types
- **Global variables**: name and type information

### Why BTF exists:

Before BTF, eBPF programs had to manually define kernel structs:

```c
// Manual definition (pre-BTF era)
struct task_struct {
    int pid;           // Hope this is at the right offset!
    char comm[16];     // Hope this is correct!
    // ... incomplete definition
};
```

**Problem**: Kernel structs change between versions. Your program breaks on different kernels.

With BTF:

```c
#include "vmlinux.h"  // Auto-generated from BTF

// struct task_struct is automatically available
// Field offsets are automatically adjusted for your kernel
```

---

## CO-RE (Compile Once, Run Everywhere)

### The portability problem:

Kernel struct layouts change between versions:

```
Kernel 5.4:                    Kernel 5.10:
struct task_struct {           struct task_struct {
    int pid;       ← offset 0      long state;    ← offset 0
    long state;    ← offset 8      int pid;       ← offset 8
    ...                            ...
};                             };
```

If you compile for 5.4, your offsets are **wrong** on 5.10!

### CO-RE solution:

CO-RE uses BTF to **rewrite offsets at load time**:

1. **Compile time**: Compiler emits **relocation records**
2. **Load time**: libbpf reads BTF from target kernel
3. **Relocation**: libbpf adjusts offsets for actual kernel structs

### Using CO-RE:

```c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

SEC("kprobe/do_something")
int my_prog(struct pt_regs *ctx) {
    struct task_struct *task = (void *)bpf_get_current_task();

    // Without CO-RE (breaks across kernels):
    int pid = task->pid;  // ✗ Wrong offset on some kernels

    // With CO-RE (portable):
    int pid = BPF_CORE_READ(task, pid);  // ✓ Correct on all kernels

    return 0;
}
```

### CO-RE macros:

| Macro | Purpose |
|-------|---------|
| `BPF_CORE_READ(src, field)` | Read single field |
| `BPF_CORE_READ_INTO(&dst, src, field)` | Read into variable |
| `bpf_core_field_exists(type, field)` | Check if field exists |
| `bpf_core_field_offset(type, field)` | Get field offset |
| `bpf_core_type_exists(type)` | Check if type exists |

---

## BTF Sources

### 1. Kernel BTF

Location: `/sys/kernel/btf/vmlinux`

Contains type info for **all kernel types**.

```bash
# Check if BTF is available
ls -lh /sys/kernel/btf/vmlinux

# Requires kernel config:
# CONFIG_DEBUG_INFO_BTF=y
```

### 2. Module BTF

Location: `/sys/kernel/btf/<module_name>`

Contains type info for **loaded kernel modules**.

```bash
# List module BTF
ls /sys/kernel/btf/

# Example:
# /sys/kernel/btf/nf_conntrack
# /sys/kernel/btf/iptable_filter
```

### 3. Program BTF

Embedded in **compiled eBPF objects** (`.bpf.o` files).

```bash
# Dump BTF from object file
bpftool btf dump file prog.bpf.o
```

---

## Generating vmlinux.h

### What is vmlinux.h?

`vmlinux.h` is a **single header file** containing all kernel types, generated from BTF.

### Why use it?

Instead of:
```c
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/net.h>
// ... hundreds of headers, with dependency issues
```

You write:
```c
#include "vmlinux.h"
// Everything you need, no conflicts
```

### Generating vmlinux.h:

```bash
# Generate from kernel BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# File will be ~10MB, 200k+ lines
```

### Using vmlinux.h:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Now you can use any kernel type:
struct task_struct *task;
struct file *file;
struct sk_buff *skb;
// No manual definitions needed!
```

---

## BTF Structure

### Type encoding:

BTF encodes types efficiently:

```
Type ID | Kind       | Name           | Info
--------|------------|----------------|---------------------
1       | INT        | int            | size=4, encoding=signed
2       | PTR        | (anon)         | points_to=1
3       | STRUCT     | task_struct    | members=...
4       | UNION      | wait_queue_entry| members=...
5       | ENUM       | pid_type       | enumerators=...
```

### Viewing BTF:

```bash
# Dump in C format (human-readable)
bpftool btf dump file /sys/kernel/btf/vmlinux format c

# Dump raw format (for tools)
bpftool btf dump file /sys/kernel/btf/vmlinux format raw

# Search for specific type
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "struct task_struct"
```

---

## BTF in Action

### Example: Portable network tracing

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);

    // Read socket family (portable across kernels)
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // Read source port (portable)
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // This works on kernel 4.19, 5.4, 5.10, 6.x without recompilation!
    bpf_printk("TCP send: family=%d, port=%d\n", family, sport);

    return 0;
}
```

---

## BTF and Maps

### Typed maps:

BTF allows maps to have **typed keys and values**:

```c
struct event {
    u32 pid;
    char comm[16];
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);              // BTF: key is u32
    __type(value, struct event);   // BTF: value is struct event
} events SEC(".maps");
```

### Benefits:

1. **User-space introspection**: Tools can see map structure
2. **Better debugging**: `bpftool map dump` shows field names
3. **Type safety**: Compiler catches type mismatches

### Viewing map BTF:

```bash
# Show map with type info
sudo bpftool map show id 123

# Dump with field names
sudo bpftool map dump id 123
```

---

## BTF Debugging

### Check if BTF is available:

```bash
# Method 1: Check file
ls /sys/kernel/btf/vmlinux && echo "BTF available" || echo "BTF not available"

# Method 2: Use bpftool
sudo bpftool feature probe | grep BTF
```

### Common BTF errors:

| Error | Cause | Solution |
|-------|-------|----------|
| `libbpf: failed to find BTF` | No kernel BTF | Upgrade kernel or use non-CO-RE approach |
| `CO-RE relocations not supported` | Old libbpf | Update libbpf to 0.4+ |
| `Type ... not found in kernel BTF` | Kernel doesn't have this type | Use `bpf_core_type_exists()` to check |

---

## BTF Requirements

### Kernel requirements:

- **Minimum**: Linux 5.2+ (basic BTF support)
- **Recommended**: Linux 5.10+ (full CO-RE support)
- **Config**: `CONFIG_DEBUG_INFO_BTF=y`

### User-space requirements:

- **libbpf**: 0.4+ for full CO-RE support
- **bpftool**: Recent version (check with `bpftool version`)
- **clang/llvm**: 10+ for CO-RE relocation generation

### Checking your system:

```bash
# Kernel version
uname -r

# BTF availability
ls /sys/kernel/btf/vmlinux

# libbpf version
ldconfig -p | grep libbpf
pkg-config --modversion libbpf

# clang version (need 10+)
clang --version
```

---

## Fallback Strategies (No BTF)

If your target kernel doesn't have BTF:

### Option 1: Manual struct definitions

Define structs yourself (not portable):

```c
// Manually define for your specific kernel version
struct task_struct {
    long state;        // Kernel 5.10 offset
    int pid;           // Check actual offset!
    // ...
};
```

### Option 2: BCC approach

Use BCC which includes kernel headers at runtime.

### Option 3: Ship multiple versions

Compile for each target kernel version and ship all variants.

---

## Summary

| Feature | Without BTF | With BTF |
|---------|-------------|----------|
| **Portability** | Break on kernel changes | Work across kernel versions |
| **Development** | Manual struct definitions | Auto-generated vmlinux.h |
| **Map introspection** | No type info | Full type info |
| **Debugging** | Limited | Field names, types visible |
| **Future-proof** | No | Yes (field checks at runtime) |

---

## Next Steps

1. Check if your kernel has BTF:
   ```bash
   ls -lh /sys/kernel/btf/vmlinux
   ```

2. Generate vmlinux.h:
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```

3. Explore kernel types:
   ```bash
   grep "struct task_struct" vmlinux.h
   grep "struct sock" vmlinux.h
   ```

4. Read the next doc: **04-kernel-configs.md**

---

## References

- [BTF Documentation](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [CO-RE Documentation](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [libbpf CO-RE](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
