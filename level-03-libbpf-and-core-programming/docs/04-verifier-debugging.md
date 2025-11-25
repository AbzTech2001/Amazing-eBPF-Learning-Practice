# eBPF Verifier Debugging

## Overview

The **eBPF verifier** is the kernel component that ensures BPF programs are safe to run. Understanding verifier errors and how to debug them is critical for eBPF development.

---

## What the Verifier Checks

```
┌─────────────────────────────────────────────────────────┐
│  eBPF Verifier Safety Guarantees                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ✓ No unbounded loops (must be provably terminating)   │
│  ✓ No out-of-bounds memory access                      │
│  ✓ No use of uninitialized variables                   │
│  ✓ No unsafe pointer arithmetic                        │
│  ✓ Correct helper function usage                       │
│  ✓ Valid map access                                    │
│  ✓ Instruction limit (<1M instructions)                │
│  ✓ Stack size limit (512 bytes)                        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Common Verifier Errors

### 1. Invalid Memory Access

```c
// ERROR: invalid mem access 'map_value_or_null'

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);

    // WRONG: Accessing without NULL check
    *value += 1;  // Verifier error!

    return 0;
}
```

**Fix: Always NULL-check map lookups**
```c
__u64 *value = bpf_map_lookup_elem(&stats, &key);
if (!value)  // NULL check required!
    return 0;

*value += 1;  // Now safe
```

### 2. Unbounded Loop

```c
// ERROR: back-edge from insn X to Y

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    // WRONG: Verifier can't prove this terminates
    for (int i = 0; i < 100; i++) {
        bpf_printk("iteration %d\n", i);
    }
    return 0;
}
```

**Fix: Use #pragma unroll**
```c
#pragma unroll
for (int i = 0; i < 10; i++) {  // Unrolled at compile-time
    bpf_printk("iteration %d\n", i);
}
```

Or use bounded loop (kernel 5.3+):
```c
for (int i = 0; i < 100 && i < 100; i++) {  // Bounded
    bpf_printk("iteration %d\n", i);
}
```

### 3. Stack Size Exceeded

```c
// ERROR: combined stack size of N calls is M. Too large

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    // WRONG: Too much stack space
    char buffer[1024];  // Stack limit is 512 bytes!

    bpf_probe_read_kernel_str(buffer, sizeof(buffer), ctx);
    return 0;
}
```

**Fix: Use per-CPU array for large buffers**
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[1024]);
} heap SEC(".maps");

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    __u32 zero = 0;
    char *buffer = bpf_map_lookup_elem(&heap, &zero);
    if (!buffer)
        return 0;

    bpf_probe_read_kernel_str(buffer, 1024, ctx);
    return 0;
}
```

### 4. Invalid Argument to Helper

```c
// ERROR: helper access to the memory is rejected

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    // WRONG: Can't pass kernel pointer to bpf_probe_read_user
    char comm[16];
    bpf_probe_read_user(&comm, sizeof(comm), &task->comm);  // Error!

    return 0;
}
```

**Fix: Use correct helper variant**
```c
// Use bpf_probe_read_kernel for kernel memory
bpf_probe_read_kernel(&comm, sizeof(comm), &task->comm);

// Or better: use BPF_CORE_READ
char comm[16];
BPF_CORE_READ_STR_INTO(&comm, task, comm);
```

### 5. Uninitialized Variable

```c
// ERROR: R1 !read_ok

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx)
{
    __u64 value;

    // WRONG: value is uninitialized
    bpf_printk("value: %llu\n", value);  // Verifier error!

    return 0;
}
```

**Fix: Initialize before use**
```c
__u64 value = 0;  // Explicit initialization
bpf_printk("value: %llu\n", value);
```

---

## Enabling Verifier Logs

### Method 1: libbpf Debug Logs

```c
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;  // Skip debug unless needed

    return vfprintf(stderr, format, args);
}

int main(void)
{
    libbpf_set_print(libbpf_print_fn);

    // Now you'll see detailed verifier errors
    struct my_prog_bpf *skel = my_prog_bpf__open_and_load();
    // ...
}
```

### Method 2: Manual Load with Log Buffer

```c
char log_buf[16384];
struct bpf_load_program_attr load_attr = {
    .log_level = 1,  // Or 2 for more verbose
    .log_buf = log_buf,
    .log_size = sizeof(log_buf),
};

int fd = bpf_load_program_xattr(&load_attr, NULL, 0);
if (fd < 0) {
    fprintf(stderr, "Verifier log:\n%s\n", log_buf);
}
```

### Method 3: bpftool

```bash
# Try to load manually and see verifier logs
sudo bpftool prog load my_prog.bpf.o /sys/fs/bpf/my_prog

# Or increase log level
sudo bpftool prog load my_prog.bpf.o /sys/fs/bpf/my_prog \
    type kprobe \
    log_level 2
```

---

## Reading Verifier Logs

### Typical Verifier Output

```
0: (bf) r6 = r1
1: (b7) r1 = 0
2: (63) *(u32 *)(r10 -4) = r1
3: (bf) r2 = r10
4: (07) r2 += -4
5: (18) r1 = 0xffff888012345678
7: (85) call bpf_map_lookup_elem#1
8: (15) if r0 == 0x0 goto pc+2
9: (79) r1 = *(u64 *)(r0 +0)
10: (07) r1 += 1
11: (7b) *(u64 *)(r0 +0) = r1
12: (b7) r0 = 0
13: (95) exit

Registers:
R0=map_value(id=0,off=0,ks=4,vs=8,imm=0) R1=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff))
R6=ctx(id=0,off=0,imm=0) R10=fp0,call_-1

Instruction 9: R0 could be NULL, but dereferenced anyway
```

### Decoding:
- **Line numbers**: `0:`, `1:`, etc. - instruction offsets
- **Instructions**: `(bf)` = mov, `(85)` = call, etc.
- **Registers**: `r0-r10` (r10 is stack pointer)
- **Register types**: `ctx`, `map_value`, `inv` (scalar), etc.
- **Error location**: Points to exact instruction that failed

---

## Advanced Debugging Techniques

### 1. Simplify to Minimal Reproducer

```c
// Start with failing program
SEC("kprobe/complex_function")
int complex_prog(struct pt_regs *ctx)
{
    // 200 lines of code...
}

// Reduce to smallest failing case
SEC("kprobe/complex_function")
int minimal_prog(struct pt_regs *ctx)
{
    // Only the lines that cause verifier error
    __u64 *val = bpf_map_lookup_elem(&map, &key);
    *val += 1;  // This line fails
    return 0;
}

// Now the issue is obvious: missing NULL check
```

### 2. Add Bounds Checks

```c
// Verifier needs help proving bounds

char data[64];
int idx = ctx->arg1;  // From user input

// WRONG: Verifier can't prove idx is in bounds
data[idx] = 'x';

// RIGHT: Explicit bounds check
if (idx >= 0 && idx < 64)
    data[idx] = 'x';
```

### 3. Use __builtin_preserve_access_index

For CO-RE field access issues:
```c
// If verifier complains about field access
struct task_struct *task = ...;

// Try:
pid_t pid = __builtin_preserve_access_index(({
    task->pid;
}));
```

### 4. Split into Helper Functions

```c
// If hitting complexity limits, split logic

static __always_inline int process_packet(void *data, void *data_end)
{
    // Packet processing logic
    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    return process_packet(data, data_end);
}
```

---

## Verifier Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Max instructions | 1,000,000 | Kernel 5.2+ (was 4096) |
| Stack size | 512 bytes | Per program |
| Max programs | No hard limit | System resources |
| Max map entries | No hard limit | Memory limited |
| Max tail calls | 32 | Recursion depth |
| Max loop iterations | Varies | Must be bounded |

---

## Common Patterns and Solutions

### Pattern 1: Packet Parsing

```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // CRITICAL: Bounds check EVERY pointer dereference
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)  // Bounds check
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  // Another bounds check
        return XDP_PASS;

    // Now safe to access ip->protocol, etc.
    return XDP_PASS;
}
```

### Pattern 2: String Copies

```c
// Use bounded string helpers

char comm[16];
struct task_struct *task = (void *)bpf_get_current_task();

// GOOD: Bounded read
bpf_probe_read_kernel_str(comm, sizeof(comm), &task->comm);

// Or with CO-RE:
BPF_CORE_READ_STR_INTO(&comm, task, comm);
```

### Pattern 3: Array Access

```c
// Verifier needs proof of bounds

#define MAX_ENTRIES 256
__u32 array[MAX_ENTRIES];

__u32 idx = bpf_get_smp_processor_id();

// WRONG: Verifier can't prove bounds
array[idx] = value;

// RIGHT: Explicit check
if (idx < MAX_ENTRIES)
    array[idx] = value;
```

---

## Debugging Checklist

When verifier rejects your program:

1. **Read the error message carefully**
   - Note the failing instruction number
   - Check register states
   - Look for NULL/bounds issues

2. **Enable verbose logging**
   ```c
   libbpf_set_print(libbpf_print_fn);
   ```

3. **Check common issues**
   - [ ] NULL checks after map lookups
   - [ ] Bounds checks for arrays/packet data
   - [ ] Stack size < 512 bytes
   - [ ] Loops are bounded or unrolled
   - [ ] Variables initialized before use
   - [ ] Correct helper function for pointer type

4. **Simplify the program**
   - Comment out code until it loads
   - Find minimal failing case

5. **Check kernel version**
   ```bash
   uname -r  # Some features need newer kernels
   ```

6. **Try bpftool**
   ```bash
   sudo bpftool prog load my.bpf.o /sys/fs/bpf/test log_level 2
   ```

---

## Tools for Debugging

### 1. llvm-objdump

View BPF bytecode before verification:
```bash
llvm-objdump -d -S my_prog.bpf.o
```

### 2. bpftool

```bash
# Load with verbose logs
sudo bpftool prog load my.bpf.o /sys/fs/bpf/test \
    type kprobe \
    log_level 2 \
    log_file verifier.log

# Inspect loaded programs
sudo bpftool prog show
sudo bpftool prog dump xlated id <ID>
```

### 3. Verifier Simulation

Try [bpf-mock-verifier](https://github.com/libbpf/bpf-mock-verifier) for offline testing.

---

## Best Practices

1. **Start simple, add complexity gradually**
2. **Add bounds checks early and often**
3. **Use helper functions to organize code**
4. **Test on target kernel version**
5. **Keep functions small** (<1000 instructions)
6. **Use CO-RE for portability**
7. **Enable debug logs during development**
8. **Read verifier logs carefully** - they tell you exactly what's wrong

---

## References

- [Kernel Verifier Documentation](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
- [Cilium BPF Reference](https://docs.cilium.io/en/stable/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
