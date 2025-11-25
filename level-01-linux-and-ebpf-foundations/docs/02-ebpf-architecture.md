# eBPF Architecture Deep Dive

## Overview

This document explains how eBPF works under the hood: the VM, verifier, JIT compiler, and runtime execution.

---

## The eBPF Virtual Machine

### What is the eBPF VM?

The eBPF VM is a **register-based virtual machine** inside the Linux kernel that executes BPF bytecode.

### Key characteristics:

- **11 registers** (R0-R10)
  - R0: Return value
  - R1-R5: Function arguments
  - R6-R9: Callee-saved registers
  - R10: Stack pointer (read-only)

- **512-byte stack** per program

- **64-bit architecture** (registers are 64-bit)

- **Instructions**: Similar to assembly
  - Load/store
  - Arithmetic operations
  - Jumps (conditional/unconditional)
  - Function calls (helpers)

### Example BPF bytecode:

```
0: r1 = 0
1: r2 = 10
2: r1 += r2
3: exit
```

---

## Instruction Set Architecture

### Instruction format:

```
┌─────────┬─────────┬─────────┬─────────┬─────────────────┐
│  opcode │   dst   │   src   │  offset │   immediate     │
│ (8 bit) │ (4 bit) │ (4 bit) │ (16 bit)│    (32 bit)     │
└─────────┴─────────┴─────────┴─────────┴─────────────────┘
```

### Instruction classes:

| Class | Purpose | Example |
|-------|---------|---------|
| `BPF_ALU64` | 64-bit arithmetic | `r0 += r1` |
| `BPF_ALU` | 32-bit arithmetic | `w0 += w1` |
| `BPF_LD` | Load immediate | `r0 = 0x1234` |
| `BPF_LDX` | Load from memory | `r0 = *(u64 *)(r1 + 8)` |
| `BPF_ST` | Store immediate | `*(u64 *)(r1 + 8) = 0x5678` |
| `BPF_STX` | Store register | `*(u64 *)(r1 + 8) = r2` |
| `BPF_JMP` | Jumps | `if r0 > 10 goto +5` |
| `BPF_JMP32` | 32-bit jumps | `if w0 > 10 goto +5` |

### Viewing bytecode:

```bash
# Compile C to BPF bytecode
clang -target bpf -O2 -c prog.bpf.c -o prog.bpf.o

# Disassemble
llvm-objdump -d prog.bpf.o

# After loading, inspect with bpftool
sudo bpftool prog dump xlated id <ID>
```

---

## The Verifier

### What is the verifier?

The **verifier** is a static analyzer that proves your eBPF program is **safe** before it runs.

### Safety guarantees:

1. **No crashes**: Program won't cause kernel panic
2. **Bounded execution**: No infinite loops, program will terminate
3. **Memory safety**: No out-of-bounds access, no invalid pointers
4. **Type safety**: Correct use of contexts and maps

### Verification process:

```
┌──────────────────────────────────────────────────────┐
│  1. LOAD: User submits BPF program bytecode          │
│     ↓                                                 │
│  2. VERIFIER: Static analysis                        │
│     • Check all code paths reach BPF_EXIT            │
│     • Track register states at each instruction      │
│     • Validate memory accesses                       │
│     • Ensure no unbounded loops                      │
│     • Verify helper function calls                   │
│     ↓                                                 │
│  3. DECISION:                                         │
│     → PASS: JIT compile and load                     │
│     → FAIL: Return error with log                    │
└──────────────────────────────────────────────────────┘
```

### Register state tracking:

The verifier tracks **possible values** for each register at each instruction:

```
Register states:
  SCALAR_VALUE     : Unknown integer
  PTR_TO_CTX       : Pointer to program context
  PTR_TO_MAP_VALUE : Pointer to map value
  PTR_TO_STACK     : Pointer to stack
  PTR_TO_PACKET    : Pointer to network packet (XDP)
```

### Example verification:

```c
// BAD: Unbounded loop
for (int i = 0; i < n; i++) {  // n could be anything!
    // ...
}
// Verifier rejects: can't prove termination

// GOOD: Bounded loop with pragma
#pragma unroll
for (int i = 0; i < 10; i++) {  // Unrolled at compile time
    // ...
}
// Verifier accepts: no actual loop in bytecode
```

### Common verifier errors:

| Error | Meaning | Fix |
|-------|---------|-----|
| `back-edge from insn X to Y` | Loop detected | Use `#pragma unroll` or verifier-friendly patterns |
| `R1 type=inv expected=ctx` | Wrong register type | Check context access, ensure correct pointer type |
| `invalid bpf_context access` | Bad offset in context | Use `BPF_CORE_READ` or correct struct definition |
| `unreachable insn` | Dead code | Remove unreachable paths |
| `invalid mem access 'scalar'` | Dereferencing invalid pointer | NULL check before access |

### Verifier limits:

- **Max instructions**: ~1 million (kernel 5.2+), 4096 (older)
- **Max stack size**: 512 bytes
- **Max complexity**: Based on register state combinations

---

## JIT Compilation

### What is JIT?

The **Just-In-Time compiler** translates eBPF bytecode to **native machine code** for performance.

### Without JIT (interpreted):

```
BPF instruction → Interpreter executes → Slow
```

### With JIT:

```
BPF bytecode → Native x86_64/ARM64 code → Fast
```

### Performance impact:

- **JIT disabled**: 5-10x slower (bytecode interpretation)
- **JIT enabled**: Near-native performance

### Enabling JIT:

```bash
# Check JIT status
cat /proc/sys/net/core/bpf_jit_enable
# 0 = disabled, 1 = enabled, 2 = enabled with debug

# Enable JIT
sudo sysctl net.core.bpf_jit_enable=1

# Make persistent
echo "net.core.bpf_jit_enable = 1" | sudo tee /etc/sysctl.d/99-bpf.conf
```

### Viewing JIT code:

```bash
# Dump native assembly for a loaded program
sudo bpftool prog dump jited id <ID>

# Example output:
#   0: push   %rbp
#   1: mov    %rsp,%rbp
#   4: sub    $0x10,%rsp
#   ...
```

### JIT on different architectures:

| Arch | JIT Support | Notes |
|------|-------------|-------|
| x86_64 | Excellent | Full support since 3.16 |
| ARM64 | Excellent | Full support since 3.18 |
| ARM32 | Good | Limited support |
| RISC-V | Good | Added in 5.1 |
| s390x | Good | IBM Z mainframe |

---

## Program Lifecycle

### Step-by-step execution:

```
1. DEVELOPMENT
   ┌────────────────────────────────────┐
   │ Developer writes prog.bpf.c        │
   └──────────────┬─────────────────────┘
                  │
                  ▼
2. COMPILATION
   ┌────────────────────────────────────┐
   │ clang -target bpf -c prog.bpf.c   │
   │ → prog.bpf.o (ELF with BPF code)  │
   └──────────────┬─────────────────────┘
                  │
                  ▼
3. LOADING (user-space)
   ┌────────────────────────────────────┐
   │ User-space loader:                 │
   │  • Opens prog.bpf.o                │
   │  • Extracts BPF sections           │
   │  • Calls bpf() syscall             │
   └──────────────┬─────────────────────┘
                  │ bpf(BPF_PROG_LOAD)
                  ▼
4. VERIFICATION (kernel)
   ┌────────────────────────────────────┐
   │ Kernel verifier:                   │
   │  • Checks safety                   │
   │  • Validates all paths             │
   │  • Pass? → JIT compile             │
   │  • Fail? → Return error            │
   └──────────────┬─────────────────────┘
                  │
                  ▼
5. JIT COMPILATION
   ┌────────────────────────────────────┐
   │ JIT compiler:                      │
   │  • BPF bytecode → native code      │
   │  • Optimizations                   │
   └──────────────┬─────────────────────┘
                  │
                  ▼
6. ATTACHMENT
   ┌────────────────────────────────────┐
   │ Attach to hook:                    │
   │  • kprobe, tracepoint, XDP, etc.  │
   │  • Returns bpf_link                │
   └──────────────┬─────────────────────┘
                  │
                  ▼
7. RUNTIME
   ┌────────────────────────────────────┐
   │ Kernel event occurs                │
   │  → eBPF program runs               │
   │  → Updates maps/buffers            │
   │  → User-space reads data           │
   └────────────────────────────────────┘
```

---

## Memory Model

### What memory can eBPF access?

1. **Stack**: 512 bytes per program
   ```c
   u64 local_var = 123;  // On stack
   ```

2. **Maps**: Shared storage between kernel/user-space
   ```c
   u64 *val = bpf_map_lookup_elem(&my_map, &key);
   ```

3. **Context**: Program-type-specific input
   ```c
   struct pt_regs *ctx = ...;  // kprobe context
   ```

4. **Helpers**: Read kernel memory via helpers
   ```c
   bpf_probe_read_kernel(&data, sizeof(data), src);
   ```

### Memory access rules:

- **Direct access**: Only stack and verified context pointers
- **Maps**: Via helper functions only
- **Kernel memory**: Via `bpf_probe_read_*` helpers (safe)
- **Bounds checking**: Verifier ensures all accesses are in bounds

---

## Helper Functions

### What are helpers?

Helpers are **kernel-provided functions** that eBPF programs can call.

### Categories:

| Category | Examples |
|----------|----------|
| **Map operations** | `bpf_map_lookup_elem`, `bpf_map_update_elem` |
| **Memory access** | `bpf_probe_read_kernel`, `bpf_probe_read_user` |
| **Networking** | `bpf_skb_load_bytes`, `bpf_redirect` |
| **Time** | `bpf_ktime_get_ns`, `bpf_ktime_get_boot_ns` |
| **Process info** | `bpf_get_current_pid_tgid`, `bpf_get_current_comm` |
| **Output** | `bpf_printk`, `bpf_ringbuf_submit` |
| **Random** | `bpf_get_prandom_u32` |

### Helper availability:

Not all helpers are available to all program types!

```bash
# Check available helpers for a program type
sudo bpftool feature probe kernel | grep -A 50 "Scanning eBPF helper functions"
```

### Example usage:

```c
// Get current time
u64 ts = bpf_ktime_get_ns();

// Get process info
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;
u32 tid = pid_tgid & 0xFFFFFFFF;

// Read kernel memory safely
struct task_struct *task = (void *)bpf_get_current_task();
u64 start_time;
bpf_probe_read_kernel(&start_time, sizeof(start_time), &task->start_time);
```

---

## Summary

| Component | Purpose | Key Takeaway |
|-----------|---------|--------------|
| **VM** | Execute BPF bytecode | Register-based, 11 registers, 512-byte stack |
| **Verifier** | Ensure safety | Static analysis, no crashes, bounded execution |
| **JIT** | Performance | Compiles to native code, enable with sysctl |
| **Helpers** | Kernel functions | Safe way to access kernel features |

---

## Next Steps

1. Read the next doc: **03-btf-and-type-info.md**
2. Try loading and inspecting the minimal program in `../src/`
3. Experiment with verifier errors by intentionally breaking the program
4. Dump JIT code and compare to BPF bytecode

---

## References

- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF Instruction Set](https://www.kernel.org/doc/Documentation/networking/filter.txt)
- [Verifier Documentation](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
