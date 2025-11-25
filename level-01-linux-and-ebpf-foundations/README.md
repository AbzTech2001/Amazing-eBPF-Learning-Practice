# Level 01: Linux & eBPF Foundations

## Overview

This level establishes the foundation for eBPF mastery by covering:
- Essential Linux kernel concepts for understanding eBPF
- eBPF architecture: VM, verifier, JIT compilation
- BTF (BPF Type Format) and why it's critical for portability
- Practical usage of `bpftool` for inspection and debugging
- Kernel configuration requirements

**Goal**: By the end of this level, you'll understand how eBPF programs execute in the kernel, how to verify kernel support, inspect running programs/maps, and troubleshoot common setup issues.

---

## Concepts Introduced

### 1. Linux Fundamentals for eBPF

| Concept | Why It Matters for eBPF |
|---------|-------------------------|
| **Syscalls** | eBPF programs can trace syscalls; `bpf()` syscall loads programs |
| **procfs** | `/proc` exposes kernel state; useful for debugging and validation |
| **cgroups** | eBPF can attach to cgroup hooks for process/network control |
| **namespaces** | Understanding isolation helps with Kubernetes/container tracing |
| **netns** | Network namespaces affect eBPF network program attachment |

### 2. eBPF Architecture

```
┌─────────────────────────────────────────────────────┐
│  eBPF Program Lifecycle                             │
├─────────────────────────────────────────────────────┤
│  1. Write C code (*.bpf.c)                         │
│  2. Compile to eBPF bytecode (clang + LLVM)        │
│  3. Load via bpf() syscall                         │
│  4. Verifier checks safety                         │
│     - No unbounded loops                           │
│     - No out-of-bounds memory access               │
│     - No unsafe pointer operations                 │
│     - Max 1M instructions (kernel version dependent)│
│  5. JIT compile to native code                     │
│  6. Attach to hook (kprobe, tracepoint, XDP, etc.) │
│  7. Run when kernel event fires                    │
└─────────────────────────────────────────────────────┘
```

**Key Components:**

- **BPF VM**: Executes eBPF bytecode in kernel space (sandboxed)
- **Verifier**: Static analyzer ensuring programs are safe (no crashes, no infinite loops)
- **JIT Compiler**: Translates bytecode to native machine code for performance
- **Maps**: Data structures for sharing data between eBPF programs and user space
- **Helpers**: Kernel-provided functions eBPF programs can call

### 3. BTF (BPF Type Format)

BTF is a metadata format describing types and function signatures in the kernel and eBPF programs.

**Why BTF is Critical:**
- **CO-RE (Compile Once, Run Everywhere)**: Write portable programs that work across kernel versions
- **Type information**: Enables safer map operations and better debugging
- **vmlinux.h**: Auto-generated header with all kernel types (no manual struct definitions)

**Checking BTF Support:**
```bash
# Check if kernel has BTF
ls /sys/kernel/btf/vmlinux

# Dump BTF info for a type
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "struct task_struct"
```

### 4. Required Kernel Configurations

Minimum kernel version: **4.18+** (recommend 5.10+ for modern features)

Essential configs:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y         # For BTF support
CONFIG_KPROBES=y                # For kprobe attachment
CONFIG_TRACEPOINTS=y            # For tracepoint attachment
```

Check your kernel:
```bash
zcat /proc/config.gz | grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF"
# OR
grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r)
```

---

## Tools & Dependencies

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **bpftool** | Inspect/manage eBPF programs and maps | `apt install linux-tools-common linux-tools-generic` |
| **clang** | Compile eBPF C code to bytecode | `apt install clang llvm` |
| **libbpf-dev** | Headers for future levels | `apt install libbpf-dev` |
| **gcc** | Build user-space loaders | Usually pre-installed |
| **make** | Build automation | `apt install build-essential` |

### Installation Script

Run:
```bash
./tools/setup-environment.sh
./tools/verify-setup.sh
```

---

## Kernel Facilities Used

- **bpf() syscall**: Load programs, create maps, attach to hooks
- **procfs**: Read `/proc/sys/kernel/bpf_*` for runtime stats
- **sysfs**: Read `/sys/kernel/btf/vmlinux` for type info
- **debugfs**: Some tools use `/sys/kernel/debug/tracing` for tracepoints

---

## Execution Steps

### Step 1: Verify Kernel Support
```bash
cd lab/
./01-check-kernel-support.sh
```

**Expected output:**
- Kernel version
- eBPF config status
- BTF availability
- Mounted bpf filesystem

### Step 2: Explore bpftool
```bash
./02-inspect-with-bpftool.sh
```

Learn to:
- List loaded programs: `bpftool prog list`
- List maps: `bpftool map list`
- Show program details: `bpftool prog show id <ID>`
- Dump map contents: `bpftool map dump id <ID>`

### Step 3: Load a Minimal eBPF Program
```bash
cd ../src/
make
./03-load-simple-program.sh
```

This loads `minimal.bpf.c` (a tracepoint program) and verifies it's running.

### Step 4: Explore BTF
```bash
cd ../lab/
./04-btf-exploration.sh
```

Dump kernel types and understand how CO-RE uses BTF for portability.

---

## Practical Tasks (10+)

### Task 1: Kernel Configuration Audit
**Objective**: Verify your kernel has all necessary eBPF features enabled.

**Steps:**
1. Find your running kernel config file (`/proc/config.gz` or `/boot/config-*`)
2. Check for `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
3. If any are missing, note which ones and research if your distro provides them via modules

**Deliverable**: A text file listing all BPF-related config values.

---

### Task 2: BTF Availability Check
**Objective**: Confirm BTF is present and explore its structure.

**Steps:**
1. Check if `/sys/kernel/btf/vmlinux` exists
2. Use `bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -100`
3. Search for a common kernel struct: `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "struct file "`

**Deliverable**: Screenshot or output showing the `struct file` definition from BTF.

---

### Task 3: Enumerate Loaded eBPF Programs
**Objective**: Use `bpftool` to see what eBPF programs are already running on your system.

**Steps:**
1. Run `sudo bpftool prog list`
2. Pick one program and run `sudo bpftool prog show id <ID>`
3. Note the program type (e.g., tracepoint, kprobe)

**Deliverable**: Paste output and identify what the program does (e.g., systemd, Docker, other).

---

### Task 4: Inspect eBPF Maps
**Objective**: Explore existing eBPF maps on the system.

**Steps:**
1. Run `sudo bpftool map list`
2. Choose a map and dump its contents: `sudo bpftool map dump id <ID>`
3. Identify the key/value types

**Deliverable**: Describe one map's purpose based on its name and contents.

---

### Task 5: Build and Load Minimal eBPF Program
**Objective**: Compile and load the provided `minimal.bpf.c` program.

**Steps:**
1. `cd src/`
2. `make`
3. Run the loader: `sudo ./minimal_loader`
4. Verify it's loaded: `sudo bpftool prog list | grep minimal`

**Deliverable**: Confirm the program ID appears in `bpftool` output.

---

### Task 6: Attach to a Tracepoint
**Objective**: Modify `minimal.bpf.c` to attach to a different tracepoint.

**Steps:**
1. List available tracepoints: `sudo ls /sys/kernel/debug/tracing/events/syscalls/`
2. Change the tracepoint in `minimal.bpf.c` from `sys_enter_execve` to `sys_enter_openat`
3. Recompile and load
4. Trigger the tracepoint by opening a file: `cat /etc/hostname`

**Deliverable**: Describe any output or lack thereof (we'll add proper logging in Level 2/3).

---

### Task 7: Explore BPF Filesystem
**Objective**: Understand where eBPF objects are pinned.

**Steps:**
1. Check if bpf filesystem is mounted: `mount | grep bpf`
2. If not, mount it: `sudo mount -t bpf none /sys/fs/bpf`
3. List pinned objects: `ls -la /sys/fs/bpf/`

**Deliverable**: Explain what "pinning" means for eBPF programs/maps.

---

### Task 8: Read eBPF Runtime Stats
**Objective**: Understand eBPF resource limits and statistics.

**Steps:**
1. Check JIT status: `cat /proc/sys/net/core/bpf_jit_enable` (should be 1)
2. Check max program size: `cat /proc/sys/net/core/bpf_jit_limit`
3. Look at verifier stats if available: `cat /proc/kallsyms | grep bpf_stats_enabled`

**Deliverable**: List the values and explain what `bpf_jit_enable=1` means.

---

### Task 9: Understand Program Types
**Objective**: Research and document different eBPF program types.

**Steps:**
1. Read `man bpf` or kernel docs on program types
2. Create a table with: program type, use case, example hook

Example:
| Type | Use Case | Hook |
|------|----------|------|
| BPF_PROG_TYPE_KPROBE | Trace kernel functions | Any kernel function |
| BPF_PROG_TYPE_XDP | Packet processing | NIC driver |

**Deliverable**: A markdown table with at least 6 program types.

---

### Task 10: Inspect Helper Functions
**Objective**: Discover what helper functions are available to eBPF programs.

**Steps:**
1. Run `bpftool feature probe kernel` (shows helpers available)
2. Or check `/usr/include/linux/bpf.h` for `bpf_helper_defs.h`
3. Pick 3 helpers (e.g., `bpf_printk`, `bpf_get_current_pid_tgid`, `bpf_map_lookup_elem`)

**Deliverable**: Short description of what each helper does.

---

### Task 11: Generate vmlinux.h
**Objective**: Create a portable header with all kernel types.

**Steps:**
1. Run `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
2. Open `vmlinux.h` and search for `struct task_struct`
3. Note how many lines the file has (`wc -l vmlinux.h`)

**Deliverable**: Report the file size and explain why this is useful for CO-RE.

---

### Task 12: Trace bpf() Syscalls
**Objective**: See how user-space interacts with eBPF subsystem.

**Steps:**
1. Use `strace` to trace bpf syscalls: `sudo strace -e bpf bpftool prog list`
2. Observe the syscall arguments
3. Identify operations: `BPF_PROG_GET_NEXT_ID`, `BPF_OBJ_GET_INFO_BY_FD`

**Deliverable**: Paste a snippet of `strace` output and explain one operation.

---

## Real-World Challenges (5+)

### Challenge 1: Missing BTF Support
**Scenario**: You're on an older kernel (e.g., 4.19) without `CONFIG_DEBUG_INFO_BTF=y`.

**Problem**:
- `/sys/kernel/btf/vmlinux` doesn't exist
- CO-RE programs fail to load
- You see: `libbpf: failed to find BTF info for kernel`

**Your Task**:
1. Detect BTF absence programmatically (script)
2. Research fallback strategies:
   - Ship pre-compiled BPF objects for specific kernels?
   - Use non-CO-RE approach with manual struct definitions?
3. Document trade-offs of each approach

**Expected Outcome**: A decision matrix: when to require BTF vs. when to support older kernels.

---

### Challenge 2: Kernel Config Locked Down
**Scenario**: You're on a production Ubuntu server. `/proc/config.gz` doesn't exist, and `/boot/config-*` is missing.

**Problem**:
- You can't verify if eBPF features are enabled
- Some eBPF programs fail with cryptic errors like `Operation not supported`

**Your Task**:
1. Try alternative methods to check kernel features:
   - `zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null`
   - Check if eBPF works empirically: try loading a minimal program
   - Use `bpftool feature probe` to detect available features
2. Write a robust detection script that tries multiple methods
3. Decide: continue or abort if critical features missing

**Expected Outcome**: A shell script that gracefully handles missing config files.

---

### Challenge 3: bpftool Not Found
**Scenario**: On some minimal Linux installations (e.g., Alpine, old Debian), `bpftool` is not installed by default.

**Problem**:
- `bpftool` command not found
- Package manager doesn't have `bpftool` (or it's named differently)
- You need it for debugging

**Your Task**:
1. Research how to install `bpftool` on:
   - Ubuntu/Debian: `linux-tools-$(uname -r)` or `linux-tools-generic`
   - Fedora/RHEL: `bpftool` package
   - Alpine: may need to compile from kernel source
2. If unavailable, compile from kernel source:
   ```bash
   git clone --depth 1 https://github.com/torvalds/linux.git
   cd linux/tools/bpf/bpftool
   make
   sudo make install
   ```
3. Document install steps for 3 distros

**Expected Outcome**: A `INSTALL.md` with distro-specific instructions.

---

### Challenge 4: Permission Denied Loading Programs
**Scenario**: You try to load an eBPF program as a non-root user and get:
```
bpf() syscall failed: Operation not permitted
```

**Problem**:
- eBPF requires `CAP_BPF` and `CAP_NET_ADMIN` capabilities (kernel 5.8+)
- Older kernels require full root
- Docker containers may not have necessary capabilities

**Your Task**:
1. Check kernel version: `uname -r`
2. If 5.8+, try granting capabilities:
   ```bash
   sudo setcap cap_bpf,cap_net_admin+ep ./my_program
   ```
3. If in Docker, ensure container runs with `--privileged` or specific caps:
   ```bash
   docker run --cap-add=BPF --cap-add=NET_ADMIN ...
   ```
4. Document when root is required vs. when capabilities suffice

**Expected Outcome**: A security guide explaining least-privilege eBPF execution.

---

### Challenge 5: Verifier Rejects Simple Program
**Scenario**: You modify `minimal.bpf.c` to add a loop:
```c
for (int i = 0; i < 100; i++) {
    // do something
}
```

**Problem**:
```
Verifier log:
back-edge from insn 10 to 5
```

**Your Task**:
1. Understand why verifier rejects loops (can't prove termination)
2. Rewrite using:
   - `#pragma unroll` to unroll loops at compile time
   - Or bounded iteration with verifier-friendly patterns
3. Load the fixed program successfully

**Expected Outcome**: Working program with verifier-approved loop (unrolled or bounded).

---

### Challenge 6: Debugging Verifier Rejections
**Scenario**: Your program is rejected with a long verifier log:
```
R1 type=inv expected=ctx
invalid bpf_context access off=8 size=8
```

**Problem**:
- Verifier logs are cryptic
- You don't know which line of code caused the issue
- No stack trace or clear error message

**Your Task**:
1. Enable verbose verifier output: `echo 2 | sudo tee /proc/sys/kernel/bpf_verbose`
2. Re-run and capture full verifier log
3. Learn to read verifier state: register types, bounds, pointer tracking
4. Fix the specific issue (usually: incorrect pointer arithmetic or accessing wrong offset in context)

**Expected Outcome**: Document 3 common verifier error patterns and how to fix them.

---

## Learning Checklist

By the end of Level 01, you should be able to:

- [ ] Explain how the eBPF VM, verifier, and JIT work together
- [ ] Verify kernel has required eBPF configs enabled
- [ ] Check if BTF is available and understand its purpose
- [ ] Use `bpftool` to list, inspect, and debug programs/maps
- [ ] Load a minimal eBPF program and verify it's running
- [ ] Understand different eBPF program types and when to use each
- [ ] Read and interpret basic verifier error messages
- [ ] Generate `vmlinux.h` for CO-RE development
- [ ] Explain the difference between BCC, bpftrace, and libbpf approaches
- [ ] Troubleshoot common setup issues (missing tools, permissions, BTF)

---

## Next Steps

Once you're comfortable with these foundations, proceed to:

**Level 02**: BCC, bpftrace & Core Tracing Tools
- Write custom BCC/bpftrace scripts
- Profile CPU, disk, network performance
- Understand kprobes and tracepoints deeply
- Analyze tool overhead and when to avoid them

---

## References

- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [BPF and XDP Reference Guide (Cilium)](https://docs.cilium.io/en/stable/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [bpftool man page](https://man7.org/linux/man-pages/man8/bpftool.8.html)

---

**Ready to start? Run `./tools/setup-environment.sh` to install dependencies!**
