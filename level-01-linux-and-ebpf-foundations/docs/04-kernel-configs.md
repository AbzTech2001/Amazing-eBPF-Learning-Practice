# Kernel Configuration for eBPF

## Overview

This document covers the kernel configuration options required for eBPF and how to check/enable them.

---

## Essential Kernel Configs

### Core eBPF Support

These are **required** for any eBPF functionality:

```bash
CONFIG_BPF=y                    # Basic BPF support
CONFIG_BPF_SYSCALL=y            # Enable bpf() syscall
CONFIG_BPF_JIT=y                # JIT compiler support
CONFIG_HAVE_EBPF_JIT=y          # Architecture has JIT
```

### Recommended Configs

These enable common eBPF features:

```bash
CONFIG_BPF_EVENTS=y             # Tracing/perf events support
CONFIG_DEBUG_INFO_BTF=y         # BTF type information (critical for CO-RE)
CONFIG_DEBUG_INFO_BTF_MODULES=y # BTF for modules (optional but useful)
CONFIG_KPROBES=y                # kprobe support
CONFIG_KPROBE_EVENTS=y          # kprobe event support
CONFIG_UPROBE_EVENTS=y          # uprobe event support
CONFIG_TRACEPOINTS=y            # Stable tracepoint support
CONFIG_FTRACE=y                 # Function tracing infrastructure
```

### Advanced Configs

For specific use cases:

```bash
# Networking
CONFIG_BPF_STREAM_PARSER=y      # BPF stream parser
CONFIG_NET_CLS_BPF=y            # BPF classifier (tc)
CONFIG_NET_ACT_BPF=y            # BPF action (tc)
CONFIG_XDP_SOCKETS=y            # XDP AF_XDP sockets

# Cgroup
CONFIG_CGROUP_BPF=y             # cgroup-bpf support
CONFIG_SOCK_CGROUP_DATA=y       # Socket cgroup data

# Security
CONFIG_BPF_LSM=y                # LSM hooks (kernel 5.7+)
CONFIG_LSM="...,bpf"            # Enable BPF in LSM list

# Performance
CONFIG_BPF_JIT_ALWAYS_ON=y      # Force JIT (no fallback to interpreter)
CONFIG_BPF_JIT_DEFAULT_ON=y     # Enable JIT by default
```

---

## Checking Your Kernel Config

### Method 1: /proc/config.gz

If enabled (`CONFIG_IKCONFIG_PROC=y`):

```bash
# Check if available
ls /proc/config.gz

# Extract and search
zcat /proc/config.gz | grep BPF

# Check specific config
zcat /proc/config.gz | grep CONFIG_BPF=
```

### Method 2: /boot/config-*

Standard location on most distros:

```bash
# Current kernel config
cat /boot/config-$(uname -r) | grep BPF

# All kernel configs
ls /boot/config-*
```

### Method 3: /sys/kernel/kconfig.gz

On some systems:

```bash
# Check if available
ls /sys/kernel/kconfig.gz

# Extract
zcat /sys/kernel/kconfig.gz | grep BPF
```

### Method 4: bpftool feature probe

Runtime feature detection:

```bash
# Probe all BPF features
sudo bpftool feature probe kernel

# Specific checks
sudo bpftool feature probe kernel | grep -i btf
sudo bpftool feature probe kernel | grep -i jit
```

---

## Kernel Version Requirements

### Minimum versions for key features:

| Feature | Minimum Kernel | Recommended |
|---------|---------------|-------------|
| Basic eBPF | 3.18+ | 4.18+ |
| Networking (XDP) | 4.8+ | 5.10+ |
| BTF | 4.18+ | 5.10+ |
| CO-RE | 5.2+ | 5.10+ |
| Ring buffer | 5.8+ | 5.10+ |
| LSM hooks | 5.7+ | 5.10+ |
| CAP_BPF capability | 5.8+ | 5.10+ |

### Recommended baseline: **Linux 5.10 LTS**

Why 5.10?
- Long-term support (LTS)
- Full BTF/CO-RE support
- Modern helper functions
- Stable APIs
- Good distro support

---

## Distribution Defaults

### Ubuntu/Debian

Most configs enabled by default on recent versions:

```bash
# Ubuntu 20.04+, Debian 11+
# BTF: ✓ (if kernel 5.10+)
# BPF_SYSCALL: ✓
# KPROBES: ✓
# XDP: ✓
```

Check:
```bash
grep CONFIG_BPF /boot/config-$(uname -r)
```

### Fedora/RHEL/CentOS

Generally excellent eBPF support:

```bash
# Fedora 33+, RHEL 8.3+
# Most eBPF features enabled
```

### Arch Linux

Bleeding-edge kernel with most features:

```bash
# Usually latest stable kernel
# Most eBPF configs enabled
```

---

## Enabling Missing Configs

### For custom kernels:

If you compile your own kernel:

```bash
# Download kernel source
cd /usr/src/linux-$(uname -r)

# Configure
make menuconfig

# Navigate to:
# General setup
#   → BPF subsystem

# Enable required options, then:
make -j$(nproc)
sudo make modules_install
sudo make install
sudo update-grub  # or equivalent
```

### For distribution kernels:

You typically **cannot change configs** without recompiling.

Options:
1. Upgrade to a newer kernel version (if available)
2. Use a different kernel flavor (e.g., `linux-generic` vs `linux-aws`)
3. Compile a custom kernel

---

## Runtime Checks

### Check BPF syscall:

```bash
# Try loading a trivial program
# If CONFIG_BPF_SYSCALL is disabled, you'll see:
# "bpf() syscall not available"
```

### Check BTF:

```bash
# If CONFIG_DEBUG_INFO_BTF is disabled:
ls /sys/kernel/btf/vmlinux
# ls: cannot access '/sys/kernel/btf/vmlinux': No such file or directory
```

### Check JIT:

```bash
cat /proc/sys/net/core/bpf_jit_enable
# 0 = disabled
# 1 = enabled
# 2 = enabled with debug
```

### Check tracepoints:

```bash
# If CONFIG_TRACEPOINTS is disabled:
ls /sys/kernel/debug/tracing/events/
# Directory won't exist or will be empty
```

---

## Common Config Issues

### Issue 1: No BTF

**Symptom**: `libbpf: failed to find BTF`

**Cause**: `CONFIG_DEBUG_INFO_BTF=n`

**Fix**:
- Upgrade kernel to one with BTF support
- OR use non-CO-RE approach (manual struct definitions)

### Issue 2: Cannot load programs

**Symptom**: `bpf() syscall failed: Function not implemented`

**Cause**: `CONFIG_BPF_SYSCALL=n`

**Fix**:
- Use a kernel with BPF support (most modern distros)
- Cannot be enabled at runtime

### Issue 3: Tracepoints don't work

**Symptom**: `Failed to attach to tracepoint`

**Cause**: `CONFIG_TRACEPOINTS=n` or `CONFIG_FTRACE=n`

**Fix**:
- Enable in kernel config and recompile
- OR use kprobes instead (less stable API)

### Issue 4: XDP not available

**Symptom**: `XDP not supported on this interface`

**Cause**:
- `CONFIG_XDP_SOCKETS=n`
- OR driver doesn't support XDP

**Fix**:
- Enable XDP in kernel config
- Check driver support: `ethtool -i eth0`

---

## Security Considerations

### CAP_BPF capability (kernel 5.8+)

On newer kernels, you can grant BPF access without full root:

```bash
# Grant CAP_BPF and CAP_NET_ADMIN to a binary
sudo setcap cap_bpf,cap_net_admin+ep ./my_bpf_program

# Now can run without root
./my_bpf_program
```

### Before kernel 5.8:

Need **full root** or run via `sudo`.

### Restricting BPF access:

```bash
# Disable unprivileged BPF (recommended in production)
sudo sysctl kernel.unprivileged_bpf_disabled=1

# Make persistent
echo "kernel.unprivileged_bpf_disabled = 1" | sudo tee /etc/sysctl.d/99-bpf-security.conf
```

---

## Recommended Configuration Matrix

### Development Environment

```bash
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_TRACEPOINTS=y
CONFIG_FTRACE=y
CONFIG_XDP_SOCKETS=y
CONFIG_CGROUP_BPF=y
CONFIG_BPF_LSM=y  # if kernel 5.7+
```

### Production Environment

All of the above, plus:

```bash
CONFIG_BPF_JIT_ALWAYS_ON=y  # No interpreter fallback (more secure)
```

Runtime settings:
```bash
kernel.unprivileged_bpf_disabled=1  # Disable unprivileged BPF
net.core.bpf_jit_enable=1           # Enable JIT
```

---

## Verification Script

Create a script to check all configs:

```bash
#!/bin/bash
# check-bpf-configs.sh

CONFIG_FILE=""
if [ -f /proc/config.gz ]; then
    CONFIG_CMD="zcat /proc/config.gz"
elif [ -f /boot/config-$(uname -r) ]; then
    CONFIG_CMD="cat /boot/config-$(uname -r)"
else
    echo "Cannot find kernel config"
    exit 1
fi

CONFIGS=(
    "CONFIG_BPF"
    "CONFIG_BPF_SYSCALL"
    "CONFIG_BPF_JIT"
    "CONFIG_DEBUG_INFO_BTF"
    "CONFIG_KPROBES"
    "CONFIG_TRACEPOINTS"
    "CONFIG_XDP_SOCKETS"
    "CONFIG_CGROUP_BPF"
)

for cfg in "${CONFIGS[@]}"; do
    value=$($CONFIG_CMD | grep "^$cfg=" | cut -d= -f2)
    if [ "$value" = "y" ]; then
        echo "✓ $cfg=y"
    else
        echo "✗ $cfg not enabled"
    fi
done
```

---

## Summary

### Must-have configs:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
```

### Nice-to-have configs:

```
CONFIG_KPROBES=y
CONFIG_TRACEPOINTS=y
CONFIG_XDP_SOCKETS=y
CONFIG_BPF_LSM=y
```

### Minimum kernel: **4.18+**
### Recommended kernel: **5.10+ (LTS)**

---

## Next Steps

1. Check your kernel configs:
   ```bash
   ../lab/01-check-kernel-support.sh
   ```

2. If missing features, consider:
   - Upgrading kernel
   - Using different kernel flavor
   - Compiling custom kernel

3. Proceed to running the labs and tasks in the main README.md

---

## References

- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [Linux Kernel Configuration Guide](https://www.kernel.org/doc/html/latest/admin-guide/README.html)
