#!/bin/bash

# Lab 01: Check Kernel Support for eBPF
# This script provides a comprehensive overview of your system's eBPF capabilities

echo "========================================"
echo "eBPF Kernel Support Check"
echo "========================================"
echo ""

# System Information
echo "=== System Information ==="
echo "Kernel Version: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo ""

# Kernel Version Check
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)

echo "=== eBPF Feature Support by Kernel Version ==="
echo ""
echo "Your kernel: $KERNEL_MAJOR.$KERNEL_MINOR"
echo ""
echo "Feature availability:"
echo "  3.18+  : Basic BPF"
echo "  4.1+   : kprobes, tracepoints"
echo "  4.4+   : BPF helpers expanded"
echo "  4.8+   : XDP"
echo "  4.10+  : cgroup-bpf"
echo "  4.15+  : BTF initial support"
echo "  4.18+  : BPF Type Format (BTF)"
echo "  5.2+   : BPF ring buffer"
echo "  5.7+   : BPF LSM hooks"
echo "  5.8+   : CAP_BPF capability"
echo "  5.10+  : Recommended minimum (LTS)"
echo ""

if [ $KERNEL_MAJOR -lt 4 ] || ([ $KERNEL_MAJOR -eq 4 ] && [ $KERNEL_MINOR -lt 18 ]); then
    echo "WARNING: Your kernel is older than 4.18. Some features may not be available."
    echo "         Consider upgrading to kernel 5.10+ (LTS) for full eBPF support."
elif [ $KERNEL_MAJOR -lt 5 ] || ([ $KERNEL_MAJOR -eq 5 ] && [ $KERNEL_MINOR -lt 10 ]); then
    echo "INFO: Your kernel supports most eBPF features."
    echo "      For cutting-edge features, consider kernel 5.10+."
else
    echo "EXCELLENT: Your kernel has modern eBPF support!"
fi
echo ""

# Check kernel config
echo "=== Kernel Configuration ==="
echo ""

CONFIG_FILE=""
if [ -f /proc/config.gz ]; then
    CONFIG_FILE="/proc/config.gz"
    CONFIG_CMD="zcat /proc/config.gz"
    echo "Config source: /proc/config.gz"
elif [ -f "/boot/config-$(uname -r)" ]; then
    CONFIG_FILE="/boot/config-$(uname -r)"
    CONFIG_CMD="cat /boot/config-$(uname -r)"
    echo "Config source: /boot/config-$(uname -r)"
else
    echo "WARNING: Cannot find kernel config file"
    echo "         Checked: /proc/config.gz and /boot/config-$(uname -r)"
    echo "         Some checks will be skipped"
    echo ""
    CONFIG_FILE=""
fi

if [ -n "$CONFIG_FILE" ]; then
    echo ""
    echo "Essential BPF configs:"
    echo ""

    CONFIGS=(
        "CONFIG_BPF:Basic BPF support"
        "CONFIG_BPF_SYSCALL:BPF system call"
        "CONFIG_BPF_JIT:BPF JIT compiler"
        "CONFIG_HAVE_EBPF_JIT:eBPF JIT support"
        "CONFIG_BPF_EVENTS:BPF event support"
        "CONFIG_DEBUG_INFO_BTF:BTF debug info"
        "CONFIG_KPROBES:kprobe support"
        "CONFIG_KPROBE_EVENTS:kprobe event support"
        "CONFIG_TRACEPOINTS:Tracepoint support"
        "CONFIG_BPF_STREAM_PARSER:BPF stream parser"
        "CONFIG_CGROUP_BPF:cgroup-BPF support"
        "CONFIG_BPF_LSM:BPF LSM hooks"
        "CONFIG_XDP_SOCKETS:XDP sockets"
    )

    for config_line in "${CONFIGS[@]}"; do
        CONFIG_NAME=$(echo $config_line | cut -d: -f1)
        CONFIG_DESC=$(echo $config_line | cut -d: -f2)

        printf "  %-30s " "$CONFIG_DESC:"

        if [ -n "$CONFIG_CMD" ]; then
            VALUE=$($CONFIG_CMD 2>/dev/null | grep "^$CONFIG_NAME=" | cut -d= -f2)

            if [ "$VALUE" = "y" ]; then
                echo "✓ Enabled"
            elif [ "$VALUE" = "m" ]; then
                echo "⚠ Module"
            elif [ -z "$VALUE" ]; then
                echo "✗ Not set"
            else
                echo "? Unknown ($VALUE)"
            fi
        fi
    done
    echo ""
fi

# BTF Check
echo "=== BPF Type Format (BTF) ==="
echo ""

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ BTF is available"
    echo "  Location: /sys/kernel/btf/vmlinux"

    BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null)
    if [ -n "$BTF_SIZE" ]; then
        BTF_SIZE_MB=$(echo "scale=2; $BTF_SIZE / 1024 / 1024" | bc 2>/dev/null || echo "N/A")
        echo "  Size: $BTF_SIZE bytes ($BTF_SIZE_MB MB)"
    fi

    # Try to count types
    if command -v bpftool &> /dev/null; then
        echo ""
        echo "  Checking BTF contents..."
        TYPE_COUNT=$(sudo bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -c "^struct\|^union\|^enum" || echo "0")
        echo "  Types defined: ~$TYPE_COUNT"
    fi
else
    echo "✗ BTF is NOT available"
    echo "  This means:"
    echo "    - CO-RE (Compile Once, Run Everywhere) won't work"
    echo "    - You'll need to define kernel structs manually"
    echo "    - Programs won't be portable across kernel versions"
    echo ""
    echo "  To enable BTF, you need kernel compiled with CONFIG_DEBUG_INFO_BTF=y"
fi
echo ""

# BPF Filesystem
echo "=== BPF Filesystem ==="
echo ""

if mount | grep -q "type bpf"; then
    echo "✓ BPF filesystem is mounted"
    mount | grep "type bpf"
    echo ""
    echo "  Pinned objects:"
    if [ -d /sys/fs/bpf ]; then
        OBJECT_COUNT=$(find /sys/fs/bpf -type f 2>/dev/null | wc -l)
        if [ $OBJECT_COUNT -gt 0 ]; then
            echo "    $OBJECT_COUNT objects found in /sys/fs/bpf"
            echo ""
            echo "    Examples:"
            find /sys/fs/bpf -type f 2>/dev/null | head -5
        else
            echo "    No pinned objects (this is normal)"
        fi
    fi
else
    echo "✗ BPF filesystem is NOT mounted"
    echo ""
    echo "  To mount it:"
    echo "    sudo mount -t bpf none /sys/fs/bpf"
    echo ""
    echo "  To make it persistent, add to /etc/fstab:"
    echo "    none /sys/fs/bpf bpf defaults 0 0"
fi
echo ""

# JIT Compiler
echo "=== BPF JIT Compiler ==="
echo ""

if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    JIT_STATUS=$(cat /proc/sys/net/core/bpf_jit_enable)

    case $JIT_STATUS in
        0)
            echo "⚠ JIT is DISABLED (interpreted mode)"
            echo "  Programs will be significantly slower"
            echo "  To enable: sudo sysctl net.core.bpf_jit_enable=1"
            ;;
        1)
            echo "✓ JIT is ENABLED"
            echo "  Programs will be compiled to native code for best performance"
            ;;
        2)
            echo "ℹ JIT is ENABLED with debug output"
            echo "  This mode is for kernel developers"
            ;;
        *)
            echo "? Unknown JIT status: $JIT_STATUS"
            ;;
    esac

    if [ -f /proc/sys/net/core/bpf_jit_limit ]; then
        JIT_LIMIT=$(cat /proc/sys/net/core/bpf_jit_limit)
        JIT_LIMIT_MB=$(echo "scale=2; $JIT_LIMIT / 1024 / 1024" | bc 2>/dev/null || echo "N/A")
        echo "  JIT memory limit: $JIT_LIMIT bytes ($JIT_LIMIT_MB MB)"
    fi
else
    echo "⚠ Cannot check JIT status"
fi
echo ""

# Probe kernel features using bpftool
if command -v bpftool &> /dev/null; then
    echo "=== Probing Kernel Features with bpftool ==="
    echo ""
    echo "Available program types:"
    echo ""

    # Get available program types
    sudo bpftool feature probe kernel 2>/dev/null | grep "eBPF program_type" | head -10
    echo "  ... (run 'sudo bpftool feature probe kernel' for full list)"
    echo ""

    echo "Available helper functions (sample):"
    echo ""
    sudo bpftool feature probe kernel 2>/dev/null | grep "eBPF helpers" -A 5 | head -8
    echo "  ... (many more helpers available)"
else
    echo "=== bpftool not available ==="
    echo "Install bpftool to probe additional kernel features"
fi

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo ""

# Calculate readiness score
SCORE=0
MAX_SCORE=6

[ $KERNEL_MAJOR -gt 4 ] || ([ $KERNEL_MAJOR -eq 4 ] && [ $KERNEL_MINOR -ge 18 ]) && ((SCORE++))
[ -f /sys/kernel/btf/vmlinux ] && ((SCORE++))
mount | grep -q "type bpf" && ((SCORE++))
[ -f /proc/sys/net/core/bpf_jit_enable ] && [ "$(cat /proc/sys/net/core/bpf_jit_enable)" = "1" ] && ((SCORE++))
command -v bpftool &> /dev/null && ((SCORE++))
[ -f /usr/include/bpf/bpf.h ] && ((SCORE++))

echo "eBPF Readiness Score: $SCORE / $MAX_SCORE"
echo ""

if [ $SCORE -ge 5 ]; then
    echo "✓ EXCELLENT: Your system is well-configured for eBPF development"
elif [ $SCORE -ge 3 ]; then
    echo "⚠ GOOD: Most features available, but some improvements possible"
else
    echo "✗ LIMITED: Several important features are missing"
    echo "  Run '../tools/setup-environment.sh' to improve your setup"
fi

echo ""
echo "For detailed tool checks, run: ../tools/verify-setup.sh"
echo ""
