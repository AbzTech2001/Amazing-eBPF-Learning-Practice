#!/bin/bash
# Level 04: Verify Networking & Observability Environment

set -e

echo "========================================="
echo "Level 04: Environment Verification"
echo "========================================="
echo ""

PASSED=0
FAILED=0

check_command() {
    local cmd=$1
    local name=$2
    echo -n "Checking $name... "
    if command -v $cmd &> /dev/null; then
        echo "✓ Found"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "✗ NOT FOUND"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_kernel_feature() {
    local feature=$1
    local name=$2
    echo -n "Checking $name... "
    if grep -q "CONFIG_$feature=y" /boot/config-$(uname -r) 2>/dev/null || \
       zgrep -q "CONFIG_$feature=y" /proc/config.gz 2>/dev/null; then
        echo "✓ Enabled"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "⚠ Not found or disabled"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "=== Required Commands ==="
check_command clang "Clang compiler"
check_command bpftool "bpftool"
check_command tc "Traffic Control (tc)"
check_command ip "iproute2 (ip)"
check_command tcpdump "tcpdump"
echo ""

echo "=== XDP Support ==="
check_kernel_feature "BPF" "BPF subsystem"
check_kernel_feature "XDP_SOCKETS" "XDP sockets"
echo -n "Checking BTF for CO-RE... "
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ Available"
    PASSED=$((PASSED + 1))
else
    echo "✗ NOT FOUND"
    FAILED=$((FAILED + 1))
fi
echo ""

echo "=== TC (Traffic Control) Support ==="
echo -n "Checking tc cls_bpf support... "
if tc filter help 2>&1 | grep -q "bpf"; then
    echo "✓ Available"
    PASSED=$((PASSED + 1))
else
    echo "✗ NOT FOUND"
    FAILED=$((FAILED + 1))
fi
echo ""

echo "=== LSM BPF Support ==="
if [ -f /sys/kernel/security/lsm ]; then
    LSM_MODULES=$(cat /sys/kernel/security/lsm)
    echo -n "Checking LSM BPF... "
    if echo "$LSM_MODULES" | grep -q "bpf"; then
        echo "✓ Enabled"
        PASSED=$((PASSED + 1))
    else
        echo "⚠ Not enabled (Current LSM: $LSM_MODULES)"
        echo "   To enable: add 'lsm=...,bpf' to kernel cmdline"
        FAILED=$((FAILED + 1))
    fi
else
    echo "⚠ Cannot check LSM status"
    FAILED=$((FAILED + 1))
fi
echo ""

echo "=== Network Interfaces ==="
echo "Available interfaces:"
ip link show | grep -E "^[0-9]+" | awk '{print "  " $2}' | sed 's/:$//'
echo ""

echo "=== Test XDP Attachment ==="
echo -n "Testing XDP program attachment... "
# Get first non-loopback interface
IFACE=$(ip link show | grep -v "lo:" | grep -E "^[0-9]+: " | head -1 | awk '{print $2}' | sed 's/:$//')

if [ -n "$IFACE" ]; then
    # Create minimal XDP program
    cat > /tmp/test_xdp.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    if clang -O2 -target bpf -c /tmp/test_xdp.c -o /tmp/test_xdp.o 2>/dev/null; then
        # Try to attach (requires root)
        if [ "$EUID" -eq 0 ]; then
            if ip link set dev $IFACE xdpgeneric obj /tmp/test_xdp.o sec xdp 2>/dev/null; then
                echo "✓ XDP attachment works on $IFACE"
                PASSED=$((PASSED + 1))
                # Clean up
                ip link set dev $IFACE xdpgeneric off 2>/dev/null
            else
                echo "✗ XDP attachment failed"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "⚠ Skipped (requires root)"
        fi
    else
        echo "✗ Compilation failed"
        FAILED=$((FAILED + 1))
    fi

    rm -f /tmp/test_xdp.c /tmp/test_xdp.o
else
    echo "✗ No network interface found"
    FAILED=$((FAILED + 1))
fi
echo ""

echo "========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================="

if [ $FAILED -eq 0 ]; then
    echo "✓ All checks passed! You're ready for Level 04."
    exit 0
else
    echo "⚠ Some checks failed. This is OK for learning."
    echo "   Run setup-networking.sh to install missing components."
    exit 0  # Don't fail, just warn
fi
