#!/bin/bash
# Level 03: Verify libbpf Development Environment

set -e

echo "========================================="
echo "libbpf Environment Verification"
echo "========================================="
echo ""

PASSED=0
FAILED=0

check_command() {
    local cmd=$1
    local name=$2
    echo -n "Checking $name... "
    if command -v $cmd &> /dev/null; then
        echo "✓ Found: $(command -v $cmd)"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "✗ NOT FOUND"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_file() {
    local file=$1
    local name=$2
    echo -n "Checking $name... "
    if [ -f "$file" ]; then
        echo "✓ Found: $file"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "✗ NOT FOUND"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_library() {
    local lib=$1
    local name=$2
    echo -n "Checking $name... "
    if ldconfig -p | grep -q "$lib"; then
        echo "✓ Found"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "✗ NOT FOUND"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "=== Required Commands ==="
check_command clang "Clang compiler"
check_command llvm-strip "LLVM strip"
check_command bpftool "bpftool"
check_command pkg-config "pkg-config"
echo ""

echo "=== BTF Support ==="
check_file /sys/kernel/btf/vmlinux "Kernel BTF"
echo ""

echo "=== Header Files ==="
check_file /usr/include/bpf/bpf.h "libbpf headers"
check_file /usr/include/bpf/libbpf.h "libbpf.h"
check_file /usr/include/bpf/bpf_helpers.h "bpf_helpers.h"
check_file /usr/include/bpf/bpf_tracing.h "bpf_tracing.h"
check_file /usr/include/bpf/bpf_core_read.h "bpf_core_read.h"
echo ""

echo "=== Libraries ==="
check_library "libbpf.so" "libbpf shared library"
check_library "libelf.so" "libelf shared library"
check_library "libz.so" "zlib shared library"
echo ""

echo "=== Kernel Headers ==="
KERNEL_VERSION=$(uname -r)
check_file "/usr/src/linux-headers-$KERNEL_VERSION/include/linux/types.h" "Kernel headers for $KERNEL_VERSION"
echo ""

echo "=== Test Compilation ==="
echo -n "Testing BPF compilation... "
cat > /tmp/test_bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("execve: %s\n", comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

if clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c /tmp/test_bpf.c -o /tmp/test_bpf.o 2>/dev/null; then
    echo "✓ Compilation successful"
    PASSED=$((PASSED + 1))

    # Test skeleton generation
    echo -n "Testing skeleton generation... "
    if bpftool gen skeleton /tmp/test_bpf.o > /tmp/test_bpf.skel.h 2>/dev/null; then
        echo "✓ Skeleton generation successful"
        PASSED=$((PASSED + 1))
    else
        echo "✗ FAILED"
        FAILED=$((FAILED + 1))
    fi

    rm -f /tmp/test_bpf.o /tmp/test_bpf.skel.h
else
    echo "✗ FAILED"
    FAILED=$((FAILED + 1))
fi
rm -f /tmp/test_bpf.c
echo ""

echo "========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================="

if [ $FAILED -eq 0 ]; then
    echo "✓ All checks passed! You're ready for Level 03."
    exit 0
else
    echo "✗ Some checks failed. Please run setup-libbpf.sh or install missing components."
    exit 1
fi
