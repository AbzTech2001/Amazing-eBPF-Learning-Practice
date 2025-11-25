#!/bin/bash
# Generate vmlinux.h from kernel BTF

set -e

echo "========================================="
echo "vmlinux.h Generation"
echo "========================================="
echo ""

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "✗ bpftool not found. Please install it first."
    exit 1
fi

# Check if BTF is available
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "✗ Kernel BTF not found at /sys/kernel/btf/vmlinux"
    echo ""
    echo "Your kernel does not have BTF support enabled."
    echo "Please use a kernel with CONFIG_DEBUG_INFO_BTF=y (kernel 5.2+)"
    exit 1
fi

# Determine output location
if [ -n "$1" ]; then
    OUTPUT="$1"
else
    OUTPUT="vmlinux.h"
fi

echo "Generating vmlinux.h from kernel BTF..."
echo "Kernel version: $(uname -r)"
echo "Output file: $OUTPUT"
echo ""

# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUTPUT"

if [ $? -eq 0 ]; then
    FILE_SIZE=$(stat -f%z "$OUTPUT" 2>/dev/null || stat -c%s "$OUTPUT" 2>/dev/null)
    LINE_COUNT=$(wc -l < "$OUTPUT")

    echo "✓ Successfully generated vmlinux.h"
    echo ""
    echo "Statistics:"
    echo "  File size: $((FILE_SIZE / 1024 / 1024)) MB"
    echo "  Line count: $LINE_COUNT lines"
    echo ""
    echo "Usage in your BPF programs:"
    echo '  #include "vmlinux.h"'
    echo '  #include <bpf/bpf_helpers.h>'
    echo ""
else
    echo "✗ Failed to generate vmlinux.h"
    exit 1
fi
