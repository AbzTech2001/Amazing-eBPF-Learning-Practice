#!/bin/bash

# Level 01: Verify eBPF Setup Script
# Checks that all required tools and dependencies are properly installed

echo "========================================="
echo "eBPF Setup Verification"
echo "========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SUCCESS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_command() {
    local cmd=$1
    local name=$2
    local required=$3

    echo -n "Checking $name... "
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓ Found${NC}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}✗ Not found (REQUIRED)${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            echo -e "${YELLOW}⚠ Not found (optional)${NC}"
            WARN_COUNT=$((WARN_COUNT + 1))
        fi
        return 1
    fi
}

check_file() {
    local file=$1
    local name=$2
    local required=$3

    echo -n "Checking $name... "
    if [ -f "$file" ] || [ -d "$file" ]; then
        echo -e "${GREEN}✓ Found${NC}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}✗ Not found (REQUIRED)${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            echo -e "${YELLOW}⚠ Not found (optional)${NC}"
            WARN_COUNT=$((WARN_COUNT + 1))
        fi
        return 1
    fi
}

echo "=== Required Tools ==="
echo ""

check_command "bpftool" "bpftool" "required"
if command -v bpftool &> /dev/null; then
    echo "  Version: $(bpftool version 2>&1 | head -n 1)"
fi

check_command "clang" "clang" "required"
if command -v clang &> /dev/null; then
    echo "  Version: $(clang --version | head -n 1)"
fi

check_command "llc" "LLVM" "required"
if command -v llc &> /dev/null; then
    echo "  Version: $(llc --version | head -n 1)"
fi

check_command "gcc" "GCC" "required"
if command -v gcc &> /dev/null; then
    echo "  Version: $(gcc --version | head -n 1)"
fi

check_command "make" "Make" "required"

echo ""
echo "=== Optional Tools ==="
echo ""

check_command "bpftrace" "bpftrace" "optional"
check_command "python3" "Python3" "optional"
check_command "strace" "strace" "optional"

echo ""
echo "=== Library Headers ==="
echo ""

check_file "/usr/include/bpf/bpf.h" "libbpf headers" "required"
check_file "/usr/include/bpf/libbpf.h" "libbpf.h" "required"
check_file "/usr/include/linux/bpf.h" "linux/bpf.h" "required"

# Check for kernel headers
echo -n "Checking kernel headers... "
KERNEL_VER=$(uname -r)
if [ -d "/usr/src/linux-headers-$KERNEL_VER" ] || \
   [ -d "/usr/src/kernels/$KERNEL_VER" ] || \
   [ -d "/lib/modules/$KERNEL_VER/build" ]; then
    echo -e "${GREEN}✓ Found${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${RED}✗ Not found (REQUIRED)${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "=== Kernel Support ==="
echo ""

# Check kernel version
KERNEL_VER_NUM=$(uname -r | cut -d. -f1,2)
echo -n "Kernel version (need 4.18+)... "
if awk -v ver="$KERNEL_VER_NUM" 'BEGIN {exit !(ver >= 4.18)}'; then
    echo -e "${GREEN}✓ $(uname -r)${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${YELLOW}⚠ $(uname -r) (may have limited features)${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# Check BTF support
echo -n "BTF support... "
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo -e "${GREEN}✓ Available${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${YELLOW}⚠ Not available (CO-RE may not work)${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# Check BPF filesystem
echo -n "BPF filesystem... "
if mount | grep -q "type bpf"; then
    echo -e "${GREEN}✓ Mounted${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    mount | grep "type bpf"
else
    echo -e "${YELLOW}⚠ Not mounted${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
    echo "  To mount: sudo mount -t bpf none /sys/fs/bpf"
fi

# Check JIT compiler
echo -n "BPF JIT compiler... "
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    JIT_STATUS=$(cat /proc/sys/net/core/bpf_jit_enable)
    if [ "$JIT_STATUS" = "1" ]; then
        echo -e "${GREEN}✓ Enabled${NC}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo -e "${YELLOW}⚠ Disabled (programs will be slower)${NC}"
        WARN_COUNT=$((WARN_COUNT + 1))
        echo "  To enable: sudo sysctl net.core.bpf_jit_enable=1"
    fi
else
    echo -e "${YELLOW}⚠ Cannot check${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# Try to check kernel configs
echo ""
echo -n "Kernel config access... "
if [ -f /proc/config.gz ]; then
    echo -e "${GREEN}✓ /proc/config.gz${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))

    echo ""
    echo "=== Key Kernel Configs ==="
    echo ""
    CONFIGS=("CONFIG_BPF" "CONFIG_BPF_SYSCALL" "CONFIG_BPF_JIT" "CONFIG_DEBUG_INFO_BTF" "CONFIG_KPROBES" "CONFIG_TRACEPOINTS")

    for cfg in "${CONFIGS[@]}"; do
        echo -n "  $cfg... "
        VAL=$(zcat /proc/config.gz 2>/dev/null | grep "^$cfg=" | cut -d= -f2)
        if [ "$VAL" = "y" ]; then
            echo -e "${GREEN}✓ enabled${NC}"
        elif [ "$VAL" = "m" ]; then
            echo -e "${YELLOW}⚠ module${NC}"
        else
            echo -e "${RED}✗ disabled${NC}"
        fi
    done
elif [ -f "/boot/config-$(uname -r)" ]; then
    echo -e "${GREEN}✓ /boot/config-$(uname -r)${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))

    echo ""
    echo "=== Key Kernel Configs ==="
    echo ""
    CONFIGS=("CONFIG_BPF" "CONFIG_BPF_SYSCALL" "CONFIG_BPF_JIT" "CONFIG_DEBUG_INFO_BTF" "CONFIG_KPROBES" "CONFIG_TRACEPOINTS")

    for cfg in "${CONFIGS[@]}"; do
        echo -n "  $cfg... "
        VAL=$(grep "^$cfg=" "/boot/config-$(uname -r)" 2>/dev/null | cut -d= -f2)
        if [ "$VAL" = "y" ]; then
            echo -e "${GREEN}✓ enabled${NC}"
        elif [ "$VAL" = "m" ]; then
            echo -e "${YELLOW}⚠ module${NC}"
        else
            echo -e "${RED}✗ disabled${NC}"
        fi
    done
else
    echo -e "${YELLOW}⚠ Not accessible${NC}"
    WARN_COUNT=$((WARN_COUNT + 1))
    echo "  Use 'bpftool feature probe' as alternative"
fi

# Test actual BPF functionality
echo ""
echo "=== Functional Tests ==="
echo ""

echo -n "Can list BPF programs... "
if sudo bpftool prog list &> /dev/null; then
    echo -e "${GREEN}✓ Yes${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${RED}✗ Failed${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo -n "Can list BPF maps... "
if sudo bpftool map list &> /dev/null; then
    echo -e "${GREEN}✓ Yes${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${RED}✗ Failed${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo -n "Can probe kernel features... "
if sudo bpftool feature probe kernel &> /dev/null; then
    echo -e "${GREEN}✓ Yes${NC}"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${RED}✗ Failed${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "========================================="
echo "Summary"
echo "========================================="
echo -e "${GREEN}Passed: $SUCCESS_COUNT${NC}"
echo -e "${YELLOW}Warnings: $WARN_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ Your system is ready for eBPF development!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run './lab/01-check-kernel-support.sh' for detailed kernel info"
    echo "  2. Try './lab/02-inspect-with-bpftool.sh' to explore eBPF"
    echo "  3. Read README.md for learning tasks"
    exit 0
else
    echo -e "${RED}✗ Some required components are missing${NC}"
    echo ""
    echo "Run './tools/setup-environment.sh' to install missing tools"
    exit 1
fi
