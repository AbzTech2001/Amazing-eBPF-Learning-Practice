#!/bin/bash
# Detect kernel eBPF capabilities for production deployment

set -e

echo "========================================="
echo "eBPF Kernel Capability Detection"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_result() {
    local status=$1
    local message=$2

    case $status in
        pass)
            echo -e "${GREEN}✓${NC} $message"
            ;;
        warn)
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        fail)
            echo -e "${RED}✗${NC} $message"
            ;;
    esac
}

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo "=== System Information ==="
echo "Kernel: $KERNEL_VERSION"
echo "Architecture: $(uname -m)"
echo "Distribution: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo ""

echo "=== Core BPF Support ==="

# Check BPF syscall
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    UNPRIVILEGED_BPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    if [ "$UNPRIVILEGED_BPF" -eq 0 ]; then
        print_result "warn" "Unprivileged BPF enabled (security risk)"
    else
        print_result "pass" "Unprivileged BPF disabled (secure)"
    fi
else
    print_result "warn" "Cannot check unprivileged BPF status"
fi

# Check BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux)
    print_result "pass" "BTF available (size: $((BTF_SIZE / 1024)) KB)"
else
    print_result "fail" "BTF not available (CO-RE not possible)"
fi

# Check bpftool
if command -v bpftool &> /dev/null; then
    BPFTOOL_VERSION=$(bpftool version | head -1)
    print_result "pass" "bpftool available ($BPFTOOL_VERSION)"
else
    print_result "fail" "bpftool not found"
fi

echo ""
echo "=== Program Types ==="

# Helper to check program type
check_prog_type() {
    local type=$1
    local name=$2
    local min_kernel=$3

    if [ $KERNEL_MAJOR -gt $(echo $min_kernel | cut -d. -f1) ] || \
       ([ $KERNEL_MAJOR -eq $(echo $min_kernel | cut -d. -f1) ] && \
        [ $KERNEL_MINOR -ge $(echo $min_kernel | cut -d. -f2) ]); then
        print_result "pass" "$name (requires $min_kernel+)"
    else
        print_result "fail" "$name (requires $min_kernel+, have $KERNEL_MAJOR.$KERNEL_MINOR)"
    fi
}

check_prog_type "kprobe" "Kprobe/Kretprobe" "4.1"
check_prog_type "tracepoint" "Tracepoint" "4.7"
check_prog_type "xdp" "XDP" "4.8"
check_prog_type "perf_event" "Perf Event" "4.9"
check_prog_type "cgroup_skb" "Cgroup SKB" "4.10"
check_prog_type "cgroup_sock" "Cgroup Socket" "4.10"
check_prog_type "sched_cls" "TC (cls_bpf)" "4.1"
check_prog_type "sched_act" "TC (act_bpf)" "4.1"
check_prog_type "socket_filter" "Socket Filter" "3.19"
check_prog_type "raw_tracepoint" "Raw Tracepoint" "4.17"
check_prog_type "fentry" "Fentry/Fexit" "5.5"
check_prog_type "lsm" "LSM" "5.7"

echo ""
echo "=== Map Types ==="

check_map_type() {
    local name=$1
    local min_kernel=$2

    if [ $KERNEL_MAJOR -gt $(echo $min_kernel | cut -d. -f1) ] || \
       ([ $KERNEL_MAJOR -eq $(echo $min_kernel | cut -d. -f1) ] && \
        [ $KERNEL_MINOR -ge $(echo $min_kernel | cut -d. -f2) ]); then
        print_result "pass" "$name"
    else
        print_result "fail" "$name (requires $min_kernel+)"
    fi
}

check_map_type "Hash map" "3.19"
check_map_type "Array map" "3.19"
check_map_type "Per-CPU hash" "4.6"
check_map_type "Per-CPU array" "4.6"
check_map_type "LRU hash" "4.10"
check_map_type "Ring buffer" "5.8"
check_map_type "LPM trie" "4.11"
check_map_type "Stack trace" "4.6"

echo ""
echo "=== Helper Functions ==="

# Sample important helpers
if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 2 ]; then
    print_result "pass" "bpf_probe_read_kernel (safe kernel reads)"
else
    print_result "warn" "bpf_probe_read_kernel not available (use bpf_probe_read)"
fi

if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 5 ]; then
    print_result "pass" "bpf_sk_storage (socket-local storage)"
else
    print_result "warn" "bpf_sk_storage not available"
fi

if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 8 ]; then
    print_result "pass" "bpf_ringbuf_* (ring buffer helpers)"
else
    print_result "warn" "Ring buffer helpers not available"
fi

echo ""
echo "=== Advanced Features ==="

# Check CO-RE
if [ -f /sys/kernel/btf/vmlinux ]; then
    print_result "pass" "CO-RE (BTF-based portability)"
else
    print_result "fail" "CO-RE not available"
fi

# Check LSM BPF
if [ -f /sys/kernel/security/lsm ]; then
    LSM_MODULES=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_MODULES" | grep -q "bpf"; then
        print_result "pass" "LSM BPF enabled"
    else
        print_result "warn" "LSM BPF not enabled (add 'lsm=...,bpf' to kernel cmdline)"
    fi
fi

# Check CAP_BPF
if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 8 ]; then
    print_result "pass" "CAP_BPF capability (fine-grained permissions)"
else
    print_result "warn" "CAP_BPF not available (requires CAP_SYS_ADMIN)"
fi

# Check bounded loops
if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 3 ]; then
    print_result "pass" "Bounded loops (loop support)"
else
    print_result "warn" "Bounded loops not available (must use #pragma unroll)"
fi

# Check global variables
if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 2 ]; then
    print_result "pass" "Global variables (data/rodata/bss sections)"
else
    print_result "warn" "Global variables not available"
fi

echo ""
echo "=== Resource Limits ==="

if [ -f /proc/sys/kernel/bpf_stats_enabled ]; then
    BPF_STATS=$(cat /proc/sys/kernel/bpf_stats_enabled)
    if [ "$BPF_STATS" -eq 1 ]; then
        print_result "pass" "BPF statistics enabled"
    else
        print_result "warn" "BPF statistics disabled (echo 1 > /proc/sys/kernel/bpf_stats_enabled)"
    fi
fi

# Check memlock limit
MEMLOCK_LIMIT=$(ulimit -l)
if [ "$MEMLOCK_LIMIT" == "unlimited" ] || [ "$MEMLOCK_LIMIT" -gt 65536 ]; then
    print_result "pass" "Memlock limit sufficient: $MEMLOCK_LIMIT KB"
else
    print_result "warn" "Memlock limit may be too low: $MEMLOCK_LIMIT KB (increase with ulimit -l)"
fi

echo ""
echo "=== Summary ==="
echo ""

if [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 10 ]; then
    echo -e "${GREEN}✓ Kernel $KERNEL_VERSION is excellent for production eBPF${NC}"
elif [ $KERNEL_MAJOR -ge 5 ] && [ $KERNEL_MINOR -ge 2 ]; then
    echo -e "${GREEN}✓ Kernel $KERNEL_VERSION is good for production eBPF${NC}"
elif [ $KERNEL_MAJOR -ge 4 ] && [ $KERNEL_MINOR -ge 18 ]; then
    echo -e "${YELLOW}⚠ Kernel $KERNEL_VERSION has basic eBPF support (consider upgrading)${NC}"
else
    echo -e "${RED}✗ Kernel $KERNEL_VERSION has limited eBPF support (upgrade recommended)${NC}"
fi

echo ""
echo "Recommended minimum: Linux 5.10 LTS"
echo "Optimal: Linux 5.15 LTS or newer"
echo ""
