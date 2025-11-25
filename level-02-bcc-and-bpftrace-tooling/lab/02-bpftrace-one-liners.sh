#!/bin/bash

# Lab 02: bpftrace One-Liners
# Learn bpftrace through practical one-liner examples

echo "========================================="
echo "bpftrace One-Liners Lab"
echo "========================================="
echo ""

# Check if bpftrace is installed
if ! command -v bpftrace &> /dev/null; then
    echo "ERROR: bpftrace is not installed"
    echo "Run: sudo ../tools/setup-bcc-bpftrace.sh"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This lab needs root privileges"
    echo "Re-running with sudo..."
    sudo "$0" "$@"
    exit $?
fi

echo "This lab teaches bpftrace through one-liners."
echo "Each example will run for a few seconds."
echo ""
read -p "Press Enter to start..."
echo ""

# Helper function
run_oneliner() {
    local num=$1
    local desc=$2
    local cmd=$3
    local duration=${4:-10}

    echo "========================================="
    echo "Example $num: $desc"
    echo "========================================="
    echo ""
    echo "One-liner:"
    echo "  $cmd"
    echo ""
    echo "Running for $duration seconds..."
    echo ""

    timeout $duration bash -c "$cmd" || true

    echo ""
    echo "---"
    echo ""
    read -p "Press Enter for next example..."
    echo ""
}

# Example 1: Hello World
run_oneliner "1" "Hello World" \
    "bpftrace -e 'BEGIN { printf(\"Hello from bpftrace!\\\n\"); exit(); }'" \
    5

echo "Explanation:"
echo "  - BEGIN probe runs once at startup"
echo "  - printf() prints output"
echo "  - exit() terminates bpftrace"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 2: Count syscalls by process
run_oneliner "2" "Count syscalls by process" \
    "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" \
    10

echo "Explanation:"
echo "  - Attaches to syscall entry tracepoint"
echo "  - @[comm] creates a map keyed by process name"
echo "  - count() increments counter"
echo "  - Results printed at exit (Ctrl-C)"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 3: Trace file opens
run_oneliner "3" "Trace file opens" \
    "bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf(\"%s opened %s\\\n\", comm, str(args->filename)); }'" \
    10

echo "Explanation:"
echo "  - Traces openat() syscall (modern version of open)"
echo "  - args->filename accesses tracepoint argument"
echo "  - str() reads null-terminated string from kernel"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 4: Read latency histogram
run_oneliner "4" "Read syscall latency histogram" \
    "bpftrace -e 'tracepoint:syscalls:sys_enter_read { @start[tid] = nsecs; } tracepoint:syscalls:sys_exit_read /@start[tid]/ { @us = hist((nsecs - @start[tid]) / 1000); delete(@start[tid]); }'" \
    10

echo "Explanation:"
echo "  - Measures time between read() entry and exit"
echo "  - @start[tid] stores timestamp per thread"
echo "  - hist() creates power-of-2 histogram"
echo "  - Shows distribution of read latencies"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 5: TCP connections
echo "========================================="
echo "Example 5: Trace TCP connections"
echo "========================================="
echo ""
echo "This example requires kernel struct access"
echo "Creating script file temporarily..."
echo ""

cat > /tmp/bpftrace_tcp.bt << 'EOF'
#include <net/sock.h>

kprobe:tcp_connect
{
    $sk = (struct sock *)arg0;
    $family = $sk->__sk_common.skc_family;

    if ($family == AF_INET) {
        $daddr = $sk->__sk_common.skc_daddr;
        $dport = $sk->__sk_common.skc_dport;
        $dport = ($dport >> 8) | (($dport << 8) & 0xff00);

        printf("%s connecting to %s:%d\n",
               comm,
               ntop(AF_INET, $daddr),
               $dport);
    }
}
EOF

echo "Script:"
cat /tmp/bpftrace_tcp.bt
echo ""
echo "Running for 15 seconds..."
echo "Try: curl http://example.com (in another terminal)"
echo ""

timeout 15 bpftrace /tmp/bpftrace_tcp.bt || true

rm /tmp/bpftrace_tcp.bt

echo ""
echo "Explanation:"
echo "  - Attaches to tcp_connect kprobe"
echo "  - Reads struct sock fields"
echo "  - ntop() converts IP to string"
echo "  - Shows destination IP and port"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 6: CPU profiling
run_oneliner "6" "CPU profiler (sample stacks)" \
    "bpftrace -e 'profile:hz:99 { @[comm] = count(); }'" \
    10

echo "Explanation:"
echo "  - Samples CPU at 99Hz (99 times per second)"
echo "  - Counts samples per process"
echo "  - Shows which processes use most CPU"
echo "  - For full stacks: @[kstack, ustack, comm] = count()"
echo ""
read -p "Press Enter to continue..."
echo ""

# Example 7: Network packet size histogram
run_oneliner "7" "Network packet size distribution" \
    "bpftrace -e 'tracepoint:net:netif_receive_skb { @bytes = hist(args->len); }'" \
    10

echo "Explanation:"
echo "  - Traces received network packets"
echo "  - args->len is packet length"
echo "  - Histogram shows size distribution"
echo "  - Useful for understanding traffic patterns"
echo ""
read -p "Press Enter to continue..."
echo ""

# Summary
echo "========================================="
echo "Lab Summary"
echo "========================================="
echo ""
echo "You learned bpftrace fundamentals:"
echo ""
echo "1. BEGIN/END probes"
echo "2. Tracepoints (stable kernel instrumentation)"
echo "3. Kprobes (dynamic kernel function tracing)"
echo "4. Maps and aggregations (@map, count(), hist())"
echo "5. Built-in variables (comm, pid, nsecs, args)"
echo "6. String handling (str(), ntop())"
echo "7. Filtering (/condition/)"
echo ""
echo "Common one-liner patterns:"
echo ""
echo "Count by key:"
echo "  @[key] = count()"
echo ""
echo "Histogram:"
echo "  @map = hist(value)"
echo ""
echo "Latency measurement:"
echo "  entry: @start[tid] = nsecs"
echo "  exit:  @lat = hist(nsecs - @start[tid])"
echo ""
echo "Filtering:"
echo "  probe /pid == 1234/ { }"
echo ""
echo "Next steps:"
echo "  1. Try your own one-liners"
echo "  2. List probes: sudo bpftrace -l 'tracepoint:*'"
echo "  3. Read ../docs/02-bpftrace-deep-dive.md"
echo "  4. Explore example scripts in ../examples/bpftrace/"
echo ""
echo "Useful references:"
echo "  - bpftrace one-liner tutorial:"
echo "    https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md"
echo ""
