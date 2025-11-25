#!/bin/bash

# Lab 01: Explore BCC Tools
# This lab introduces you to the BCC tool collection

echo "========================================="
echo "BCC Tools Exploration Lab"
echo "========================================="
echo ""

# Check if BCC is installed
if ! python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "ERROR: BCC is not installed"
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

# Find BCC tools directory
BCC_TOOLS=""
for dir in /usr/share/bcc/tools /usr/sbin; do
    if [ -f "$dir/execsnoop" ] || [ -f "$dir/execsnoop.py" ]; then
        BCC_TOOLS="$dir"
        break
    fi
done

if [ -z "$BCC_TOOLS" ]; then
    echo "ERROR: Cannot find BCC tools"
    echo "Expected locations:"
    echo "  /usr/share/bcc/tools/"
    echo "  /usr/sbin/"
    exit 1
fi

echo "BCC tools found at: $BCC_TOOLS"
echo ""

# Function to run a tool with explanation
run_tool() {
    local tool=$1
    local desc=$2
    local args=$3
    local duration=${4:-5}

    echo "========================================="
    echo "Tool: $tool"
    echo "========================================="
    echo ""
    echo "Description: $desc"
    echo ""
    echo "Running for $duration seconds..."
    echo "Press Ctrl+C to stop early"
    echo ""

    # Find tool (with or without .py extension)
    local tool_path=""
    if [ -f "$BCC_TOOLS/$tool" ]; then
        tool_path="$BCC_TOOLS/$tool"
    elif [ -f "$BCC_TOOLS/$tool.py" ]; then
        tool_path="$BCC_TOOLS/$tool.py"
    else
        echo "Tool not found: $tool"
        return
    fi

    # Run tool with timeout
    timeout $duration $tool_path $args || true

    echo ""
    echo "---"
    echo ""
}

echo "This lab will demonstrate several BCC tools."
echo "Each tool will run for a few seconds."
echo ""
read -p "Press Enter to continue..."
echo ""

# Lab 1: execsnoop - Trace process execution
run_tool "execsnoop" "Trace new process execution" "" 10

echo "What you saw:"
echo "  - Every new process that was executed"
echo "  - Parent process ID (PPID)"
echo "  - Arguments passed to the command"
echo ""
echo "Try running some commands in another terminal to see them appear!"
echo ""
read -p "Press Enter for next tool..."
echo ""

# Lab 2: opensnoop - Trace file opens
run_tool "opensnoop" "Trace open() syscalls" "-n 20" 10

echo "What you saw:"
echo "  - Processes opening files"
echo "  - File paths being accessed"
echo "  - Useful for finding what files an app uses"
echo ""
read -p "Press Enter for next tool..."
echo ""

# Lab 3: biolatency - Block I/O latency histogram
echo "========================================="
echo "Tool: biolatency"
echo "========================================="
echo ""
echo "Description: Measure block I/O latency distribution"
echo ""
echo "Collecting data for 10 seconds..."
echo "Generating some I/O in background..."
echo ""

# Generate I/O
dd if=/dev/zero of=/tmp/bcc_test_io bs=1M count=50 2>/dev/null &
DD_PID=$!

# Run biolatency
timeout 10 $BCC_TOOLS/biolatency 1 10 || true

# Cleanup
wait $DD_PID 2>/dev/null || true
rm -f /tmp/bcc_test_io

echo ""
echo "What you saw:"
echo "  - Histogram of I/O latencies in microseconds"
echo "  - Distribution shows if I/O is fast (SSD) or slow (HDD)"
echo "  - Most values in 0-100 usecs = SSD"
echo "  - Values in milliseconds = HDD or slow I/O"
echo ""
read -p "Press Enter for next tool..."
echo ""

# Lab 4: tcpconnect - Trace TCP active connections
echo "========================================="
echo "Tool: tcpconnect"
echo "========================================="
echo ""
echo "Description: Trace active TCP connections (client-initiated)"
echo ""
echo "Running for 15 seconds..."
echo "Try making some network connections:"
echo "  curl http://example.com"
echo "  ping google.com"
echo "  ssh user@host"
echo ""

timeout 15 $BCC_TOOLS/tcpconnect || true

echo ""
echo "What you saw:"
echo "  - PID and process name making connections"
echo "  - Destination IP and port"
echo "  - Useful for finding what services apps connect to"
echo ""
read -p "Press Enter for next tool..."
echo ""

# Lab 5: funccount - Count kernel function calls
echo "========================================="
echo "Tool: funccount"
echo "========================================="
echo ""
echo "Description: Count kernel function calls"
echo ""
echo "Example: Counting VFS (Virtual File System) calls"
echo "Running for 10 seconds..."
echo ""

timeout 10 $BCC_TOOLS/funccount 'vfs_*' || true

echo ""
echo "What you saw:"
echo "  - Count of VFS function calls"
echo "  - vfs_read, vfs_write, vfs_open, etc."
echo "  - Shows which VFS operations are most common"
echo ""
read -p "Press Enter for summary..."
echo ""

# Summary
echo "========================================="
echo "Lab Summary"
echo "========================================="
echo ""
echo "You explored several BCC tools:"
echo ""
echo "1. execsnoop    - Process execution tracing"
echo "2. opensnoop    - File open() tracing"
echo "3. biolatency   - Block I/O latency histogram"
echo "4. tcpconnect   - TCP connection tracing"
echo "5. funccount    - Kernel function call counting"
echo ""
echo "BCC provides 100+ tools. Explore more:"
echo "  ls $BCC_TOOLS/"
echo ""
echo "Popular tools to try:"
echo "  - tcpaccept     : Trace TCP passive connections (server accept)"
echo "  - tcpretrans    : Trace TCP retransmissions"
echo "  - runqlat       : Scheduler run queue latency"
echo "  - profile       : CPU profiler"
echo "  - trace         : Arbitrary tracepoint/kprobe tracing"
echo ""
echo "Documentation:"
echo "  - Tool man pages: man <tool-name>"
echo "  - Online: https://github.com/iovisor/bcc/tree/master/tools"
echo ""
echo "Next steps:"
echo "  1. Try more tools from $BCC_TOOLS/"
echo "  2. Read ../docs/01-bcc-deep-dive.md"
echo "  3. Write your own BCC scripts in ../examples/bcc/"
echo "  4. Try lab 02: ./02-bpftrace-one-liners.sh"
echo ""
