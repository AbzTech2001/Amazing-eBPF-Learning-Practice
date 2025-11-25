#!/usr/bin/env python3
# syscall_latency.py - Measure syscall latency distribution
#
# This demonstrates:
# - Tracing syscall entry and exit
# - Measuring time between events
# - Using BPF histograms
# - Per-syscall breakdown

from bcc import BPF
from time import sleep

# eBPF program
prog = """
#include <uapi/linux/ptrace.h>

// Store start time for each thread
BPF_HASH(start, u64);

// Histogram: latency distribution (microseconds)
BPF_HISTOGRAM(dist);

// Per-syscall histogram
BPF_HASH(syscall_dist, u64, u64);

// Tracepoint: syscall entry
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    start.update(&tid, &ts);

    return 0;
}

// Tracepoint: syscall exit
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 *tsp, delta;

    // Lookup start time
    tsp = start.lookup(&tid);
    if (tsp == 0) {
        return 0;   // Missed entry
    }

    // Calculate latency in microseconds
    delta = (bpf_ktime_get_ns() - *tsp) / 1000;

    // Store in histogram
    dist.increment(bpf_log2l(delta));

    // Cleanup
    start.delete(&tid);

    return 0;
}
"""

# Load BPF program
print("Loading BPF program...")
b = BPF(text=prog)
print("Measuring syscall latency... (this will have overhead!)")
print("Collecting data for 10 seconds...")

# Collect for 10 seconds
sleep(10)

# Print histogram
print("\nSyscall Latency Distribution (microseconds):")
b["dist"].print_log2_hist("latency (usecs)")

print("\nNotes:")
print("- This traces ALL syscalls system-wide (high overhead)")
print("- For production, use filtering or sampling")
print("- Histogram shows log2 distribution")
