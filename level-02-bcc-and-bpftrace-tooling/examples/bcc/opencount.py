#!/usr/bin/env python3
# opencount.py - Count open() syscalls per process
#
# This is a BCC example that demonstrates:
# - Attaching to tracepoints
# - Using BPF hash maps
# - Reading maps from Python
# - Ctrl-C handling

from bcc import BPF
from time import sleep
import signal
import sys

# eBPF program (C code)
prog = """
#include <uapi/linux/ptrace.h>

// BPF_HASH creates a hash map
// Key: PID (u32), Value: count (u64)
BPF_HASH(counts, u32, u64);

// Tracepoint: syscalls/sys_enter_openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Increment counter for this PID
    u64 zero = 0, *val;
    val = counts.lookup_or_try_init(&pid, &zero);
    if (val) {
        (*val)++;
    }

    return 0;
}
"""

# Load BPF program
print("Loading BPF program...")
b = BPF(text=prog)
print("BPF program loaded. Tracing open() syscalls... Ctrl-C to stop.")

# Graceful exit on Ctrl-C
def signal_handler(sig, frame):
    print("\n\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Print header
print("\n%-8s %-16s %-10s" % ("PID", "COMM", "COUNT"))

try:
    while True:
        sleep(1)

        # Clear screen (optional)
        # print("\033[2J\033[H")

        # Iterate over hash map
        counts = b["counts"]

        # Build list of (pid, count) tuples
        data = []
        for k, v in counts.items():
            data.append((k.value, v.value))

        # Sort by count (descending)
        data.sort(key=lambda x: x[1], reverse=True)

        # Print top 20
        for pid, count in data[:20]:
            try:
                # Get process name from /proc
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
            except:
                comm = "<unknown>"

            print("%-8d %-16s %-10d" % (pid, comm, count))

        # Optional: clear map for next interval
        # counts.clear()

except KeyboardInterrupt:
    pass

print("\n\nTop processes by open() calls:")
print("%-8s %-16s %-10s" % ("PID", "COMM", "TOTAL"))

# Final summary
counts = b["counts"]
data = []
for k, v in counts.items():
    data.append((k.value, v.value))

data.sort(key=lambda x: x[1], reverse=True)

for pid, count in data[:20]:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            comm = f.read().strip()
    except:
        comm = "<unknown>"

    print("%-8d %-16s %-10d" % (pid, comm, count))
