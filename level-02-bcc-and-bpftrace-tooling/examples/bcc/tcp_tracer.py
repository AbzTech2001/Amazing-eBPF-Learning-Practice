#!/usr/bin/env python3
# tcp_tracer.py - Trace TCP connections (connect/accept)
#
# This demonstrates:
# - Attaching to kprobes
# - Reading function arguments
# - Using perf buffers for event streaming
# - Parsing network data structures

from bcc import BPF
import socket
import struct

# eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Event structure sent to user-space
struct connect_event_t {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

// Trace TCP connect (active connection)
int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    struct connect_event_t event = {};

    // Get PID and command name
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read socket information
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

    // Only trace IPv4 for simplicity
    if (family != AF_INET) {
        return 0;
    }

    // Source address and port
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport),
                          &sk->__sk_common.skc_num);

    // Destination address and port
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr),
                          &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport),
                          &sk->__sk_common.skc_dport);

    // Submit event to user-space
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""

# Load BPF program
print("Loading BPF program...")
b = BPF(text=prog)

# Attach to tcp_connect kernel function
b.attach_kprobe(event="tcp_connect", fn_name="trace_connect")

print("Tracing TCP connections... Ctrl-C to stop.")
print("%-8s %-16s %-15s %-6s %-15s %-6s" %
      ("PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT"))

# Process events from perf buffer
def print_event(cpu, data, size):
    event = b["events"].event(data)

    # Convert IP addresses from network byte order
    saddr = socket.inet_ntoa(struct.pack("I", event.saddr))
    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))

    # Convert port from network byte order
    dport = socket.ntohs(event.dport)
    sport = event.sport  # Already in host byte order

    comm = event.comm.decode('utf-8', 'replace')

    print("%-8d %-16s %-15s %-6d %-15s %-6d" %
          (event.pid, comm, saddr, sport, daddr, dport))

# Open perf buffer
b["events"].open_perf_buffer(print_event)

# Poll for events
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting...")
