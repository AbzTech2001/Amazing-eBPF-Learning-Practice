// SPDX-License-Identifier: GPL-2.0
// Minimal eBPF Program - Level 01 Example
//
// This program attaches to the sys_enter_execve tracepoint and prints
// when a new process is executed.
//
// Concepts demonstrated:
// - SEC() macro for specifying program type and attachment
// - Tracepoint context access
// - bpf_printk() for debugging output

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Character required by BPF license
char LICENSE[] SEC("license") = "GPL";

// Tracepoint format for sys_enter_execve
// Fields depend on the specific tracepoint
// For sys_enter_execve: (check /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format)
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

// SEC("tracepoint/...") tells the loader:
// - This is a tracepoint program
// - Attach to category "syscalls"
// - Attach to specific tracepoint "sys_enter_execve"
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    // Get current process ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;      // Process ID
    int tid = pid_tgid & 0xFFFFFFFF;  // Thread ID

    // Get command name (up to 16 chars)
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Print to trace pipe (/sys/kernel/debug/tracing/trace_pipe)
    // Format: "Process <name> (PID: <pid>) called execve"
    // Note: bpf_printk is limited but good for debugging
    // Production programs use ring buffers or maps
    bpf_printk("Process %s (PID: %d) called execve\\n", comm, pid);

    return 0;
}

// Alternative minimal example: Count events
//
// This demonstrates using a BPF map to count events
// Uncomment to use this instead

/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&exec_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}
*/
