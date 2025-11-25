// SPDX-License-Identifier: GPL-2.0
/* Hello World - libbpf Example
 *
 * This is a minimal libbpf program demonstrating:
 * - Basic program structure
 * - Tracepoint attachment
 * - bpf_printk for debugging
 * - Skeleton usage
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Simple counter map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

// Tracepoint: syscalls/sys_enter_execve
// Fires when a process calls execve()
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    __u32 key = 0;
    __u64 *count;

    // Get process info
    char comm[16];
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    // Print to trace pipe
    bpf_printk("execve called by PID %d (%s)\n", pid, comm);

    // Increment counter
    count = bpf_map_lookup_elem(&counter, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}
