// SPDX-License-Identifier: GPL-2.0
/* Ring Buffer Events - eBPF Side
 *
 * Demonstrates:
 * - Ring buffer for efficient event streaming
 * - CO-RE for portable struct access
 * - Event filtering
 * - Structured event data
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Event structure shared between kernel and user-space
struct event {
    __u32 pid;
    __u32 ppid;
    __u8 filename[256];
    __u8 comm[16];
};

// Ring buffer map for streaming events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB buffer
} events SEC(".maps");

// Global variable for filtering (can be set from user-space)
const volatile int min_pid = 0;

// Helper to get filename from syscall args
static __always_inline const char *get_filename(struct trace_event_raw_sys_enter *ctx)
{
    // sys_enter_execve args:
    // args[0] = filename
    // args[1] = argv
    // args[2] = envp

    const char **filename_ptr = (const char **)(ctx->args[0]);
    const char *filename;

    bpf_probe_read_user(&filename, sizeof(filename), filename_ptr);
    return filename;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct event *e;
    __u64 pid_tgid;
    __u32 pid, ppid;

    // Get process info
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    // Filter: skip if PID < min_pid
    if (pid < min_pid)
        return 0;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Buffer full - event will be dropped
        return 0;
    }

    // Fill event structure
    e->pid = pid;

    // Get parent PID using CO-RE
    task = (struct task_struct *)bpf_get_current_task();

    // CO-RE read: works across kernel versions!
    // If field doesn't exist, will gracefully handle
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->ppid = ppid;

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get filename from syscall args
    const char *filename = get_filename(ctx);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Submit event to user-space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * Learning Notes:
 *
 * Ring Buffer Benefits:
 * 1. Memory efficient - single shared buffer
 * 2. Lock-free - better performance
 * 3. Global ordering - events ordered across CPUs
 * 4. Simpler API than perf buffer
 *
 * CO-RE Magic:
 * - BPF_CORE_READ() automatically:
 *   1. Reads BTF from target kernel
 *   2. Finds correct field offset
 *   3. Handles missing fields gracefully
 *   4. Works across kernel versions!
 *
 * Ring Buffer vs Perf Buffer:
 * - Ring buf: Better for most use cases (kernel 5.8+)
 * - Perf buf: Legacy, per-CPU overhead
 *
 * Global Variables:
 * - const volatile: Read-only from eBPF, writable from user-space
 * - Set before loading program
 * - Used for configuration/filtering
 */
