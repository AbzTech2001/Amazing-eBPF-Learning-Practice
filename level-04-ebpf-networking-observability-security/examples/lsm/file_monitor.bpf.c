// SPDX-License-Identifier: GPL-2.0
/* LSM File Access Monitor
 *
 * Demonstrates:
 * - LSM hook attachment
 * - File access monitoring
 * - Security policy enforcement
 * - Event logging
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Event structure
struct file_event {
    __u32 pid;
    __u32 uid;
    __u8 comm[16];
    __u8 filename[256];
    __u32 flags;
};

// LSM hook: file_open
// Called when a file is opened
SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    struct file_event *e;
    struct task_struct *task;
    struct path *path_ptr;
    struct dentry *dentry;

    // Reserve event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;  // Allow (just couldn't log)

    // Get process info
    task = (struct task_struct *)bpf_get_current_task();
    e->pid = BPF_CORE_READ(task, tgid);
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get filename using CO-RE
    path_ptr = &file->f_path;
    dentry = BPF_CORE_READ(path_ptr, dentry);

    // Read filename
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), d_name.name);

    // Get file flags
    e->flags = BPF_CORE_READ(file, f_flags);

    // Submit event
    bpf_ringbuf_submit(e, 0);

    // Allow access (to deny: return -EPERM)
    return 0;
}

/*
 * Learning Notes:
 *
 * LSM (Linux Security Modules):
 * - Security framework in kernel
 * - eBPF can attach to LSM hooks (kernel 5.7+)
 * - Can monitor OR enforce policies
 *
 * Use Cases:
 * - File access auditing
 * - Process execution control
 * - Network connection policies
 * - Capability monitoring
 *
 * Return Values:
 * - 0: Allow operation
 * - -EPERM: Deny (permission denied)
 * - Other negative: Deny with specific error
 *
 * Common LSM Hooks:
 * - lsm/file_open: File opened
 * - lsm/file_permission: Permission check
 * - lsm/bprm_check_security: Program execution
 * - lsm/socket_connect: Network connection
 * - lsm/task_kill: Signal sending
 *
 * Production Patterns (Tetragon/Falco):
 * 1. Monitor sensitive paths (/etc/passwd, /etc/shadow)
 * 2. Alert on suspicious activity
 * 3. Enforce policies in production
 * 4. Integration with SIEM
 */
