# LSM (Linux Security Modules) with eBPF

## Overview

eBPF LSM hooks enable **runtime security enforcement** in the kernel. Used by Tetragon, Falco, and other security tools for process/file/network policy enforcement.

---

## What is LSM?

LSM provides hooks throughout the kernel for security checks:

```
┌─────────────────────────────────────────────────┐
│  Application calls open("/etc/passwd", O_RDWR)  │
└─────────────────┬───────────────────────────────┘
                  ↓
┌─────────────────────────────────────────────────┐
│  Kernel VFS Layer                               │
│  ┌──────────────────────────────────────────┐  │
│  │ 1. Check file permissions (DAC)          │  │
│  │ 2. Call LSM hook: file_open()            │  │
│  │      ↓                                    │  │
│  │    eBPF LSM Program                      │  │
│  │      ↓                                    │  │
│  │    return 0 (allow) or -EACCES (deny)   │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Enabling LSM BPF

### Kernel Requirements

- Kernel 5.7+
- `CONFIG_BPF_LSM=y`
- LSM BPF must be enabled in kernel command line

```bash
# Check if enabled
sudo cat /sys/kernel/security/lsm
# Should include "bpf"

# Enable by editing /etc/default/grub:
GRUB_CMDLINE_LINUX="lsm=lockdown,yama,apparmor,bpf"

# Update grub and reboot
sudo update-grub
sudo reboot
```

---

## Basic LSM Program

### Block Process Execution

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Blocked binaries
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[256]);
    __type(value, __u32);
} blocked_files SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec, struct linux_binprm *bprm, int ret)
{
    // If previous LSM denied, respect that
    if (ret != 0)
        return ret;

    char filename[256];
    struct file *file = BPF_CORE_READ(bprm, file);
    struct path path = BPF_CORE_READ(file, f_path);

    // Get filename
    bpf_d_path(&path, filename, sizeof(filename));

    // Check if blocked
    void *is_blocked = bpf_map_lookup_elem(&blocked_files, filename);
    if (is_blocked) {
        bpf_printk("BLOCKED execution of %s\n", filename);
        return -EACCES;  // Deny
    }

    return 0;  // Allow
}

char LICENSE[] SEC("license") = "GPL";
```

### File Access Control

```c
SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    char path[256];
    bpf_d_path(&file->f_path, path, sizeof(path));

    // Block access to /etc/shadow
    char blocked[] = "/etc/shadow";
    for (int i = 0; i < sizeof(blocked) && i < 256; i++) {
        if (path[i] != blocked[i])
            break;
        if (blocked[i] == '\0') {
            // Match found
            bpf_printk("DENIED access to /etc/shadow\n");
            return -EACCES;
        }
    }

    return 0;
}
```

### Network Security

```c
SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    // Only allow connections by specific processes
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // Block curl from connecting
    char blocked[] = "curl";
    bool matches = true;
    for (int i = 0; i < sizeof(blocked); i++) {
        if (comm[i] != blocked[i]) {
            matches = false;
            break;
        }
        if (blocked[i] == '\0')
            break;
    }

    if (matches) {
        bpf_printk("BLOCKED network connection by curl\n");
        return -EACCES;
    }

    return 0;
}
```

---

## Common LSM Hooks

| Hook | Purpose |
|------|---------|
| `bprm_check_security` | Process execution |
| `file_open` | File open operations |
| `file_permission` | File access checks |
| `inode_unlink` | File deletion |
| `inode_rename` | File rename |
| `socket_connect` | Network connections |
| `socket_bind` | Port binding |
| `socket_sendmsg` | Send network data |
| `task_kill` | Signal sending |
| `ptrace_access_check` | Debugger attachment |

Full list: `/sys/kernel/security/lsm/hooks/`

---

## Real-World Example: Container Security

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Allowed binaries in containers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, __u32);
} container_allowlist SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(container_exec_policy, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    struct task_struct *task = (void *)bpf_get_current_task();

    // Check if in container (simplified check via cgroup)
    // In production, use proper container detection

    char filename[256];
    bpf_d_path(&bprm->file->f_path, filename, sizeof(filename));

    // Check allowlist
    void *allowed = bpf_map_lookup_elem(&container_allowlist, filename);
    if (!allowed) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("Container policy violation: PID %d tried to exec %s\n",
                   pid, filename);
        return -EACCES;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## Loading LSM Programs

### Using libbpf

```c
#include "my_lsm.skel.h"

int main(void)
{
    struct my_lsm_bpf *skel;

    skel = my_lsm_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load LSM program\n");
        return 1;
    }

    // LSM programs auto-attach on load
    if (my_lsm_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach LSM program\n");
        goto cleanup;
    }

    printf("LSM policy active. Press Ctrl+C to stop.\n");
    pause();

cleanup:
    my_lsm_bpf__destroy(skel);
    return 0;
}
```

### Permissions

LSM programs require `CAP_SYS_ADMIN` and `CAP_BPF`:

```bash
# Run as root
sudo ./my_lsm_program

# Or with capabilities
sudo setcap cap_sys_admin,cap_bpf+ep ./my_lsm_program
./my_lsm_program
```

---

## Use Cases

### 1. Runtime Application Control
- Block unauthorized binaries
- Enforce execution policies
- Prevent privilege escalation

### 2. Data Loss Prevention
- Monitor file access to sensitive data
- Block unauthorized exfiltration
- Audit file operations

### 3. Network Segmentation
- Enforce which processes can connect where
- Block lateral movement
- Implement zero-trust networking

### 4. Container Security
- Enforce container runtime policies
- Prevent container breakout attempts
- Monitor privileged operations

---

## Best Practices

1. **Check previous return value**: `if (ret != 0) return ret;`
2. **Log denials**: Help debug policy issues
3. **Use maps for policy**: Don't hardcode rules
4. **Test in audit mode first**: Return 0 but log violations
5. **Handle errors gracefully**: Missing fields, NULL pointers
6. **Performance matters**: LSM hooks are on hot paths

---

## Audit Mode Pattern

```c
const volatile bool enforce = false;  // Set from userspace

SEC("lsm/file_open")
int BPF_PROG(audit_file_open, struct file *file, int ret)
{
    char path[256];
    bpf_d_path(&file->f_path, path, sizeof(path));

    // Check policy...
    bool violation = check_policy(path);

    if (violation) {
        bpf_printk("POLICY VIOLATION: access to %s\n", path);

        if (enforce)
            return -EACCES;  // Block in enforce mode
        // else: audit mode, allow but log
    }

    return 0;
}
```

---

## References

- [Kernel LSM BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [Tetragon (Security Observability)](https://github.com/cilium/tetragon)
- [Falco (Runtime Security)](https://falco.org/)
