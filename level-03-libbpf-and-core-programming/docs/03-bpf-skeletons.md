# BPF Skeletons - Type-Safe Loading

## Overview

BPF skeletons are **auto-generated C headers** that provide type-safe, ergonomic APIs for loading and interacting with eBPF programs. They eliminate boilerplate and prevent common errors.

---

## What Are Skeletons?

### Without Skeletons (Manual API)

```c
// Lots of boilerplate, error-prone
struct bpf_object *obj;
struct bpf_program *prog;
struct bpf_link *link;
struct bpf_map *map;
int map_fd;

// Open
obj = bpf_object__open_file("my_prog.bpf.o", NULL);
if (libbpf_get_error(obj)) {
    // error handling
}

// Load
if (bpf_object__load(obj)) {
    // error handling
}

// Find program by name (string - typos possible!)
prog = bpf_object__find_program_by_name(obj, "handle_execve");
if (!prog) {
    // error handling
}

// Attach
link = bpf_program__attach(prog);
if (libbpf_get_error(link)) {
    // error handling
}

// Find map by name (string - typos possible!)
map = bpf_object__find_map_by_name(obj, "events");
if (!map) {
    // error handling
}
map_fd = bpf_map__fd(map);

// ... More boilerplate
```

### With Skeletons (Auto-Generated)

```c
// Clean, type-safe, hard to misuse
#include "my_prog.skel.h"

struct my_prog_bpf *skel;

// Open, load, attach - all type-safe
skel = my_prog_bpf__open();
if (!skel) {
    // error handling
}

if (my_prog_bpf__load(skel)) {
    // error handling
}

if (my_prog_bpf__attach(skel)) {
    // error handling
}

// Access programs and maps with compile-time checking
int map_fd = bpf_map__fd(skel->maps.events);  // No string lookups!
struct bpf_link *link = skel->links.handle_execve;

// Cleanup
my_prog_bpf__destroy(skel);
```

---

## Generating Skeletons

### Step 1: Compile BPF Program

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
    -c my_prog.bpf.c -o my_prog.bpf.o
```

### Step 2: Generate Skeleton

```bash
bpftool gen skeleton my_prog.bpf.o > my_prog.skel.h
```

Or in Makefile:
```makefile
# Generate skeleton header
%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@
```

### Step 3: Include and Use

```c
#include "my_prog.skel.h"

int main(void) {
    struct my_prog_bpf *skel;

    skel = my_prog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    if (my_prog_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    // Use skel->maps, skel->progs, etc.

cleanup:
    my_prog_bpf__destroy(skel);
    return 0;
}
```

---

## Skeleton Structure

### Generated Struct

For a BPF program `my_prog.bpf.c`:

```c
struct my_prog_bpf {
    struct bpf_object_skeleton *skeleton;
    struct bpf_object *obj;

    struct {
        struct bpf_program *handle_execve;
        struct bpf_program *handle_exit;
    } progs;

    struct {
        struct bpf_link *handle_execve;
        struct bpf_link *handle_exit;
    } links;

    struct {
        struct bpf_map *events;
        struct bpf_map *config;
    } maps;

    struct {
        struct my_prog_bpf__rodata {
            int filter_pid;
            bool verbose;
        } *rodata;

        struct my_prog_bpf__bss {
            __u64 event_count;
        } *bss;
    } data;
};
```

### Generated Functions

```c
// Lifecycle management
struct my_prog_bpf *my_prog_bpf__open(void);
struct my_prog_bpf *my_prog_bpf__open_opts(const struct bpf_object_open_opts *opts);
int my_prog_bpf__load(struct my_prog_bpf *obj);
struct my_prog_bpf *my_prog_bpf__open_and_load(void);

// Attachment
int my_prog_bpf__attach(struct my_prog_bpf *obj);
void my_prog_bpf__detach(struct my_prog_bpf *obj);

// Cleanup
void my_prog_bpf__destroy(struct my_prog_bpf *obj);

// Embedded BPF object
const void *my_prog_bpf__elf_bytes(size_t *sz);
```

---

## Using Skeletons

### Basic Usage Pattern

```c
#include <signal.h>
#include <unistd.h>
#include "my_prog.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

int main(void) {
    struct my_prog_bpf *skel;
    int err;

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open BPF application
    skel = my_prog_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Optionally configure before loading
    skel->rodata->filter_pid = 1234;

    // Load and verify
    err = my_prog_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach tracepoints
    err = my_prog_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Press Ctrl+C to stop.\n");

    // Main event loop
    while (!exiting) {
        // Could poll ring buffer here
        sleep(1);
    }

cleanup:
    my_prog_bpf__destroy(skel);
    return err;
}
```

### Accessing Maps

```c
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();

// Get map FD for user-space operations
int events_fd = bpf_map__fd(skel->maps.events);

// Create ring buffer
struct ring_buffer *rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);

// Lookup/update hash maps
__u32 key = 123;
__u64 value;
bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &key, &value);
```

### Setting Global Variables

```c
// BPF side (my_prog.bpf.c)
const volatile int filter_pid = 0;
const volatile bool verbose = false;

// User-space side
struct my_prog_bpf *skel = my_prog_bpf__open();

// Set before loading
skel->rodata->filter_pid = 1234;
skel->rodata->verbose = true;

my_prog_bpf__load(skel);  // Variables frozen after this
```

### Reading BPF Variables

```c
// BPF side (my_prog.bpf.c)
__u64 event_count = 0;

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    __sync_fetch_and_add(&event_count, 1);
    return 0;
}

// User-space side
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();
my_prog_bpf__attach(skel);

// Read from user-space
while (running) {
    sleep(1);
    printf("Events: %llu\n", skel->bss->event_count);
}
```

---

## Advanced Features

### Custom Open Options

```c
LIBBPF_OPTS(bpf_object_open_opts, open_opts,
    .kernel_log_level = 1,  // Enable verifier logs
);

struct my_prog_bpf *skel = my_prog_bpf__open_opts(&open_opts);
```

### Embedding BPF Object in Binary

Instead of loading from filesystem:

```c
// Skeleton includes embedded object bytes
const void *my_prog_bpf__elf_bytes(size_t *sz);

// Load from memory
size_t sz;
const void *data = my_prog_bpf__elf_bytes(&sz);

LIBBPF_OPTS(bpf_object_open_opts, opts,
    .object_name = "my_prog_bpf",
);

struct bpf_object *obj = bpf_object__open_mem(data, sz, &opts);
```

### Selective Program Attachment

```c
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();

// Attach only specific programs
skel->links.handle_execve = bpf_program__attach(skel->progs.handle_execve);
// Don't attach handle_exit

// Later cleanup still works
my_prog_bpf__destroy(skel);  // Safely handles NULL links
```

### Manual Attachment for Custom Hooks

```c
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();

// Auto-attach doesn't work for this use case, attach manually
skel->links.my_xdp_prog = bpf_program__attach_xdp(
    skel->progs.my_xdp_prog,
    if_nametoindex("eth0")
);

if (!skel->links.my_xdp_prog) {
    fprintf(stderr, "Failed to attach XDP\n");
}
```

---

## Skeleton Benefits

### 1. Type Safety

```c
// Compile-time error if program name is wrong
skel->progs.handle_execv;  // ERROR: Did you mean handle_execve?

// vs manual API:
bpf_object__find_program_by_name(obj, "handle_execv");  // Runtime error
```

### 2. Auto-Completion

IDE/editor can suggest:
```c
skel->maps.    // Shows: events, config, stats
skel->progs.   // Shows: handle_execve, handle_exit
skel->rodata-> // Shows: filter_pid, verbose
```

### 3. Embedded BPF Object

No need to deploy separate .bpf.o file:
```c
// BPF bytecode is embedded in the skeleton header
const void *bytes = my_prog_bpf__elf_bytes(&size);
```

### 4. Consistent Cleanup

```c
// One function cleans up everything
my_prog_bpf__destroy(skel);
// Detaches all links, closes all FDs, frees memory
```

---

## Common Patterns

### Pattern 1: Ring Buffer with Skeleton

```c
// BPF side
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// User-space side
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("Event: pid=%d\n", e->pid);
    return 0;
}

int main(void) {
    struct my_prog_bpf *skel;
    struct ring_buffer *rb;

    skel = my_prog_bpf__open_and_load();
    my_prog_bpf__attach(skel);

    // Ring buffer with skeleton map
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    my_prog_bpf__destroy(skel);
}
```

### Pattern 2: Multi-Program Application

```c
// BPF side: multiple programs
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx) { /* ... */ }

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(void *ctx) { /* ... */ }

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx) { /* ... */ }

// User-space: all managed together
struct my_prog_bpf *skel = my_prog_bpf__open_and_load();
my_prog_bpf__attach(skel);  // Attaches all programs

// Access individual programs
printf("Execve prog FD: %d\n",
       bpf_program__fd(skel->progs.handle_execve));
```

### Pattern 3: Configuration via Global Variables

```c
// BPF side
const volatile int target_pid = 0;
const volatile int log_level = 0;
const volatile bool enable_stats = true;

SEC("kprobe/sys_read")
int kprobe_read(struct pt_regs *ctx) {
    if (target_pid && bpf_get_current_pid_tgid() >> 32 != target_pid)
        return 0;

    if (log_level > 1)
        bpf_printk("read syscall\n");

    if (enable_stats)
        // Update stats

    return 0;
}

// User-space: configure before loading
struct my_prog_bpf *skel = my_prog_bpf__open();

skel->rodata->target_pid = atoi(argv[1]);
skel->rodata->log_level = 2;
skel->rodata->enable_stats = false;

my_prog_bpf__load(skel);  // Config locked in
```

---

## Debugging Skeletons

### View Generated Skeleton

```bash
# Generate and inspect
bpftool gen skeleton my_prog.bpf.o > my_prog.skel.h
less my_prog.skel.h
```

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `undefined reference to 'my_prog_bpf__open'` | Skeleton not generated | Run `bpftool gen skeleton` |
| `skel->maps.mymap` doesn't exist | Map not in BPF program | Check map is defined in .bpf.c |
| Can't set `skel->rodata->var` | Not declared `const volatile` | Add `const volatile` in .bpf.c |
| `skel is NULL` after open | BPF object invalid | Check .bpf.o file exists and is valid |

### Verify Skeleton Contents

```c
struct my_prog_bpf *skel = my_prog_bpf__open();

// Check programs loaded
if (skel->progs.handle_execve)
    printf("handle_execve loaded\n");

// Check maps created
if (skel->maps.events)
    printf("events map FD: %d\n", bpf_map__fd(skel->maps.events));
```

---

## Best Practices

### 1. Always Use Skeletons for Production

Avoid manual APIs when skeletons are available.

### 2. Check Return Values

```c
if (!skel || my_prog_bpf__load(skel) || my_prog_bpf__attach(skel)) {
    // Handle error
    goto cleanup;
}
```

### 3. Use `open_and_load` for Simple Cases

```c
// Instead of:
skel = my_prog_bpf__open();
my_prog_bpf__load(skel);

// Use:
skel = my_prog_bpf__open_and_load();  // Simpler
```

Unless you need to configure between open and load.

### 4. Name BPF Files Consistently

```
my_feature.bpf.c   → compiles to → my_feature.bpf.o
                    → generates → my_feature.skel.h
                    → creates struct → my_feature_bpf
```

### 5. Embed BPF Object for Distribution

Generate skeleton with `-L` for embedded bytecode:
```bash
bpftool gen skeleton -L my_prog.bpf.o > my_prog.skel.h
```

Now your binary is self-contained (no .bpf.o file needed at runtime).

---

## Example: Complete Application

### BPF Program (process_mon.bpf.c)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

const volatile int target_pid = 0;

struct event {
    u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (target_pid && pid != target_pid)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### User-Space (process_mon.c)

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "process_mon.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    printf("PID %d executed: %s\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct process_mon_bpf *skel;
    struct ring_buffer *rb;
    int err;

    // Open BPF application
    skel = process_mon_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Configure (if PID provided)
    if (argc > 1)
        skel->rodata->target_pid = atoi(argv[1]);

    // Load and verify
    err = process_mon_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    // Attach
    err = process_mon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    printf("Monitoring process execution... Press Ctrl+C to stop.\n");

    // Poll for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
cleanup:
    process_mon_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

### Makefile

```makefile
CLANG ?= clang
BPFTOOL ?= bpftool

all: process_mon

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

process_mon.bpf.o: process_mon.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c $< -o $@

process_mon.skel.h: process_mon.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

process_mon: process_mon.c process_mon.skel.h
	$(CLANG) -g -Wall $< -o $@ -lbpf -lelf -lz

clean:
	rm -f process_mon process_mon.bpf.o process_mon.skel.h vmlinux.h
```

---

## Next Steps

- Master **CO-RE relocations** for portability
- Learn **verifier debugging** techniques
- Explore **advanced map types**
- Build **production deployment pipelines**

---

## References

- [bpftool gen skeleton documentation](https://www.mankier.com/8/bpftool-gen)
- [libbpf API](https://libbpf.readthedocs.io/)
- [Kernel BPF samples](https://github.com/torvalds/linux/tree/master/samples/bpf)
