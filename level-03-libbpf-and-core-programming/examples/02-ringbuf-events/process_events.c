// SPDX-License-Identifier: GPL-2.0
/* Ring Buffer Events - User Space
 *
 * Demonstrates:
 * - Ring buffer polling
 * - Event handling callbacks
 * - Global variable configuration
 * - Structured output
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "process_events.skel.h"

// Event structure (must match eBPF side)
struct event {
    __u32 pid;
    __u32 ppid;
    __u8 filename[256];
    __u8 comm[16];
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                          const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// Ring buffer event handler
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    // Get timestamp
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // Print event
    printf("[%s] PID %d (parent %d) executed: %s\n",
           ts, e->pid, e->ppid, e->filename);
    printf("         Process name: %s\n", e->comm);
    printf("\n");

    return 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS]\n"
            "\n"
            "Monitor process execution with eBPF\n"
            "\n"
            "OPTIONS:\n"
            "  -p PID   Only trace PIDs >= PID\n"
            "  -h       Show this help\n"
            "\n"
            "Examples:\n"
            "  %s              # Trace all processes\n"
            "  %s -p 1000      # Only trace PIDs >= 1000 (user processes)\n"
            "\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct process_events_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err, opt;
    int min_pid = 0;

    // Parse command line
    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
        case 'p':
            min_pid = atoi(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("===========================================\n");
    printf("Process Execution Monitor (Ring Buffer)\n");
    printf("===========================================\n\n");

    // Open BPF application
    printf("Opening BPF skeleton...\n");
    skel = process_events_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Set global variable for filtering
    if (min_pid > 0) {
        printf("Filtering: only PIDs >= %d\n", min_pid);
        skel->rodata->min_pid = min_pid;
    }
    printf("\n");

    // Load & verify BPF programs
    printf("Loading BPF program...\n");
    err = process_events_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }
    printf("✓ Program loaded and verified\n\n");

    // Attach tracepoint
    printf("Attaching to tracepoint...\n");
    err = process_events_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    printf("✓ Attached to sys_enter_execve\n\n");

    // Set up ring buffer
    printf("Setting up ring buffer...\n");
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    printf("✓ Ring buffer created (256 KB)\n\n");

    printf("===========================================\n");
    printf("Monitoring started!\n");
    printf("===========================================\n\n");

    printf("Watching for process execution...\n");
    printf("Press Ctrl-C to stop\n\n");

    // Main event loop
    while (!exiting) {
        // Poll ring buffer for events
        // Timeout: 100ms
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            // Interrupted by signal
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        // err > 0: number of events consumed
    }

    printf("\n\nShutting down...\n");

cleanup:
    ring_buffer__free(rb);
    process_events_bpf__destroy(skel);
    printf("✓ Cleanup complete\n");

    return err < 0 ? -err : 0;
}

/*
 * Learning Notes:
 *
 * Ring Buffer API:
 *
 * 1. ring_buffer__new(fd, callback, ctx, opts)
 *    - fd: File descriptor of ring buffer map
 *    - callback: Function called for each event
 *    - ctx: User-defined context (passed to callback)
 *    - opts: Options (usually NULL)
 *
 * 2. ring_buffer__poll(rb, timeout_ms)
 *    - Polls for events
 *    - Returns: number of events consumed, or < 0 on error
 *    - Timeout: -1 = block, 0 = non-blocking, >0 = timeout in ms
 *
 * 3. ring_buffer__free(rb)
 *    - Cleanup
 *
 * Global Variables (rodata):
 * - skel->rodata->min_pid = value;
 * - Must be set BEFORE load()
 * - Becomes const in eBPF program
 * - Allows user-space configuration
 *
 * Performance:
 * - Ring buffer is lock-free
 * - More efficient than perf buffer
 * - Events are globally ordered
 * - Shared across all CPUs
 *
 * Comparison to Perf Buffer:
 * - Ring buf: Single buffer, lock-free
 * - Perf buf: Per-CPU buffers, more overhead
 * - Ring buf is recommended for new code
 */
