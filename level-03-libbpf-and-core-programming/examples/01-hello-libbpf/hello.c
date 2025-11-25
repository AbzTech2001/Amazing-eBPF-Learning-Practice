// SPDX-License-Identifier: GPL-2.0
/* Hello World - User Space Loader
 *
 * Demonstrates:
 * - Skeleton API usage
 * - Auto-attach functionality
 * - Map reading
 * - Signal handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig)
{
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                          const char *format, va_list args)
{
    // Only print warnings and errors
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct hello_bpf *skel;
    int err;

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Signal handling for clean exit
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("===========================================\n");
    printf("Hello libbpf - Tracing execve() calls\n");
    printf("===========================================\n\n");

    // Open BPF application (but don't load yet)
    printf("1. Opening BPF skeleton...\n");
    skel = hello_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    printf("   ✓ Skeleton opened\n\n");

    // Load & verify BPF programs
    printf("2. Loading BPF program into kernel...\n");
    printf("   (verifier will check safety)\n");
    err = hello_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }
    printf("   ✓ Program loaded and verified\n");
    printf("   ✓ JIT compilation complete\n\n");

    // Attach tracepoint
    printf("3. Attaching to tracepoint...\n");
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    printf("   ✓ Attached to sys_enter_execve tracepoint\n\n");

    printf("===========================================\n");
    printf("Program is now running!\n");
    printf("===========================================\n\n");

    printf("Monitoring process execution...\n");
    printf("Try running commands in another terminal:\n");
    printf("  $ ls\n");
    printf("  $ echo hello\n");
    printf("  $ date\n\n");

    printf("To see kernel output:\n");
    printf("  $ sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    printf("Press Ctrl-C to stop...\n\n");

    // Main loop - print counter periodically
    while (!stop) {
        __u32 key = 0;
        __u64 count;

        sleep(3);

        // Read counter from map
        err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.counter),
                                  &key, &count);
        if (err < 0) {
            fprintf(stderr, "Failed to read counter: %d\n", err);
            continue;
        }

        printf("Total execve() calls: %llu\n", count);
    }

    printf("\n\nShutting down...\n");

cleanup:
    // Cleanup: detach and destroy
    hello_bpf__destroy(skel);
    printf("✓ Cleanup complete\n");
    printf("Goodbye!\n");

    return err != 0;
}

/*
 * Learning Notes:
 *
 * Skeleton API provides three main functions:
 *
 * 1. hello_bpf__open()
 *    - Opens the BPF object file
 *    - Parses ELF sections
 *    - Prepares programs and maps
 *    - Does NOT load into kernel yet
 *
 * 2. hello_bpf__load()
 *    - Loads BPF programs into kernel
 *    - Verifier checks safety
 *    - JIT compiles to native code
 *    - Creates maps
 *
 * 3. hello_bpf__attach()
 *    - Attaches programs to hooks
 *    - For tracepoints: automatically finds the right tracepoint
 *    - Returns bpf_link handles
 *
 * 4. hello_bpf__destroy()
 *    - Detaches all programs
 *    - Closes file descriptors
 *    - Frees memory
 *
 * The skeleton also provides type-safe access to:
 * - skel->maps.counter (map FDs)
 * - skel->progs.handle_execve (program FDs)
 * - skel->links.handle_execve (attach links)
 */
