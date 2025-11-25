// SPDX-License-Identifier: GPL-2.0
// Minimal eBPF Loader - Level 01 Example
//
// This is a simple user-space program that loads the minimal.bpf.o
// eBPF program and attaches it to the tracepoint.
//
// For Level 01, we keep this simple. Level 03 will cover libbpf
// skeletons which auto-generate this boilerplate.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig)
{
    stop = 1;
}

// Callback for libbpf logging
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;  // Suppress debug messages for cleaner output
    }
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err;

    printf("========================================\n");
    printf("Minimal eBPF Program Loader\n");
    printf("========================================\n\n");

    // Set up libbpf errors and debug logging
    libbpf_set_print(libbpf_print_fn);

    // Signal handler for graceful shutdown
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("1. Opening eBPF object file: minimal.bpf.o\n");

    // Open the BPF object file
    obj = bpf_object__open_file("minimal.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: Failed to open BPF object file: %s\n", strerror(errno));
        fprintf(stderr, "\nTroubleshooting:\n");
        fprintf(stderr, "  - Make sure minimal.bpf.o exists in current directory\n");
        fprintf(stderr, "  - Run 'make' to compile the program\n");
        fprintf(stderr, "  - Check file permissions\n");
        return 1;
    }

    printf("   ✓ Object file opened\n\n");

    printf("2. Loading eBPF program into kernel\n");
    printf("   (kernel verifier will check safety...)\n");

    // Load the program into the kernel
    // This triggers the verifier
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF object: %s\n", strerror(-err));
        fprintf(stderr, "\nCommon verifier errors:\n");
        fprintf(stderr, "  - Invalid memory access\n");
        fprintf(stderr, "  - Unbounded loops\n");
        fprintf(stderr, "  - Invalid helper calls\n");
        fprintf(stderr, "\nCheck dmesg for detailed verifier log:\n");
        fprintf(stderr, "  sudo dmesg | tail -50\n");
        goto cleanup;
    }

    printf("   ✓ Program loaded (verifier passed!)\n");
    printf("   ✓ JIT compilation completed\n\n");

    printf("3. Finding the tracepoint program\n");

    // Find the program we want to attach
    // In our case, it's the one with SEC("tracepoint/syscalls/sys_enter_execve")
    prog = bpf_object__find_program_by_name(obj, "handle_execve");
    if (!prog) {
        fprintf(stderr, "ERROR: Failed to find program 'handle_execve'\n");
        fprintf(stderr, "Make sure the function name in minimal.bpf.c matches\n");
        err = -ENOENT;
        goto cleanup;
    }

    printf("   ✓ Found program: handle_execve\n\n");

    printf("4. Attaching to tracepoint: syscalls/sys_enter_execve\n");

    // Attach the program to the tracepoint
    // libbpf automatically knows it's a tracepoint from the SEC() name
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Failed to attach program: %s\n", strerror(-libbpf_get_error(link)));
        fprintf(stderr, "\nPossible issues:\n");
        fprintf(stderr, "  - Tracepoint doesn't exist on this kernel\n");
        fprintf(stderr, "  - Missing permissions (need root or CAP_BPF)\n");
        fprintf(stderr, "  - Check available tracepoints: ls /sys/kernel/debug/tracing/events/\n");
        link = NULL;
        err = -1;
        goto cleanup;
    }

    printf("   ✓ Program attached!\n\n");

    printf("========================================\n");
    printf("Program is now running!\n");
    printf("========================================\n\n");

    printf("The program will print to the kernel trace pipe when execve() is called.\n");
    printf("To see output, run in another terminal:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    printf("Or trigger events by running commands, e.g.:\n");
    printf("  ls /tmp\n");
    printf("  echo 'hello'\n");
    printf("  date\n\n");

    printf("Press Ctrl+C to stop...\n\n");

    // Keep running until interrupted
    while (!stop) {
        sleep(1);
    }

    printf("\n\nReceived signal, cleaning up...\n");

cleanup:
    // Cleanup: detach and close
    if (link) {
        printf("Detaching program...\n");
        bpf_link__destroy(link);
    }

    if (obj) {
        printf("Unloading program...\n");
        bpf_object__close(obj);
    }

    printf("✓ Cleanup complete\n");
    printf("Goodbye!\n");

    return err != 0;
}

/*
 * Learning Notes:
 *
 * 1. bpf_object__open_file(): Opens the compiled BPF object (.o file)
 *    - Parses ELF sections
 *    - Extracts program and map definitions
 *    - Reads BTF information
 *
 * 2. bpf_object__load(): Loads program into kernel
 *    - Submits bytecode to kernel via bpf() syscall
 *    - Kernel verifier performs safety checks
 *    - JIT compiler generates native code
 *    - Creates maps
 *    - Returns file descriptors
 *
 * 3. bpf_program__attach(): Attaches to the hook
 *    - For tracepoints: reads section name, attaches via perf_event_open()
 *    - For kprobes: uses bpf_link API
 *    - For XDP: attaches to network interface
 *    - Returns a bpf_link handle
 *
 * 4. bpf_link__destroy(): Detaches and cleans up
 *    - Removes program from hook
 *    - Closes file descriptors
 *    - Kernel may garbage collect if no references remain
 *
 * In Level 03, we'll learn about BPF skeletons which auto-generate
 * much of this boilerplate code!
 */
