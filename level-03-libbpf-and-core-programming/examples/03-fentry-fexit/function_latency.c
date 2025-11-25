// SPDX-License-Identifier: GPL-2.0
/* User-space loader for function latency tracer */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "function_latency.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int print_histogram(struct function_latency_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.latency_hist);
    __u64 key = 0, next_key;
    __u64 value;

    printf("\nLatency Histogram (microseconds):\n");
    printf("%-12s %-12s\n", "Latency", "Count");
    printf("------------------------------\n");

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &value);
        if (value > 0) {
            printf("%-12llu %-12llu ", next_key, value);
            // ASCII bar chart
            for (int i = 0; i < value && i < 50; i++)
                printf("#");
            printf("\n");
        }
        key = next_key;
    }

    return 0;
}

static int print_stats(struct function_latency_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.stats);
    __u32 key;
    __u64 calls = 0, total_latency = 0, max_latency = 0;

    key = 0;
    bpf_map_lookup_elem(fd, &key, &calls);

    key = 1;
    bpf_map_lookup_elem(fd, &key, &total_latency);

    key = 2;
    bpf_map_lookup_elem(fd, &key, &max_latency);

    printf("\nStatistics:\n");
    printf("  Total calls:   %llu\n", calls);
    printf("  Total latency: %llu us\n", total_latency);
    printf("  Max latency:   %llu us\n", max_latency);
    if (calls > 0)
        printf("  Avg latency:   %llu us\n", total_latency / calls);

    return 0;
}

int main(int argc, char **argv)
{
    struct function_latency_bpf *skel;
    int err;

    // Set up libbpf logging
    libbpf_set_print(NULL);

    // Open BPF skeleton
    skel = function_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = function_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach tracepoints
    err = function_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracing do_unlinkat() latency... Hit Ctrl-C to end.\n");
    printf("Try: rm /tmp/testfile (in another terminal)\n\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Print stats every 5 seconds
    while (!exiting) {
        sleep(5);
        print_stats(skel);
        print_histogram(skel);
    }

    printf("\nFinal statistics:\n");
    print_stats(skel);
    print_histogram(skel);

cleanup:
    function_latency_bpf__destroy(skel);
    return err != 0;
}

/*
 * Build instructions:
 *
 * 1. Generate vmlinux.h (one time):
 *    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * 2. Compile eBPF program:
 *    clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
 *          -c function_latency.bpf.c -o function_latency.bpf.o
 *
 * 3. Generate skeleton:
 *    bpftool gen skeleton function_latency.bpf.o > function_latency.skel.h
 *
 * 4. Compile user-space:
 *    gcc -o function_latency function_latency.c -lbpf -lelf -lz
 *
 * 5. Run (requires root):
 *    sudo ./function_latency
 *
 * Testing:
 * - In another terminal: touch /tmp/testfile && rm /tmp/testfile
 * - Watch latency histogram update
 * - Observe statistics
 *
 * Understanding output:
 * - Histogram shows distribution of latencies
 * - Most operations should be <10us
 * - Spikes indicate slow I/O or contention
 */
