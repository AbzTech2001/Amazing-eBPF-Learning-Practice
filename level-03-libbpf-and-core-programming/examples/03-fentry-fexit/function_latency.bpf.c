// SPDX-License-Identifier: GPL-2.0
/* Fentry/Fexit Function Latency Tracer
 *
 * Demonstrates:
 * - Modern fentry/fexit hooks (kernel 5.5+)
 * - Function latency measurement
 * - Per-CPU hash maps
 * - BTF-enabled tracing
 * - No need for kernel headers (uses vmlinux.h)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Map to store function entry timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);    // PID
    __type(value, u64);  // Entry timestamp
} start_times SEC(".maps");

// Map to store latency histogram
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);    // Latency bucket (usec)
    __type(value, u64);  // Count
} latency_hist SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

enum {
    STAT_CALLS = 0,
    STAT_TOTAL_LATENCY,
    STAT_MAX_LATENCY,
};

// Fentry: called on function entry
// Target: do_unlinkat (example: track file deletion)
SEC("fentry/do_unlinkat")
int BPF_PROG(fentry_do_unlinkat, int dfd, struct filename *name)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    // Store entry timestamp
    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);

    // Increment call counter
    u32 key = STAT_CALLS;
    u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return 0;
}

// Fexit: called on function exit
// Has access to function arguments AND return value
SEC("fexit/do_unlinkat")
int BPF_PROG(fexit_do_unlinkat, int dfd, struct filename *name, int ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts, delta_ns, delta_us;

    // Get entry timestamp
    start_ts = bpf_map_lookup_elem(&start_times, &pid);
    if (!start_ts)
        return 0;

    // Calculate latency
    delta_ns = bpf_ktime_get_ns() - *start_ts;
    delta_us = delta_ns / 1000;  // Convert to microseconds

    // Update total latency
    u32 key = STAT_TOTAL_LATENCY;
    u64 *total = bpf_map_lookup_elem(&stats, &key);
    if (total)
        __sync_fetch_and_add(total, delta_us);

    // Update max latency
    key = STAT_MAX_LATENCY;
    u64 *max_lat = bpf_map_lookup_elem(&stats, &key);
    if (max_lat && delta_us > *max_lat)
        *max_lat = delta_us;

    // Update histogram (bucketize to nearest power of 2)
    u64 bucket = 1;
    while (bucket < delta_us && bucket < (1ULL << 32))
        bucket <<= 1;

    u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 initial = 1;
        bpf_map_update_elem(&latency_hist, &bucket, &initial, BPF_NOEXIST);
    }

    // Cleanup
    bpf_map_delete_elem(&start_times, &pid);

    return 0;
}

/*
 * Learning Notes:
 *
 * Fentry/Fexit vs Kprobe/Kretprobe:
 * ✓ Better performance (direct call, no kprobe overhead)
 * ✓ Type-safe arguments via BTF
 * ✓ Fexit has access to return value
 * ✓ No need to manually read pt_regs
 * ✗ Requires kernel 5.5+ with BTF
 * ✗ Only works on functions with BTF info
 *
 * BPF_PROG macro:
 * - Automatically handles context and arguments
 * - Type-safe function signature
 * - Much cleaner than kprobe pt_regs access
 *
 * Latency Measurement Pattern:
 * 1. fentry: store timestamp in map (keyed by PID/TID)
 * 2. fexit: lookup timestamp, calculate delta
 * 3. Store in histogram for distribution analysis
 *
 * Why do_unlinkat?
 * - It's the kernel function for file deletion
 * - Good example of observable operation
 * - Has clear entry/exit points
 *
 * Production Use (Tetragon pattern):
 * - Track syscall latencies
 * - Identify slow kernel paths
 * - Detect anomalies (e.g., unusual latency spikes)
 * - Performance profiling
 *
 * Histogram Buckets:
 * - Power-of-2 bucketization: 1, 2, 4, 8, 16, 32... usec
 * - Compact representation of latency distribution
 * - Similar to Prometheus histogram buckets
 */
