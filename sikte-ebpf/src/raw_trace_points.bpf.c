// SPDX-License-Identifier: GPL-2.0 OR MIT
#include "vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "raw_trace_points.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Ring buffer for syscall events (kernel -> userspace)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_SYSCALL_EVENTS);
} SYSCALL_EVENTS SEC(".maps");

// PID allow list (hash map used as a set)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NUM_ALLOWED_PIDS);
    __type(key, pid_t);
    __type(value, __u8);  // Value unused, only key matters
} PID_ALLOW_LIST SEC(".maps");

// Check if a TGID is in the allow list
static __always_inline bool is_tgid_in_allowlist(pid_t tgid) {
    return bpf_map_lookup_elem(&PID_ALLOW_LIST, &tgid) != NULL;
}

// Raw tracepoint handler for sys_enter
// https://elixir.bootlin.com/linux/v6.16/source/include/trace/events/syscalls.h#L20
SEC("raw_tp/sys_enter")
int sikte_raw_trace_point_at_enter(struct bpf_raw_tracepoint_args *ctx) {
    // Get current process/thread IDs
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = pid_tgid >> 32;  // TGID = userspace PID

    // Filter: only trace allowed PIDs
    if (!is_tgid_in_allowlist(tgid)) {
        return 0;
    }

    pid_t pid = (__u32)pid_tgid;  // PID in kernel = TID in userspace
    __u64 timestamp = bpf_ktime_get_ns();

    // Extract syscall ID from tracepoint context
    // ctx->args[0] is struct pt_regs*
    // ctx->args[1] is the syscall ID (long)
    __s64 syscall_id = (long)ctx->args[1];

    // Reserve space in ring buffer
    struct syscall_data *data = bpf_ringbuf_reserve(&SYSCALL_EVENTS,
                                                      sizeof(struct syscall_data), 0);
    if (!data) {
        // Ring buffer full - drop event
        // Could use bpf_printk for debugging: bpf_printk("Dropped sys_enter: tgid=%d\n", tgid);
        return 0;
    }

    // Populate syscall data
    data->timestamp = timestamp;
    data->tgid = tgid;
    data->pid = pid;
    data->state.tag = SYSCALL_STATE_AT_ENTER;
    data->state.data.at_enter.syscall_id = syscall_id;

    // Submit to ring buffer
    bpf_ringbuf_submit(data, 0);
    return 0;
}

// Raw tracepoint handler for sys_exit
// https://elixir.bootlin.com/linux/v6.16/source/include/trace/events/syscalls.h#L46
SEC("raw_tp/sys_exit")
int sikte_raw_trace_point_at_exit(struct bpf_raw_tracepoint_args *ctx) {
    // Get current process/thread IDs
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = pid_tgid >> 32;

    // Filter: only trace allowed PIDs
    if (!is_tgid_in_allowlist(tgid)) {
        return 0;
    }

    pid_t pid = (__u32)pid_tgid;
    __u64 timestamp = bpf_ktime_get_ns();

    // Extract syscall return value from tracepoint context
    // ctx->args[0] is struct pt_regs*
    // ctx->args[1] is the return value (long)
    __s64 syscall_ret = (long)ctx->args[1];

    // Reserve space in ring buffer
    struct syscall_data *data = bpf_ringbuf_reserve(&SYSCALL_EVENTS,
                                                      sizeof(struct syscall_data), 0);
    if (!data) {
        // Ring buffer full - drop event
        return 0;
    }

    // Populate syscall data
    data->timestamp = timestamp;
    data->tgid = tgid;
    data->pid = pid;
    data->state.tag = SYSCALL_STATE_AT_EXIT;
    data->state.data.at_exit.syscall_ret = syscall_ret;

    // Submit to ring buffer
    bpf_ringbuf_submit(data, 0);
    return 0;
}
