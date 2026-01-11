// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __SIKTE_H
#define __SIKTE_H

#include "vmlinux.h"

// Must match Rust constants in sikte-common
#define MAX_SYSCALL_EVENTS (1 << 20)  // 1MB ring buffer
#define NUM_ALLOWED_PIDS (1 << 10)    // 1024 PIDs

// Syscall state discriminant
enum syscall_state_tag {
    SYSCALL_STATE_AT_ENTER = 0,
    SYSCALL_STATE_AT_EXIT = 1,
};

// Syscall state data union
union syscall_state_data {
    struct {
        __s64 syscall_id;
    } at_enter;
    struct {
        __s64 syscall_ret;
    } at_exit;
};

// Syscall state (tagged union matching Rust)
struct syscall_state {
    __u32 tag;
    __u32 _padding;  // Explicit padding for 8-byte alignment
    union syscall_state_data data;
} __attribute__((aligned(8)));

// Syscall data structure matching Rust SyscallData
struct syscall_data {
    __u64 timestamp;
    pid_t tgid;
    pid_t pid;
    struct syscall_state state;
} __attribute__((aligned(8)));

#endif  // __SIKTE_H
