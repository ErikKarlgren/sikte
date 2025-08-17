/// Alias for a userspace PID. In the kernel this means the TGID, while PID is the thread ID for
/// userpace. It corresponds to libc's definition, but this compiles for me.
pub type pid_t = i32;

#[derive(Copy, Clone)]
pub enum SyscallState {
    AtEnter { syscall_id: i64 },
    AtExit { syscall_ret: i64 },
}

#[repr(C)]
pub struct SyscallData {
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,
    pub state: SyscallState,
}

/// Maximum number of allowed PIDs that the eBPF raw tracepoints program may trace
pub const NUM_ALLOWED_PIDS: u32 = 1 << 10;

/// Maximum number of syscall events (sys_enter and sys_exit) until these will start being
/// discarded
pub const MAX_SYSCALL_EVENTS: u32 = 1 << 20;
