use sikte_common::raw_tracepoints::syscalls::SyscallData;

/// Enum for representing all the possible eBPF events in this program
#[derive(Clone)]
pub enum Event {
    /// Syscall event
    Syscall(SyscallData),
}
