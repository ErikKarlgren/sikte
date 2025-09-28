use sikte_common::raw_tracepoints::syscalls::SyscallData;

/// Reads eBPF events
pub trait EventSubscriber {
    /// Get name
    fn get_name(&self) -> &str;
    /// Reads a Syscall event's data
    fn read_syscall(&mut self, syscall_data: &SyscallData);
}
