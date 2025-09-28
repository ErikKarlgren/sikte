use aya::maps::{HashMap, MapData, MapError, RingBuf};
use libc::pid_t;
use sikte_common::generic_types::Unused;

/// Syscall ring buffer
pub struct SyscallRingBuf(pub RingBuf<MapData>);

/// PID allow list. It uses an ebpf hashmap internally, where the value is unused
pub struct PidAllowList<'ebpf>(pub HashMap<&'ebpf mut MapData, pid_t, Unused>);

impl PidAllowList<'_> {
    /// Insert a PID into the allowlist
    pub fn insert(&mut self, pid: pid_t) -> Result<(), MapError> {
        self.0.insert(pid, 0, 0)
    }
}
