use libbpf_rs::MapCore;
use libc::pid_t;

use crate::common::generic_types::Unused;

/// Syscall ring buffer wrapper
pub struct SyscallRingBuf<'a> {
    map: &'a libbpf_rs::Map<'a>,
}

impl<'a> SyscallRingBuf<'a> {
    pub fn new(map: &'a libbpf_rs::Map<'a>) -> Self {
        SyscallRingBuf { map }
    }

    /// Get reference to the underlying map
    pub fn map(&self) -> &libbpf_rs::Map<'a> {
        self.map
    }
}

/// PID allow list wrapper. It uses an eBPF hashmap internally, where the value is unused.
pub struct PidAllowList<'a> {
    map: &'a libbpf_rs::Map<'a>,
}

impl<'a> PidAllowList<'a> {
    pub fn new(map: &'a libbpf_rs::Map<'a>) -> Self {
        PidAllowList { map }
    }

    /// Insert a PID into the allowlist
    pub fn insert(&self, pid: pid_t) -> Result<(), libbpf_rs::Error> {
        let key = pid.to_ne_bytes();
        let value: Unused = 0;
        let value_bytes = value.to_ne_bytes();

        self.map
            .update(&key, &value_bytes, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }
}
