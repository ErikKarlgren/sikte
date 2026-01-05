use bytemuck::{CheckedBitPattern, Pod, Zeroable};

/// Alias for a userspace PID. In the kernel this means the TGID, while PID is the thread ID for
/// userspace. It corresponds to libc's definition.
pub type PidT = i32;

/// Syscall state discriminant tag (C-compatible)
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct SyscallStateTag(pub u32);

impl SyscallStateTag {
    pub const AT_ENTER: Self = Self(0);
    pub const AT_EXIT: Self = Self(1);
}

/// Syscall data for AtEnter state
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct SyscallAtEnter {
    pub syscall_id: i64,
}

/// Syscall data for AtExit state
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct SyscallAtExit {
    pub syscall_ret: i64,
}

/// Union for syscall state data
#[repr(C)]
#[derive(Copy, Clone)]
pub union SyscallStateData {
    pub at_enter: SyscallAtEnter,
    pub at_exit: SyscallAtExit,
}

// Implement CheckedBitPattern for the union (all bit patterns are valid)
unsafe impl CheckedBitPattern for SyscallStateData {
    type Bits = [u8; 8];

    fn is_valid_bit_pattern(_bits: &Self::Bits) -> bool {
        true // All bit patterns valid for union
    }
}

/// Syscall state as tagged union (C-compatible)
///
/// This structure is binary-compatible with the C struct in raw_trace_points.h
#[repr(C, align(8))]
#[derive(Copy, Clone, CheckedBitPattern)]
pub struct SyscallState {
    pub tag: SyscallStateTag,
    pub _padding: u32, // Explicit padding for alignment
    pub data: SyscallStateData,
}

impl SyscallState {
    /// Create a syscall state for entry
    pub fn at_enter(syscall_id: i64) -> Self {
        SyscallState {
            tag: SyscallStateTag::AT_ENTER,
            _padding: 0,
            data: SyscallStateData {
                at_enter: SyscallAtEnter { syscall_id },
            },
        }
    }

    /// Create a syscall state for exit
    pub fn at_exit(syscall_ret: i64) -> Self {
        SyscallState {
            tag: SyscallStateTag::AT_EXIT,
            _padding: 0,
            data: SyscallStateData {
                at_exit: SyscallAtExit { syscall_ret },
            },
        }
    }

    /// Get syscall ID if this is an AtEnter state
    pub fn syscall_id(&self) -> Option<i64> {
        if self.tag == SyscallStateTag::AT_ENTER {
            Some(unsafe { self.data.at_enter.syscall_id })
        } else {
            None
        }
    }

    /// Get syscall return value if this is an AtExit state
    pub fn syscall_ret(&self) -> Option<i64> {
        if self.tag == SyscallStateTag::AT_EXIT {
            Some(unsafe { self.data.at_exit.syscall_ret })
        } else {
            None
        }
    }
}

impl core::fmt::Debug for SyscallState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.tag {
            SyscallStateTag::AT_ENTER => f
                .debug_struct("AtEnter")
                .field("syscall_id", &unsafe { self.data.at_enter.syscall_id })
                .finish(),
            SyscallStateTag::AT_EXIT => f
                .debug_struct("AtExit")
                .field("syscall_ret", &unsafe { self.data.at_exit.syscall_ret })
                .finish(),
            _ => f.debug_struct("Unknown").finish(),
        }
    }
}

/// Syscall Data. Aligned to 8 for use with kernel ring buffers.
///
/// This structure is binary-compatible with the C struct in raw_trace_points.h
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, CheckedBitPattern)]
pub struct SyscallData {
    pub timestamp: u64,
    pub tgid: PidT,
    pub pid: PidT,
    pub state: SyscallState,
}

/// Maximum number of allowed PIDs that the eBPF raw tracepoints program may trace
pub const NUM_ALLOWED_PIDS: u32 = 1 << 10;

/// Maximum number of syscall events (sys_enter and sys_exit) until these will start being
/// discarded
pub const MAX_SYSCALL_EVENTS: u32 = 1 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_data_layout() {
        // Verify size matches C struct
        assert_eq!(std::mem::size_of::<SyscallData>(), 32);
        assert_eq!(std::mem::align_of::<SyscallData>(), 8);
    }

    #[test]
    fn test_syscall_state_tagged_union() {
        let state = SyscallState::at_enter(42);
        assert_eq!(state.tag, SyscallStateTag::AT_ENTER);
        assert_eq!(state.syscall_id(), Some(42));
        assert_eq!(state.syscall_ret(), None);

        let state = SyscallState::at_exit(-1);
        assert_eq!(state.tag, SyscallStateTag::AT_EXIT);
        assert_eq!(state.syscall_id(), None);
        assert_eq!(state.syscall_ret(), Some(-1));
    }
}
