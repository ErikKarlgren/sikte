#[derive(Copy, Clone)]
pub enum SyscallState {
    AtEnter { syscall_id: u64 },
    AtExit { syscall_ret: u64 },
}

#[repr(C)]
pub struct SyscallData {
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,
    pub state: SyscallState,
}
