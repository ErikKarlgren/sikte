pub enum SyscallState {
    AtEnter,
    AtExit,
}

#[repr(C)]
pub struct SyscallData {
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,
    pub state: SyscallState,
}
