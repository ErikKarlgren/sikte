#[derive(Copy, Clone)]
pub enum SyscallState {
    AtEnter,
    AtExit,
}

pub type SyscallName = [u8; 150];

#[repr(C)]
pub struct SyscallData {
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,
    pub state: SyscallState,
    pub name: SyscallName,
}
