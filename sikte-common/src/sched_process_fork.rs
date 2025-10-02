use crate::raw_tracepoints::syscalls::PidT;

pub enum SchedProcessData {
    Fork(SchedProcessForkData),
    Exit(SchedProcessExitData),
}

pub struct SchedProcessForkData {
    pub parent_pid: PidT,
    pub child_pid: PidT,
}

pub struct SchedProcessExitData {
    pub pid: PidT,
}

pub const MAX_SCHED_PROCESS_EVENTS: u32 = 1 << 10;
