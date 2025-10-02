use crate::raw_tracepoints::syscalls::PidT;

pub struct SchedProcessForkData {
    pub parent_pid: PidT,
    pub child_pid: PidT,
}

pub const MAX_SCHED_PROCESS_EVENTS: u32 = 1 << 10;
