use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, r#gen::bpf_ktime_get_ns},
    macros::{raw_tracepoint, tracepoint},
    programs::{RawTracePointContext, TracePointContext},
};
use aya_log_ebpf::info;
use sikte_common::{SyscallData, SyscallName, SyscallState};

#[raw_tracepoint]
pub fn sikte_raw_trace_point_at_enter(ctx: RawTracePointContext) -> u32 {
    match try_raw_trace_points(ctx, SyscallState::AtEnter) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[raw_tracepoint]
pub fn sikte_raw_trace_point_at_exit(ctx: RawTracePointContext) -> u32 {
    match try_raw_trace_points(ctx, SyscallState::AtExit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn try_raw_trace_points(ctx: RawTracePointContext, state: SyscallState) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & (u32::MAX as u64)) as u32;
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let mut name: SyscallName = core::array::from_fn(|_| 0);
    name[0] = b'l';
    name[1] = b'm';
    name[2] = b'a';
    name[3] = b'o';

    let data = SyscallData {
        timestamp,
        tgid,
        pid,
        state,
        name,
    };

    info!(
        &ctx,
        "[{}] ({}, {}) syscall '{}' at {}",
        timestamp,
        tgid,
        pid,
        unsafe { core::str::from_utf8_unchecked(&name) },
        match state {
            SyscallState::AtEnter => "enter",
            SyscallState::AtExit => "exit",
        }
    );
    Ok(0)
}
