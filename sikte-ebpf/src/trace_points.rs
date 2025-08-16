use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, r#gen::bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use sikte_common::{SyscallData, SyscallState};

#[tracepoint]
pub fn sikte_trace_points(ctx: TracePointContext) -> u32 {
    match try_tracepoints(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn try_tracepoints(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & (u32::MAX as u64)) as u32;
    let timestamp = unsafe { bpf_ktime_get_ns() };

    // let data = SyscallData {
    //     timestamp,
    //     tgid,
    //     pid,
    //     state: SyscallState::AtEnter,
    // };

    info!(
        &ctx,
        "[tracepoint] tgid: {}, pid: {}, time: {}", tgid, pid, timestamp
    );
    Ok(0)
}
