use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, r#gen::bpf_ktime_get_ns},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

pub fn try_tracepoints(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & (u32::MAX as u64)) as u32;
    let ns = unsafe { bpf_ktime_get_ns() };

    info!(
        &ctx,
        "[tracepoint] tgid: {}, pid: {}, time: {}", tgid, pid, ns
    );
    Ok(0)
}
