use aya_ebpf::{
    EbpfContext,
    bindings::{__u64, bpf_raw_tracepoint_args},
    cty::{c_int, c_long, c_uchar, c_ulong, c_ushort},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};
use aya_log_ebpf::{error, info};
use sikte_common::SyscallState;

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sikte_raw_trace_point_at_enter(ctx: RawTracePointContext) -> u32 {
    match try_sys_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn try_sys_enter(ctx: RawTracePointContext) -> Result<u32, u32> {
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & (u32::MAX as u64)) as u32;

    let args = ctx.as_ptr() as *const [c_ulong; 2];
    let syscall_nr = unsafe { (*args)[1] };

    info!(
        &ctx,
        // "[ns: {}, tgid: {}, pid: {}] enter syscall {} ", timestamp, tgid, pid, syscall_nr,
        "enter syscall {} ",
        syscall_nr,
    );
    Ok(0)
}

#[raw_tracepoint]
pub fn sikte_raw_trace_point_at_exit(ctx: RawTracePointContext) -> u32 {
    match try_sys_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn try_sys_exit(ctx: RawTracePointContext) -> Result<u32, u32> {
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & (u32::MAX as u64)) as u32;

    let bpf_rtp_args = ctx.as_ptr() as *const bpf_raw_tracepoint_args;
    let args = bpf_rtp_args as *const [u64; 2];
    let syscall_ret = unsafe { (*args)[1] };

    info!(
        &ctx,
        "[ns: {}, tgid: {}, pid: {}] exit syscall with ret {} ",
        timestamp,
        tgid,
        pid,
        syscall_ret as i64,
        // "exit  syscall {} ",
        syscall_nr,
    );
    Ok(0)
}
