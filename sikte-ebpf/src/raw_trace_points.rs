use aya_ebpf::{
    EbpfContext,
    cty::{c_int, c_long, c_uchar, c_ulong, c_ushort},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};
use aya_log_ebpf::{error, info};
use sikte_common::SyscallState;

// TODO: check if you really needed to manually copy from `/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format`
#[repr(C)]
#[derive(Copy, Clone)]
struct SysEnter {
    common_type: c_ushort,
    common_flags: c_uchar,
    common_preempt_count: c_uchar,
    common_pid: c_int,
    id: c_long,
    args: [c_ulong; 6],
}

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

    let args = ctx.as_ptr() as *const SysEnter;
    let syscall_nr: c_long = unsafe {
        const SYSCALL_ID_OFFSET: usize = core::mem::offset_of!(SysEnter, id);

        match bpf_probe_read_kernel(args.byte_add(SYSCALL_ID_OFFSET) as *const c_long) {
            Ok(syscall) => syscall,
            Err(err) => {
                error!(&ctx, "error sys_enter: {}", err);
                return Err(err as u32);
            }
        }
    };

    info!(
        &ctx,
        // "[ns: {}, tgid: {}, pid: {}] enter syscall {} ", timestamp, tgid, pid, syscall_nr,
        "enter syscall {} ",
        syscall_nr,
    );
    Ok(0)
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SysExit {
    common_type: c_ushort,
    common_flags: c_uchar,
    common_preempt_count: c_uchar,
    common_pid: c_int,
    id: c_long,
    ret: c_long,
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

    let args = ctx.as_ptr() as *const SysExit;
    let syscall_nr: c_long = unsafe {
        const SYSCALL_ID_OFFSET: usize = core::mem::offset_of!(SysExit, id);

        match bpf_probe_read_kernel(args.byte_add(SYSCALL_ID_OFFSET) as *const c_long) {
            Ok(syscall) => syscall,
            Err(err) => {
                error!(&ctx, "error sys_exit: {}", err);
                return Err(err as u32);
            }
        }
    };

    info!(
        &ctx,
        // "[ns: {}, tgid: {}, pid: {}] exit syscall {} ", timestamp, tgid, pid, syscall_nr,
        "exit  syscall {} ",
        syscall_nr,
    );
    Ok(0)
}
