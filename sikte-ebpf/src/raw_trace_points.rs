use aya_ebpf::{
    EbpfContext,
    bindings::{__u64, bpf_raw_tracepoint_args},
    cty::{c_int, c_long, c_uchar, c_ulong, c_ushort},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{map, raw_tracepoint},
    maps::RingBuf,
    programs::RawTracePointContext,
};
use aya_log_ebpf::{error, info, warn};
use sikte_common::{SyscallData, SyscallState};

#[map]
static SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 4, 0);

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

    // https://elixir.bootlin.com/linux/v6.16/source/include/trace/events/syscalls.h#L20
    let args = ctx.as_ptr() as *const [c_ulong; 2];
    let syscall_id = unsafe { (*args)[1] };

    let data = SyscallData {
        timestamp,
        tgid,
        pid,
        state: SyscallState::AtEnter { syscall_id },
    };

    let entry = SYSCALL_EVENTS.reserve::<SyscallData>(0);
    if let Some(mut entry) = entry {
        entry.write(data);
        entry.submit(0);
        Ok(0)
    } else {
        warn!(
            &ctx,
            "Dropped sys_enter data where tgid: {}, pid: {}, syscall id: {}", tgid, pid, syscall_id
        );
        Err(1)
    }
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

    // https://elixir.bootlin.com/linux/v6.16/source/include/trace/events/syscalls.h#L46
    let args = ctx.as_ptr() as *const [c_ulong; 2];
    let syscall_ret = unsafe { (*args)[1] };

    let data = SyscallData {
        timestamp,
        tgid,
        pid,
        state: SyscallState::AtExit { syscall_ret },
    };

    let entry = SYSCALL_EVENTS.reserve::<SyscallData>(0);
    if let Some(mut entry) = entry {
        entry.write(data);
        entry.submit(0);
        Ok(0)
    } else {
        warn!(
            &ctx,
            "Dropped sys_exit  data where tgid: {}, pid: {}, syscall ret: {}",
            tgid,
            pid,
            syscall_ret
        );
        Err(1)
    }
}
