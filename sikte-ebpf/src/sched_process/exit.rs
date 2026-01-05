use aya_ebpf::{EbpfContext, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::{debug, error, warn};
use sikte_common::{
    raw_tracepoints::syscalls::PidT,
    sched_process_fork::{SchedProcessData, SchedProcessExitData},
};

use crate::{
    common::{is_tgid_in_allowlist, remove_tgid_from_allowlist, submit_or_else},
    read_field,
    sched_process::maps::SCHED_PROCESS_EVENTS,
};

/*
name: sched_process_exit
ID: 305
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:char comm[16];	offset:8;	size:16;	signed:0;
    field:pid_t pid;	offset:24;	size:4;	signed:1;
    field:int prio;	offset:28;	size:4;	signed:1;
    field:bool group_dead;	offset:32;	size:1;	signed:0;

print fmt: "comm=%s pid=%d prio=%d group_dead=%s", REC->comm, REC->pid, REC->prio, REC->group_dead ? "true" : "false"
*/

struct SchedProcessExit {
    comm: *const u8,
    pid: PidT,
}

#[tracepoint]
pub fn sikte_sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sched_process_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = read_field!(ctx, SchedProcessExit, pid)?;
    if !is_tgid_in_allowlist(pid) {
        return Ok(0);
    }

    if let Err(e) = remove_tgid_from_allowlist(pid) {
        error!(&ctx, "Error while removing TGID {}: {}", pid, e);
        return Err(1);
    }
    debug!(&ctx, "No longer tracking dead process {}", pid);

    let data = SchedProcessData::Exit(SchedProcessExitData { pid });

    submit_or_else(&SCHED_PROCESS_EVENTS, data, || {
        warn!(
            &ctx,
            "Dropped sched_process_exit data for process with pid {}", pid
        );
    })
}
