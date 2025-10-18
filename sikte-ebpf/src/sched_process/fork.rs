use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::Array,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, error, warn};
use sikte_common::{
    raw_tracepoints::syscalls::PidT,
    sched_process_fork::{SchedProcessData, SchedProcessForkData},
};

use crate::{
    common::{insert_tgid_in_allowlist, is_tgid_in_allowlist, submit_or_else},
    sched_process::maps::SCHED_PROCESS_EVENTS,
};

/*
name: sched_process_fork
ID: 302
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
    field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
    field:__data_loc char[] child_comm;	offset:16;	size:4;	signed:0;
    field:pid_t child_pid;	offset:20;	size:4;	signed:1;

print fmt: "comm=%s pid=%d child_comm=%s child_pid=%d", __get_str(parent_comm), REC->parent_pid, __get_str(child_comm), REC->child_pid
*/

struct SchedProcessFork {
    parent_pid: PidT,
    child_pid: PidT,
}

#[map]
/// Variable which will contain sikte's PID when it wishes to have its own next fork tracked and
/// added to the PID allowlist. When this fork is done, this variable is emptied by kernelspace.
/// Userspace is expected to set this variable each time just before launching a new process or command.
static SCHED_PROCESS_TRACK_SIKTE_NEXT_FORK: Array<PidT> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn sikte_sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let event = ctx.as_ptr() as *const SchedProcessFork;

    let parent_pid = unsafe { (*event).parent_pid };
    if !is_tgid_in_allowlist(parent_pid) && !is_siktes_new_fork(parent_pid) {
        return Ok(0);
    }

    let child_pid = unsafe { (*event).child_pid };

    if let Err(e) = insert_tgid_in_allowlist(child_pid) {
        error!(&ctx, "Error while inserting TGID {}: {}", child_pid, e);
        return Err(1);
    }
    debug!(&ctx, "Tracking new process {}", child_pid);

    let data = SchedProcessData::Fork(SchedProcessForkData {
        parent_pid,
        child_pid,
    });

    submit_or_else(&SCHED_PROCESS_EVENTS, data, || {
        warn!(
            &ctx,
            "Dropped sched_process_fork data where parent pid is {} and child pid {}",
            parent_pid,
            child_pid
        );
    })
}

fn is_siktes_new_fork(parent_pid: PidT) -> bool {
    match SCHED_PROCESS_TRACK_SIKTE_NEXT_FORK.get(0) {
        Some(sikte_pid) => *sikte_pid == parent_pid,
        None => false,
    }
}
